"""
Dynamic Test Data Generation Fixtures using factory_boy Patterns

This module provides comprehensive test data generation fixtures using factory_boy patterns
for creating realistic test objects, user profiles, business data models, and complex data
scenarios with comprehensive validation and edge case coverage per Section 6.6.1 requirements.

The factory fixtures implement:
- factory_boy integration for dynamic test object generation per Section 6.6.1 enhanced mocking strategy
- Production data model parity per Section 6.6.1 test data management
- pydantic model validation in test fixtures per Section 6.6.1
- Date/time handling with python-dateutil per Section 6.6.1
- Comprehensive validation testing with marshmallow schemas per Section 6.6.1
- Realistic test data volumes for performance testing per Section 6.6.1 production data model parity
- Edge case data factories for validation testing per Section 6.6.1 factory pattern
- Complex data scenario factories for integration testing per Section 6.6.1 fixture-based data

Key Features:
- Dynamic user profile generation for authentication and authorization testing
- Business model factories with full pydantic 2.3+ validation support
- Date/time factory patterns using python-dateutil 2.8+ for realistic temporal data
- Edge case and boundary condition testing for comprehensive validation coverage
- Performance test data generation with configurable volumes and complexity
- Integration test scenario factories for multi-component workflows
- MongoDB document structure preservation for seamless data layer testing
- Marshmallow schema validation integration for comprehensive data validation testing

Dependencies:
- factory_boy (≥3.3.0) for dynamic test object generation
- pydantic (≥2.3.0) for data model validation and type checking
- python-dateutil (≥2.8.0) for advanced date/time manipulation
- marshmallow (≥3.20.0) for schema validation testing
- faker (≥19.0.0) for realistic test data generation
- pytest (≥7.4.0) for test framework integration
"""

import uuid
import random
import string
from datetime import datetime, date, timezone, timedelta
from decimal import Decimal
from typing import Any, Dict, List, Optional, Set, Union, Type, Callable
from enum import Enum
import json
import re

# Third-party imports for test data generation
import factory
from factory import fuzzy, SubFactory, LazyFunction, LazyAttribute, Sequence
from factory.alchemy import SQLAlchemyModelFactory
from factory.faker import Faker
from faker import Factory as FakerFactory
from faker.providers import BaseProvider
import pytest

# Date/time handling with python-dateutil per Section 6.6.1
from dateutil.relativedelta import relativedelta
from dateutil.parser import parse as parse_date
from dateutil.tz import tzutc, tzlocal, gettz
from dateutil.utils import today

# Pydantic and marshmallow for validation testing per Section 6.6.1
from pydantic import ValidationError as PydanticValidationError
from marshmallow import ValidationError as MarshmallowValidationError

# Application imports for model validation and factory integration
try:
    from src.business.models import (
        User, UserStatus, UserRole, Organization, Product, ProductCategory, ProductStatus,
        Order, OrderItem, OrderStatus, PaymentTransaction, PaymentStatus, PaymentMethod,
        Address, ContactInfo, ContactMethod, MonetaryAmount, DateTimeRange,
        FileUpload, SystemConfiguration, Priority,
        PaginationParams, SortParams, SearchParams, ApiResponse, PaginatedResponse,
        BaseBusinessModel, BUSINESS_MODEL_REGISTRY
    )
    from src.business.exceptions import (
        DataValidationError, BusinessRuleViolationError, ErrorSeverity
    )
    from src.business.validators import ValidationMode, ValidationType
    from src.data.models import (
        User as DataUser, UserSession, FileMetadata, ApplicationLog, CacheEntry,
        ExternalAPIRequest, Configuration, PyObjectId, MongoBaseModel
    )
except ImportError:
    # Graceful handling if application modules don't exist yet
    # Create mock classes for development purposes
    class BaseBusinessModel:
        pass
    
    class User:
        pass
    
    UserStatus = UserRole = ProductStatus = OrderStatus = PaymentStatus = None
    PaymentMethod = ContactMethod = Priority = ErrorSeverity = None

# Configure structured logging for factory operations
import structlog
logger = structlog.get_logger("tests.factories")

# Initialize Faker instance with locale support
fake = FakerFactory.create(['en_US', 'en_GB', 'de_DE', 'fr_FR', 'es_ES'])


# ============================================================================
# CUSTOM FAKER PROVIDERS FOR BUSINESS-SPECIFIC DATA
# ============================================================================

class BusinessDataProvider(BaseProvider):
    """
    Custom Faker provider for business-specific data generation.
    
    Provides domain-specific data patterns for realistic business test scenarios
    including industry-standard identifiers, business terms, and workflow patterns.
    """
    
    # Business industry classifications
    industries = [
        'Technology', 'Healthcare', 'Finance', 'Retail', 'Manufacturing',
        'Education', 'Real Estate', 'Transportation', 'Energy', 'Agriculture',
        'Entertainment', 'Hospitality', 'Construction', 'Consulting', 'Non-Profit'
    ]
    
    # Business organization types
    organization_types = [
        'Corporation', 'LLC', 'Partnership', 'Sole Proprietorship',
        'Non-Profit', 'Government', 'Cooperative', 'Trust'
    ]
    
    # Payment processor names
    payment_processors = [
        'Stripe', 'PayPal', 'Square', 'Authorize.Net', 'Braintree',
        'Adyen', 'Worldpay', 'First Data', 'Chase Paymentech'
    ]
    
    # Product categories
    product_categories = [
        'Electronics', 'Clothing', 'Books', 'Home & Garden', 'Sports',
        'Toys', 'Automotive', 'Health & Beauty', 'Grocery', 'Software'
    ]
    
    # File categories for uploads
    file_categories = [
        'profile_image', 'document', 'invoice', 'contract', 'report',
        'presentation', 'spreadsheet', 'archive', 'media', 'backup'
    ]
    
    # System configuration categories
    config_categories = [
        'authentication', 'database', 'cache', 'monitoring', 'security',
        'feature_flags', 'api_limits', 'notifications', 'logging', 'performance'
    ]
    
    def industry(self) -> str:
        """Generate a random industry name."""
        return self.random_element(self.industries)
    
    def organization_type(self) -> str:
        """Generate a random organization type."""
        return self.random_element(self.organization_types)
    
    def payment_processor(self) -> str:
        """Generate a random payment processor name."""
        return self.random_element(self.payment_processors)
    
    def product_category(self) -> str:
        """Generate a random product category."""
        return self.random_element(self.product_categories)
    
    def file_category(self) -> str:
        """Generate a random file category."""
        return self.random_element(self.file_categories)
    
    def config_category(self) -> str:
        """Generate a random configuration category."""
        return self.random_element(self.config_categories)
    
    def sku(self, prefix: str = "SKU") -> str:
        """Generate a realistic SKU identifier."""
        return f"{prefix}-{self.random_int(min=1000, max=9999)}-{self.random_letters(length=3).upper()}"
    
    def order_number(self) -> str:
        """Generate a realistic order number."""
        timestamp = datetime.now().strftime("%Y%m%d")
        sequence = self.random_int(min=1000, max=9999)
        return f"ORD-{timestamp}-{sequence}"
    
    def transaction_id(self) -> str:
        """Generate a realistic transaction ID."""
        return f"TXN-{uuid.uuid4().hex[:16].upper()}"
    
    def session_id(self) -> str:
        """Generate a realistic session ID."""
        return f"sess_{uuid.uuid4().hex}"
    
    def api_key(self) -> str:
        """Generate a realistic API key."""
        return f"ak_{uuid.uuid4().hex}"
    
    def jwt_token(self) -> str:
        """Generate a mock JWT token format."""
        header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        payload = self.random_letters(length=64)
        signature = self.random_letters(length=32)
        return f"{header}.{payload}.{signature}"
    
    def phone_number_international(self) -> str:
        """Generate an international phone number."""
        country_codes = ['+1', '+44', '+49', '+33', '+34', '+39', '+31', '+46']
        country_code = self.random_element(country_codes)
        area_code = self.random_int(min=100, max=999)
        number = self.random_int(min=1000000, max=9999999)
        return f"{country_code} {area_code} {number}"
    
    def currency_code(self) -> str:
        """Generate a random currency code."""
        currencies = ['USD', 'EUR', 'GBP', 'JPY', 'CAD', 'AUD', 'CHF', 'CNY']
        return self.random_element(currencies)
    
    def file_extension(self, category: str = None) -> str:
        """Generate a file extension based on category."""
        extensions_by_category = {
            'image': ['jpg', 'jpeg', 'png', 'gif', 'webp'],
            'document': ['pdf', 'doc', 'docx', 'txt', 'rtf'],
            'spreadsheet': ['xls', 'xlsx', 'csv'],
            'presentation': ['ppt', 'pptx'],
            'archive': ['zip', 'tar', 'gz', 'rar'],
            'media': ['mp4', 'mp3', 'avi', 'mov']
        }
        
        if category and category in extensions_by_category:
            return self.random_element(extensions_by_category[category])
        
        all_extensions = []
        for exts in extensions_by_category.values():
            all_extensions.extend(exts)
        return self.random_element(all_extensions)


# Add custom provider to Faker instance
fake.add_provider(BusinessDataProvider)


# ============================================================================
# UTILITY FUNCTIONS FOR FACTORY OPERATIONS
# ============================================================================

def generate_future_datetime(min_days: int = 1, max_days: int = 365) -> datetime:
    """
    Generate a future datetime using python-dateutil per Section 6.6.1.
    
    Args:
        min_days: Minimum days in the future
        max_days: Maximum days in the future
        
    Returns:
        Future datetime with timezone awareness
    """
    base_date = datetime.now(timezone.utc)
    days_ahead = random.randint(min_days, max_days)
    return base_date + relativedelta(days=days_ahead)


def generate_past_datetime(min_days: int = 1, max_days: int = 365) -> datetime:
    """
    Generate a past datetime using python-dateutil per Section 6.6.1.
    
    Args:
        min_days: Minimum days in the past
        max_days: Maximum days in the past
        
    Returns:
        Past datetime with timezone awareness
    """
    base_date = datetime.now(timezone.utc)
    days_back = random.randint(min_days, max_days)
    return base_date - relativedelta(days=days_back)


def generate_date_range(duration_days: int = None) -> tuple[datetime, datetime]:
    """
    Generate a date range using python-dateutil per Section 6.6.1.
    
    Args:
        duration_days: Duration in days (random if None)
        
    Returns:
        Tuple of (start_datetime, end_datetime)
    """
    start_date = generate_past_datetime(max_days=30)
    
    if duration_days is None:
        duration_days = random.randint(1, 30)
    
    end_date = start_date + relativedelta(days=duration_days)
    return start_date, end_date


def generate_business_hours_range() -> tuple[datetime, datetime]:
    """
    Generate a date range within business hours using python-dateutil.
    
    Returns:
        Tuple of business hours datetime range
    """
    today_date = today()
    start_hour = random.randint(9, 16)  # 9 AM to 4 PM
    duration_hours = random.randint(1, 8 - (start_hour - 9))
    
    start_datetime = datetime.combine(today_date, datetime.min.time().replace(hour=start_hour))
    start_datetime = start_datetime.replace(tzinfo=timezone.utc)
    
    end_datetime = start_datetime + relativedelta(hours=duration_hours)
    return start_datetime, end_datetime


def generate_realistic_decimal(min_value: float = 0.01, max_value: float = 999999.99, 
                              decimal_places: int = 2) -> Decimal:
    """
    Generate realistic decimal values for monetary amounts.
    
    Args:
        min_value: Minimum decimal value
        max_value: Maximum decimal value
        decimal_places: Number of decimal places
        
    Returns:
        Decimal value with proper precision
    """
    value = random.uniform(min_value, max_value)
    format_str = f"{{:.{decimal_places}f}}"
    return Decimal(format_str.format(value))


def generate_weighted_choice(choices: List[tuple]) -> Any:
    """
    Generate weighted random choice for realistic distributions.
    
    Args:
        choices: List of (value, weight) tuples
        
    Returns:
        Weighted random choice
    """
    values, weights = zip(*choices)
    return random.choices(values, weights=weights)[0]


def validate_factory_output(model_class: Type, factory_data: Dict[str, Any]) -> bool:
    """
    Validate factory output against pydantic model per Section 6.6.1.
    
    Args:
        model_class: Pydantic model class for validation
        factory_data: Factory-generated data
        
    Returns:
        True if validation passes, False otherwise
    """
    try:
        if hasattr(model_class, 'model_validate'):
            # Pydantic v2 validation
            model_class.model_validate(factory_data)
        elif hasattr(model_class, 'parse_obj'):
            # Pydantic v1 validation (fallback)
            model_class.parse_obj(factory_data)
        else:
            # Non-Pydantic class
            model_class(**factory_data)
        return True
    except Exception as e:
        logger.warning("Factory validation failed", 
                      model=model_class.__name__,
                      error=str(e),
                      data_keys=list(factory_data.keys()))
        return False


# ============================================================================
# BASE FACTORY CLASSES WITH PYDANTIC INTEGRATION
# ============================================================================

class PydanticModelFactory(factory.Factory):
    """
    Base factory class for Pydantic model generation with validation support.
    
    Provides comprehensive factory patterns for Pydantic 2.3+ models with
    built-in validation, error handling, and business rule compliance per
    Section 6.6.1 enhanced mocking strategy.
    
    Features:
    - Automatic pydantic model validation
    - Business rule compliance checking
    - Edge case and boundary condition testing
    - Realistic data distribution patterns
    - Integration with marshmallow schema validation
    """
    
    class Meta:
        abstract = True
    
    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        """
        Override create method to add pydantic validation per Section 6.6.1.
        
        Args:
            model_class: Pydantic model class
            *args: Positional arguments
            **kwargs: Factory data
            
        Returns:
            Validated model instance
            
        Raises:
            ValidationError: If pydantic validation fails
        """
        try:
            # Remove any None values to let defaults work
            clean_kwargs = {k: v for k, v in kwargs.items() if v is not None}
            
            # Create model instance with validation
            if hasattr(model_class, 'model_validate'):
                # Pydantic v2
                instance = model_class.model_validate(clean_kwargs)
            elif hasattr(model_class, 'parse_obj'):
                # Pydantic v1 fallback
                instance = model_class.parse_obj(clean_kwargs)
            else:
                # Regular class instantiation
                instance = model_class(**clean_kwargs)
            
            # Log successful creation for debugging
            logger.debug("Factory created model instance",
                        model_type=model_class.__name__,
                        field_count=len(clean_kwargs))
            
            return instance
            
        except Exception as e:
            logger.error("Factory creation failed",
                        model_type=model_class.__name__,
                        error=str(e),
                        kwargs_keys=list(kwargs.keys()))
            
            # Re-raise with context
            raise DataValidationError(
                message=f"Factory failed to create {model_class.__name__}",
                error_code="FACTORY_CREATION_FAILED",
                context={
                    'model_type': model_class.__name__,
                    'provided_fields': list(kwargs.keys())
                },
                cause=e
            )
    
    @classmethod
    def create_batch_validated(cls, size: int, **kwargs) -> List[Any]:
        """
        Create a batch of validated model instances.
        
        Args:
            size: Number of instances to create
            **kwargs: Factory parameters
            
        Returns:
            List of validated model instances
        """
        instances = []
        for i in range(size):
            try:
                instance = cls.create(**kwargs)
                instances.append(instance)
            except Exception as e:
                logger.warning("Batch creation failed for item",
                              index=i,
                              error=str(e))
                # Continue with next item rather than failing entire batch
                continue
        
        logger.info("Batch creation completed",
                   requested_size=size,
                   created_size=len(instances))
        
        return instances
    
    @classmethod
    def create_edge_case(cls, edge_case_type: str = "boundary", **kwargs) -> Any:
        """
        Create edge case test instances for comprehensive validation testing.
        
        Args:
            edge_case_type: Type of edge case ('boundary', 'invalid', 'minimal', 'maximal')
            **kwargs: Override parameters
            
        Returns:
            Edge case model instance
        """
        edge_kwargs = kwargs.copy()
        
        if edge_case_type == "minimal":
            # Create instance with minimal required fields
            edge_kwargs.update({
                # Add minimal value overrides based on model type
                'email': 'a@b.co',  # Minimal valid email
                'name': 'A',        # Minimal name
                'amount': Decimal('0.01'),  # Minimal amount
            })
        
        elif edge_case_type == "maximal":
            # Create instance with maximum allowed values
            edge_kwargs.update({
                'email': 'a' * 50 + '@' + 'b' * 50 + '.com',  # Long email
                'name': 'A' * 200,  # Long name
                'description': 'D' * 2000,  # Long description
            })
        
        elif edge_case_type == "boundary":
            # Create instance at boundary conditions
            edge_kwargs.update({
                'created_at': datetime.now(timezone.utc),
                'updated_at': datetime.now(timezone.utc),
            })
        
        return cls.create(**edge_kwargs)


class MongoModelFactory(PydanticModelFactory):
    """
    Base factory class for MongoDB model generation with ObjectId support.
    
    Extends PydanticModelFactory with MongoDB-specific patterns including
    ObjectId generation, document structure preservation, and database-ready
    test data generation per Section 6.6.1 test data management.
    """
    
    class Meta:
        abstract = True
    
    # Standard MongoDB fields
    id = LazyFunction(lambda: str(uuid.uuid4()))
    created_at = LazyFunction(lambda: datetime.now(timezone.utc))
    updated_at = LazyFunction(lambda: datetime.now(timezone.utc))
    
    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        """Override to handle MongoDB ObjectId conversion."""
        # Convert string IDs to ObjectId if needed
        if 'id' in kwargs and isinstance(kwargs['id'], str):
            try:
                from bson import ObjectId
                if not kwargs['id'].startswith('ObjectId'):
                    kwargs['id'] = str(ObjectId())
            except ImportError:
                # If bson not available, keep as string
                pass
        
        return super()._create(model_class, *args, **kwargs)


# ============================================================================
# USER AND AUTHENTICATION FACTORIES
# ============================================================================

class UserStatusFactory(factory.Factory):
    """Factory for generating user status values with realistic distribution."""
    
    class Meta:
        model = dict
    
    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        # Realistic distribution of user statuses
        status_weights = [
            ('active', 70),      # Most users are active
            ('inactive', 15),    # Some inactive users
            ('pending', 10),     # New pending users
            ('suspended', 4),    # Few suspended users
            ('archived', 1),     # Very few archived users
        ]
        return generate_weighted_choice(status_weights)


class UserRoleFactory(factory.Factory):
    """Factory for generating user roles with realistic distribution."""
    
    class Meta:
        model = dict
    
    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        # Realistic distribution of user roles
        role_weights = [
            ('user', 80),        # Most users are regular users
            ('manager', 15),     # Some managers
            ('admin', 4),        # Few admins
            ('guest', 1),        # Very few guests
        ]
        return generate_weighted_choice(role_weights)


class ContactInfoFactory(PydanticModelFactory):
    """
    Factory for generating realistic contact information.
    
    Creates comprehensive contact data with realistic phone numbers,
    email addresses, and communication preferences for authentication
    and user profile testing per Section 6.6.1.
    """
    
    class Meta:
        model = ContactInfo if 'ContactInfo' in globals() else dict
    
    primary_email = Faker('email')
    secondary_email = Faker('email')
    primary_phone = LazyFunction(lambda: fake.phone_number_international())
    secondary_phone = LazyFunction(lambda: fake.phone_number_international())
    preferred_contact_method = LazyFunction(lambda: generate_weighted_choice([
        ('email', 60),
        ('phone', 30),
        ('sms', 8),
        ('in_app', 2)
    ]))
    allow_marketing = LazyFunction(lambda: random.choice([True, False]))
    timezone = Faker('timezone')


class AddressFactory(PydanticModelFactory):
    """
    Factory for generating realistic address information.
    
    Creates geographically consistent address data with proper postal codes,
    country codes, and regional formatting for comprehensive location testing.
    """
    
    class Meta:
        model = Address if 'Address' in globals() else dict
    
    street_line_1 = Faker('street_address')
    street_line_2 = LazyFunction(lambda: fake.secondary_address() if random.random() < 0.3 else None)
    city = Faker('city')
    state_province = Faker('state')
    postal_code = Faker('postcode')
    country_code = LazyFunction(lambda: generate_weighted_choice([
        ('US', 40),
        ('CA', 15),
        ('GB', 10),
        ('DE', 8),
        ('FR', 7),
        ('AU', 5),
        ('NL', 3),
        ('ES', 3),
        ('IT', 3),
        ('SE', 2),
        ('NO', 2),
        ('DK', 2)
    ]))


class UserFactory(PydanticModelFactory):
    """
    Comprehensive user profile factory for authentication and authorization testing.
    
    Generates realistic user profiles with proper authentication data, contact
    information, preferences, and access control patterns per Section 6.6.1
    test data management requirements.
    
    Features:
    - Realistic user data distribution
    - Proper email and username generation
    - Authentication metadata
    - Contact information integration
    - Role-based permission assignment
    - Account status and security settings
    """
    
    class Meta:
        model = User if 'User' in globals() else dict
    
    # Core identification
    id = LazyFunction(lambda: str(uuid.uuid4()))
    username = Sequence(lambda n: f"user_{n:04d}")
    email = Faker('email')
    
    # Personal information
    first_name = Faker('first_name')
    last_name = Faker('last_name')
    display_name = LazyAttribute(lambda obj: f"{obj.first_name} {obj.last_name}")
    avatar_url = LazyFunction(lambda: f"https://api.dicebear.com/7.x/avataaars/svg?seed={uuid.uuid4().hex}")
    
    # Account status and role
    status = LazyFunction(UserStatusFactory._create)
    role = LazyFunction(UserRoleFactory._create)
    permissions = LazyFunction(lambda: random.sample([
        'read_profile', 'update_profile', 'read_orders', 'create_orders',
        'read_products', 'manage_products', 'read_users', 'manage_users',
        'read_reports', 'create_reports', 'system_admin'
    ], k=random.randint(1, 5)))
    
    # Contact information
    contact_info = SubFactory(ContactInfoFactory)
    
    # Authentication and security
    last_login_at = LazyFunction(lambda: generate_past_datetime(max_days=30))
    password_changed_at = LazyFunction(lambda: generate_past_datetime(max_days=90))
    login_attempts = LazyFunction(lambda: random.randint(0, 3))
    is_locked = LazyFunction(lambda: random.random() < 0.05)  # 5% locked accounts
    lock_expires_at = LazyFunction(lambda: generate_future_datetime(max_days=7) if random.random() < 0.05 else None)
    
    # Preferences
    language_code = LazyFunction(lambda: generate_weighted_choice([
        ('en', 60),
        ('es', 15),
        ('fr', 8),
        ('de', 7),
        ('it', 5),
        ('pt', 3),
        ('nl', 2)
    ]))
    timezone = Faker('timezone')
    date_format = LazyFunction(lambda: generate_weighted_choice([
        ('YYYY-MM-DD', 40),
        ('MM/DD/YYYY', 30),
        ('DD/MM/YYYY', 20),
        ('DD-MM-YYYY', 10)
    ]))
    
    # Audit fields
    created_at = LazyFunction(lambda: generate_past_datetime(max_days=365))
    updated_at = LazyFunction(lambda: datetime.now(timezone.utc))
    version = 1
    
    @classmethod
    def create_admin_user(cls, **kwargs) -> Any:
        """Create an admin user with elevated permissions."""
        admin_kwargs = {
            'role': 'admin',
            'status': 'active',
            'permissions': [
                'read_profile', 'update_profile', 'read_orders', 'create_orders',
                'manage_orders', 'read_products', 'manage_products', 'read_users',
                'manage_users', 'read_reports', 'create_reports', 'manage_reports',
                'system_admin', 'user_admin', 'content_admin'
            ],
            'is_locked': False,
            'email_verified': True,
        }
        admin_kwargs.update(kwargs)
        return cls.create(**admin_kwargs)
    
    @classmethod
    def create_locked_user(cls, **kwargs) -> Any:
        """Create a locked user for security testing."""
        locked_kwargs = {
            'status': 'suspended',
            'is_locked': True,
            'lock_expires_at': generate_future_datetime(min_days=1, max_days=30),
            'failed_login_attempts': random.randint(5, 10),
            'last_login_at': generate_past_datetime(min_days=7, max_days=30),
        }
        locked_kwargs.update(kwargs)
        return cls.create(**locked_kwargs)
    
    @classmethod
    def create_new_user(cls, **kwargs) -> Any:
        """Create a new pending user for registration testing."""
        new_kwargs = {
            'status': 'pending',
            'email_verified': False,
            'phone_verified': False,
            'login_count': 0,
            'last_login_at': None,
            'permissions': ['read_profile'],
            'created_at': datetime.now(timezone.utc),
            'updated_at': datetime.now(timezone.utc),
        }
        new_kwargs.update(kwargs)
        return cls.create(**new_kwargs)


class DataUserFactory(MongoModelFactory):
    """
    Data layer user factory for MongoDB document testing.
    
    Creates MongoDB-compatible user documents preserving existing document
    structures from Node.js implementation for data layer integration testing.
    """
    
    class Meta:
        model = DataUser if 'DataUser' in globals() else dict
    
    # MongoDB document structure preservation
    email = Faker('email')
    username = Sequence(lambda n: f"datauser_{n:04d}")
    password_hash = LazyFunction(lambda: f"$2b$12${uuid.uuid4().hex}")
    salt = LazyFunction(lambda: uuid.uuid4().hex[:16])
    
    # Profile data
    first_name = Faker('first_name')
    last_name = Faker('last_name')
    display_name = LazyAttribute(lambda obj: f"{obj.first_name} {obj.last_name}")
    avatar_url = LazyFunction(lambda: f"https://api.dicebear.com/7.x/avataaars/svg?seed={uuid.uuid4().hex}")
    
    # Status and role
    status = LazyFunction(UserStatusFactory._create)
    role = LazyFunction(UserRoleFactory._create)
    permissions = LazyFunction(lambda: random.sample([
        'read_profile', 'update_profile', 'read_orders', 'create_orders'
    ], k=random.randint(1, 3)))
    
    # External auth integration
    auth0_user_id = LazyFunction(lambda: f"auth0|{uuid.uuid4().hex}")
    external_ids = LazyFunction(lambda: {
        'google': f"google_{uuid.uuid4().hex}",
        'facebook': f"facebook_{random.randint(100000, 999999)}"
    } if random.random() < 0.3 else {})
    
    # Account verification
    email_verified = LazyFunction(lambda: random.random() < 0.8)
    phone_number = LazyFunction(lambda: fake.phone_number_international() if random.random() < 0.6 else None)
    phone_verified = LazyFunction(lambda: random.random() < 0.7)
    
    # Activity tracking
    last_login = LazyFunction(lambda: generate_past_datetime(max_days=30))
    last_activity = LazyFunction(lambda: generate_past_datetime(max_days=7))
    login_count = LazyFunction(lambda: random.randint(1, 100))
    
    # Security fields
    failed_login_attempts = LazyFunction(lambda: random.randint(0, 3))
    account_locked_until = LazyFunction(lambda: generate_future_datetime(max_days=7) if random.random() < 0.05 else None)
    password_changed_at = LazyFunction(lambda: generate_past_datetime(max_days=90))
    
    # User preferences
    preferences = LazyFunction(lambda: {
        'theme': random.choice(['light', 'dark']),
        'notifications': random.choice([True, False]),
        'language': random.choice(['en', 'es', 'fr', 'de']),
        'timezone': fake.timezone()
    })
    privacy_settings = LazyFunction(lambda: {
        'public_profile': random.choice([True, False]),
        'show_email': random.choice([True, False]),
        'marketing_emails': random.choice([True, False])
    })


class UserSessionFactory(MongoModelFactory):
    """
    User session factory for session management testing.
    
    Creates realistic user session data for authentication state testing,
    Redis session storage validation, and distributed session management.
    """
    
    class Meta:
        model = UserSession if 'UserSession' in globals() else dict
    
    session_id = LazyFunction(lambda: fake.session_id())
    user_id = LazyFunction(lambda: str(uuid.uuid4()))
    
    # Session metadata
    status = LazyFunction(lambda: generate_weighted_choice([
        ('active', 80),
        ('expired', 15),
        ('revoked', 5)
    ]))
    ip_address = Faker('ipv4')
    user_agent = Faker('user_agent')
    
    # Session lifecycle
    expires_at = LazyFunction(lambda: generate_future_datetime(min_days=1, max_days=30))
    last_accessed = LazyFunction(lambda: generate_past_datetime(max_days=1))
    
    # Security tokens
    csrf_token = LazyFunction(lambda: uuid.uuid4().hex)
    refresh_token = LazyFunction(lambda: uuid.uuid4().hex)
    login_method = LazyFunction(lambda: random.choice(['password', 'oauth', 'sso', 'api_key']))
    
    # Session data
    data = LazyFunction(lambda: {
        'user_preferences': {
            'theme': random.choice(['light', 'dark']),
            'language': random.choice(['en', 'es', 'fr', 'de'])
        },
        'cart_items': random.randint(0, 5),
        'last_page': fake.uri_path(),
        'session_start': datetime.now(timezone.utc).isoformat()
    })


# ============================================================================
# BUSINESS MODEL FACTORIES
# ============================================================================

class MonetaryAmountFactory(PydanticModelFactory):
    """
    Factory for generating realistic monetary amounts with proper precision.
    
    Creates monetary data with appropriate currency codes, decimal precision,
    and realistic value distributions for financial testing scenarios.
    """
    
    class Meta:
        model = MonetaryAmount if 'MonetaryAmount' in globals() else dict
    
    amount = LazyFunction(lambda: generate_realistic_decimal(0.01, 999999.99))
    currency_code = LazyFunction(lambda: fake.currency_code())
    
    @classmethod
    def create_small_amount(cls, **kwargs) -> Any:
        """Create small monetary amounts for micro-transaction testing."""
        small_kwargs = {
            'amount': generate_realistic_decimal(0.01, 9.99),
            'currency_code': 'USD'
        }
        small_kwargs.update(kwargs)
        return cls.create(**small_kwargs)
    
    @classmethod
    def create_large_amount(cls, **kwargs) -> Any:
        """Create large monetary amounts for enterprise transaction testing."""
        large_kwargs = {
            'amount': generate_realistic_decimal(10000.00, 999999.99),
            'currency_code': 'USD'
        }
        large_kwargs.update(kwargs)
        return cls.create(**large_kwargs)
    
    @classmethod
    def create_zero_amount(cls, **kwargs) -> Any:
        """Create zero amount for free product/service testing."""
        zero_kwargs = {
            'amount': Decimal('0.00'),
            'currency_code': 'USD'
        }
        zero_kwargs.update(kwargs)
        return cls.create(**zero_kwargs)


class DateTimeRangeFactory(PydanticModelFactory):
    """
    Factory for generating date/time ranges using python-dateutil per Section 6.6.1.
    
    Creates realistic temporal ranges for appointment scheduling, business hours,
    event management, and time-based business logic testing.
    """
    
    class Meta:
        model = DateTimeRange if 'DateTimeRange' in globals() else dict
    
    start_datetime = LazyFunction(lambda: generate_past_datetime(max_days=30))
    end_datetime = LazyFunction(lambda: generate_future_datetime(min_days=1, max_days=60))
    timezone_name = Faker('timezone')
    all_day = LazyFunction(lambda: random.random() < 0.2)  # 20% all-day events
    
    @classmethod
    def create_business_hours(cls, **kwargs) -> Any:
        """Create business hours range for scheduling testing."""
        start_dt, end_dt = generate_business_hours_range()
        business_kwargs = {
            'start_datetime': start_dt,
            'end_datetime': end_dt,
            'timezone_name': 'UTC',
            'all_day': False
        }
        business_kwargs.update(kwargs)
        return cls.create(**business_kwargs)
    
    @classmethod
    def create_all_day_event(cls, **kwargs) -> Any:
        """Create all-day event range for calendar testing."""
        today_date = today()
        start_dt = datetime.combine(today_date, datetime.min.time()).replace(tzinfo=timezone.utc)
        end_dt = start_dt + relativedelta(days=1)
        
        all_day_kwargs = {
            'start_datetime': start_dt,
            'end_datetime': end_dt,
            'timezone_name': 'UTC',
            'all_day': True
        }
        all_day_kwargs.update(kwargs)
        return cls.create(**all_day_kwargs)


class OrganizationFactory(PydanticModelFactory):
    """
    Organization factory for business entity testing.
    
    Creates realistic organization data with proper business identifiers,
    contact information, and hierarchical relationships for B2B testing scenarios.
    """
    
    class Meta:
        model = Organization if 'Organization' in globals() else dict
    
    id = LazyFunction(lambda: str(uuid.uuid4()))
    name = Faker('company')
    legal_name = LazyAttribute(lambda obj: f"{obj.name} LLC")
    business_type = LazyFunction(lambda: fake.organization_type())
    
    # Business identifiers
    tax_id = LazyFunction(lambda: f"{random.randint(10, 99)}-{random.randint(1000000, 9999999)}")
    registration_number = LazyFunction(lambda: f"REG{random.randint(100000, 999999)}")
    
    # Contact information
    primary_contact = SubFactory(ContactInfoFactory)
    billing_address = SubFactory(AddressFactory)
    shipping_address = SubFactory(AddressFactory)
    
    # Business details
    website_url = Faker('url')
    description = Faker('text', max_nb_chars=500)
    industry = LazyFunction(lambda: fake.industry())
    employee_count = LazyFunction(lambda: generate_weighted_choice([
        (random.randint(1, 10), 30),      # Small business
        (random.randint(11, 50), 25),     # Medium business
        (random.randint(51, 200), 20),    # Large business
        (random.randint(201, 1000), 15),  # Enterprise
        (random.randint(1001, 5000), 10), # Large enterprise
    ]))
    
    # Status and verification
    status = LazyFunction(UserStatusFactory._create)
    is_verified = LazyFunction(lambda: random.random() < 0.7)  # 70% verified
    verification_date = LazyFunction(lambda: generate_past_datetime(max_days=180) if random.random() < 0.7 else None)
    
    # Hierarchy
    parent_organization_id = LazyFunction(lambda: str(uuid.uuid4()) if random.random() < 0.2 else None)
    
    # Audit fields
    created_at = LazyFunction(lambda: generate_past_datetime(max_days=365))
    updated_at = LazyFunction(lambda: datetime.now(timezone.utc))
    version = 1


class ProductCategoryFactory(PydanticModelFactory):
    """
    Product category factory for catalog organization testing.
    
    Creates hierarchical product categories with realistic names, descriptions,
    and display settings for e-commerce catalog management testing.
    """
    
    class Meta:
        model = ProductCategory if 'ProductCategory' in globals() else dict
    
    id = LazyFunction(lambda: str(uuid.uuid4()))
    name = LazyFunction(lambda: fake.product_category())
    slug = LazyAttribute(lambda obj: re.sub(r'[^a-z0-9\-]', '', obj.name.lower().replace(' ', '-')))
    description = Faker('text', max_nb_chars=300)
    
    # Hierarchy
    parent_category_id = LazyFunction(lambda: str(uuid.uuid4()) if random.random() < 0.3 else None)
    sort_order = LazyFunction(lambda: random.randint(0, 100))
    
    # Display settings
    image_url = LazyFunction(lambda: f"https://picsum.photos/400/300?random={random.randint(1, 1000)}")
    is_visible = LazyFunction(lambda: random.random() < 0.9)  # 90% visible
    
    # Audit fields
    created_at = LazyFunction(lambda: generate_past_datetime(max_days=365))
    updated_at = LazyFunction(lambda: datetime.now(timezone.utc))
    version = 1


class ProductFactory(PydanticModelFactory):
    """
    Product factory for catalog and inventory testing.
    
    Creates comprehensive product data with pricing, inventory, categorization,
    and metadata for e-commerce testing scenarios per Section 6.6.1.
    """
    
    class Meta:
        model = Product if 'Product' in globals() else dict
    
    id = LazyFunction(lambda: str(uuid.uuid4()))
    sku = LazyFunction(lambda: fake.sku())
    name = Faker('catch_phrase')
    slug = LazyAttribute(lambda obj: re.sub(r'[^a-z0-9\-]', '', obj.name.lower().replace(' ', '-')))
    description = Faker('text', max_nb_chars=1500)
    short_description = Faker('text', max_nb_chars=300)
    
    # Categorization
    category_id = LazyFunction(lambda: str(uuid.uuid4()))
    tags = LazyFunction(lambda: random.sample([
        'electronics', 'clothing', 'home', 'sports', 'books', 'toys',
        'automotive', 'health', 'beauty', 'garden', 'tools', 'music'
    ], k=random.randint(1, 4)))
    brand = Faker('company')
    
    # Pricing
    base_price = SubFactory(MonetaryAmountFactory)
    sale_price = LazyFunction(lambda: MonetaryAmountFactory.create_small_amount() if random.random() < 0.3 else None)
    cost_price = LazyFunction(lambda: MonetaryAmountFactory.create_small_amount() if random.random() < 0.8 else None)
    
    # Inventory
    status = LazyFunction(lambda: generate_weighted_choice([
        ('active', 70),
        ('inactive', 15),
        ('out_of_stock', 10),
        ('discontinued', 4),
        ('draft', 1)
    ]))
    inventory_quantity = LazyFunction(lambda: random.randint(0, 1000))
    low_stock_threshold = LazyFunction(lambda: random.randint(5, 20))
    track_inventory = LazyFunction(lambda: random.random() < 0.9)  # 90% track inventory
    
    # Physical attributes
    weight = LazyFunction(lambda: generate_realistic_decimal(0.1, 50.0) if random.random() < 0.8 else None)
    dimensions = LazyFunction(lambda: {
        'length': float(generate_realistic_decimal(1.0, 100.0)),
        'width': float(generate_realistic_decimal(1.0, 100.0)),
        'height': float(generate_realistic_decimal(1.0, 100.0))
    } if random.random() < 0.7 else None)
    
    # Digital content
    images = LazyFunction(lambda: [
        f"https://picsum.photos/800/600?random={random.randint(1, 1000) + i}"
        for i in range(random.randint(1, 5))
    ])
    documents = LazyFunction(lambda: [
        {
            'name': f'document_{i}.pdf',
            'url': f'https://example.com/docs/document_{i}.pdf',
            'type': 'manual'
        }
        for i in range(random.randint(0, 3))
    ])
    
    # SEO
    meta_title = LazyAttribute(lambda obj: obj.name[:60])
    meta_description = LazyAttribute(lambda obj: obj.short_description[:160] if obj.short_description else None)
    
    # Audit fields
    created_at = LazyFunction(lambda: generate_past_datetime(max_days=365))
    updated_at = LazyFunction(lambda: datetime.now(timezone.utc))
    version = 1
    
    @classmethod
    def create_digital_product(cls, **kwargs) -> Any:
        """Create digital product without physical attributes."""
        digital_kwargs = {
            'weight': None,
            'dimensions': None,
            'track_inventory': False,
            'inventory_quantity': 999999,  # Unlimited digital inventory
        }
        digital_kwargs.update(kwargs)
        return cls.create(**digital_kwargs)
    
    @classmethod
    def create_out_of_stock_product(cls, **kwargs) -> Any:
        """Create out-of-stock product for inventory testing."""
        oos_kwargs = {
            'status': 'out_of_stock',
            'inventory_quantity': 0,
            'track_inventory': True,
        }
        oos_kwargs.update(kwargs)
        return cls.create(**oos_kwargs)


class OrderItemFactory(PydanticModelFactory):
    """
    Order item factory for line item testing.
    
    Creates realistic order line items with product references, quantities,
    pricing calculations, and discount applications for order processing testing.
    """
    
    class Meta:
        model = OrderItem if 'OrderItem' in globals() else dict
    
    product_id = LazyFunction(lambda: str(uuid.uuid4()))
    product_sku = LazyFunction(lambda: fake.sku())
    product_name = Faker('catch_phrase')
    quantity = LazyFunction(lambda: random.randint(1, 10))
    unit_price = SubFactory(MonetaryAmountFactory)
    
    # Calculated fields
    total_price = LazyAttribute(lambda obj: MonetaryAmount(
        amount=obj.unit_price.amount * obj.quantity,
        currency_code=obj.unit_price.currency_code
    ))
    
    # Optional discounts and taxes
    discount_amount = LazyFunction(lambda: MonetaryAmountFactory.create_small_amount() if random.random() < 0.2 else None)
    tax_amount = LazyFunction(lambda: MonetaryAmountFactory.create_small_amount() if random.random() < 0.8 else None)
    
    # Product snapshot
    product_attributes = LazyFunction(lambda: {
        'color': random.choice(['red', 'blue', 'green', 'black', 'white']),
        'size': random.choice(['XS', 'S', 'M', 'L', 'XL']),
        'material': random.choice(['cotton', 'polyester', 'wool', 'silk', 'denim'])
    } if random.random() < 0.6 else None)


class OrderFactory(PydanticModelFactory):
    """
    Order factory for transaction and order management testing.
    
    Creates comprehensive order data with customer information, line items,
    pricing calculations, and status tracking for e-commerce workflow testing.
    """
    
    class Meta:
        model = Order if 'Order' in globals() else dict
    
    id = LazyFunction(lambda: str(uuid.uuid4()))
    order_number = LazyFunction(lambda: fake.order_number())
    
    # Customer information
    customer_id = LazyFunction(lambda: str(uuid.uuid4()) if random.random() < 0.8 else None)
    customer_email = Faker('email')
    customer_name = Faker('name')
    
    # Order items - create 1-5 items per order
    items = LazyFunction(lambda: OrderItemFactory.create_batch_validated(random.randint(1, 5)))
    
    # Pricing calculations
    subtotal = LazyFunction(lambda: MonetaryAmountFactory.create_large_amount())
    tax_amount = LazyFunction(lambda: MonetaryAmountFactory.create_small_amount())
    shipping_amount = LazyFunction(lambda: MonetaryAmountFactory.create_small_amount())
    discount_amount = LazyFunction(lambda: MonetaryAmountFactory.create_small_amount() if random.random() < 0.3 else MonetaryAmount(amount=Decimal('0.00'), currency_code='USD'))
    total_amount = LazyAttribute(lambda obj: MonetaryAmount(
        amount=obj.subtotal.amount + obj.tax_amount.amount + obj.shipping_amount.amount - obj.discount_amount.amount,
        currency_code=obj.subtotal.currency_code
    ))
    
    # Addresses
    billing_address = SubFactory(AddressFactory)
    shipping_address = SubFactory(AddressFactory)
    
    # Status and tracking
    status = LazyFunction(lambda: generate_weighted_choice([
        ('pending', 20),
        ('confirmed', 25),
        ('processing', 20),
        ('shipped', 20),
        ('delivered', 10),
        ('cancelled', 4),
        ('refunded', 1)
    ]))
    order_date = LazyFunction(lambda: generate_past_datetime(max_days=30))
    shipped_date = LazyFunction(lambda: generate_past_datetime(max_days=14) if random.random() < 0.6 else None)
    delivered_date = LazyFunction(lambda: generate_past_datetime(max_days=7) if random.random() < 0.4 else None)
    
    # Additional information
    notes = LazyFunction(lambda: fake.text(max_nb_chars=200) if random.random() < 0.3 else None)
    tracking_number = LazyFunction(lambda: f"TRK{random.randint(100000000, 999999999)}" if random.random() < 0.6 else None)
    payment_method = LazyFunction(lambda: generate_weighted_choice([
        ('credit_card', 60),
        ('debit_card', 20),
        ('digital_wallet', 10),
        ('bank_transfer', 5),
        ('cash', 3),
        ('cryptocurrency', 2)
    ]))
    
    # Audit fields
    created_at = LazyFunction(lambda: generate_past_datetime(max_days=90))
    updated_at = LazyFunction(lambda: datetime.now(timezone.utc))
    version = 1
    
    @classmethod
    def create_completed_order(cls, **kwargs) -> Any:
        """Create completed order for fulfillment testing."""
        completed_kwargs = {
            'status': 'delivered',
            'shipped_date': generate_past_datetime(min_days=7, max_days=21),
            'delivered_date': generate_past_datetime(min_days=1, max_days=7),
            'tracking_number': f"TRK{random.randint(100000000, 999999999)}"
        }
        completed_kwargs.update(kwargs)
        return cls.create(**completed_kwargs)
    
    @classmethod
    def create_cancelled_order(cls, **kwargs) -> Any:
        """Create cancelled order for refund testing."""
        cancelled_kwargs = {
            'status': 'cancelled',
            'shipped_date': None,
            'delivered_date': None,
            'tracking_number': None,
            'notes': 'Order cancelled by customer request'
        }
        cancelled_kwargs.update(kwargs)
        return cls.create(**cancelled_kwargs)


class PaymentTransactionFactory(PydanticModelFactory):
    """
    Payment transaction factory for financial processing testing.
    
    Creates realistic payment transaction data with security metadata,
    processor integration, and status tracking for payment workflow testing.
    """
    
    class Meta:
        model = PaymentTransaction if 'PaymentTransaction' in globals() else dict
    
    id = LazyFunction(lambda: str(uuid.uuid4()))
    transaction_id = LazyFunction(lambda: fake.transaction_id())
    
    # Related entities
    order_id = LazyFunction(lambda: str(uuid.uuid4()))
    customer_id = LazyFunction(lambda: str(uuid.uuid4()))
    
    # Payment details
    amount = SubFactory(MonetaryAmountFactory)
    payment_method = LazyFunction(lambda: generate_weighted_choice([
        ('credit_card', 60),
        ('debit_card', 20),
        ('digital_wallet', 10),
        ('bank_transfer', 5),
        ('cash', 3),
        ('cryptocurrency', 2)
    ]))
    payment_status = LazyFunction(lambda: generate_weighted_choice([
        ('completed', 70),
        ('pending', 15),
        ('processing', 8),
        ('failed', 5),
        ('cancelled', 2)
    ]))
    
    # Payment processor
    processor_name = LazyFunction(lambda: fake.payment_processor())
    processor_response = LazyFunction(lambda: {
        'transaction_id': fake.transaction_id(),
        'authorization_code': f"AUTH{random.randint(100000, 999999)}",
        'response_code': '00' if random.random() < 0.9 else '05',
        'message': 'Approved' if random.random() < 0.9 else 'Declined'
    })
    
    # Security and fraud detection
    risk_score = LazyFunction(lambda: round(random.uniform(0.0, 1.0), 3))
    ip_address = Faker('ipv4')
    user_agent = Faker('user_agent')
    
    # Timestamps
    initiated_at = LazyFunction(lambda: generate_past_datetime(max_days=30))
    processed_at = LazyAttribute(lambda obj: obj.initiated_at + relativedelta(seconds=random.randint(1, 300)) if obj.payment_status == 'completed' else None)
    expires_at = LazyFunction(lambda: generate_future_datetime(min_days=1, max_days=7))
    
    # Additional information
    description = Faker('text', max_nb_chars=200)
    reference_number = LazyFunction(lambda: f"REF{random.randint(100000, 999999)}")
    failure_reason = LazyFunction(lambda: random.choice([
        'Insufficient funds', 'Card expired', 'Invalid card number',
        'Transaction declined by issuer', 'Security verification failed'
    ]) if random.random() < 0.1 else None)
    
    # Audit fields
    created_at = LazyFunction(lambda: generate_past_datetime(max_days=90))
    updated_at = LazyFunction(lambda: datetime.now(timezone.utc))
    version = 1
    
    @classmethod
    def create_failed_transaction(cls, **kwargs) -> Any:
        """Create failed transaction for error handling testing."""
        failed_kwargs = {
            'payment_status': 'failed',
            'processed_at': None,
            'failure_reason': random.choice([
                'Insufficient funds', 'Card expired', 'Invalid card number',
                'Transaction declined by issuer', 'Security verification failed'
            ]),
            'processor_response': {
                'response_code': '05',
                'message': 'Declined'
            }
        }
        failed_kwargs.update(kwargs)
        return cls.create(**failed_kwargs)


# ============================================================================
# FILE AND SYSTEM MODEL FACTORIES
# ============================================================================

class FileUploadFactory(PydanticModelFactory):
    """
    File upload factory for file management testing.
    
    Creates realistic file upload data with proper MIME types, size validation,
    security metadata, and storage information for file processing workflows.
    """
    
    class Meta:
        model = FileUpload if 'FileUpload' in globals() else dict
    
    id = LazyFunction(lambda: str(uuid.uuid4()))
    filename = LazyFunction(lambda: f"{fake.word()}.{fake.file_extension()}")
    content_type = LazyFunction(lambda: generate_weighted_choice([
        ('image/jpeg', 25),
        ('image/png', 20),
        ('application/pdf', 20),
        ('text/plain', 10),
        ('application/msword', 8),
        ('application/vnd.openxmlformats-officedocument.wordprocessingml.document', 7),
        ('application/vnd.ms-excel', 5),
        ('text/csv', 3),
        ('application/json', 2)
    ]))
    file_size = LazyFunction(lambda: random.randint(1024, 10_000_000))  # 1KB to 10MB
    
    # Storage information
    storage_path = LazyFunction(lambda: f"uploads/{uuid.uuid4().hex[:8]}/{uuid.uuid4().hex}")
    storage_url = LazyAttribute(lambda obj: f"https://cdn.example.com/{obj.storage_path}")
    
    # Security and validation
    checksum = LazyFunction(lambda: uuid.uuid4().hex)
    is_virus_scanned = LazyFunction(lambda: random.random() < 0.95)  # 95% scanned
    scan_result = LazyFunction(lambda: 'clean' if random.random() < 0.99 else 'threat_detected')
    
    # Metadata
    uploaded_by = LazyFunction(lambda: str(uuid.uuid4()))
    upload_date = LazyFunction(lambda: generate_past_datetime(max_days=30))
    expires_at = LazyFunction(lambda: generate_future_datetime(min_days=30, max_days=365))
    
    # Categorization
    category = LazyFunction(lambda: fake.file_category())
    tags = LazyFunction(lambda: random.sample([
        'document', 'image', 'report', 'invoice', 'contract',
        'presentation', 'media', 'backup', 'import', 'export'
    ], k=random.randint(1, 3)))
    
    # Audit fields
    created_at = LazyFunction(lambda: generate_past_datetime(max_days=90))
    updated_at = LazyFunction(lambda: datetime.now(timezone.utc))
    version = 1
    
    @classmethod
    def create_image_file(cls, **kwargs) -> Any:
        """Create image file for media testing."""
        image_kwargs = {
            'filename': f"image_{random.randint(1000, 9999)}.jpg",
            'content_type': 'image/jpeg',
            'file_size': random.randint(50000, 2000000),  # 50KB to 2MB
            'category': 'profile_image',
            'tags': ['image', 'media', 'profile']
        }
        image_kwargs.update(kwargs)
        return cls.create(**image_kwargs)
    
    @classmethod
    def create_large_file(cls, **kwargs) -> Any:
        """Create large file for performance testing."""
        large_kwargs = {
            'filename': f"large_file_{random.randint(1000, 9999)}.zip",
            'content_type': 'application/zip',
            'file_size': random.randint(50_000_000, 100_000_000),  # 50MB to 100MB
            'category': 'archive',
            'tags': ['large', 'archive', 'backup']
        }
        large_kwargs.update(kwargs)
        return cls.create(**large_kwargs)


class SystemConfigurationFactory(PydanticModelFactory):
    """
    System configuration factory for application settings testing.
    
    Creates realistic system configuration data with proper value types,
    validation constraints, and environment-specific settings for configuration
    management testing.
    """
    
    class Meta:
        model = SystemConfiguration if 'SystemConfiguration' in globals() else dict
    
    id = LazyFunction(lambda: str(uuid.uuid4()))
    key = LazyFunction(lambda: f"{fake.config_category()}.{fake.word()}_{fake.word()}")
    value = LazyFunction(lambda: generate_weighted_choice([
        (fake.word(), 30),               # String values
        (random.randint(1, 1000), 25),   # Integer values
        (round(random.uniform(0.1, 100.0), 2), 20),  # Float values
        (random.choice([True, False]), 15),  # Boolean values
        ({fake.word(): fake.word()}, 10)     # JSON values
    ]))
    value_type = LazyAttribute(lambda obj: {
        str: 'string',
        int: 'integer',
        float: 'float',
        bool: 'boolean',
        dict: 'json'
    }.get(type(obj.value), 'string'))
    
    # Metadata
    description = Faker('text', max_nb_chars=300)
    category = LazyFunction(lambda: fake.config_category())
    is_sensitive = LazyFunction(lambda: random.random() < 0.1)  # 10% sensitive
    is_readonly = LazyFunction(lambda: random.random() < 0.2)   # 20% readonly
    
    # Validation constraints
    min_value = LazyFunction(lambda: random.randint(0, 10) if random.random() < 0.3 else None)
    max_value = LazyFunction(lambda: random.randint(100, 1000) if random.random() < 0.3 else None)
    allowed_values = LazyFunction(lambda: [fake.word() for _ in range(random.randint(2, 5))] if random.random() < 0.2 else None)
    
    # Environment settings
    environment = LazyFunction(lambda: generate_weighted_choice([
        ('production', 40),
        ('staging', 30),
        ('development', 20),
        ('testing', 10)
    ]))
    requires_restart = LazyFunction(lambda: random.random() < 0.3)  # 30% require restart
    
    # Audit fields
    created_at = LazyFunction(lambda: generate_past_datetime(max_days=180))
    updated_at = LazyFunction(lambda: datetime.now(timezone.utc))
    version = 1


# ============================================================================
# API AND RESPONSE MODEL FACTORIES
# ============================================================================

class PaginationParamsFactory(PydanticModelFactory):
    """
    Pagination parameters factory for API request testing.
    
    Creates realistic pagination parameters with boundary conditions and
    edge cases for comprehensive API pagination testing.
    """
    
    class Meta:
        model = PaginationParams if 'PaginationParams' in globals() else dict
    
    page = LazyFunction(lambda: random.randint(1, 10))
    page_size = LazyFunction(lambda: generate_weighted_choice([
        (10, 20),    # Small pages
        (20, 40),    # Standard pages
        (50, 25),    # Large pages
        (100, 15)    # Maximum pages
    ]))
    
    @classmethod
    def create_first_page(cls, **kwargs) -> Any:
        """Create first page parameters for initial request testing."""
        first_kwargs = {'page': 1, 'page_size': 20}
        first_kwargs.update(kwargs)
        return cls.create(**first_kwargs)
    
    @classmethod
    def create_large_page(cls, **kwargs) -> Any:
        """Create large page parameters for performance testing."""
        large_kwargs = {'page': 1, 'page_size': 100}
        large_kwargs.update(kwargs)
        return cls.create(**large_kwargs)


class SearchParamsFactory(PydanticModelFactory):
    """
    Search parameters factory for API search testing.
    
    Creates realistic search parameters with query strings, filters, and
    options for comprehensive search functionality testing.
    """
    
    class Meta:
        model = SearchParams if 'SearchParams' in globals() else dict
    
    query = LazyFunction(lambda: fake.word() if random.random() < 0.8 else None)
    filters = LazyFunction(lambda: {
        'category': random.choice(['electronics', 'clothing', 'books']),
        'price_min': random.randint(10, 50),
        'price_max': random.randint(100, 500),
        'in_stock': random.choice([True, False])
    } if random.random() < 0.6 else None)
    include_inactive = LazyFunction(lambda: random.random() < 0.2)  # 20% include inactive
    
    @classmethod
    def create_empty_search(cls, **kwargs) -> Any:
        """Create empty search for default result testing."""
        empty_kwargs = {'query': None, 'filters': None, 'include_inactive': False}
        empty_kwargs.update(kwargs)
        return cls.create(**empty_kwargs)
    
    @classmethod
    def create_complex_search(cls, **kwargs) -> Any:
        """Create complex search with multiple filters."""
        complex_kwargs = {
            'query': fake.words(nb=3, ext_word_list=None),
            'filters': {
                'category': random.choice(['electronics', 'clothing', 'books']),
                'brand': fake.company(),
                'price_min': random.randint(10, 50),
                'price_max': random.randint(100, 500),
                'rating_min': random.randint(1, 4),
                'in_stock': True,
                'featured': random.choice([True, False]),
                'created_after': generate_past_datetime(max_days=30).isoformat()
            },
            'include_inactive': False
        }
        complex_kwargs.update(kwargs)
        return cls.create(**complex_kwargs)


class ApiResponseFactory(PydanticModelFactory):
    """
    API response factory for response format testing.
    
    Creates standardized API response structures with success/error patterns,
    metadata, and consistent formatting for API contract testing.
    """
    
    class Meta:
        model = ApiResponse if 'ApiResponse' in globals() else dict
    
    success = LazyFunction(lambda: random.random() < 0.85)  # 85% success rate
    data = LazyFunction(lambda: {
        'id': str(uuid.uuid4()),
        'name': fake.word(),
        'value': random.randint(1, 100)
    } if random.random() < 0.9 else None)
    message = LazyFunction(lambda: random.choice([
        'Operation completed successfully',
        'Data retrieved successfully',
        'Resource created successfully',
        'Resource updated successfully'
    ]) if random.random() < 0.7 else None)
    errors = LazyFunction(lambda: [
        {
            'field': 'email',
            'message': 'Invalid email format',
            'code': 'VALIDATION_ERROR'
        }
    ] if random.random() < 0.15 else None)
    metadata = LazyFunction(lambda: {
        'request_duration_ms': random.randint(10, 500),
        'api_version': '1.0',
        'rate_limit_remaining': random.randint(90, 100)
    } if random.random() < 0.5 else None)
    timestamp = LazyFunction(lambda: datetime.now(timezone.utc))
    request_id = LazyFunction(lambda: str(uuid.uuid4()))
    
    @classmethod
    def create_success_response(cls, data: Any = None, **kwargs) -> Any:
        """Create successful API response."""
        success_kwargs = {
            'success': True,
            'data': data or {'result': 'success'},
            'errors': None,
            'message': 'Operation completed successfully'
        }
        success_kwargs.update(kwargs)
        return cls.create(**success_kwargs)
    
    @classmethod
    def create_error_response(cls, errors: List[Dict] = None, **kwargs) -> Any:
        """Create error API response."""
        error_kwargs = {
            'success': False,
            'data': None,
            'errors': errors or [{'field': 'general', 'message': 'An error occurred', 'code': 'GENERAL_ERROR'}],
            'message': 'Operation failed'
        }
        error_kwargs.update(kwargs)
        return cls.create(**error_kwargs)


# ============================================================================
# COMPLEX DATA SCENARIO FACTORIES
# ============================================================================

class IntegrationTestScenarioFactory:
    """
    Complex data scenario factory for integration testing per Section 6.6.1.
    
    Creates comprehensive test scenarios with multiple related models for
    end-to-end workflow testing and complex business logic validation.
    """
    
    @staticmethod
    def create_e_commerce_scenario() -> Dict[str, Any]:
        """
        Create complete e-commerce scenario with user, products, and orders.
        
        Returns:
            Dictionary containing all related models for e-commerce testing
        """
        # Create organization
        organization = OrganizationFactory.create()
        
        # Create users
        admin_user = UserFactory.create_admin_user()
        customer_user = UserFactory.create()
        
        # Create product categories
        categories = ProductCategoryFactory.create_batch_validated(3)
        
        # Create products
        products = []
        for category in categories:
            category_products = ProductFactory.create_batch_validated(
                random.randint(2, 5),
                category_id=category.id if hasattr(category, 'id') else str(uuid.uuid4())
            )
            products.extend(category_products)
        
        # Create orders
        orders = []
        for _ in range(random.randint(2, 5)):
            # Select random products for order
            order_products = random.sample(products, k=random.randint(1, 3))
            order_items = []
            
            for product in order_products:
                item = OrderItemFactory.create(
                    product_id=product.id if hasattr(product, 'id') else str(uuid.uuid4()),
                    product_sku=product.sku if hasattr(product, 'sku') else fake.sku(),
                    product_name=product.name if hasattr(product, 'name') else fake.word()
                )
                order_items.append(item)
            
            order = OrderFactory.create(
                customer_id=customer_user.id if hasattr(customer_user, 'id') else str(uuid.uuid4()),
                customer_email=customer_user.email if hasattr(customer_user, 'email') else fake.email(),
                items=order_items
            )
            orders.append(order)
        
        # Create payment transactions
        transactions = []
        for order in orders:
            transaction = PaymentTransactionFactory.create(
                order_id=order.id if hasattr(order, 'id') else str(uuid.uuid4()),
                customer_id=customer_user.id if hasattr(customer_user, 'id') else str(uuid.uuid4()),
                amount=order.total_amount if hasattr(order, 'total_amount') else MonetaryAmountFactory.create()
            )
            transactions.append(transaction)
        
        return {
            'organization': organization,
            'admin_user': admin_user,
            'customer_user': customer_user,
            'categories': categories,
            'products': products,
            'orders': orders,
            'transactions': transactions,
            'scenario_type': 'e_commerce',
            'created_at': datetime.now(timezone.utc)
        }
    
    @staticmethod
    def create_user_lifecycle_scenario() -> Dict[str, Any]:
        """
        Create user lifecycle scenario from registration to activity.
        
        Returns:
            Dictionary containing user lifecycle models for testing
        """
        # Create new pending user
        new_user = UserFactory.create_new_user()
        
        # Create user sessions
        sessions = UserSessionFactory.create_batch_validated(
            random.randint(2, 5),
            user_id=new_user.id if hasattr(new_user, 'id') else str(uuid.uuid4())
        )
        
        # Create file uploads
        files = FileUploadFactory.create_batch_validated(
            random.randint(1, 3),
            uploaded_by=new_user.id if hasattr(new_user, 'id') else str(uuid.uuid4())
        )
        
        # Create configuration for user
        configs = SystemConfigurationFactory.create_batch_validated(
            random.randint(2, 4),
            environment='development'
        )
        
        return {
            'user': new_user,
            'sessions': sessions,
            'files': files,
            'configurations': configs,
            'scenario_type': 'user_lifecycle',
            'created_at': datetime.now(timezone.utc)
        }
    
    @staticmethod
    def create_performance_test_dataset(volume: str = 'medium') -> Dict[str, Any]:
        """
        Create performance test dataset with configurable volume per Section 6.6.1.
        
        Args:
            volume: Dataset volume ('small', 'medium', 'large', 'xlarge')
            
        Returns:
            Dictionary containing performance test dataset
        """
        volume_configs = {
            'small': {'users': 10, 'products': 50, 'orders': 20},
            'medium': {'users': 100, 'products': 500, 'orders': 200},
            'large': {'users': 1000, 'products': 5000, 'orders': 2000},
            'xlarge': {'users': 10000, 'products': 50000, 'orders': 20000}
        }
        
        config = volume_configs.get(volume, volume_configs['medium'])
        
        # Create users with realistic distribution
        users = []
        admin_count = max(1, config['users'] // 20)  # 5% admins
        manager_count = config['users'] // 10        # 10% managers
        regular_count = config['users'] - admin_count - manager_count
        
        users.extend(UserFactory.create_batch_validated(admin_count, role='admin'))
        users.extend(UserFactory.create_batch_validated(manager_count, role='manager'))
        users.extend(UserFactory.create_batch_validated(regular_count, role='user'))
        
        # Create product categories
        category_count = max(5, config['products'] // 100)
        categories = ProductCategoryFactory.create_batch_validated(category_count)
        
        # Create products distributed across categories
        products = []
        products_per_category = config['products'] // len(categories)
        for category in categories:
            category_products = ProductFactory.create_batch_validated(
                products_per_category,
                category_id=category.id if hasattr(category, 'id') else str(uuid.uuid4())
            )
            products.extend(category_products)
        
        # Create orders with random distribution
        orders = []
        for _ in range(config['orders']):
            customer = random.choice(users)
            order_products = random.sample(products, k=random.randint(1, 5))
            
            order_items = []
            for product in order_products:
                item = OrderItemFactory.create(
                    product_id=product.id if hasattr(product, 'id') else str(uuid.uuid4()),
                    product_sku=product.sku if hasattr(product, 'sku') else fake.sku(),
                    product_name=product.name if hasattr(product, 'name') else fake.word()
                )
                order_items.append(item)
            
            order = OrderFactory.create(
                customer_id=customer.id if hasattr(customer, 'id') else str(uuid.uuid4()),
                customer_email=customer.email if hasattr(customer, 'email') else fake.email(),
                items=order_items
            )
            orders.append(order)
        
        return {
            'users': users,
            'categories': categories,
            'products': products,
            'orders': orders,
            'volume': volume,
            'config': config,
            'scenario_type': 'performance_dataset',
            'created_at': datetime.now(timezone.utc)
        }
    
    @staticmethod
    def create_edge_case_scenario() -> Dict[str, Any]:
        """
        Create edge case scenario for boundary testing per Section 6.6.1.
        
        Returns:
            Dictionary containing edge case models for validation testing
        """
        # Edge case users
        edge_users = [
            UserFactory.create_edge_case('minimal'),
            UserFactory.create_edge_case('maximal'),
            UserFactory.create_locked_user(),
            UserFactory.create_new_user()
        ]
        
        # Edge case products
        edge_products = [
            ProductFactory.create_edge_case('minimal'),
            ProductFactory.create_edge_case('maximal'),
            ProductFactory.create_digital_product(),
            ProductFactory.create_out_of_stock_product()
        ]
        
        # Edge case orders
        edge_orders = [
            OrderFactory.create_completed_order(),
            OrderFactory.create_cancelled_order()
        ]
        
        # Edge case transactions
        edge_transactions = [
            PaymentTransactionFactory.create_failed_transaction()
        ]
        
        # Edge case files
        edge_files = [
            FileUploadFactory.create_image_file(),
            FileUploadFactory.create_large_file()
        ]
        
        return {
            'edge_users': edge_users,
            'edge_products': edge_products,
            'edge_orders': edge_orders,
            'edge_transactions': edge_transactions,
            'edge_files': edge_files,
            'scenario_type': 'edge_case_testing',
            'created_at': datetime.now(timezone.utc)
        }


# ============================================================================
# PYTEST FIXTURES INTEGRATION
# ============================================================================

@pytest.fixture
def user_factory():
    """Pytest fixture providing UserFactory for test functions."""
    return UserFactory


@pytest.fixture
def product_factory():
    """Pytest fixture providing ProductFactory for test functions."""
    return ProductFactory


@pytest.fixture
def order_factory():
    """Pytest fixture providing OrderFactory for test functions."""
    return OrderFactory


@pytest.fixture
def organization_factory():
    """Pytest fixture providing OrganizationFactory for test functions."""
    return OrganizationFactory


@pytest.fixture
def integration_scenario_factory():
    """Pytest fixture providing IntegrationTestScenarioFactory for test functions."""
    return IntegrationTestScenarioFactory


@pytest.fixture
def sample_user(user_factory):
    """Pytest fixture providing a sample user instance."""
    return user_factory.create()


@pytest.fixture
def sample_admin_user(user_factory):
    """Pytest fixture providing a sample admin user instance."""
    return user_factory.create_admin_user()


@pytest.fixture
def sample_product(product_factory):
    """Pytest fixture providing a sample product instance."""
    return product_factory.create()


@pytest.fixture
def sample_order(order_factory):
    """Pytest fixture providing a sample order instance."""
    return order_factory.create()


@pytest.fixture
def e_commerce_scenario(integration_scenario_factory):
    """Pytest fixture providing complete e-commerce test scenario."""
    return integration_scenario_factory.create_e_commerce_scenario()


@pytest.fixture
def performance_dataset_small(integration_scenario_factory):
    """Pytest fixture providing small performance test dataset."""
    return integration_scenario_factory.create_performance_test_dataset('small')


@pytest.fixture
def edge_case_scenario(integration_scenario_factory):
    """Pytest fixture providing edge case test scenario."""
    return integration_scenario_factory.create_edge_case_scenario()


# ============================================================================
# FACTORY VALIDATION AND TESTING UTILITIES
# ============================================================================

def validate_all_factories():
    """
    Validate all factory outputs for consistency and correctness.
    
    Runs comprehensive validation tests on all factory classes to ensure
    they generate valid data according to pydantic models and business rules.
    
    Returns:
        Dict with validation results for each factory
    """
    results = {}
    
    # List all factory classes
    factory_classes = [
        UserFactory, DataUserFactory, UserSessionFactory,
        OrganizationFactory, ProductCategoryFactory, ProductFactory,
        OrderItemFactory, OrderFactory, PaymentTransactionFactory,
        FileUploadFactory, SystemConfigurationFactory,
        PaginationParamsFactory, SearchParamsFactory, ApiResponseFactory,
        ContactInfoFactory, AddressFactory, MonetaryAmountFactory,
        DateTimeRangeFactory
    ]
    
    for factory_class in factory_classes:
        factory_name = factory_class.__name__
        try:
            # Test basic creation
            instance = factory_class.create()
            results[factory_name] = {
                'basic_creation': True,
                'instance_type': type(instance).__name__,
                'validation_passed': True
            }
            
            # Test batch creation
            batch = factory_class.create_batch_validated(3)
            results[factory_name]['batch_creation'] = len(batch) == 3
            
            logger.info("Factory validation passed", factory=factory_name)
            
        except Exception as e:
            results[factory_name] = {
                'basic_creation': False,
                'error': str(e),
                'validation_passed': False
            }
            logger.error("Factory validation failed", factory=factory_name, error=str(e))
    
    return results


def generate_test_data_summary(scenario_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate summary statistics for test data scenarios.
    
    Args:
        scenario_data: Test scenario data from factory
        
    Returns:
        Summary statistics and metadata
    """
    summary = {
        'scenario_type': scenario_data.get('scenario_type', 'unknown'),
        'created_at': scenario_data.get('created_at'),
        'total_objects': 0,
        'object_counts': {},
        'data_volume_mb': 0
    }
    
    for key, value in scenario_data.items():
        if isinstance(value, list):
            summary['object_counts'][key] = len(value)
            summary['total_objects'] += len(value)
        elif hasattr(value, '__dict__'):
            summary['object_counts'][key] = 1
            summary['total_objects'] += 1
    
    # Estimate data volume (rough calculation)
    import sys
    try:
        data_size = sys.getsizeof(str(scenario_data))
        summary['data_volume_mb'] = round(data_size / (1024 * 1024), 2)
    except Exception:
        summary['data_volume_mb'] = 0
    
    return summary


# ============================================================================
# FACTORY REGISTRY AND EXPORT
# ============================================================================

# Registry of all factory classes for dynamic access
FACTORY_REGISTRY = {
    # User and authentication factories
    'UserFactory': UserFactory,
    'DataUserFactory': DataUserFactory,
    'UserSessionFactory': UserSessionFactory,
    'ContactInfoFactory': ContactInfoFactory,
    'AddressFactory': AddressFactory,
    
    # Business model factories
    'OrganizationFactory': OrganizationFactory,
    'ProductCategoryFactory': ProductCategoryFactory,
    'ProductFactory': ProductFactory,
    'OrderItemFactory': OrderItemFactory,
    'OrderFactory': OrderFactory,
    'PaymentTransactionFactory': PaymentTransactionFactory,
    
    # Utility model factories
    'MonetaryAmountFactory': MonetaryAmountFactory,
    'DateTimeRangeFactory': DateTimeRangeFactory,
    'FileUploadFactory': FileUploadFactory,
    'SystemConfigurationFactory': SystemConfigurationFactory,
    
    # API model factories
    'PaginationParamsFactory': PaginationParamsFactory,
    'SearchParamsFactory': SearchParamsFactory,
    'ApiResponseFactory': ApiResponseFactory,
    
    # Scenario factories
    'IntegrationTestScenarioFactory': IntegrationTestScenarioFactory,
}


def get_factory_by_name(factory_name: str) -> Optional[Type]:
    """
    Get factory class by name from registry.
    
    Args:
        factory_name: Name of the factory class to retrieve
        
    Returns:
        Factory class if found, None otherwise
    """
    return FACTORY_REGISTRY.get(factory_name)


# Export all factories and utilities
__all__ = [
    # Factory classes
    'PydanticModelFactory', 'MongoModelFactory',
    'UserFactory', 'DataUserFactory', 'UserSessionFactory',
    'ContactInfoFactory', 'AddressFactory',
    'OrganizationFactory', 'ProductCategoryFactory', 'ProductFactory',
    'OrderItemFactory', 'OrderFactory', 'PaymentTransactionFactory',
    'MonetaryAmountFactory', 'DateTimeRangeFactory',
    'FileUploadFactory', 'SystemConfigurationFactory',
    'PaginationParamsFactory', 'SearchParamsFactory', 'ApiResponseFactory',
    'IntegrationTestScenarioFactory',
    
    # Utility functions
    'generate_future_datetime', 'generate_past_datetime', 'generate_date_range',
    'generate_business_hours_range', 'generate_realistic_decimal',
    'generate_weighted_choice', 'validate_factory_output',
    'validate_all_factories', 'generate_test_data_summary',
    'get_factory_by_name',
    
    # Registry
    'FACTORY_REGISTRY',
    
    # Faker instance and provider
    'fake', 'BusinessDataProvider'
]


# Module initialization
logger.info("Factory fixtures module initialized successfully",
           factory_count=len(FACTORY_REGISTRY),
           faker_providers=['BusinessDataProvider'],
           pydantic_integration=True,
           dateutil_integration=True)