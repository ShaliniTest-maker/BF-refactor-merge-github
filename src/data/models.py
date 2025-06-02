"""
Data models and schema definitions preserving existing MongoDB document structures.

This module implements Pydantic 2.3+ models for type safety and data validation without 
modifying underlying database schemas, maintaining complete compatibility with existing 
Node.js data structures per Section 6.2.1 schema preservation requirements.

The models provide:
- Complete preservation of existing MongoDB document structures
- Python-specific validation and serialization patterns
- Type hints and validation while preserving existing schema patterns
- Serialization/deserialization patterns for MongoDB documents
- Zero database schema changes during migration
"""

from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from bson import ObjectId
from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator
from pydantic.types import EmailStr


class PyObjectId(ObjectId):
    """Custom ObjectId type for Pydantic models to handle MongoDB ObjectId serialization."""
    
    @classmethod
    def __get_validators__(cls):
        yield cls.validate
    
    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)
    
    @classmethod
    def __get_pydantic_core_schema__(cls, source_type, handler):
        from pydantic_core import core_schema
        return core_schema.json_or_python_schema(
            json_schema=core_schema.str_schema(),
            python_schema=core_schema.union_schema([
                core_schema.is_instance_schema(ObjectId),
                core_schema.chain_schema([
                    core_schema.str_schema(),
                    core_schema.no_info_plain_validator_function(cls.validate),
                ])
            ]),
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda x: str(x)
            ),
        )


class MongoBaseModel(BaseModel):
    """
    Base model for MongoDB document structures.
    
    Provides common configuration and validation patterns for all MongoDB-backed
    data models while preserving existing document structures and field patterns.
    """
    
    model_config = ConfigDict(
        # Preserve existing MongoDB document structures
        populate_by_name=True,
        # Allow ObjectId and other MongoDB types
        arbitrary_types_allowed=True,
        # Use enum values for serialization
        use_enum_values=True,
        # Preserve original field names from Node.js implementation
        alias_generator=None,
        # Enable JSON schema generation
        json_schema_extra={
            "examples": []
        }
    )
    
    # MongoDB document ID field - preserving existing _id patterns
    id: Optional[PyObjectId] = Field(default=None, alias="_id")
    
    # Standard MongoDB metadata fields preserving Node.js patterns
    created_at: Optional[datetime] = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    @field_validator('created_at', 'updated_at', mode='before')
    @classmethod
    def validate_datetime_fields(cls, v):
        """Validate and normalize datetime fields maintaining existing patterns."""
        if v is None:
            return datetime.now(timezone.utc)
        if isinstance(v, str):
            # Handle ISO 8601 strings from Node.js implementation
            return datetime.fromisoformat(v.replace('Z', '+00:00'))
        if isinstance(v, datetime):
            # Ensure timezone awareness
            if v.tzinfo is None:
                return v.replace(tzinfo=timezone.utc)
            return v
        return v
    
    @model_validator(mode='before')
    @classmethod
    def handle_mongo_id(cls, values):
        """Handle MongoDB _id field conversion maintaining existing patterns."""
        if isinstance(values, dict):
            # Handle _id field from MongoDB documents
            if '_id' in values and 'id' not in values:
                values['id'] = values['_id']
            # Handle string ObjectIds from Node.js implementation
            if 'id' in values and isinstance(values['id'], str):
                if ObjectId.is_valid(values['id']):
                    values['id'] = ObjectId(values['id'])
        return values
    
    def to_mongo_dict(self) -> Dict[str, Any]:
        """
        Convert model to MongoDB document format.
        
        Returns:
            Dict representing MongoDB document with proper _id field
        """
        data = self.model_dump(by_alias=True, exclude_unset=True)
        if 'id' in data:
            data['_id'] = data.pop('id')
        return data
    
    @classmethod
    def from_mongo_dict(cls, data: Dict[str, Any]) -> 'MongoBaseModel':
        """
        Create model instance from MongoDB document.
        
        Args:
            data: MongoDB document dictionary
            
        Returns:
            Model instance with proper field mapping
        """
        if data is None:
            return None
        return cls(**data)


class UserStatus(str, Enum):
    """User account status enumeration preserving existing Node.js patterns."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING = "pending"


class UserRole(str, Enum):
    """User role enumeration maintaining existing authorization patterns."""
    ADMIN = "admin"
    USER = "user"
    MODERATOR = "moderator"
    VIEWER = "viewer"


class User(MongoBaseModel):
    """
    User model preserving existing MongoDB user document structures.
    
    Maintains complete compatibility with Node.js user data patterns including
    authentication fields, profile information, and authorization metadata.
    """
    
    # Core user identification fields
    email: EmailStr = Field(..., description="User email address")
    username: str = Field(..., min_length=3, max_length=50, description="Unique username")
    
    # Authentication fields preserving Node.js patterns
    password_hash: Optional[str] = Field(default=None, description="Hashed password")
    salt: Optional[str] = Field(default=None, description="Password salt")
    
    # Profile information matching existing schema
    first_name: Optional[str] = Field(default=None, max_length=100)
    last_name: Optional[str] = Field(default=None, max_length=100)
    display_name: Optional[str] = Field(default=None, max_length=150)
    avatar_url: Optional[str] = Field(default=None, description="Profile picture URL")
    
    # Authorization and status fields
    status: UserStatus = Field(default=UserStatus.ACTIVE)
    role: UserRole = Field(default=UserRole.USER)
    permissions: List[str] = Field(default_factory=list, description="User permissions")
    
    # External authentication integration
    auth0_user_id: Optional[str] = Field(default=None, description="Auth0 user identifier")
    external_ids: Dict[str, str] = Field(default_factory=dict, description="External service IDs")
    
    # Account metadata preserving existing patterns
    email_verified: bool = Field(default=False)
    phone_number: Optional[str] = Field(default=None)
    phone_verified: bool = Field(default=False)
    
    # Timestamps and activity tracking
    last_login: Optional[datetime] = Field(default=None)
    last_activity: Optional[datetime] = Field(default=None)
    login_count: int = Field(default=0)
    
    # Account security fields
    failed_login_attempts: int = Field(default=0)
    account_locked_until: Optional[datetime] = Field(default=None)
    password_changed_at: Optional[datetime] = Field(default=None)
    
    # Privacy and preferences
    preferences: Dict[str, Any] = Field(default_factory=dict)
    privacy_settings: Dict[str, bool] = Field(default_factory=dict)
    
    @field_validator('email')
    @classmethod
    def validate_email_uniqueness(cls, v):
        """Validate email format maintaining existing patterns."""
        return v.lower().strip()
    
    @field_validator('username')
    @classmethod
    def validate_username_format(cls, v):
        """Validate username format preserving Node.js validation."""
        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username can only contain letters, numbers, underscores, and hyphens')
        return v.lower().strip()


class SessionStatus(str, Enum):
    """Session status enumeration for session management."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class UserSession(MongoBaseModel):
    """
    User session model for Redis and MongoDB session storage.
    
    Preserves existing session management patterns from Node.js implementation
    with support for distributed session storage across Flask instances.
    """
    
    # Session identification
    session_id: str = Field(..., description="Unique session identifier")
    user_id: PyObjectId = Field(..., description="Associated user ID")
    
    # Session metadata
    status: SessionStatus = Field(default=SessionStatus.ACTIVE)
    ip_address: Optional[str] = Field(default=None)
    user_agent: Optional[str] = Field(default=None)
    
    # Session lifecycle
    expires_at: datetime = Field(..., description="Session expiration timestamp")
    last_accessed: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Security and tracking
    csrf_token: Optional[str] = Field(default=None)
    refresh_token: Optional[str] = Field(default=None)
    login_method: Optional[str] = Field(default=None, description="Authentication method used")
    
    # Session data
    data: Dict[str, Any] = Field(default_factory=dict, description="Session data storage")
    
    @field_validator('expires_at', mode='before')
    @classmethod
    def validate_expiration(cls, v):
        """Ensure session expiration is in the future."""
        if isinstance(v, str):
            v = datetime.fromisoformat(v.replace('Z', '+00:00'))
        if v <= datetime.now(timezone.utc):
            raise ValueError('Session expiration must be in the future')
        return v


class FileStatus(str, Enum):
    """File upload status enumeration."""
    UPLOADING = "uploading"
    COMPLETED = "completed"
    FAILED = "failed"
    DELETED = "deleted"


class FileMetadata(MongoBaseModel):
    """
    File metadata model for S3 and file storage operations.
    
    Maintains compatibility with existing file upload patterns from Node.js
    implementation including multipart uploads and S3 integration.
    """
    
    # File identification
    filename: str = Field(..., description="Original filename")
    file_key: str = Field(..., description="S3 object key or storage identifier")
    
    # File properties
    content_type: str = Field(..., description="MIME type")
    file_size: int = Field(..., ge=0, description="File size in bytes")
    checksum: Optional[str] = Field(default=None, description="File checksum")
    
    # Upload metadata
    status: FileStatus = Field(default=FileStatus.UPLOADING)
    upload_id: Optional[str] = Field(default=None, description="Multipart upload ID")
    
    # S3 integration fields
    bucket_name: str = Field(..., description="S3 bucket name")
    s3_url: Optional[str] = Field(default=None, description="S3 object URL")
    cloudfront_url: Optional[str] = Field(default=None, description="CloudFront distribution URL")
    
    # Access control
    is_public: bool = Field(default=False)
    access_permissions: List[str] = Field(default_factory=list)
    
    # Associated entities
    owner_id: PyObjectId = Field(..., description="File owner user ID")
    associated_entity_type: Optional[str] = Field(default=None)
    associated_entity_id: Optional[PyObjectId] = Field(default=None)
    
    # File processing
    processed: bool = Field(default=False)
    processing_metadata: Dict[str, Any] = Field(default_factory=dict)
    
    @field_validator('file_size')
    @classmethod
    def validate_file_size(cls, v):
        """Validate file size limits."""
        max_size = 100 * 1024 * 1024  # 100MB
        if v > max_size:
            raise ValueError(f'File size cannot exceed {max_size} bytes')
        return v


class LogLevel(str, Enum):
    """Log level enumeration for application logging."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ApplicationLog(MongoBaseModel):
    """
    Application log model for structured logging and monitoring.
    
    Supports enterprise logging requirements with integration for monitoring
    systems and log aggregation platforms.
    """
    
    # Log identification
    log_id: str = Field(..., description="Unique log entry identifier")
    
    # Log metadata
    level: LogLevel = Field(..., description="Log severity level")
    message: str = Field(..., description="Log message")
    logger_name: str = Field(..., description="Logger name or module")
    
    # Request context
    request_id: Optional[str] = Field(default=None, description="Request correlation ID")
    user_id: Optional[PyObjectId] = Field(default=None, description="Associated user ID")
    session_id: Optional[str] = Field(default=None, description="Session identifier")
    
    # Application context
    module: str = Field(..., description="Application module")
    function: Optional[str] = Field(default=None, description="Function name")
    line_number: Optional[int] = Field(default=None, description="Code line number")
    
    # Exception details
    exception_type: Optional[str] = Field(default=None)
    exception_message: Optional[str] = Field(default=None)
    stack_trace: Optional[str] = Field(default=None)
    
    # Additional metadata
    extra_data: Dict[str, Any] = Field(default_factory=dict, description="Additional log data")
    tags: List[str] = Field(default_factory=list, description="Log tags for filtering")
    
    # Performance metrics
    duration_ms: Optional[float] = Field(default=None, description="Operation duration")
    memory_usage: Optional[int] = Field(default=None, description="Memory usage in bytes")


class CacheEntryType(str, Enum):
    """Cache entry type enumeration."""
    RESPONSE = "response"
    SESSION = "session"
    USER_DATA = "user_data"
    COMPUTED = "computed"
    EXTERNAL_API = "external_api"


class CacheEntry(MongoBaseModel):
    """
    Cache entry model for Redis caching operations.
    
    Maintains compatibility with existing caching patterns from Node.js
    implementation including TTL management and cache invalidation.
    """
    
    # Cache identification
    cache_key: str = Field(..., description="Cache key identifier")
    entry_type: CacheEntryType = Field(..., description="Type of cached data")
    
    # Cache data
    data: Dict[str, Any] = Field(..., description="Cached data")
    compressed: bool = Field(default=False, description="Whether data is compressed")
    
    # Cache lifecycle
    ttl_seconds: int = Field(..., ge=1, description="Time to live in seconds")
    expires_at: datetime = Field(..., description="Cache expiration timestamp")
    
    # Cache metadata
    cache_hits: int = Field(default=0, description="Number of cache hits")
    last_accessed: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Associated entities
    user_id: Optional[PyObjectId] = Field(default=None, description="Associated user ID")
    entity_type: Optional[str] = Field(default=None, description="Associated entity type")
    entity_id: Optional[str] = Field(default=None, description="Associated entity ID")
    
    # Invalidation tracking
    invalidation_tags: List[str] = Field(default_factory=list, description="Tags for cache invalidation")
    version: int = Field(default=1, description="Cache entry version")
    
    @field_validator('expires_at', mode='before')
    @classmethod
    def validate_expiration(cls, v):
        """Ensure cache expiration is in the future."""
        if isinstance(v, str):
            v = datetime.fromisoformat(v.replace('Z', '+00:00'))
        return v


class APIRequestStatus(str, Enum):
    """API request status enumeration."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class ExternalAPIRequest(MongoBaseModel):
    """
    External API request model for tracking and monitoring.
    
    Preserves existing external service integration patterns from Node.js
    implementation with circuit breaker and retry logic support.
    """
    
    # Request identification
    request_id: str = Field(..., description="Unique request identifier")
    correlation_id: Optional[str] = Field(default=None, description="Request correlation ID")
    
    # API details
    service_name: str = Field(..., description="External service name")
    endpoint_url: str = Field(..., description="API endpoint URL")
    http_method: str = Field(..., description="HTTP method")
    
    # Request metadata
    status: APIRequestStatus = Field(default=APIRequestStatus.PENDING)
    
    # Request data
    request_headers: Dict[str, str] = Field(default_factory=dict)
    request_body: Optional[Dict[str, Any]] = Field(default=None)
    query_parameters: Dict[str, str] = Field(default_factory=dict)
    
    # Response data
    response_status_code: Optional[int] = Field(default=None)
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_body: Optional[Dict[str, Any]] = Field(default=None)
    
    # Performance tracking
    request_start_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    request_end_time: Optional[datetime] = Field(default=None)
    duration_ms: Optional[float] = Field(default=None)
    
    # Error handling
    error_message: Optional[str] = Field(default=None)
    error_code: Optional[str] = Field(default=None)
    retry_count: int = Field(default=0)
    max_retries: int = Field(default=3)
    
    # Circuit breaker integration
    circuit_breaker_state: Optional[str] = Field(default=None)
    
    # Associated entities
    user_id: Optional[PyObjectId] = Field(default=None, description="Associated user ID")
    session_id: Optional[str] = Field(default=None, description="Session identifier")
    
    @field_validator('http_method')
    @classmethod
    def validate_http_method(cls, v):
        """Validate HTTP method format."""
        valid_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        if v.upper() not in valid_methods:
            raise ValueError(f'Invalid HTTP method: {v}')
        return v.upper()


class ConfigurationScope(str, Enum):
    """Configuration scope enumeration."""
    GLOBAL = "global"
    USER = "user"
    SESSION = "session"
    FEATURE = "feature"


class Configuration(MongoBaseModel):
    """
    Application configuration model for feature flags and settings.
    
    Supports dynamic configuration management maintaining compatibility
    with existing configuration patterns from Node.js implementation.
    """
    
    # Configuration identification
    config_key: str = Field(..., description="Configuration key identifier")
    scope: ConfigurationScope = Field(..., description="Configuration scope")
    
    # Configuration data
    value: Union[str, int, float, bool, Dict[str, Any], List[Any]] = Field(..., description="Configuration value")
    data_type: str = Field(..., description="Value data type")
    
    # Configuration metadata
    description: Optional[str] = Field(default=None, description="Configuration description")
    category: Optional[str] = Field(default=None, description="Configuration category")
    
    # Scope-specific fields
    user_id: Optional[PyObjectId] = Field(default=None, description="User-specific configuration")
    session_id: Optional[str] = Field(default=None, description="Session-specific configuration")
    feature_name: Optional[str] = Field(default=None, description="Feature-specific configuration")
    
    # Configuration lifecycle
    is_active: bool = Field(default=True)
    effective_from: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    effective_until: Optional[datetime] = Field(default=None)
    
    # Version control
    version: int = Field(default=1)
    previous_value: Optional[Union[str, int, float, bool, Dict[str, Any], List[Any]]] = Field(default=None)
    
    @field_validator('data_type')
    @classmethod
    def validate_data_type(cls, v):
        """Validate data type specification."""
        valid_types = ['string', 'integer', 'float', 'boolean', 'object', 'array']
        if v not in valid_types:
            raise ValueError(f'Invalid data type: {v}')
        return v


# Export all models for easy importing
__all__ = [
    'PyObjectId',
    'MongoBaseModel',
    'User',
    'UserStatus',
    'UserRole',
    'UserSession',
    'SessionStatus',
    'FileMetadata',
    'FileStatus',
    'ApplicationLog',
    'LogLevel',
    'CacheEntry',
    'CacheEntryType',
    'ExternalAPIRequest',
    'APIRequestStatus',
    'Configuration',
    'ConfigurationScope'
]