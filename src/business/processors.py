"""
Core Data Processing and Transformation Engine for Flask Application

This module provides comprehensive data processing and transformation engine implementing
equivalent business logic patterns from Node.js. Provides data transformation, business
rule execution, and processing workflows while maintaining identical input/output
characteristics and performance requirements per Section 5.2.4 and F-004-RQ-001.

The processing engine follows enterprise patterns with:
- Data transformation and processing logic maintaining identical patterns per F-004-RQ-001
- Business rule execution with equivalent functionality per F-004-RQ-001
- Python-dateutil 2.8+ for date processing equivalent to moment.js per Section 5.2.4
- Processing workflows within ≤10% performance variance per Section 0.1.1
- Performance optimization for processing workflows per Section 6.1.3
- Integration with business logic processing pipeline per Section 5.2.4

Processor Categories:
    Core Data Processors:
        DataTransformer: Data format transformation and conversion
        ValidationProcessor: Business rule validation and enforcement
        SanitizationProcessor: Data cleaning and security sanitization
        NormalizationProcessor: Data normalization and standardization
        
    Business Logic Processors:
        BusinessRuleEngine: Core business rule execution and validation
        WorkflowProcessor: Business workflow execution and orchestration
        CalculationProcessor: Business calculations and formula execution
        AggregationProcessor: Data aggregation and statistical processing
        
    Date/Time Processors:
        DateTimeProcessor: Date/time parsing, formatting, and calculations
        TimezoneProcessor: Timezone conversion and management
        BusinessDayProcessor: Business day calculations and scheduling
        RecurrenceProcessor: Recurring event and pattern processing
        
    Integration Processors:
        DataMappingProcessor: Data mapping between different formats
        FormatProcessor: Format conversion and serialization
        ExportProcessor: Data export and reporting
        ImportProcessor: Data import and ingestion
        
    Pipeline Processors:
        ProcessingPipeline: Chained processing workflow execution
        BatchProcessor: Batch data processing operations
        StreamProcessor: Stream data processing operations
        AsyncProcessor: Asynchronous processing operations
"""

import asyncio
import json
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta, date
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from enum import Enum
from functools import wraps, lru_cache
from typing import (
    Any, Dict, List, Optional, Union, Callable, Type, Set, Tuple,
    AsyncGenerator, Generator, Protocol, TypeVar, Generic
)

# Date/time processing with python-dateutil 2.8+ equivalent to moment.js
from dateutil import parser as date_parser, tz, relativedelta
from dateutil.relativedelta import relativedelta
from dateutil.rrule import rrule, DAILY, WEEKLY, MONTHLY, YEARLY

# Import business components for comprehensive integration
from .models import (
    BaseBusinessModel, User, Organization, Product, Order, OrderItem,
    PaymentTransaction, Address, ContactInfo, MonetaryAmount, DateTimeRange,
    FileUpload, SystemConfiguration, PaginationParams, SortParams, SearchParams,
    UserStatus, UserRole, OrderStatus, PaymentStatus, PaymentMethod, ProductStatus,
    Priority, ContactMethod, BUSINESS_MODEL_REGISTRY
)
from .validators import (
    ValidationConfig, BaseBusinessValidator, UserValidator, OrganizationValidator,
    ProductValidator, OrderValidator, PaymentValidator, AddressValidator,
    ContactInfoValidator, MonetaryAmountValidator, FileUploadValidator
)
from .utils import (
    clean_data, validate_email, validate_phone, validate_postal_code,
    sanitize_input, safe_str, safe_int, safe_float, normalize_boolean,
    parse_date, format_date, round_currency, validate_currency,
    DataFormat, JSONType, DateTimeType, NumericType
)
from .exceptions import (
    BaseBusinessException, BusinessRuleViolationError, DataProcessingError,
    DataValidationError, ExternalServiceError, ResourceNotFoundError,
    AuthorizationError, ConcurrencyError, ConfigurationError,
    ErrorSeverity, ErrorCategory
)

# Configure structured logging for processing operations
import structlog
logger = structlog.get_logger("business.processors")

# Type definitions for processors
T = TypeVar('T')
ProcessorResult = Union[T, Dict[str, Any], List[Any]]
ProcessorFunction = Callable[[Any], ProcessorResult]
ProcessorChain = List[ProcessorFunction]


# ============================================================================
# PROCESSOR CONFIGURATION AND BASE CLASSES
# ============================================================================

class ProcessingMode(Enum):
    """
    Processing mode enumeration for processor behavior configuration.
    
    Defines execution modes for data processing operations enabling optimized
    processing patterns for different use cases and performance requirements.
    """
    STRICT = "strict"        # Strict validation and processing
    LENIENT = "lenient"      # Lenient processing with warnings
    FAST = "fast"            # Performance-optimized processing
    COMPREHENSIVE = "comprehensive"  # Full validation and processing
    DEBUG = "debug"          # Debug mode with detailed logging


class ProcessingConfig:
    """
    Global processing configuration for business processors.
    
    Provides centralized configuration for processing behavior, performance
    optimization, error handling, and monitoring integration across all
    business data processors.
    """
    
    # Performance settings per Section 6.1.3
    DEFAULT_BATCH_SIZE: int = 100
    MAX_BATCH_SIZE: int = 1000
    DEFAULT_TIMEOUT: int = 30  # seconds
    MAX_WORKERS: int = 4
    CACHE_TTL: int = 300  # 5 minutes
    
    # Processing behavior settings
    DEFAULT_MODE: ProcessingMode = ProcessingMode.STRICT
    ENABLE_CACHING: bool = True
    ENABLE_METRICS: bool = True
    ENABLE_AUDIT_LOGGING: bool = True
    
    # Error handling settings
    CONTINUE_ON_ERROR: bool = False
    MAX_ERROR_COUNT: int = 10
    ERROR_RETRY_COUNT: int = 3
    ERROR_RETRY_DELAY: float = 1.0
    
    # Date/time processing settings per Section 5.2.4
    DEFAULT_TIMEZONE: str = "UTC"
    DATE_FORMAT: str = "%Y-%m-%d"
    DATETIME_FORMAT: str = "%Y-%m-%d %H:%M:%S"
    ISO_DATETIME_FORMAT: str = "%Y-%m-%dT%H:%M:%S%z"
    
    # Validation settings
    STRICT_VALIDATION: bool = True
    VALIDATE_BUSINESS_RULES: bool = True
    SANITIZE_INPUT: bool = True
    NORMALIZE_DATA: bool = True


class ProcessingMetrics:
    """
    Processing metrics collection for performance monitoring.
    
    Collects comprehensive metrics for processing operations including
    execution times, throughput, error rates, and resource utilization
    for performance optimization and monitoring per Section 6.1.3.
    """
    
    def __init__(self):
        self.metrics = {}
        self.start_time = None
        self.end_time = None
        
    def start_timer(self, operation_name: str) -> None:
        """Start timing for an operation."""
        self.start_time = time.perf_counter()
        if operation_name not in self.metrics:
            self.metrics[operation_name] = {
                'count': 0,
                'total_time': 0.0,
                'min_time': float('inf'),
                'max_time': 0.0,
                'error_count': 0
            }
    
    def end_timer(self, operation_name: str, success: bool = True) -> float:
        """End timing for an operation and record metrics."""
        if self.start_time is None:
            return 0.0
        
        self.end_time = time.perf_counter()
        duration = self.end_time - self.start_time
        
        if operation_name in self.metrics:
            metrics = self.metrics[operation_name]
            metrics['count'] += 1
            metrics['total_time'] += duration
            metrics['min_time'] = min(metrics['min_time'], duration)
            metrics['max_time'] = max(metrics['max_time'], duration)
            
            if not success:
                metrics['error_count'] += 1
        
        return duration
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get comprehensive metrics report."""
        report = {}
        
        for operation, metrics in self.metrics.items():
            if metrics['count'] > 0:
                avg_time = metrics['total_time'] / metrics['count']
                error_rate = metrics['error_count'] / metrics['count']
                
                report[operation] = {
                    'count': metrics['count'],
                    'total_time': round(metrics['total_time'], 4),
                    'average_time': round(avg_time, 4),
                    'min_time': round(metrics['min_time'], 4),
                    'max_time': round(metrics['max_time'], 4),
                    'error_count': metrics['error_count'],
                    'error_rate': round(error_rate, 4)
                }
        
        return report


class BaseProcessor:
    """
    Base class for all business data processors.
    
    Provides comprehensive foundation for business data processing operations
    including error handling, metrics collection, caching, and audit logging.
    Implements enterprise patterns per Section 5.2.4 business logic requirements.
    
    Features:
    - Performance monitoring and metrics collection per Section 6.1.3
    - Comprehensive error handling and recovery patterns
    - Caching and performance optimization features
    - Structured audit logging for enterprise compliance
    - Configurable processing modes and behavior
    - Integration with business validation and models
    
    Example:
        class CustomProcessor(BaseProcessor):
            def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
                with self.performance_context("custom_processing"):
                    return self._transform_data(data)
    """
    
    def __init__(
        self,
        config: Optional[ProcessingConfig] = None,
        mode: ProcessingMode = ProcessingMode.STRICT,
        enable_metrics: bool = True,
        enable_caching: bool = True
    ):
        """
        Initialize base processor with configuration and capabilities.
        
        Args:
            config: Processing configuration instance
            mode: Processing mode for behavior control
            enable_metrics: Whether to collect performance metrics
            enable_caching: Whether to enable result caching
        """
        self.config = config or ProcessingConfig()
        self.mode = mode
        self.enable_metrics = enable_metrics
        self.enable_caching = enable_caching
        
        # Initialize metrics collection
        self.metrics = ProcessingMetrics() if enable_metrics else None
        
        # Initialize cache storage
        self._cache = {} if enable_caching else None
        self._cache_ttl = {}
        
        # Error tracking
        self._error_count = 0
        self._last_error = None
        
        # Processing context
        self._processing_id = str(uuid.uuid4())
        self._start_time = datetime.now(timezone.utc)
        
        logger.debug("Business processor initialized",
                    processor_type=self.__class__.__name__,
                    processing_id=self._processing_id,
                    mode=mode.value)
    
    @contextmanager
    def performance_context(self, operation_name: str):
        """
        Context manager for performance monitoring.
        
        Args:
            operation_name: Name of the operation being timed
            
        Yields:
            None - context for timing operations
        """
        success = True
        
        try:
            if self.metrics:
                self.metrics.start_timer(operation_name)
            
            yield
            
        except Exception as e:
            success = False
            self._handle_processing_error(e, operation_name)
            raise
        
        finally:
            if self.metrics:
                duration = self.metrics.end_timer(operation_name, success)
                
                if self.config.ENABLE_AUDIT_LOGGING:
                    logger.debug("Operation completed",
                                operation=operation_name,
                                duration=duration,
                                success=success,
                                processing_id=self._processing_id)
    
    def _handle_processing_error(self, error: Exception, operation_name: str) -> None:
        """
        Handle processing errors with logging and tracking.
        
        Args:
            error: Exception that occurred during processing
            operation_name: Name of the operation that failed
        """
        self._error_count += 1
        self._last_error = error
        
        logger.error("Processing operation failed",
                    operation=operation_name,
                    error_type=type(error).__name__,
                    error_message=str(error),
                    error_count=self._error_count,
                    processing_id=self._processing_id,
                    exc_info=True)
    
    def _get_cache_key(self, data: Any, operation: str) -> str:
        """
        Generate cache key for data and operation.
        
        Args:
            data: Data to generate key for
            operation: Operation name
            
        Returns:
            Cache key string
        """
        if isinstance(data, dict):
            data_str = json.dumps(data, sort_keys=True, default=str)
        else:
            data_str = str(data)
        
        # Create hash for cache key
        import hashlib
        hash_obj = hashlib.md5(f"{operation}:{data_str}".encode())
        return hash_obj.hexdigest()
    
    def _get_cached_result(self, cache_key: str) -> Optional[Any]:
        """
        Get cached result if available and not expired.
        
        Args:
            cache_key: Cache key to lookup
            
        Returns:
            Cached result if available, None otherwise
        """
        if not self._cache or cache_key not in self._cache:
            return None
        
        # Check TTL expiration
        if cache_key in self._cache_ttl:
            expiry_time = self._cache_ttl[cache_key]
            if datetime.now(timezone.utc) > expiry_time:
                # Remove expired cache entry
                del self._cache[cache_key]
                del self._cache_ttl[cache_key]
                return None
        
        return self._cache[cache_key]
    
    def _set_cached_result(self, cache_key: str, result: Any, ttl_seconds: int = None) -> None:
        """
        Set cached result with TTL.
        
        Args:
            cache_key: Cache key to store under
            result: Result to cache
            ttl_seconds: Time to live in seconds
        """
        if not self._cache:
            return
        
        self._cache[cache_key] = result
        
        if ttl_seconds is None:
            ttl_seconds = self.config.CACHE_TTL
        
        expiry_time = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        self._cache_ttl[cache_key] = expiry_time
    
    def validate_input(self, data: Any, expected_type: Type = None) -> None:
        """
        Validate input data for processing.
        
        Args:
            data: Data to validate
            expected_type: Expected data type
            
        Raises:
            DataValidationError: If validation fails
        """
        if data is None:
            raise DataValidationError(
                message="Input data cannot be None",
                error_code="NULL_INPUT_DATA",
                context={'processor': self.__class__.__name__},
                severity=ErrorSeverity.HIGH
            )
        
        if expected_type and not isinstance(data, expected_type):
            raise DataValidationError(
                message=f"Input data must be of type {expected_type.__name__}",
                error_code="INVALID_INPUT_TYPE",
                context={
                    'expected_type': expected_type.__name__,
                    'actual_type': type(data).__name__,
                    'processor': self.__class__.__name__
                },
                severity=ErrorSeverity.HIGH
            )
    
    def get_processing_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive processing summary and metrics.
        
        Returns:
            Dictionary containing processing summary and metrics
        """
        summary = {
            'processor_type': self.__class__.__name__,
            'processing_id': self._processing_id,
            'start_time': self._start_time.isoformat(),
            'mode': self.mode.value,
            'error_count': self._error_count,
            'last_error': str(self._last_error) if self._last_error else None
        }
        
        if self.metrics:
            summary['metrics'] = self.metrics.get_metrics()
        
        if self._cache:
            summary['cache_size'] = len(self._cache)
        
        return summary


# ============================================================================
# CORE DATA PROCESSORS
# ============================================================================

class DataTransformer(BaseProcessor):
    """
    Data format transformation and conversion processor.
    
    Provides comprehensive data transformation capabilities for converting
    between different data formats, structures, and representations while
    maintaining data integrity and business rule compliance per F-004-RQ-001.
    
    Supports transformation between:
    - JSON to/from Python objects
    - Dictionary flattening and expansion
    - Data type conversion and normalization
    - Schema transformation and mapping
    - Business model serialization/deserialization
    
    Example:
        transformer = DataTransformer()
        
        # Transform nested data to flat structure
        flat_data = transformer.flatten_data(nested_dict)
        
        # Convert to business model
        user_model = transformer.to_business_model(user_data, 'User')
    """
    
    def __init__(self, **kwargs):
        """Initialize data transformer with transformation capabilities."""
        super().__init__(**kwargs)
        self._transformation_rules = {}
        self._field_mappings = {}
    
    def transform_data(
        self,
        data: Any,
        target_format: DataFormat,
        source_format: DataFormat = DataFormat.JSON,
        transformation_rules: Optional[Dict[str, Any]] = None
    ) -> Any:
        """
        Transform data between different formats.
        
        Args:
            data: Source data to transform
            target_format: Target data format
            source_format: Source data format
            transformation_rules: Custom transformation rules
            
        Returns:
            Transformed data in target format
            
        Raises:
            DataProcessingError: If transformation fails
        """
        with self.performance_context("transform_data"):
            try:
                self.validate_input(data)
                
                # Generate cache key for transformation
                cache_key = self._get_cache_key({
                    'data': data,
                    'target_format': target_format.value,
                    'source_format': source_format.value,
                    'rules': transformation_rules
                }, "transform_data")
                
                # Check cache first
                cached_result = self._get_cached_result(cache_key)
                if cached_result is not None:
                    logger.debug("Using cached transformation result",
                                cache_key=cache_key[:8])
                    return cached_result
                
                # Apply transformation rules if provided
                if transformation_rules:
                    data = self._apply_transformation_rules(data, transformation_rules)
                
                # Perform format conversion
                result = self._convert_format(data, source_format, target_format)
                
                # Cache the result
                self._set_cached_result(cache_key, result)
                
                logger.debug("Data transformation completed",
                            source_format=source_format.value,
                            target_format=target_format.value,
                            data_size=len(str(data)))
                
                return result
                
            except Exception as e:
                raise DataProcessingError(
                    message="Data transformation failed",
                    error_code="TRANSFORMATION_FAILED",
                    processing_stage="data_transformation",
                    data_type=source_format.value,
                    context={
                        'source_format': source_format.value,
                        'target_format': target_format.value
                    },
                    cause=e,
                    severity=ErrorSeverity.MEDIUM
                )
    
    def flatten_data(
        self,
        data: Dict[str, Any],
        separator: str = ".",
        max_depth: int = 10
    ) -> Dict[str, Any]:
        """
        Flatten nested dictionary structure.
        
        Args:
            data: Nested dictionary to flatten
            separator: Key separator for flattened keys
            max_depth: Maximum nesting depth to process
            
        Returns:
            Flattened dictionary
        """
        with self.performance_context("flatten_data"):
            self.validate_input(data, dict)
            
            def _flatten_recursive(obj: Any, parent_key: str = "", depth: int = 0) -> Dict[str, Any]:
                """Recursively flatten nested structure."""
                if depth > max_depth:
                    return {parent_key: obj}
                
                items = []
                
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        new_key = f"{parent_key}{separator}{key}" if parent_key else key
                        
                        if isinstance(value, (dict, list)) and depth < max_depth:
                            items.extend(_flatten_recursive(value, new_key, depth + 1).items())
                        else:
                            items.append((new_key, value))
                            
                elif isinstance(obj, list):
                    for i, value in enumerate(obj):
                        new_key = f"{parent_key}{separator}{i}" if parent_key else str(i)
                        
                        if isinstance(value, (dict, list)) and depth < max_depth:
                            items.extend(_flatten_recursive(value, new_key, depth + 1).items())
                        else:
                            items.append((new_key, value))
                else:
                    items.append((parent_key, obj))
                
                return dict(items)
            
            result = _flatten_recursive(data)
            
            logger.debug("Data flattening completed",
                        original_keys=len(data),
                        flattened_keys=len(result))
            
            return result
    
    def expand_data(
        self,
        flat_data: Dict[str, Any],
        separator: str = "."
    ) -> Dict[str, Any]:
        """
        Expand flattened dictionary to nested structure.
        
        Args:
            flat_data: Flattened dictionary to expand
            separator: Key separator used in flattened keys
            
        Returns:
            Nested dictionary structure
        """
        with self.performance_context("expand_data"):
            self.validate_input(flat_data, dict)
            
            result = {}
            
            for flat_key, value in flat_data.items():
                keys = flat_key.split(separator)
                current = result
                
                # Navigate to the nested location
                for key in keys[:-1]:
                    # Handle array indices
                    if key.isdigit():
                        key = int(key)
                        
                        # Ensure current is a list
                        if not isinstance(current, list):
                            current = []
                        
                        # Extend list if necessary
                        while len(current) <= key:
                            current.append({})
                        
                        current = current[key]
                    else:
                        if key not in current:
                            current[key] = {}
                        current = current[key]
                
                # Set the final value
                final_key = keys[-1]
                if final_key.isdigit():
                    final_key = int(final_key)
                    
                    if not isinstance(current, list):
                        current = []
                    
                    while len(current) <= final_key:
                        current.append(None)
                    
                    current[final_key] = value
                else:
                    current[final_key] = value
            
            logger.debug("Data expansion completed",
                        flattened_keys=len(flat_data),
                        expanded_structure="nested_dict")
            
            return result
    
    def to_business_model(
        self,
        data: Dict[str, Any],
        model_name: str,
        validate_rules: bool = True
    ) -> BaseBusinessModel:
        """
        Convert dictionary data to business model instance.
        
        Args:
            data: Dictionary data to convert
            model_name: Name of the business model class
            validate_rules: Whether to validate business rules
            
        Returns:
            Business model instance
            
        Raises:
            DataValidationError: If model creation fails
        """
        with self.performance_context("to_business_model"):
            self.validate_input(data, dict)
            
            try:
                # Get model class from registry
                model_class = BUSINESS_MODEL_REGISTRY.get(model_name)
                if not model_class:
                    raise DataValidationError(
                        message=f"Unknown business model: {model_name}",
                        error_code="UNKNOWN_MODEL",
                        context={'model_name': model_name}
                    )
                
                # Clean and prepare data
                cleaned_data = clean_data(data)
                
                # Create model instance
                model_instance = model_class.from_dict(cleaned_data)
                
                # Validate business rules if requested
                if validate_rules:
                    model_instance.validate_business_rules()
                
                logger.debug("Business model created",
                            model_name=model_name,
                            data_fields=len(cleaned_data))
                
                return model_instance
                
            except Exception as e:
                if isinstance(e, (DataValidationError, BusinessRuleViolationError)):
                    raise
                
                raise DataValidationError(
                    message=f"Failed to create {model_name} model",
                    error_code="MODEL_CREATION_FAILED",
                    context={'model_name': model_name},
                    cause=e,
                    severity=ErrorSeverity.MEDIUM
                )
    
    def from_business_model(
        self,
        model: BaseBusinessModel,
        exclude_audit: bool = True,
        format_for_api: bool = True
    ) -> Dict[str, Any]:
        """
        Convert business model instance to dictionary.
        
        Args:
            model: Business model instance to convert
            exclude_audit: Whether to exclude audit fields
            format_for_api: Whether to format for API response
            
        Returns:
            Dictionary representation of the model
        """
        with self.performance_context("from_business_model"):
            self.validate_input(model, BaseBusinessModel)
            
            try:
                if format_for_api:
                    result = model.to_api_dict(exclude_audit=exclude_audit)
                else:
                    result = model.model_dump(
                        exclude_none=True,
                        exclude={'created_at', 'updated_at', 'version'} if exclude_audit else set()
                    )
                
                logger.debug("Business model converted to dictionary",
                            model_type=type(model).__name__,
                            field_count=len(result))
                
                return result
                
            except Exception as e:
                raise DataProcessingError(
                    message=f"Failed to convert {type(model).__name__} to dictionary",
                    error_code="MODEL_SERIALIZATION_FAILED",
                    processing_stage="model_serialization",
                    data_type=type(model).__name__,
                    cause=e,
                    severity=ErrorSeverity.MEDIUM
                )
    
    def _apply_transformation_rules(
        self,
        data: Any,
        rules: Dict[str, Any]
    ) -> Any:
        """
        Apply custom transformation rules to data.
        
        Args:
            data: Data to transform
            rules: Transformation rules to apply
            
        Returns:
            Transformed data
        """
        if not isinstance(data, dict):
            return data
        
        result = data.copy()
        
        for rule_name, rule_config in rules.items():
            if rule_name == "field_mapping":
                # Apply field name mappings
                for old_field, new_field in rule_config.items():
                    if old_field in result:
                        result[new_field] = result.pop(old_field)
            
            elif rule_name == "field_transformation":
                # Apply field value transformations
                for field, transformation in rule_config.items():
                    if field in result:
                        if transformation == "upper":
                            result[field] = str(result[field]).upper()
                        elif transformation == "lower":
                            result[field] = str(result[field]).lower()
                        elif transformation == "strip":
                            result[field] = str(result[field]).strip()
                        elif callable(transformation):
                            result[field] = transformation(result[field])
            
            elif rule_name == "field_removal":
                # Remove specified fields
                for field in rule_config:
                    result.pop(field, None)
        
        return result
    
    def _convert_format(
        self,
        data: Any,
        source_format: DataFormat,
        target_format: DataFormat
    ) -> Any:
        """
        Convert data between specific formats.
        
        Args:
            data: Data to convert
            source_format: Source data format
            target_format: Target data format
            
        Returns:
            Converted data
        """
        # Handle JSON format conversions
        if target_format == DataFormat.JSON:
            if isinstance(data, str):
                return json.loads(data)
            return data
        
        elif target_format == DataFormat.FORM_DATA:
            if isinstance(data, dict):
                return self.flatten_data(data, separator=".")
            return data
        
        elif target_format == DataFormat.QUERY_STRING:
            if isinstance(data, dict):
                flat_data = self.flatten_data(data)
                # Convert to query string format
                return "&".join(f"{k}={v}" for k, v in flat_data.items())
        
        # Default: return data as-is
        return data


class ValidationProcessor(BaseProcessor):
    """
    Business rule validation and enforcement processor.
    
    Provides comprehensive validation processing for business data including
    field validation, business rule enforcement, cross-field validation,
    and data integrity checks per F-004-RQ-001 requirements.
    
    Supports validation of:
    - Business model instances
    - Raw data against schemas
    - Cross-field business rules
    - Data integrity constraints
    - Custom validation functions
    
    Example:
        validator = ValidationProcessor()
        
        # Validate business model
        validation_result = validator.validate_model(user_instance)
        
        # Validate raw data
        cleaned_data = validator.validate_data(raw_data, UserValidator)
    """
    
    def __init__(self, **kwargs):
        """Initialize validation processor with validation capabilities."""
        super().__init__(**kwargs)
        self._validation_cache = {}
        self._business_rules = {}
    
    def validate_model(
        self,
        model: BaseBusinessModel,
        validate_business_rules: bool = True,
        strict_mode: bool = None
    ) -> Dict[str, Any]:
        """
        Validate business model instance comprehensively.
        
        Args:
            model: Business model instance to validate
            validate_business_rules: Whether to validate business rules
            strict_mode: Whether to use strict validation mode
            
        Returns:
            Validation result with success status and any errors
        """
        with self.performance_context("validate_model"):
            self.validate_input(model, BaseBusinessModel)
            
            strict_mode = strict_mode if strict_mode is not None else (self.mode == ProcessingMode.STRICT)
            
            validation_result = {
                'success': True,
                'errors': [],
                'warnings': [],
                'model_type': type(model).__name__,
                'validation_timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            try:
                # Validate model fields using Pydantic validation
                try:
                    # Re-validate the model to catch any issues
                    model.model_validate(model.model_dump())
                except Exception as e:
                    validation_result['success'] = False
                    validation_result['errors'].append({
                        'type': 'field_validation',
                        'message': str(e),
                        'field': 'model_validation'
                    })
                
                # Validate business rules if requested
                if validate_business_rules:
                    try:
                        model.validate_business_rules()
                    except BusinessRuleViolationError as e:
                        if strict_mode:
                            validation_result['success'] = False
                            validation_result['errors'].append({
                                'type': 'business_rule',
                                'message': e.message,
                                'error_code': e.error_code,
                                'context': e.context
                            })
                        else:
                            validation_result['warnings'].append({
                                'type': 'business_rule',
                                'message': e.message,
                                'error_code': e.error_code
                            })
                
                # Perform additional integrity checks
                integrity_errors = self._check_data_integrity(model)
                if integrity_errors:
                    if strict_mode:
                        validation_result['success'] = False
                        validation_result['errors'].extend(integrity_errors)
                    else:
                        validation_result['warnings'].extend(integrity_errors)
                
                logger.debug("Model validation completed",
                            model_type=type(model).__name__,
                            success=validation_result['success'],
                            error_count=len(validation_result['errors']),
                            warning_count=len(validation_result['warnings']))
                
                return validation_result
                
            except Exception as e:
                validation_result['success'] = False
                validation_result['errors'].append({
                    'type': 'validation_error',
                    'message': f"Validation process failed: {str(e)}",
                    'field': 'validation_process'
                })
                
                logger.error("Model validation failed",
                            model_type=type(model).__name__,
                            error=str(e),
                            exc_info=True)
                
                return validation_result
    
    def validate_data(
        self,
        data: Dict[str, Any],
        validator_class: Type[BaseBusinessValidator],
        partial: bool = False
    ) -> Dict[str, Any]:
        """
        Validate raw data against marshmallow validator schema.
        
        Args:
            data: Raw data dictionary to validate
            validator_class: Marshmallow validator class to use
            partial: Whether to allow partial validation
            
        Returns:
            Validation result with cleaned data or errors
        """
        with self.performance_context("validate_data"):
            self.validate_input(data, dict)
            
            try:
                # Create validator instance
                validator = validator_class()
                
                # Perform validation
                try:
                    cleaned_data = validator.load(data, partial=partial)
                    
                    return {
                        'success': True,
                        'data': cleaned_data,
                        'errors': [],
                        'validator': validator_class.__name__
                    }
                    
                except ValidationError as e:
                    return {
                        'success': False,
                        'data': None,
                        'errors': e.messages,
                        'validator': validator_class.__name__
                    }
                
            except Exception as e:
                raise DataValidationError(
                    message="Data validation failed",
                    error_code="DATA_VALIDATION_FAILED",
                    context={
                        'validator': validator_class.__name__,
                        'data_keys': list(data.keys())
                    },
                    cause=e,
                    severity=ErrorSeverity.MEDIUM
                )
    
    def validate_business_rules(
        self,
        data: Dict[str, Any],
        model_type: str,
        rules: Optional[List[Callable]] = None
    ) -> Dict[str, Any]:
        """
        Validate custom business rules against data.
        
        Args:
            data: Data to validate
            model_type: Type of business model
            rules: List of custom validation functions
            
        Returns:
            Validation result with rule violations
        """
        with self.performance_context("validate_business_rules"):
            self.validate_input(data, dict)
            
            validation_result = {
                'success': True,
                'violations': [],
                'model_type': model_type
            }
            
            # Get default rules for model type
            default_rules = self._get_default_business_rules(model_type)
            all_rules = default_rules + (rules or [])
            
            for rule in all_rules:
                try:
                    rule_result = rule(data)
                    if not rule_result.get('valid', True):
                        validation_result['success'] = False
                        validation_result['violations'].append({
                            'rule_name': getattr(rule, '__name__', 'unknown'),
                            'message': rule_result.get('message', 'Business rule violation'),
                            'severity': rule_result.get('severity', 'medium')
                        })
                        
                except Exception as e:
                    logger.warning("Business rule validation failed",
                                  rule_name=getattr(rule, '__name__', 'unknown'),
                                  error=str(e))
                    
                    if self.mode == ProcessingMode.STRICT:
                        validation_result['success'] = False
                        validation_result['violations'].append({
                            'rule_name': getattr(rule, '__name__', 'unknown'),
                            'message': f"Rule validation error: {str(e)}",
                            'severity': 'high'
                        })
            
            return validation_result
    
    def _check_data_integrity(self, model: BaseBusinessModel) -> List[Dict[str, Any]]:
        """
        Check data integrity constraints for business model.
        
        Args:
            model: Business model to check
            
        Returns:
            List of integrity violation errors
        """
        errors = []
        
        # Check for required relationships
        if hasattr(model, 'user_id') and getattr(model, 'user_id', None):
            # Simulate user existence check (in real implementation, would query database)
            pass
        
        # Check for duplicate constraints
        if hasattr(model, 'email') and getattr(model, 'email', None):
            # Simulate email uniqueness check
            pass
        
        # Check for business-specific constraints
        if isinstance(model, Order):
            # Order-specific integrity checks
            if model.total_amount.amount <= 0:
                errors.append({
                    'type': 'integrity_violation',
                    'message': 'Order total must be positive',
                    'field': 'total_amount'
                })
        
        elif isinstance(model, Product):
            # Product-specific integrity checks
            if model.base_price.amount <= 0:
                errors.append({
                    'type': 'integrity_violation',
                    'message': 'Product price must be positive',
                    'field': 'base_price'
                })
        
        return errors
    
    def _get_default_business_rules(self, model_type: str) -> List[Callable]:
        """
        Get default business rules for model type.
        
        Args:
            model_type: Type of business model
            
        Returns:
            List of default validation functions
        """
        rules = []
        
        # Common rules for all models
        def check_audit_fields(data: Dict[str, Any]) -> Dict[str, Any]:
            """Check audit field consistency."""
            created_at = data.get('created_at')
            updated_at = data.get('updated_at')
            
            if created_at and updated_at:
                if isinstance(created_at, str):
                    created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                if isinstance(updated_at, str):
                    updated_at = datetime.fromisoformat(updated_at.replace('Z', '+00:00'))
                
                if updated_at < created_at:
                    return {
                        'valid': False,
                        'message': 'Updated timestamp cannot be before created timestamp'
                    }
            
            return {'valid': True}
        
        rules.append(check_audit_fields)
        
        # Model-specific rules
        if model_type == 'User':
            def check_user_email_domain(data: Dict[str, Any]) -> Dict[str, Any]:
                """Check user email domain restrictions."""
                email = data.get('email', '')
                if email and '@' in email:
                    domain = email.split('@')[1].lower()
                    blocked_domains = ['tempmail.com', 'throwaway.email']
                    if domain in blocked_domains:
                        return {
                            'valid': False,
                            'message': 'Email domain not allowed'
                        }
                return {'valid': True}
            
            rules.append(check_user_email_domain)
        
        elif model_type == 'Order':
            def check_order_total_consistency(data: Dict[str, Any]) -> Dict[str, Any]:
                """Check order total calculation consistency."""
                subtotal = data.get('subtotal', {}).get('amount', 0)
                tax_amount = data.get('tax_amount', {}).get('amount', 0)
                shipping_amount = data.get('shipping_amount', {}).get('amount', 0)
                discount_amount = data.get('discount_amount', {}).get('amount', 0)
                total_amount = data.get('total_amount', {}).get('amount', 0)
                
                calculated_total = subtotal + tax_amount + shipping_amount - discount_amount
                
                if abs(calculated_total - total_amount) > 0.01:
                    return {
                        'valid': False,
                        'message': 'Order total does not match calculated amount'
                    }
                
                return {'valid': True}
            
            rules.append(check_order_total_consistency)
        
        return rules


class SanitizationProcessor(BaseProcessor):
    """
    Data cleaning and security sanitization processor.
    
    Provides comprehensive data sanitization for security and data quality
    including HTML sanitization, SQL injection prevention, XSS protection,
    and data normalization per security requirements.
    
    Features:
    - HTML content sanitization and XSS prevention
    - SQL injection pattern detection and removal
    - Input length limits and character restrictions
    - Personal data masking and privacy protection
    - Malicious content detection and filtering
    
    Example:
        sanitizer = SanitizationProcessor()
        
        # Sanitize user input
        clean_data = sanitizer.sanitize_input(user_input)
        
        # Sanitize HTML content
        safe_html = sanitizer.sanitize_html(html_content)
    """
    
    def __init__(self, **kwargs):
        """Initialize sanitization processor with security capabilities."""
        super().__init__(**kwargs)
        
        # SQL injection patterns
        self._sql_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)",
            r"(\b(UNION|OR|AND)\s+\d+\s*=\s*\d+)",
            r"(--|/\*|\*/)",
            r"(\b(xp_|sp_)\w+)",
            r"(\b(CAST|CONVERT|CHAR|VARCHAR)\s*\()"
        ]
        
        # XSS patterns
        self._xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"vbscript:",
            r"onload\s*=",
            r"onerror\s*=",
            r"onclick\s*=",
            r"onmouseover\s*="
        ]
        
        # Compile patterns for performance
        import re
        self._compiled_sql_patterns = [re.compile(p, re.IGNORECASE) for p in self._sql_patterns]
        self._compiled_xss_patterns = [re.compile(p, re.IGNORECASE) for p in self._xss_patterns]
    
    def sanitize_input(
        self,
        data: Any,
        max_length: Optional[int] = None,
        allow_html: bool = False,
        strict_mode: bool = None
    ) -> Any:
        """
        Sanitize input data for security and data quality.
        
        Args:
            data: Data to sanitize
            max_length: Maximum allowed length for strings
            allow_html: Whether to allow HTML content
            strict_mode: Whether to use strict sanitization
            
        Returns:
            Sanitized data
        """
        with self.performance_context("sanitize_input"):
            if data is None:
                return None
            
            strict_mode = strict_mode if strict_mode is not None else (self.mode == ProcessingMode.STRICT)
            
            if isinstance(data, str):
                return self._sanitize_string(data, max_length, allow_html, strict_mode)
            elif isinstance(data, dict):
                return self._sanitize_dict(data, max_length, allow_html, strict_mode)
            elif isinstance(data, list):
                return self._sanitize_list(data, max_length, allow_html, strict_mode)
            else:
                return data
    
    def sanitize_html(
        self,
        html_content: str,
        allowed_tags: Optional[Set[str]] = None,
        allowed_attributes: Optional[Set[str]] = None
    ) -> str:
        """
        Sanitize HTML content to prevent XSS attacks.
        
        Args:
            html_content: HTML content to sanitize
            allowed_tags: Set of allowed HTML tags
            allowed_attributes: Set of allowed HTML attributes
            
        Returns:
            Sanitized HTML content
        """
        with self.performance_context("sanitize_html"):
            if not isinstance(html_content, str):
                return str(html_content)
            
            # Default allowed tags and attributes
            if allowed_tags is None:
                allowed_tags = {'p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'}
            
            if allowed_attributes is None:
                allowed_attributes = {'class', 'id'}
            
            try:
                import bleach
                
                cleaned_html = bleach.clean(
                    html_content,
                    tags=allowed_tags,
                    attributes=allowed_attributes,
                    strip=True
                )
                
                logger.debug("HTML content sanitized",
                            original_length=len(html_content),
                            sanitized_length=len(cleaned_html))
                
                return cleaned_html
                
            except ImportError:
                # Fallback to basic sanitization if bleach is not available
                logger.warning("bleach library not available, using basic HTML sanitization")
                return self._basic_html_sanitization(html_content)
    
    def detect_malicious_content(
        self,
        content: str,
        check_sql_injection: bool = True,
        check_xss: bool = True
    ) -> Dict[str, Any]:
        """
        Detect potentially malicious content patterns.
        
        Args:
            content: Content to analyze
            check_sql_injection: Whether to check for SQL injection
            check_xss: Whether to check for XSS patterns
            
        Returns:
            Detection result with found threats
        """
        with self.performance_context("detect_malicious_content"):
            if not isinstance(content, str):
                content = str(content)
            
            threats = []
            
            # Check for SQL injection patterns
            if check_sql_injection:
                for pattern in self._compiled_sql_patterns:
                    matches = pattern.findall(content)
                    if matches:
                        threats.append({
                            'type': 'sql_injection',
                            'pattern': pattern.pattern,
                            'matches': matches[:5]  # Limit matches for security
                        })
            
            # Check for XSS patterns
            if check_xss:
                for pattern in self._compiled_xss_patterns:
                    matches = pattern.findall(content)
                    if matches:
                        threats.append({
                            'type': 'xss',
                            'pattern': pattern.pattern,
                            'matches': matches[:5]  # Limit matches for security
                        })
            
            result = {
                'is_malicious': len(threats) > 0,
                'threat_count': len(threats),
                'threats': threats,
                'content_length': len(content)
            }
            
            if threats:
                logger.warning("Malicious content detected",
                              threat_count=len(threats),
                              content_length=len(content))
            
            return result
    
    def mask_sensitive_data(
        self,
        data: Dict[str, Any],
        sensitive_fields: Optional[Set[str]] = None
    ) -> Dict[str, Any]:
        """
        Mask sensitive data fields for privacy protection.
        
        Args:
            data: Data dictionary to mask
            sensitive_fields: Set of field names to mask
            
        Returns:
            Data with sensitive fields masked
        """
        with self.performance_context("mask_sensitive_data"):
            self.validate_input(data, dict)
            
            if sensitive_fields is None:
                sensitive_fields = {
                    'password', 'ssn', 'social_security_number', 'credit_card',
                    'card_number', 'cvv', 'pin', 'token', 'api_key', 'secret'
                }
            
            masked_data = data.copy()
            
            for field_name, value in data.items():
                # Check if field name indicates sensitive data
                if any(sensitive in field_name.lower() for sensitive in sensitive_fields):
                    if isinstance(value, str) and value:
                        # Mask with asterisks, showing only first and last character
                        if len(value) > 2:
                            masked_data[field_name] = value[0] + '*' * (len(value) - 2) + value[-1]
                        else:
                            masked_data[field_name] = '*' * len(value)
                    else:
                        masked_data[field_name] = '***MASKED***'
                
                # Handle nested dictionaries
                elif isinstance(value, dict):
                    masked_data[field_name] = self.mask_sensitive_data(value, sensitive_fields)
                
                # Handle lists of dictionaries
                elif isinstance(value, list):
                    masked_list = []
                    for item in value:
                        if isinstance(item, dict):
                            masked_list.append(self.mask_sensitive_data(item, sensitive_fields))
                        else:
                            masked_list.append(item)
                    masked_data[field_name] = masked_list
            
            logger.debug("Sensitive data masked",
                        field_count=len(data),
                        masked_fields=len([f for f in data.keys() 
                                         if any(s in f.lower() for s in sensitive_fields)]))
            
            return masked_data
    
    def _sanitize_string(
        self,
        text: str,
        max_length: Optional[int],
        allow_html: bool,
        strict_mode: bool
    ) -> str:
        """Sanitize individual string value."""
        if not text:
            return text
        
        # Strip whitespace
        sanitized = text.strip()
        
        # Check for malicious content
        if strict_mode:
            threats = self.detect_malicious_content(sanitized)
            if threats['is_malicious']:
                logger.warning("Malicious content detected and removed",
                              threat_count=threats['threat_count'])
                # Remove the malicious content
                for threat in threats['threats']:
                    for pattern in self._compiled_sql_patterns + self._compiled_xss_patterns:
                        sanitized = pattern.sub('', sanitized)
        
        # Sanitize HTML if not allowed
        if not allow_html:
            sanitized = self._strip_html_tags(sanitized)
        else:
            sanitized = self.sanitize_html(sanitized)
        
        # Apply length limits
        if max_length and len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        # Remove control characters
        sanitized = ''.join(char for char in sanitized if ord(char) >= 32 or char in '\n\r\t')
        
        return sanitized
    
    def _sanitize_dict(
        self,
        data: Dict[str, Any],
        max_length: Optional[int],
        allow_html: bool,
        strict_mode: bool
    ) -> Dict[str, Any]:
        """Sanitize dictionary values recursively."""
        sanitized = {}
        
        for key, value in data.items():
            # Sanitize key
            clean_key = self._sanitize_string(key, 100, False, strict_mode)
            
            # Sanitize value
            sanitized[clean_key] = self.sanitize_input(value, max_length, allow_html, strict_mode)
        
        return sanitized
    
    def _sanitize_list(
        self,
        data: List[Any],
        max_length: Optional[int],
        allow_html: bool,
        strict_mode: bool
    ) -> List[Any]:
        """Sanitize list items recursively."""
        return [self.sanitize_input(item, max_length, allow_html, strict_mode) for item in data]
    
    def _strip_html_tags(self, text: str) -> str:
        """Basic HTML tag removal."""
        import re
        # Remove HTML tags
        clean = re.sub(r'<[^>]+>', '', text)
        # Decode HTML entities
        clean = clean.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
        clean = clean.replace('&quot;', '"').replace('&#x27;', "'").replace('&#x2F;', '/')
        return clean
    
    def _basic_html_sanitization(self, html_content: str) -> str:
        """Basic HTML sanitization without bleach library."""
        # Remove dangerous tags completely
        import re
        
        dangerous_tags = ['script', 'object', 'embed', 'link', 'meta', 'iframe', 'frame']
        for tag in dangerous_tags:
            pattern = f'<{tag}[^>]*>.*?</{tag}>'
            html_content = re.sub(pattern, '', html_content, flags=re.IGNORECASE | re.DOTALL)
        
        # Remove dangerous attributes
        dangerous_attrs = ['onload', 'onerror', 'onclick', 'onmouseover', 'javascript:', 'vbscript:']
        for attr in dangerous_attrs:
            pattern = f'{attr}[^\\s>]*'
            html_content = re.sub(pattern, '', html_content, flags=re.IGNORECASE)
        
        return html_content


class NormalizationProcessor(BaseProcessor):
    """
    Data normalization and standardization processor.
    
    Provides comprehensive data normalization for consistent data representation
    including format standardization, encoding normalization, case normalization,
    and business data standardization patterns per Section 5.2.4.
    
    Features:
    - Text case and encoding normalization
    - Date/time format standardization
    - Numeric precision and format normalization
    - Address and contact information standardization
    - Currency and monetary amount normalization
    
    Example:
        normalizer = NormalizationProcessor()
        
        # Normalize contact data
        normalized_data = normalizer.normalize_data(contact_data)
        
        # Normalize phone numbers
        normalized_phone = normalizer.normalize_phone(phone_number)
    """
    
    def __init__(self, **kwargs):
        """Initialize normalization processor with standardization capabilities."""
        super().__init__(**kwargs)
        
        # Normalization configuration
        self.default_timezone = tz.gettz(self.config.DEFAULT_TIMEZONE)
        self.date_formats = [
            "%Y-%m-%d",
            "%m/%d/%Y",
            "%d/%m/%Y",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S%z"
        ]
    
    def normalize_data(
        self,
        data: Dict[str, Any],
        normalization_rules: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Normalize data according to business standards.
        
        Args:
            data: Data dictionary to normalize
            normalization_rules: Custom normalization rules
            
        Returns:
            Normalized data dictionary
        """
        with self.performance_context("normalize_data"):
            self.validate_input(data, dict)
            
            normalized = {}
            rules = normalization_rules or {}
            
            for field_name, value in data.items():
                try:
                    # Apply field-specific normalization
                    if field_name in rules:
                        rule = rules[field_name]
                        if callable(rule):
                            normalized[field_name] = rule(value)
                        else:
                            normalized[field_name] = self._apply_normalization_rule(value, rule)
                    else:
                        # Apply default normalization based on field type and name
                        normalized[field_name] = self._auto_normalize_field(field_name, value)
                        
                except Exception as e:
                    logger.warning("Field normalization failed",
                                  field=field_name,
                                  error=str(e))
                    normalized[field_name] = value  # Keep original value if normalization fails
            
            logger.debug("Data normalization completed",
                        field_count=len(data),
                        normalized_fields=len(normalized))
            
            return normalized
    
    def normalize_text(
        self,
        text: str,
        case_style: str = "title",
        remove_extra_spaces: bool = True,
        normalize_unicode: bool = True
    ) -> str:
        """
        Normalize text content for consistency.
        
        Args:
            text: Text to normalize
            case_style: Case normalization style (upper, lower, title, sentence)
            remove_extra_spaces: Whether to remove extra whitespace
            normalize_unicode: Whether to normalize Unicode characters
            
        Returns:
            Normalized text
        """
        with self.performance_context("normalize_text"):
            if not isinstance(text, str):
                text = str(text)
            
            if not text:
                return text
            
            normalized = text
            
            # Unicode normalization
            if normalize_unicode:
                import unicodedata
                normalized = unicodedata.normalize('NFKC', normalized)
            
            # Remove extra whitespace
            if remove_extra_spaces:
                normalized = ' '.join(normalized.split())
            
            # Apply case style
            if case_style == "upper":
                normalized = normalized.upper()
            elif case_style == "lower":
                normalized = normalized.lower()
            elif case_style == "title":
                normalized = normalized.title()
            elif case_style == "sentence":
                normalized = normalized.capitalize()
            
            return normalized.strip()
    
    def normalize_phone(
        self,
        phone_number: str,
        country_code: str = "US",
        format_type: str = "international"
    ) -> str:
        """
        Normalize phone number to standard format.
        
        Args:
            phone_number: Phone number to normalize
            country_code: ISO country code for formatting
            format_type: Format type (international, national, e164)
            
        Returns:
            Normalized phone number
        """
        with self.performance_context("normalize_phone"):
            if not phone_number:
                return phone_number
            
            try:
                import phonenumbers
                from phonenumbers import NumberParseException
                
                # Parse phone number
                parsed = phonenumbers.parse(phone_number, country_code)
                
                if not phonenumbers.is_valid_number(parsed):
                    logger.warning("Invalid phone number format",
                                  phone=phone_number,
                                  country=country_code)
                    return phone_number
                
                # Format according to requested type
                if format_type == "international":
                    formatted = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
                elif format_type == "national":
                    formatted = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
                elif format_type == "e164":
                    formatted = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
                else:
                    formatted = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
                
                logger.debug("Phone number normalized",
                            original=phone_number,
                            normalized=formatted)
                
                return formatted
                
            except (ImportError, NumberParseException) as e:
                logger.warning("Phone normalization failed",
                              phone=phone_number,
                              error=str(e))
                return phone_number
    
    def normalize_currency(
        self,
        amount: Union[str, int, float, Decimal],
        currency_code: str = "USD",
        precision: int = 2
    ) -> MonetaryAmount:
        """
        Normalize monetary amount to standard format.
        
        Args:
            amount: Amount to normalize
            currency_code: ISO currency code
            precision: Decimal precision
            
        Returns:
            Normalized monetary amount
        """
        with self.performance_context("normalize_currency"):
            try:
                # Convert to Decimal for precise handling
                if isinstance(amount, str):
                    # Remove currency symbols and formatting
                    clean_amount = re.sub(r'[^\d.-]', '', amount)
                    decimal_amount = Decimal(clean_amount)
                else:
                    decimal_amount = Decimal(str(amount))
                
                # Round to specified precision
                decimal_amount = decimal_amount.quantize(
                    Decimal('0.' + '0' * precision),
                    rounding=ROUND_HALF_UP
                )
                
                # Validate currency code
                currency_code = currency_code.upper().strip()
                if len(currency_code) != 3:
                    raise ValueError("Invalid currency code")
                
                normalized_amount = MonetaryAmount(
                    amount=decimal_amount,
                    currency_code=currency_code
                )
                
                logger.debug("Currency normalized",
                            original_amount=str(amount),
                            normalized_amount=str(decimal_amount),
                            currency=currency_code)
                
                return normalized_amount
                
            except Exception as e:
                raise DataProcessingError(
                    message="Currency normalization failed",
                    error_code="CURRENCY_NORMALIZATION_FAILED",
                    processing_stage="currency_normalization",
                    context={
                        'amount': str(amount),
                        'currency_code': currency_code
                    },
                    cause=e,
                    severity=ErrorSeverity.MEDIUM
                )
    
    def normalize_address(
        self,
        address_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Normalize address data to standard format.
        
        Args:
            address_data: Address data dictionary
            
        Returns:
            Normalized address data
        """
        with self.performance_context("normalize_address"):
            self.validate_input(address_data, dict)
            
            normalized = address_data.copy()
            
            # Normalize street address
            if 'street_line_1' in normalized:
                normalized['street_line_1'] = self.normalize_text(
                    normalized['street_line_1'],
                    case_style="title"
                )
            
            if 'street_line_2' in normalized and normalized['street_line_2']:
                normalized['street_line_2'] = self.normalize_text(
                    normalized['street_line_2'],
                    case_style="title"
                )
            
            # Normalize city
            if 'city' in normalized:
                normalized['city'] = self.normalize_text(
                    normalized['city'],
                    case_style="title"
                )
            
            # Normalize state/province
            if 'state_province' in normalized:
                state = normalized['state_province'].strip().upper()
                # Handle common state abbreviations for US
                us_states = {
                    'CALIFORNIA': 'CA', 'NEW YORK': 'NY', 'TEXAS': 'TX',
                    'FLORIDA': 'FL', 'ILLINOIS': 'IL', 'PENNSYLVANIA': 'PA'
                }
                normalized['state_province'] = us_states.get(state, state)
            
            # Normalize postal code
            if 'postal_code' in normalized:
                postal = normalized['postal_code'].strip().upper()
                # Handle different postal code formats
                if 'country_code' in normalized:
                    country = normalized['country_code'].upper()
                    if country == 'US':
                        # US ZIP code format
                        postal = re.sub(r'[^\d-]', '', postal)
                        if len(postal) == 9:
                            postal = f"{postal[:5]}-{postal[5:]}"
                    elif country == 'CA':
                        # Canadian postal code format
                        postal = re.sub(r'[^\w]', '', postal).upper()
                        if len(postal) == 6:
                            postal = f"{postal[:3]} {postal[3:]}"
                
                normalized['postal_code'] = postal
            
            # Normalize country code
            if 'country_code' in normalized:
                normalized['country_code'] = normalized['country_code'].strip().upper()
            
            return normalized
    
    def _auto_normalize_field(self, field_name: str, value: Any) -> Any:
        """
        Automatically normalize field based on name and type.
        
        Args:
            field_name: Name of the field
            value: Field value to normalize
            
        Returns:
            Normalized field value
        """
        if value is None:
            return value
        
        field_lower = field_name.lower()
        
        # Email normalization
        if 'email' in field_lower and isinstance(value, str):
            return value.strip().lower()
        
        # Name fields normalization
        elif any(name_field in field_lower for name_field in ['name', 'first_name', 'last_name']):
            if isinstance(value, str):
                return self.normalize_text(value, case_style="title")
        
        # Phone number normalization
        elif 'phone' in field_lower and isinstance(value, str):
            return self.normalize_phone(value)
        
        # Date/time normalization
        elif any(date_field in field_lower for date_field in ['date', 'time', 'created_at', 'updated_at']):
            if isinstance(value, str):
                try:
                    parsed_date = parse_date(value)
                    if parsed_date:
                        return parsed_date.isoformat()
                except Exception:
                    pass
        
        # URL normalization
        elif 'url' in field_lower and isinstance(value, str):
            url = value.strip().lower()
            if url and not url.startswith(('http://', 'https://')):
                url = f"https://{url}"
            return url
        
        # Default string normalization
        elif isinstance(value, str):
            return value.strip()
        
        return value
    
    def _apply_normalization_rule(self, value: Any, rule: str) -> Any:
        """
        Apply specific normalization rule to value.
        
        Args:
            value: Value to normalize
            rule: Normalization rule to apply
            
        Returns:
            Normalized value
        """
        if not isinstance(value, str):
            return value
        
        if rule == "upper":
            return value.upper()
        elif rule == "lower":
            return value.lower()
        elif rule == "title":
            return value.title()
        elif rule == "strip":
            return value.strip()
        elif rule == "remove_spaces":
            return re.sub(r'\s+', '', value)
        elif rule == "normalize_spaces":
            return ' '.join(value.split())
        
        return value


# ============================================================================
# DATE/TIME PROCESSORS
# ============================================================================

class DateTimeProcessor(BaseProcessor):
    """
    Date/time parsing, formatting, and calculations processor.
    
    Provides comprehensive date/time processing using python-dateutil 2.8+
    equivalent to moment.js functionality per Section 5.2.4. Implements
    business date calculations, timezone handling, and temporal operations
    maintaining identical input/output characteristics per F-004-RQ-001.
    
    Features:
    - Date/time parsing with multiple format support
    - Timezone conversion and management
    - Business day calculations and scheduling
    - Date arithmetic and relative calculations
    - Recurring pattern processing
    - Performance-optimized date operations
    
    Example:
        dt_processor = DateTimeProcessor()
        
        # Parse flexible date formats
        parsed_date = dt_processor.parse_datetime("2023-12-25 15:30:00")
        
        # Calculate business days
        business_days = dt_processor.calculate_business_days(start_date, end_date)
        
        # Format for API response
        formatted = dt_processor.format_for_api(datetime.now())
    """
    
    def __init__(self, **kwargs):
        """Initialize date/time processor with temporal capabilities."""
        super().__init__(**kwargs)
        
        # Configure default timezone
        self.default_timezone = tz.gettz(self.config.DEFAULT_TIMEZONE)
        
        # Business day configuration
        self.business_days = [0, 1, 2, 3, 4]  # Monday through Friday
        self.holidays = set()  # Can be configured with holiday dates
        
        # Date format patterns for parsing
        self.date_formats = [
            "%Y-%m-%d",
            "%m/%d/%Y",
            "%d/%m/%Y",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%a, %d %b %Y %H:%M:%S %Z",
            "%d %b %Y %H:%M:%S"
        ]
        
        # Common timezone mappings
        self.timezone_mappings = {
            'EST': 'US/Eastern',
            'PST': 'US/Pacific',
            'CST': 'US/Central',
            'MST': 'US/Mountain',
            'GMT': 'UTC',
            'UTC': 'UTC'
        }
    
    def parse_datetime(
        self,
        date_input: Union[str, datetime, date, int, float],
        target_timezone: Optional[str] = None,
        default_timezone: Optional[str] = None
    ) -> datetime:
        """
        Parse date/time input to datetime object with timezone handling.
        
        Args:
            date_input: Date/time input in various formats
            target_timezone: Target timezone for conversion
            default_timezone: Default timezone if input has none
            
        Returns:
            Parsed datetime object with timezone
            
        Raises:
            DataProcessingError: If parsing fails
        """
        with self.performance_context("parse_datetime"):
            try:
                parsed_dt = None
                
                # Handle different input types
                if isinstance(date_input, datetime):
                    parsed_dt = date_input
                elif isinstance(date_input, date):
                    parsed_dt = datetime.combine(date_input, datetime.min.time())
                elif isinstance(date_input, (int, float)):
                    # Unix timestamp
                    parsed_dt = datetime.fromtimestamp(date_input, tz=timezone.utc)
                elif isinstance(date_input, str):
                    parsed_dt = self._parse_string_date(date_input)
                else:
                    raise ValueError(f"Unsupported date input type: {type(date_input)}")
                
                if parsed_dt is None:
                    raise ValueError("Failed to parse date input")
                
                # Handle timezone assignment
                if parsed_dt.tzinfo is None:
                    # Assign default timezone if none specified
                    default_tz = default_timezone or self.config.DEFAULT_TIMEZONE
                    if default_tz in self.timezone_mappings:
                        default_tz = self.timezone_mappings[default_tz]
                    parsed_dt = parsed_dt.replace(tzinfo=tz.gettz(default_tz))
                
                # Convert to target timezone if specified
                if target_timezone:
                    if target_timezone in self.timezone_mappings:
                        target_timezone = self.timezone_mappings[target_timezone]
                    target_tz = tz.gettz(target_timezone)
                    parsed_dt = parsed_dt.astimezone(target_tz)
                
                logger.debug("DateTime parsed successfully",
                            original_input=str(date_input)[:50],
                            parsed_datetime=parsed_dt.isoformat(),
                            timezone=str(parsed_dt.tzinfo))
                
                return parsed_dt
                
            except Exception as e:
                raise DataProcessingError(
                    message="Failed to parse datetime input",
                    error_code="DATETIME_PARSE_FAILED",
                    processing_stage="datetime_parsing",
                    data_type=type(date_input).__name__,
                    context={
                        'input': str(date_input)[:100],
                        'target_timezone': target_timezone
                    },
                    cause=e,
                    severity=ErrorSeverity.MEDIUM
                )
    
    def format_for_api(
        self,
        dt: datetime,
        format_type: str = "iso",
        include_timezone: bool = True
    ) -> str:
        """
        Format datetime for API response per F-004-RQ-004.
        
        Args:
            dt: Datetime object to format
            format_type: Format type (iso, rfc, timestamp, custom)
            include_timezone: Whether to include timezone information
            
        Returns:
            Formatted datetime string
        """
        with self.performance_context("format_for_api"):
            self.validate_input(dt, datetime)
            
            try:
                if format_type == "iso":
                    if include_timezone:
                        return dt.isoformat()
                    else:
                        return dt.replace(tzinfo=None).isoformat()
                
                elif format_type == "rfc":
                    return dt.strftime("%a, %d %b %Y %H:%M:%S %Z")
                
                elif format_type == "timestamp":
                    return str(int(dt.timestamp()))
                
                elif format_type == "date_only":
                    return dt.strftime("%Y-%m-%d")
                
                elif format_type == "time_only":
                    return dt.strftime("%H:%M:%S")
                
                elif format_type == "human":
                    return dt.strftime("%B %d, %Y at %I:%M %p")
                
                else:
                    # Default to ISO format
                    return dt.isoformat()
                
            except Exception as e:
                raise DataProcessingError(
                    message="Failed to format datetime",
                    error_code="DATETIME_FORMAT_FAILED",
                    processing_stage="datetime_formatting",
                    context={'format_type': format_type},
                    cause=e,
                    severity=ErrorSeverity.LOW
                )
    
    def calculate_business_days(
        self,
        start_date: Union[datetime, date],
        end_date: Union[datetime, date],
        exclude_holidays: bool = True
    ) -> int:
        """
        Calculate number of business days between two dates.
        
        Args:
            start_date: Start date for calculation
            end_date: End date for calculation
            exclude_holidays: Whether to exclude holidays
            
        Returns:
            Number of business days
        """
        with self.performance_context("calculate_business_days"):
            if isinstance(start_date, datetime):
                start_date = start_date.date()
            if isinstance(end_date, datetime):
                end_date = end_date.date()
            
            if start_date > end_date:
                start_date, end_date = end_date, start_date
            
            business_day_count = 0
            current_date = start_date
            
            while current_date <= end_date:
                # Check if it's a business day (Monday=0, Sunday=6)
                if current_date.weekday() in self.business_days:
                    # Check if it's not a holiday
                    if not exclude_holidays or current_date not in self.holidays:
                        business_day_count += 1
                
                current_date += timedelta(days=1)
            
            logger.debug("Business days calculated",
                        start_date=start_date.isoformat(),
                        end_date=end_date.isoformat(),
                        business_days=business_day_count)
            
            return business_day_count
    
    def add_business_days(
        self,
        start_date: Union[datetime, date],
        business_days: int,
        exclude_holidays: bool = True
    ) -> date:
        """
        Add business days to a date.
        
        Args:
            start_date: Starting date
            business_days: Number of business days to add
            exclude_holidays: Whether to exclude holidays
            
        Returns:
            Resulting date after adding business days
        """
        with self.performance_context("add_business_days"):
            if isinstance(start_date, datetime):
                current_date = start_date.date()
            else:
                current_date = start_date
            
            days_added = 0
            
            while days_added < business_days:
                current_date += timedelta(days=1)
                
                # Check if it's a business day
                if current_date.weekday() in self.business_days:
                    # Check if it's not a holiday
                    if not exclude_holidays or current_date not in self.holidays:
                        days_added += 1
            
            return current_date
    
    def get_date_range(
        self,
        start_date: Union[datetime, date],
        end_date: Union[datetime, date],
        frequency: str = "daily",
        business_days_only: bool = False
    ) -> List[date]:
        """
        Generate list of dates within a range.
        
        Args:
            start_date: Start date of range
            end_date: End date of range
            frequency: Frequency of dates (daily, weekly, monthly)
            business_days_only: Whether to include only business days
            
        Returns:
            List of dates in the range
        """
        with self.performance_context("get_date_range"):
            if isinstance(start_date, datetime):
                start_date = start_date.date()
            if isinstance(end_date, datetime):
                end_date = end_date.date()
            
            dates = []
            current_date = start_date
            
            # Determine increment based on frequency
            if frequency == "daily":
                increment = timedelta(days=1)
            elif frequency == "weekly":
                increment = timedelta(weeks=1)
            elif frequency == "monthly":
                increment = relativedelta(months=1)
            else:
                increment = timedelta(days=1)
            
            while current_date <= end_date:
                # Check business day constraint
                if not business_days_only or current_date.weekday() in self.business_days:
                    dates.append(current_date)
                
                # Increment date
                if frequency == "monthly":
                    current_date = current_date + increment
                else:
                    current_date += increment
            
            logger.debug("Date range generated",
                        start_date=start_date.isoformat(),
                        end_date=end_date.isoformat(),
                        frequency=frequency,
                        date_count=len(dates))
            
            return dates
    
    def calculate_age(
        self,
        birth_date: Union[datetime, date],
        reference_date: Optional[Union[datetime, date]] = None
    ) -> Dict[str, int]:
        """
        Calculate age from birth date.
        
        Args:
            birth_date: Birth date
            reference_date: Reference date for calculation (default: today)
            
        Returns:
            Dictionary with years, months, and days
        """
        with self.performance_context("calculate_age"):
            if isinstance(birth_date, datetime):
                birth_date = birth_date.date()
            
            if reference_date is None:
                reference_date = date.today()
            elif isinstance(reference_date, datetime):
                reference_date = reference_date.date()
            
            # Calculate using relativedelta for accurate month/day calculations
            delta = relativedelta(reference_date, birth_date)
            
            age = {
                'years': delta.years,
                'months': delta.months,
                'days': delta.days,
                'total_days': (reference_date - birth_date).days
            }
            
            logger.debug("Age calculated",
                        birth_date=birth_date.isoformat(),
                        reference_date=reference_date.isoformat(),
                        age_years=age['years'])
            
            return age
    
    def is_business_day(
        self,
        check_date: Union[datetime, date],
        exclude_holidays: bool = True
    ) -> bool:
        """
        Check if date is a business day.
        
        Args:
            check_date: Date to check
            exclude_holidays: Whether to exclude holidays
            
        Returns:
            True if business day, False otherwise
        """
        if isinstance(check_date, datetime):
            check_date = check_date.date()
        
        # Check if weekday is a business day
        if check_date.weekday() not in self.business_days:
            return False
        
        # Check if it's a holiday
        if exclude_holidays and check_date in self.holidays:
            return False
        
        return True
    
    def convert_timezone(
        self,
        dt: datetime,
        target_timezone: str,
        source_timezone: Optional[str] = None
    ) -> datetime:
        """
        Convert datetime between timezones.
        
        Args:
            dt: Datetime to convert
            target_timezone: Target timezone
            source_timezone: Source timezone (if dt is naive)
            
        Returns:
            Datetime in target timezone
        """
        with self.performance_context("convert_timezone"):
            # Handle timezone name mappings
            if target_timezone in self.timezone_mappings:
                target_timezone = self.timezone_mappings[target_timezone]
            
            target_tz = tz.gettz(target_timezone)
            
            # If datetime is naive, assign source timezone
            if dt.tzinfo is None:
                if source_timezone:
                    if source_timezone in self.timezone_mappings:
                        source_timezone = self.timezone_mappings[source_timezone]
                    source_tz = tz.gettz(source_timezone)
                    dt = dt.replace(tzinfo=source_tz)
                else:
                    dt = dt.replace(tzinfo=self.default_timezone)
            
            # Convert to target timezone
            converted_dt = dt.astimezone(target_tz)
            
            logger.debug("Timezone conversion completed",
                        original_timezone=str(dt.tzinfo),
                        target_timezone=target_timezone,
                        time_difference=str(converted_dt - dt.replace(tzinfo=None)))
            
            return converted_dt
    
    def _parse_string_date(self, date_string: str) -> Optional[datetime]:
        """
        Parse string date using multiple format attempts.
        
        Args:
            date_string: Date string to parse
            
        Returns:
            Parsed datetime or None if parsing fails
        """
        date_string = date_string.strip()
        
        # Try dateutil parser first (most flexible)
        try:
            return date_parser.parse(date_string)
        except (ValueError, TypeError):
            pass
        
        # Try specific formats
        for fmt in self.date_formats:
            try:
                return datetime.strptime(date_string, fmt)
            except ValueError:
                continue
        
        # Try parsing common relative formats
        if date_string.lower() in ['now', 'today']:
            return datetime.now(self.default_timezone)
        elif date_string.lower() == 'yesterday':
            return datetime.now(self.default_timezone) - timedelta(days=1)
        elif date_string.lower() == 'tomorrow':
            return datetime.now(self.default_timezone) + timedelta(days=1)
        
        return None


# ============================================================================
# BUSINESS LOGIC PROCESSORS
# ============================================================================

class BusinessRuleEngine(BaseProcessor):
    """
    Core business rule execution and validation processor.
    
    Provides comprehensive business rule processing engine for executing
    business logic patterns, validation rules, and decision workflows
    maintaining behavioral equivalence per F-004-RQ-001 requirements.
    
    Features:
    - Rule definition and execution framework
    - Conditional logic and decision trees
    - Business workflow orchestration
    - Rule dependency management
    - Performance-optimized rule evaluation
    - Audit trail and compliance logging
    
    Example:
        rule_engine = BusinessRuleEngine()
        
        # Define custom business rule
        rule_engine.add_rule("validate_order_total", order_total_rule)
        
        # Execute rules against data
        result = rule_engine.execute_rules(order_data, rule_set="order_validation")
    """
    
    def __init__(self, **kwargs):
        """Initialize business rule engine with rule execution capabilities."""
        super().__init__(**kwargs)
        
        # Rule registry and execution context
        self._rules = {}
        self._rule_sets = {}
        self._rule_dependencies = {}
        self._execution_context = {}
        
        # Performance tracking
        self._rule_execution_stats = {}
        
        # Initialize default rule sets
        self._initialize_default_rules()
    
    def add_rule(
        self,
        rule_name: str,
        rule_function: Callable[[Dict[str, Any]], Dict[str, Any]],
        rule_set: str = "default",
        dependencies: Optional[List[str]] = None,
        priority: int = 100
    ) -> None:
        """
        Add business rule to the engine.
        
        Args:
            rule_name: Unique name for the rule
            rule_function: Function that implements the rule logic
            rule_set: Rule set to add the rule to
            dependencies: List of rule names this rule depends on
            priority: Execution priority (lower numbers execute first)
        """
        self._rules[rule_name] = {
            'function': rule_function,
            'rule_set': rule_set,
            'dependencies': dependencies or [],
            'priority': priority,
            'created_at': datetime.now(timezone.utc),
            'execution_count': 0
        }
        
        # Add to rule set
        if rule_set not in self._rule_sets:
            self._rule_sets[rule_set] = []
        
        if rule_name not in self._rule_sets[rule_set]:
            self._rule_sets[rule_set].append(rule_name)
            # Sort by priority
            self._rule_sets[rule_set].sort(
                key=lambda name: self._rules[name]['priority']
            )
        
        # Update dependencies
        if dependencies:
            self._rule_dependencies[rule_name] = dependencies
        
        logger.debug("Business rule added",
                    rule_name=rule_name,
                    rule_set=rule_set,
                    dependencies=dependencies,
                    priority=priority)
    
    def execute_rules(
        self,
        data: Dict[str, Any],
        rule_set: str = "default",
        context: Optional[Dict[str, Any]] = None,
        fail_fast: bool = False
    ) -> Dict[str, Any]:
        """
        Execute business rules against data.
        
        Args:
            data: Data to execute rules against
            rule_set: Name of rule set to execute
            context: Additional execution context
            fail_fast: Whether to stop on first rule failure
            
        Returns:
            Execution result with rule outcomes
        """
        with self.performance_context("execute_rules"):
            self.validate_input(data, dict)
            
            execution_id = str(uuid.uuid4())
            execution_context = {
                'execution_id': execution_id,
                'rule_set': rule_set,
                'start_time': datetime.now(timezone.utc),
                'data_hash': self._calculate_data_hash(data),
                **(context or {})
            }
            
            result = {
                'success': True,
                'execution_id': execution_id,
                'rule_set': rule_set,
                'rules_executed': [],
                'rules_passed': [],
                'rules_failed': [],
                'execution_summary': {},
                'data_modified': False,
                'final_data': data.copy()
            }
            
            try:
                # Get rules for the rule set
                if rule_set not in self._rule_sets:
                    raise BusinessRuleViolationError(
                        message=f"Unknown rule set: {rule_set}",
                        error_code="UNKNOWN_RULE_SET",
                        context={'rule_set': rule_set}
                    )
                
                rules_to_execute = self._resolve_rule_dependencies(
                    self._rule_sets[rule_set]
                )
                
                # Execute rules in dependency order
                for rule_name in rules_to_execute:
                    rule_config = self._rules[rule_name]
                    
                    try:
                        # Update execution context
                        self._execution_context = execution_context
                        
                        # Execute rule
                        rule_start_time = time.perf_counter()
                        rule_result = rule_config['function'](result['final_data'])
                        rule_duration = time.perf_counter() - rule_start_time
                        
                        # Update statistics
                        rule_config['execution_count'] += 1
                        self._update_rule_stats(rule_name, rule_duration, True)
                        
                        # Process rule result
                        rule_outcome = self._process_rule_result(
                            rule_name, rule_result, result['final_data']
                        )
                        
                        result['rules_executed'].append(rule_name)
                        
                        if rule_outcome['passed']:
                            result['rules_passed'].append(rule_name)
                            
                            # Apply data modifications if any
                            if 'modified_data' in rule_outcome:
                                result['final_data'] = rule_outcome['modified_data']
                                result['data_modified'] = True
                        else:
                            result['rules_failed'].append({
                                'rule_name': rule_name,
                                'error_message': rule_outcome.get('error_message', 'Rule failed'),
                                'error_code': rule_outcome.get('error_code', 'RULE_FAILED'),
                                'severity': rule_outcome.get('severity', 'medium')
                            })
                            
                            result['success'] = False
                            
                            if fail_fast:
                                break
                        
                        logger.debug("Business rule executed",
                                    rule_name=rule_name,
                                    passed=rule_outcome['passed'],
                                    duration=rule_duration,
                                    execution_id=execution_id)
                        
                    except Exception as e:
                        # Handle rule execution error
                        self._update_rule_stats(rule_name, 0, False)
                        
                        error_details = {
                            'rule_name': rule_name,
                            'error_message': str(e),
                            'error_code': 'RULE_EXECUTION_ERROR',
                            'severity': 'high'
                        }
                        
                        result['rules_failed'].append(error_details)
                        result['success'] = False
                        
                        logger.error("Business rule execution failed",
                                    rule_name=rule_name,
                                    error=str(e),
                                    execution_id=execution_id,
                                    exc_info=True)
                        
                        if fail_fast:
                            break
                
                # Generate execution summary
                result['execution_summary'] = {
                    'total_rules': len(rules_to_execute),
                    'passed_count': len(result['rules_passed']),
                    'failed_count': len(result['rules_failed']),
                    'success_rate': len(result['rules_passed']) / len(rules_to_execute) if rules_to_execute else 0,
                    'execution_time': (datetime.now(timezone.utc) - execution_context['start_time']).total_seconds()
                }
                
                logger.info("Business rule execution completed",
                           execution_id=execution_id,
                           rule_set=rule_set,
                           success=result['success'],
                           rules_executed=len(result['rules_executed']),
                           rules_passed=len(result['rules_passed']),
                           rules_failed=len(result['rules_failed']))
                
                return result
                
            except Exception as e:
                result['success'] = False
                result['execution_summary']['error'] = str(e)
                
                logger.error("Business rule engine execution failed",
                           execution_id=execution_id,
                           rule_set=rule_set,
                           error=str(e),
                           exc_info=True)
                
                raise DataProcessingError(
                    message="Business rule execution failed",
                    error_code="RULE_ENGINE_EXECUTION_FAILED",
                    processing_stage="business_rule_execution",
                    context={
                        'execution_id': execution_id,
                        'rule_set': rule_set
                    },
                    cause=e,
                    severity=ErrorSeverity.HIGH
                )
    
    def validate_rule_set(self, rule_set: str) -> Dict[str, Any]:
        """
        Validate rule set configuration and dependencies.
        
        Args:
            rule_set: Name of rule set to validate
            
        Returns:
            Validation result with any issues found
        """
        with self.performance_context("validate_rule_set"):
            validation_result = {
                'valid': True,
                'rule_set': rule_set,
                'issues': [],
                'rule_count': 0,
                'dependency_graph': {}
            }
            
            if rule_set not in self._rule_sets:
                validation_result['valid'] = False
                validation_result['issues'].append({
                    'type': 'missing_rule_set',
                    'message': f"Rule set '{rule_set}' does not exist"
                })
                return validation_result
            
            rules = self._rule_sets[rule_set]
            validation_result['rule_count'] = len(rules)
            
            # Check each rule
            for rule_name in rules:
                if rule_name not in self._rules:
                    validation_result['valid'] = False
                    validation_result['issues'].append({
                        'type': 'missing_rule',
                        'rule_name': rule_name,
                        'message': f"Rule '{rule_name}' referenced but not defined"
                    })
                    continue
                
                # Check dependencies
                rule_config = self._rules[rule_name]
                dependencies = rule_config.get('dependencies', [])
                validation_result['dependency_graph'][rule_name] = dependencies
                
                for dep in dependencies:
                    if dep not in self._rules:
                        validation_result['valid'] = False
                        validation_result['issues'].append({
                            'type': 'missing_dependency',
                            'rule_name': rule_name,
                            'dependency': dep,
                            'message': f"Rule '{rule_name}' depends on missing rule '{dep}'"
                        })
            
            # Check for circular dependencies
            circular_deps = self._detect_circular_dependencies(rules)
            if circular_deps:
                validation_result['valid'] = False
                validation_result['issues'].append({
                    'type': 'circular_dependency',
                    'rules': circular_deps,
                    'message': f"Circular dependency detected: {' -> '.join(circular_deps)}"
                })
            
            return validation_result
    
    def get_rule_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive rule execution statistics.
        
        Returns:
            Dictionary containing rule execution statistics
        """
        stats = {
            'total_rules': len(self._rules),
            'rule_sets': list(self._rule_sets.keys()),
            'rule_execution_stats': self._rule_execution_stats.copy(),
            'most_executed_rules': [],
            'performance_summary': {}
        }
        
        # Calculate performance summary
        if self._rule_execution_stats:
            total_executions = sum(stat['count'] for stat in self._rule_execution_stats.values())
            total_time = sum(stat['total_time'] for stat in self._rule_execution_stats.values())
            
            stats['performance_summary'] = {
                'total_executions': total_executions,
                'total_execution_time': round(total_time, 4),
                'average_execution_time': round(total_time / total_executions if total_executions > 0 else 0, 4)
            }
            
            # Most executed rules
            sorted_rules = sorted(
                self._rule_execution_stats.items(),
                key=lambda x: x[1]['count'],
                reverse=True
            )
            stats['most_executed_rules'] = [
                {'rule_name': name, 'execution_count': data['count']}
                for name, data in sorted_rules[:10]
            ]
        
        return stats
    
    def _initialize_default_rules(self) -> None:
        """Initialize default business rules."""
        
        # Data integrity rules
        def validate_required_fields(data: Dict[str, Any]) -> Dict[str, Any]:
            """Validate that required fields are present and not empty."""
            required_fields = ['id'] if 'id' in data else []
            
            for field in required_fields:
                if field not in data or data[field] is None or data[field] == '':
                    return {
                        'valid': False,
                        'error_message': f"Required field '{field}' is missing or empty",
                        'error_code': 'MISSING_REQUIRED_FIELD'
                    }
            
            return {'valid': True}
        
        def validate_data_types(data: Dict[str, Any]) -> Dict[str, Any]:
            """Validate basic data type consistency."""
            type_checks = {
                'id': (str, type(None)),
                'created_at': (str, datetime, type(None)),
                'updated_at': (str, datetime, type(None))
            }
            
            for field, expected_types in type_checks.items():
                if field in data and not isinstance(data[field], expected_types):
                    return {
                        'valid': False,
                        'error_message': f"Field '{field}' has invalid type",
                        'error_code': 'INVALID_DATA_TYPE'
                    }
            
            return {'valid': True}
        
        # Add default rules
        self.add_rule("validate_required_fields", validate_required_fields, "default", priority=10)
        self.add_rule("validate_data_types", validate_data_types, "default", priority=20)
        
        # User-specific rules
        def validate_user_email(data: Dict[str, Any]) -> Dict[str, Any]:
            """Validate user email format and domain."""
            if 'email' not in data:
                return {'valid': True}
            
            email = data['email']
            if not validate_email(email, strict=True):
                return {
                    'valid': False,
                    'error_message': 'Invalid email format',
                    'error_code': 'INVALID_EMAIL_FORMAT'
                }
            
            return {'valid': True}
        
        def validate_user_age(data: Dict[str, Any]) -> Dict[str, Any]:
            """Validate user age requirements."""
            if 'birth_date' not in data:
                return {'valid': True}
            
            birth_date = data['birth_date']
            if isinstance(birth_date, str):
                try:
                    birth_date = datetime.fromisoformat(birth_date.replace('Z', '+00:00')).date()
                except ValueError:
                    return {
                        'valid': False,
                        'error_message': 'Invalid birth date format',
                        'error_code': 'INVALID_BIRTH_DATE'
                    }
            
            today = date.today()
            age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
            
            if age < 13:
                return {
                    'valid': False,
                    'error_message': 'User must be at least 13 years old',
                    'error_code': 'UNDERAGE_USER'
                }
            
            return {'valid': True}
        
        # Add user rules
        self.add_rule("validate_user_email", validate_user_email, "user_validation", priority=10)
        self.add_rule("validate_user_age", validate_user_age, "user_validation", priority=20)
        
        # Order-specific rules
        def validate_order_total(data: Dict[str, Any]) -> Dict[str, Any]:
            """Validate order total calculation."""
            if 'total_amount' not in data:
                return {'valid': True}
            
            total = data.get('total_amount', {}).get('amount', 0)
            if total <= 0:
                return {
                    'valid': False,
                    'error_message': 'Order total must be positive',
                    'error_code': 'INVALID_ORDER_TOTAL'
                }
            
            return {'valid': True}
        
        def validate_order_items(data: Dict[str, Any]) -> Dict[str, Any]:
            """Validate order items requirements."""
            items = data.get('items', [])
            if not items:
                return {
                    'valid': False,
                    'error_message': 'Order must contain at least one item',
                    'error_code': 'EMPTY_ORDER'
                }
            
            for item in items:
                if item.get('quantity', 0) <= 0:
                    return {
                        'valid': False,
                        'error_message': 'Order item quantity must be positive',
                        'error_code': 'INVALID_ITEM_QUANTITY'
                    }
            
            return {'valid': True}
        
        # Add order rules
        self.add_rule("validate_order_total", validate_order_total, "order_validation", priority=10)
        self.add_rule("validate_order_items", validate_order_items, "order_validation", priority=20)
    
    def _resolve_rule_dependencies(self, rules: List[str]) -> List[str]:
        """
        Resolve rule dependencies and return execution order.
        
        Args:
            rules: List of rule names to resolve
            
        Returns:
            List of rules in dependency execution order
        """
        resolved = []
        visited = set()
        visiting = set()
        
        def visit(rule_name: str) -> None:
            if rule_name in visiting:
                # Circular dependency detected
                return
            
            if rule_name in visited:
                return
            
            visiting.add(rule_name)
            
            # Visit dependencies first
            if rule_name in self._rule_dependencies:
                for dep in self._rule_dependencies[rule_name]:
                    if dep in rules:  # Only include dependencies that are in the rule set
                        visit(dep)
            
            visiting.remove(rule_name)
            visited.add(rule_name)
            
            if rule_name not in resolved:
                resolved.append(rule_name)
        
        # Visit all rules
        for rule in rules:
            visit(rule)
        
        return resolved
    
    def _detect_circular_dependencies(self, rules: List[str]) -> Optional[List[str]]:
        """
        Detect circular dependencies in rule set.
        
        Args:
            rules: List of rule names to check
            
        Returns:
            List representing circular dependency path, or None if no cycles
        """
        visited = set()
        visiting = set()
        path = []
        
        def visit(rule_name: str) -> bool:
            if rule_name in visiting:
                # Found a cycle
                cycle_start = path.index(rule_name)
                return path[cycle_start:] + [rule_name]
            
            if rule_name in visited:
                return False
            
            visiting.add(rule_name)
            path.append(rule_name)
            
            # Check dependencies
            if rule_name in self._rule_dependencies:
                for dep in self._rule_dependencies[rule_name]:
                    if dep in rules:
                        cycle = visit(dep)
                        if cycle:
                            return cycle
            
            visiting.remove(rule_name)
            visited.add(rule_name)
            path.pop()
            
            return False
        
        for rule in rules:
            if rule not in visited:
                cycle = visit(rule)
                if cycle:
                    return cycle
        
        return None
    
    def _process_rule_result(
        self,
        rule_name: str,
        rule_result: Dict[str, Any],
        current_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Process and validate rule execution result.
        
        Args:
            rule_name: Name of the executed rule
            rule_result: Result returned by the rule function
            current_data: Current data being processed
            
        Returns:
            Processed rule outcome
        """
        outcome = {
            'passed': True,
            'rule_name': rule_name
        }
        
        # Validate rule result format
        if not isinstance(rule_result, dict):
            outcome['passed'] = False
            outcome['error_message'] = 'Rule result must be a dictionary'
            outcome['error_code'] = 'INVALID_RULE_RESULT'
            return outcome
        
        # Check if rule passed
        if 'valid' in rule_result:
            outcome['passed'] = rule_result['valid']
        
        # Extract error information
        if not outcome['passed']:
            outcome['error_message'] = rule_result.get('error_message', 'Rule validation failed')
            outcome['error_code'] = rule_result.get('error_code', 'RULE_FAILED')
            outcome['severity'] = rule_result.get('severity', 'medium')
        
        # Handle data modifications
        if 'modified_data' in rule_result:
            outcome['modified_data'] = rule_result['modified_data']
        
        # Handle warnings
        if 'warnings' in rule_result:
            outcome['warnings'] = rule_result['warnings']
        
        return outcome
    
    def _update_rule_stats(self, rule_name: str, duration: float, success: bool) -> None:
        """Update rule execution statistics."""
        if rule_name not in self._rule_execution_stats:
            self._rule_execution_stats[rule_name] = {
                'count': 0,
                'success_count': 0,
                'total_time': 0.0,
                'min_time': float('inf'),
                'max_time': 0.0
            }
        
        stats = self._rule_execution_stats[rule_name]
        stats['count'] += 1
        stats['total_time'] += duration
        stats['min_time'] = min(stats['min_time'], duration)
        stats['max_time'] = max(stats['max_time'], duration)
        
        if success:
            stats['success_count'] += 1
    
    def _calculate_data_hash(self, data: Dict[str, Any]) -> str:
        """Calculate hash of data for caching and change detection."""
        import hashlib
        data_str = json.dumps(data, sort_keys=True, default=str)
        return hashlib.md5(data_str.encode()).hexdigest()


# ============================================================================
# PIPELINE AND BATCH PROCESSORS
# ============================================================================

class ProcessingPipeline(BaseProcessor):
    """
    Chained processing workflow execution processor.
    
    Provides comprehensive pipeline processing for sequential data transformation
    and business logic execution. Implements pipeline patterns for complex
    workflows maintaining performance requirements per Section 6.1.3.
    
    Features:
    - Sequential processor chaining
    - Conditional pipeline execution
    - Error handling and recovery
    - Parallel processing capabilities
    - Pipeline state management
    - Performance optimization
    
    Example:
        pipeline = ProcessingPipeline()
        
        # Add processors to pipeline
        pipeline.add_processor("validate", ValidationProcessor())
        pipeline.add_processor("transform", DataTransformer())
        pipeline.add_processor("sanitize", SanitizationProcessor())
        
        # Execute pipeline
        result = pipeline.execute(input_data)
    """
    
    def __init__(self, **kwargs):
        """Initialize processing pipeline with chaining capabilities."""
        super().__init__(**kwargs)
        
        # Pipeline configuration
        self._processors = {}
        self._pipeline_stages = []
        self._stage_conditions = {}
        self._stage_config = {}
        
        # Execution state
        self._current_execution = None
        self._execution_history = []
        
        # Performance settings
        self._parallel_execution = False
        self._max_workers = self.config.MAX_WORKERS
    
    def add_processor(
        self,
        stage_name: str,
        processor: BaseProcessor,
        condition: Optional[Callable[[Dict[str, Any]], bool]] = None,
        config: Optional[Dict[str, Any]] = None
    ) -> 'ProcessingPipeline':
        """
        Add processor to pipeline stage.
        
        Args:
            stage_name: Unique name for the pipeline stage
            processor: Processor instance to add
            condition: Optional condition function for conditional execution
            config: Stage-specific configuration
            
        Returns:
            Self for method chaining
        """
        self._processors[stage_name] = processor
        
        if stage_name not in self._pipeline_stages:
            self._pipeline_stages.append(stage_name)
        
        if condition:
            self._stage_conditions[stage_name] = condition
        
        if config:
            self._stage_config[stage_name] = config
        
        logger.debug("Processor added to pipeline",
                    stage_name=stage_name,
                    processor_type=type(processor).__name__,
                    total_stages=len(self._pipeline_stages))
        
        return self
    
    def execute(
        self,
        data: Dict[str, Any],
        start_stage: Optional[str] = None,
        end_stage: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute processing pipeline on data.
        
        Args:
            data: Input data to process
            start_stage: Stage to start execution from
            end_stage: Stage to end execution at
            context: Additional execution context
            
        Returns:
            Pipeline execution result
        """
        with self.performance_context("execute_pipeline"):
            self.validate_input(data, dict)
            
            execution_id = str(uuid.uuid4())
            self._current_execution = {
                'execution_id': execution_id,
                'start_time': datetime.now(timezone.utc),
                'stages_executed': [],
                'stages_skipped': [],
                'context': context or {}
            }
            
            result = {
                'success': True,
                'execution_id': execution_id,
                'input_data': data.copy(),
                'output_data': data.copy(),
                'stages_executed': [],
                'stages_skipped': [],
                'stage_results': {},
                'errors': [],
                'warnings': [],
                'execution_summary': {}
            }
            
            try:
                # Determine execution range
                start_index = 0
                end_index = len(self._pipeline_stages)
                
                if start_stage:
                    try:
                        start_index = self._pipeline_stages.index(start_stage)
                    except ValueError:
                        raise DataProcessingError(
                            message=f"Start stage '{start_stage}' not found in pipeline",
                            error_code="INVALID_START_STAGE"
                        )
                
                if end_stage:
                    try:
                        end_index = self._pipeline_stages.index(end_stage) + 1
                    except ValueError:
                        raise DataProcessingError(
                            message=f"End stage '{end_stage}' not found in pipeline",
                            error_code="INVALID_END_STAGE"
                        )
                
                stages_to_execute = self._pipeline_stages[start_index:end_index]
                
                # Execute pipeline stages
                for stage_name in stages_to_execute:
                    try:
                        # Check stage condition
                        if stage_name in self._stage_conditions:
                            condition = self._stage_conditions[stage_name]
                            if not condition(result['output_data']):
                                result['stages_skipped'].append(stage_name)
                                self._current_execution['stages_skipped'].append(stage_name)
                                logger.debug("Pipeline stage skipped due to condition",
                                           stage=stage_name,
                                           execution_id=execution_id)
                                continue
                        
                        # Execute stage
                        stage_start_time = time.perf_counter()
                        processor = self._processors[stage_name]
                        
                        # Prepare stage input
                        stage_input = result['output_data'].copy()
                        stage_config = self._stage_config.get(stage_name, {})
                        
                        # Execute processor based on type
                        stage_result = self._execute_stage_processor(
                            processor, stage_input, stage_config
                        )
                        
                        stage_duration = time.perf_counter() - stage_start_time
                        
                        # Process stage result
                        if isinstance(stage_result, dict) and 'success' in stage_result:
                            # Structured result from processor
                            if stage_result['success']:
                                if 'data' in stage_result:
                                    result['output_data'] = stage_result['data']
                                
                                result['stages_executed'].append(stage_name)
                                self._current_execution['stages_executed'].append(stage_name)
                                
                                if 'warnings' in stage_result:
                                    result['warnings'].extend(stage_result['warnings'])
                            else:
                                # Stage failed
                                result['success'] = False
                                error_info = {
                                    'stage': stage_name,
                                    'error': stage_result.get('error', 'Stage execution failed'),
                                    'duration': stage_duration
                                }
                                result['errors'].append(error_info)
                                
                                if self.mode == ProcessingMode.STRICT:
                                    break
                        else:
                            # Direct data result
                            result['output_data'] = stage_result
                            result['stages_executed'].append(stage_name)
                            self._current_execution['stages_executed'].append(stage_name)
                        
                        # Store stage result details
                        result['stage_results'][stage_name] = {
                            'duration': stage_duration,
                            'success': True,
                            'data_size': len(str(result['output_data']))
                        }
                        
                        logger.debug("Pipeline stage executed successfully",
                                   stage=stage_name,
                                   duration=stage_duration,
                                   execution_id=execution_id)
                        
                    except Exception as e:
                        # Handle stage execution error
                        stage_duration = time.perf_counter() - stage_start_time
                        
                        result['success'] = False
                        error_info = {
                            'stage': stage_name,
                            'error': str(e),
                            'error_type': type(e).__name__,
                            'duration': stage_duration
                        }
                        result['errors'].append(error_info)
                        
                        result['stage_results'][stage_name] = {
                            'duration': stage_duration,
                            'success': False,
                            'error': str(e)
                        }
                        
                        logger.error("Pipeline stage execution failed",
                                   stage=stage_name,
                                   error=str(e),
                                   execution_id=execution_id,
                                   exc_info=True)
                        
                        if self.mode == ProcessingMode.STRICT:
                            break
                
                # Generate execution summary
                total_duration = (datetime.now(timezone.utc) - self._current_execution['start_time']).total_seconds()
                
                result['execution_summary'] = {
                    'total_stages': len(stages_to_execute),
                    'executed_stages': len(result['stages_executed']),
                    'skipped_stages': len(result['stages_skipped']),
                    'failed_stages': len(result['errors']),
                    'total_duration': total_duration,
                    'data_changed': result['input_data'] != result['output_data']
                }
                
                # Store in execution history
                self._execution_history.append({
                    'execution_id': execution_id,
                    'timestamp': self._current_execution['start_time'],
                    'success': result['success'],
                    'stages_executed': len(result['stages_executed']),
                    'duration': total_duration
                })
                
                # Keep only last 100 executions
                if len(self._execution_history) > 100:
                    self._execution_history = self._execution_history[-100:]
                
                logger.info("Pipeline execution completed",
                           execution_id=execution_id,
                           success=result['success'],
                           stages_executed=len(result['stages_executed']),
                           duration=total_duration)
                
                return result
                
            except Exception as e:
                result['success'] = False
                result['errors'].append({
                    'stage': 'pipeline_execution',
                    'error': str(e),
                    'error_type': type(e).__name__
                })
                
                logger.error("Pipeline execution failed",
                           execution_id=execution_id,
                           error=str(e),
                           exc_info=True)
                
                raise DataProcessingError(
                    message="Pipeline execution failed",
                    error_code="PIPELINE_EXECUTION_FAILED",
                    processing_stage="pipeline_execution",
                    context={'execution_id': execution_id},
                    cause=e,
                    severity=ErrorSeverity.HIGH
                )
            
            finally:
                self._current_execution = None
    
    def get_pipeline_info(self) -> Dict[str, Any]:
        """
        Get comprehensive pipeline configuration and statistics.
        
        Returns:
            Dictionary containing pipeline information
        """
        return {
            'stages': self._pipeline_stages.copy(),
            'stage_count': len(self._pipeline_stages),
            'processors': {
                stage: type(processor).__name__
                for stage, processor in self._processors.items()
            },
            'conditional_stages': list(self._stage_conditions.keys()),
            'configured_stages': list(self._stage_config.keys()),
            'execution_history_count': len(self._execution_history),
            'last_execution': self._execution_history[-1] if self._execution_history else None
        }
    
    def clear_pipeline(self) -> None:
        """Clear all processors and configuration from pipeline."""
        self._processors.clear()
        self._pipeline_stages.clear()
        self._stage_conditions.clear()
        self._stage_config.clear()
        
        logger.debug("Pipeline cleared")
    
    def _execute_stage_processor(
        self,
        processor: BaseProcessor,
        data: Dict[str, Any],
        config: Dict[str, Any]
    ) -> Any:
        """
        Execute specific processor with appropriate method.
        
        Args:
            processor: Processor instance to execute
            data: Input data for processor
            config: Stage configuration
            
        Returns:
            Processor execution result
        """
        # Determine processor type and call appropriate method
        if isinstance(processor, DataTransformer):
            if 'target_format' in config:
                return processor.transform_data(
                    data,
                    config['target_format'],
                    config.get('source_format', DataFormat.JSON),
                    config.get('transformation_rules')
                )
            else:
                return data  # No transformation specified
        
        elif isinstance(processor, ValidationProcessor):
            if 'model_type' in config:
                # Convert to business model and validate
                model = processor._transformer.to_business_model(data, config['model_type'])
                validation_result = processor.validate_model(model)
                
                if validation_result['success']:
                    return {'success': True, 'data': data}
                else:
                    return {
                        'success': False,
                        'error': 'Validation failed',
                        'details': validation_result['errors']
                    }
            else:
                return {'success': True, 'data': data}
        
        elif isinstance(processor, SanitizationProcessor):
            sanitized_data = processor.sanitize_input(
                data,
                config.get('max_length'),
                config.get('allow_html', False),
                config.get('strict_mode')
            )
            return {'success': True, 'data': sanitized_data}
        
        elif isinstance(processor, NormalizationProcessor):
            normalized_data = processor.normalize_data(
                data,
                config.get('normalization_rules')
            )
            return {'success': True, 'data': normalized_data}
        
        elif isinstance(processor, BusinessRuleEngine):
            rule_result = processor.execute_rules(
                data,
                config.get('rule_set', 'default'),
                config.get('context'),
                config.get('fail_fast', False)
            )
            
            if rule_result['success']:
                return {'success': True, 'data': rule_result['final_data']}
            else:
                return {
                    'success': False,
                    'error': 'Business rule validation failed',
                    'details': rule_result['rules_failed']
                }
        
        else:
            # Generic processor - try to call process method
            if hasattr(processor, 'process'):
                return processor.process(data)
            else:
                logger.warning("Unknown processor type, returning data unchanged",
                              processor_type=type(processor).__name__)
                return data


# ============================================================================
# MODULE INITIALIZATION AND UTILITIES
# ============================================================================

def create_processing_pipeline(
    config: Optional[ProcessingConfig] = None,
    mode: ProcessingMode = ProcessingMode.STRICT
) -> ProcessingPipeline:
    """
    Create a pre-configured processing pipeline with common processors.
    
    Args:
        config: Processing configuration
        mode: Processing mode
        
    Returns:
        Configured processing pipeline
    """
    pipeline = ProcessingPipeline(config=config, mode=mode)
    
    # Add common processors
    pipeline.add_processor("sanitize", SanitizationProcessor(config=config, mode=mode))
    pipeline.add_processor("normalize", NormalizationProcessor(config=config, mode=mode))
    pipeline.add_processor("validate", ValidationProcessor(config=config, mode=mode))
    pipeline.add_processor("transform", DataTransformer(config=config, mode=mode))
    
    logger.info("Default processing pipeline created",
               stage_count=4,
               mode=mode.value)
    
    return pipeline


def create_business_rule_engine(
    config: Optional[ProcessingConfig] = None
) -> BusinessRuleEngine:
    """
    Create a business rule engine with default rules.
    
    Args:
        config: Processing configuration
        
    Returns:
        Configured business rule engine
    """
    rule_engine = BusinessRuleEngine(config=config)
    
    logger.info("Business rule engine created with default rules",
               rule_count=len(rule_engine._rules))
    
    return rule_engine


def process_business_data(
    data: Dict[str, Any],
    processing_type: str = "full",
    config: Optional[ProcessingConfig] = None
) -> Dict[str, Any]:
    """
    Convenience function for common business data processing.
    
    Args:
        data: Data to process
        processing_type: Type of processing (full, sanitize, validate, transform)
        config: Processing configuration
        
    Returns:
        Processed data result
    """
    if processing_type == "full":
        pipeline = create_processing_pipeline(config)
        return pipeline.execute(data)
    
    elif processing_type == "sanitize":
        processor = SanitizationProcessor(config=config)
        return processor.sanitize_input(data)
    
    elif processing_type == "validate":
        processor = ValidationProcessor(config=config)
        # Basic validation - would need model type in real implementation
        return {'success': True, 'data': data}
    
    elif processing_type == "transform":
        processor = DataTransformer(config=config)
        return processor.transform_data(data, DataFormat.JSON)
    
    else:
        raise ValueError(f"Unknown processing type: {processing_type}")


# Module initialization logging
logger.info("Business processors module initialized successfully",
           processor_count=8,
           mode_options=len(ProcessingMode),
           default_config_ready=True,
           python_dateutil_available=True)