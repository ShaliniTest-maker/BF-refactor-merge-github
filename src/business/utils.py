"""
Business Logic Utility Functions for Flask Application

This module provides comprehensive business logic utility functions for data manipulation,
transformation helpers, date/time processing, and business calculation utilities. Implements
reusable helper functions for business logic operations with comprehensive type hints and
documentation per Section 5.2.4 Business Logic Engine requirements.

The utility functions follow enterprise patterns with:
- Data manipulation and transformation helpers per Section 5.2.4
- Python-dateutil 2.8+ for date processing equivalent to moment.js
- Business calculation and processing utilities per Section 5.2.4
- Comprehensive type hints and documentation per Python best practices
- Integration with business exceptions for error handling
- Performance optimization maintaining ≤10% variance requirement

Functions:
    Data Manipulation:
        clean_data: Clean and sanitize data structures
        transform_data: Transform data between formats
        merge_data: Merge multiple data structures
        flatten_data: Flatten nested data structures
        filter_data: Filter data based on criteria
        
    Date/Time Processing:
        parse_date: Parse date strings with timezone handling
        format_date: Format dates for API responses
        calculate_date_difference: Calculate time differences
        get_business_days: Calculate business days between dates
        convert_timezone: Convert dates between timezones
        
    Business Calculations:
        calculate_percentage: Calculate percentage values
        apply_discount: Apply discount calculations
        calculate_tax: Calculate tax amounts
        round_currency: Round monetary values properly
        validate_currency: Validate currency amounts
        
    Validation Utilities:
        validate_email: Email format validation
        validate_phone: Phone number validation
        validate_postal_code: Postal code validation
        sanitize_input: Sanitize user input
        validate_json_schema: JSON schema validation
        
    Type Conversion:
        safe_int: Safe integer conversion
        safe_float: Safe float conversion
        safe_str: Safe string conversion
        normalize_boolean: Boolean normalization
        parse_json: Safe JSON parsing
"""

import json
import re
import decimal
import logging
from datetime import datetime, timezone, timedelta, date
from typing import Any, Dict, List, Optional, Union, Tuple, Callable, Type, Set
from dateutil import parser as date_parser, tz
from dateutil.relativedelta import relativedelta
import structlog
import hashlib
import uuid
from enum import Enum

# Import business exceptions for error handling
from .exceptions import (
    BaseBusinessException,
    BusinessRuleViolationError,
    DataProcessingError,
    DataValidationError,
    ConfigurationError,
    ErrorSeverity
)

# Configure structured logging for business utilities
logger = structlog.get_logger("business.utils")

# Type aliases for better code readability
JSONType = Union[str, int, float, bool, None, Dict[str, Any], List[Any]]
DateTimeType = Union[datetime, date, str]
NumericType = Union[int, float, decimal.Decimal]


class DataFormat(Enum):
    """
    Enumeration of supported data formats for transformation utilities.
    
    Provides standardized format types for data transformation operations
    enabling consistent data processing across business logic modules.
    """
    JSON = "json"
    CSV = "csv"
    XML = "xml"
    YAML = "yaml"
    FORM_DATA = "form_data"
    QUERY_STRING = "query_string"


class CurrencyCode(Enum):
    """
    Enumeration of supported currency codes for financial calculations.
    
    Provides standardized currency codes for business calculation utilities
    following ISO 4217 currency code standards.
    """
    USD = "USD"
    EUR = "EUR"
    GBP = "GBP"
    CAD = "CAD"
    AUD = "AUD"
    JPY = "JPY"


class TimezoneRegion(Enum):
    """
    Enumeration of common timezone regions for date processing utilities.
    
    Provides standardized timezone identifiers for business date/time
    operations enabling consistent timezone handling across modules.
    """
    UTC = "UTC"
    US_EASTERN = "America/New_York"
    US_CENTRAL = "America/Chicago"
    US_MOUNTAIN = "America/Denver"
    US_PACIFIC = "America/Los_Angeles"
    EUROPE_LONDON = "Europe/London"
    EUROPE_PARIS = "Europe/Paris"
    ASIA_TOKYO = "Asia/Tokyo"


# ============================================================================
# DATA MANIPULATION UTILITIES
# ============================================================================

def clean_data(
    data: Union[Dict[str, Any], List[Any]], 
    remove_empty: bool = True,
    remove_none: bool = True,
    strip_strings: bool = True,
    convert_types: bool = False
) -> Union[Dict[str, Any], List[Any]]:
    """
    Clean and sanitize data structures for business processing.
    
    Provides comprehensive data cleaning functionality for incoming data
    processing, ensuring consistent data quality for business logic operations.
    Implements data sanitization per Section 5.2.4 data transformation requirements.
    
    Args:
        data: Input data structure to clean (dict or list)
        remove_empty: Remove empty strings and empty collections
        remove_none: Remove None values from data
        strip_strings: Strip whitespace from string values
        convert_types: Attempt basic type conversions (string numbers to numeric)
        
    Returns:
        Cleaned data structure with same type as input
        
    Raises:
        DataProcessingError: If data cleaning fails or invalid data type provided
        
    Example:
        dirty_data = {
            'name': '  John Doe  ',
            'email': '',
            'age': '25',
            'notes': None,
            'tags': []
        }
        
        clean_data = clean_data(
            dirty_data,
            remove_empty=True,
            remove_none=True,
            strip_strings=True,
            convert_types=True
        )
        # Result: {'name': 'John Doe', 'age': 25}
    """
    try:
        logger.debug("Starting data cleaning operation", 
                    data_type=type(data).__name__, 
                    remove_empty=remove_empty,
                    remove_none=remove_none)
        
        if isinstance(data, dict):
            return _clean_dict(data, remove_empty, remove_none, strip_strings, convert_types)
        elif isinstance(data, list):
            return _clean_list(data, remove_empty, remove_none, strip_strings, convert_types)
        else:
            raise DataProcessingError(
                message="Unsupported data type for cleaning operation",
                error_code="UNSUPPORTED_DATA_TYPE",
                processing_stage="data_cleaning",
                data_type=type(data).__name__,
                context={'supported_types': ['dict', 'list']},
                severity=ErrorSeverity.MEDIUM
            )
            
    except Exception as e:
        if isinstance(e, BaseBusinessException):
            raise
        
        raise DataProcessingError(
            message="Failed to clean data structure",
            error_code="DATA_CLEANING_FAILED",
            processing_stage="data_cleaning",
            data_type=type(data).__name__,
            cause=e,
            severity=ErrorSeverity.MEDIUM
        )


def _clean_dict(
    data: Dict[str, Any], 
    remove_empty: bool, 
    remove_none: bool, 
    strip_strings: bool, 
    convert_types: bool
) -> Dict[str, Any]:
    """Internal helper for cleaning dictionary data structures."""
    cleaned = {}
    
    for key, value in data.items():
        # Clean nested structures recursively
        if isinstance(value, (dict, list)):
            cleaned_value = clean_data(value, remove_empty, remove_none, strip_strings, convert_types)
            if not remove_empty or cleaned_value:
                cleaned[key] = cleaned_value
        elif isinstance(value, str):
            # Process string values
            processed_value = value.strip() if strip_strings else value
            
            # Type conversion for string numbers
            if convert_types and processed_value:
                try:
                    # Try integer conversion first
                    if processed_value.isdigit() or (processed_value.startswith('-') and processed_value[1:].isdigit()):
                        processed_value = int(processed_value)
                    # Try float conversion
                    elif '.' in processed_value:
                        processed_value = float(processed_value)
                except (ValueError, TypeError):
                    pass  # Keep as string if conversion fails
            
            # Apply filtering rules
            if remove_empty and not processed_value:
                continue
            if remove_none and processed_value is None:
                continue
                
            cleaned[key] = processed_value
        else:
            # Handle non-string values
            if remove_none and value is None:
                continue
            if remove_empty and value == "" or (isinstance(value, (list, dict)) and not value):
                continue
                
            cleaned[key] = value
    
    return cleaned


def _clean_list(
    data: List[Any], 
    remove_empty: bool, 
    remove_none: bool, 
    strip_strings: bool, 
    convert_types: bool
) -> List[Any]:
    """Internal helper for cleaning list data structures."""
    cleaned = []
    
    for item in data:
        if isinstance(item, (dict, list)):
            cleaned_item = clean_data(item, remove_empty, remove_none, strip_strings, convert_types)
            if not remove_empty or cleaned_item:
                cleaned.append(cleaned_item)
        elif isinstance(item, str):
            processed_item = item.strip() if strip_strings else item
            
            if convert_types and processed_item:
                try:
                    if processed_item.isdigit() or (processed_item.startswith('-') and processed_item[1:].isdigit()):
                        processed_item = int(processed_item)
                    elif '.' in processed_item:
                        processed_item = float(processed_item)
                except (ValueError, TypeError):
                    pass
            
            if remove_empty and not processed_item:
                continue
            if remove_none and processed_item is None:
                continue
                
            cleaned.append(processed_item)
        else:
            if remove_none and item is None:
                continue
            if remove_empty and item == "" or (isinstance(item, (list, dict)) and not item):
                continue
                
            cleaned.append(item)
    
    return cleaned


def transform_data(
    data: Dict[str, Any], 
    field_mapping: Dict[str, str],
    transformers: Optional[Dict[str, Callable[[Any], Any]]] = None,
    remove_unmapped: bool = False
) -> Dict[str, Any]:
    """
    Transform data between different formats using field mapping.
    
    Provides flexible data transformation capabilities for converting data
    between different schemas, API formats, and business object structures.
    Implements data transformation per Section 5.2.4 business logic requirements.
    
    Args:
        data: Source data dictionary to transform
        field_mapping: Mapping of source fields to target fields
        transformers: Optional field-specific transformation functions
        remove_unmapped: Remove fields not present in mapping
        
    Returns:
        Transformed data dictionary with mapped fields
        
    Raises:
        DataProcessingError: If transformation fails or invalid mapping provided
        
    Example:
        api_data = {
            'firstName': 'John',
            'lastName': 'Doe',
            'emailAddress': 'john@example.com',
            'dateOfBirth': '1990-01-01'
        }
        
        field_mapping = {
            'firstName': 'first_name',
            'lastName': 'last_name',
            'emailAddress': 'email',
            'dateOfBirth': 'birth_date'
        }
        
        transformers = {
            'birth_date': lambda x: parse_date(x)
        }
        
        transformed = transform_data(api_data, field_mapping, transformers)
        # Result: {'first_name': 'John', 'last_name': 'Doe', 'email': 'john@example.com', 'birth_date': datetime(...)}
    """
    try:
        logger.debug("Starting data transformation", 
                    source_fields=list(data.keys()),
                    target_fields=list(field_mapping.values()),
                    has_transformers=bool(transformers))
        
        if not isinstance(data, dict):
            raise DataProcessingError(
                message="Data must be a dictionary for transformation",
                error_code="INVALID_TRANSFORM_INPUT",
                processing_stage="data_transformation",
                data_type=type(data).__name__,
                severity=ErrorSeverity.MEDIUM
            )
        
        if not isinstance(field_mapping, dict):
            raise DataProcessingError(
                message="Field mapping must be a dictionary",
                error_code="INVALID_FIELD_MAPPING",
                processing_stage="data_transformation",
                context={'mapping_type': type(field_mapping).__name__},
                severity=ErrorSeverity.MEDIUM
            )
        
        transformed = {}
        transformers = transformers or {}
        
        # Apply field mapping and transformations
        for source_field, target_field in field_mapping.items():
            if source_field in data:
                value = data[source_field]
                
                # Apply transformer if available
                if target_field in transformers:
                    try:
                        value = transformers[target_field](value)
                    except Exception as transform_error:
                        raise DataProcessingError(
                            message=f"Transformation failed for field '{target_field}'",
                            error_code="FIELD_TRANSFORM_FAILED",
                            processing_stage="field_transformation",
                            context={
                                'source_field': source_field,
                                'target_field': target_field,
                                'source_value': str(value)[:100]  # Truncate for security
                            },
                            cause=transform_error,
                            severity=ErrorSeverity.MEDIUM
                        )
                
                transformed[target_field] = value
        
        # Include unmapped fields if requested
        if not remove_unmapped:
            mapped_source_fields = set(field_mapping.keys())
            for field, value in data.items():
                if field not in mapped_source_fields:
                    transformed[field] = value
        
        logger.debug("Data transformation completed successfully",
                    transformed_fields=len(transformed))
        
        return transformed
        
    except Exception as e:
        if isinstance(e, BaseBusinessException):
            raise
        
        raise DataProcessingError(
            message="Data transformation operation failed",
            error_code="DATA_TRANSFORM_FAILED",
            processing_stage="data_transformation",
            cause=e,
            severity=ErrorSeverity.MEDIUM
        )


def merge_data(
    *data_sources: Dict[str, Any],
    merge_strategy: str = "override",
    deep_merge: bool = True
) -> Dict[str, Any]:
    """
    Merge multiple data structures with configurable merge strategies.
    
    Provides flexible data merging capabilities for combining configuration data,
    API responses, and business object data. Supports deep merging for nested
    structures and multiple merge strategies for conflict resolution.
    
    Args:
        *data_sources: Variable number of data dictionaries to merge
        merge_strategy: Strategy for handling conflicts ("override", "preserve", "combine")
        deep_merge: Enable deep merging for nested dictionaries
        
    Returns:
        Merged data dictionary containing combined data from all sources
        
    Raises:
        DataProcessingError: If merge operation fails or invalid strategy provided
        
    Example:
        base_config = {'api': {'timeout': 30}, 'debug': False}
        user_config = {'api': {'retries': 3}, 'debug': True}
        env_config = {'api': {'host': 'prod.example.com'}}
        
        merged = merge_data(base_config, user_config, env_config, merge_strategy="override")
        # Result: {'api': {'timeout': 30, 'retries': 3, 'host': 'prod.example.com'}, 'debug': True}
    """
    try:
        logger.debug("Starting data merge operation",
                    source_count=len(data_sources),
                    merge_strategy=merge_strategy,
                    deep_merge=deep_merge)
        
        valid_strategies = {"override", "preserve", "combine"}
        if merge_strategy not in valid_strategies:
            raise DataProcessingError(
                message=f"Invalid merge strategy: {merge_strategy}",
                error_code="INVALID_MERGE_STRATEGY",
                processing_stage="data_merge",
                context={
                    'provided_strategy': merge_strategy,
                    'valid_strategies': list(valid_strategies)
                },
                severity=ErrorSeverity.MEDIUM
            )
        
        if not data_sources:
            return {}
        
        # Validate all sources are dictionaries
        for i, source in enumerate(data_sources):
            if not isinstance(source, dict):
                raise DataProcessingError(
                    message=f"Data source {i} must be a dictionary",
                    error_code="INVALID_MERGE_SOURCE",
                    processing_stage="data_merge",
                    context={
                        'source_index': i,
                        'source_type': type(source).__name__
                    },
                    severity=ErrorSeverity.MEDIUM
                )
        
        # Start with first source as base
        result = dict(data_sources[0])
        
        # Merge remaining sources
        for source in data_sources[1:]:
            result = _merge_dictionaries(result, source, merge_strategy, deep_merge)
        
        logger.debug("Data merge completed successfully",
                    result_fields=len(result))
        
        return result
        
    except Exception as e:
        if isinstance(e, BaseBusinessException):
            raise
        
        raise DataProcessingError(
            message="Data merge operation failed",
            error_code="DATA_MERGE_FAILED",
            processing_stage="data_merge",
            cause=e,
            severity=ErrorSeverity.MEDIUM
        )


def _merge_dictionaries(
    target: Dict[str, Any], 
    source: Dict[str, Any], 
    strategy: str, 
    deep: bool
) -> Dict[str, Any]:
    """Internal helper for merging two dictionaries."""
    for key, value in source.items():
        if key not in target:
            # Key doesn't exist in target, add it
            target[key] = value
        elif strategy == "preserve":
            # Preserve existing value in target
            continue
        elif strategy == "override":
            # Override with source value
            if deep and isinstance(target[key], dict) and isinstance(value, dict):
                target[key] = _merge_dictionaries(target[key], value, strategy, deep)
            else:
                target[key] = value
        elif strategy == "combine":
            # Combine values based on type
            if isinstance(target[key], list) and isinstance(value, list):
                target[key] = target[key] + value
            elif isinstance(target[key], dict) and isinstance(value, dict):
                target[key] = _merge_dictionaries(target[key], value, strategy, deep)
            else:
                target[key] = value
    
    return target


def flatten_data(
    data: Dict[str, Any], 
    separator: str = ".",
    max_depth: Optional[int] = None
) -> Dict[str, Any]:
    """
    Flatten nested data structures to single-level dictionaries.
    
    Converts deeply nested dictionary structures to flat key-value pairs
    using configurable key separators. Useful for form data processing,
    configuration flattening, and API data transformation.
    
    Args:
        data: Nested dictionary to flatten
        separator: Character(s) to use for joining nested keys
        max_depth: Maximum depth to flatten (None for unlimited)
        
    Returns:
        Flattened dictionary with dot-notation keys
        
    Raises:
        DataProcessingError: If flattening fails or invalid data provided
        
    Example:
        nested_data = {
            'user': {
                'profile': {
                    'name': 'John Doe',
                    'age': 30
                },
                'preferences': {
                    'theme': 'dark'
                }
            },
            'settings': {
                'notifications': True
            }
        }
        
        flattened = flatten_data(nested_data)
        # Result: {
        #     'user.profile.name': 'John Doe',
        #     'user.profile.age': 30,
        #     'user.preferences.theme': 'dark',
        #     'settings.notifications': True
        # }
    """
    try:
        logger.debug("Starting data flattening operation",
                    separator=separator,
                    max_depth=max_depth)
        
        if not isinstance(data, dict):
            raise DataProcessingError(
                message="Data must be a dictionary for flattening",
                error_code="INVALID_FLATTEN_INPUT",
                processing_stage="data_flattening",
                data_type=type(data).__name__,
                severity=ErrorSeverity.MEDIUM
            )
        
        def _flatten_recursive(obj: Any, parent_key: str = "", depth: int = 0) -> Dict[str, Any]:
            """Recursive function to flatten nested structures."""
            items = []
            
            if isinstance(obj, dict):
                for key, value in obj.items():
                    new_key = f"{parent_key}{separator}{key}" if parent_key else key
                    
                    # Check depth limit
                    if max_depth is not None and depth >= max_depth:
                        items.append((new_key, value))
                    elif isinstance(value, dict) and value:  # Non-empty dict
                        items.extend(_flatten_recursive(value, new_key, depth + 1).items())
                    else:
                        items.append((new_key, value))
            else:
                items.append((parent_key, obj))
            
            return dict(items)
        
        flattened = _flatten_recursive(data)
        
        logger.debug("Data flattening completed successfully",
                    original_keys=len(data),
                    flattened_keys=len(flattened))
        
        return flattened
        
    except Exception as e:
        if isinstance(e, BaseBusinessException):
            raise
        
        raise DataProcessingError(
            message="Data flattening operation failed",
            error_code="DATA_FLATTEN_FAILED",
            processing_stage="data_flattening",
            cause=e,
            severity=ErrorSeverity.MEDIUM
        )


def filter_data(
    data: Union[List[Dict[str, Any]], Dict[str, Any]], 
    criteria: Dict[str, Any],
    match_mode: str = "all"
) -> Union[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Filter data based on specified criteria and matching rules.
    
    Provides flexible data filtering capabilities for business logic operations,
    supporting multiple filtering criteria and matching modes for complex
    data selection requirements.
    
    Args:
        data: Data to filter (list of dicts or single dict)
        criteria: Filtering criteria as key-value pairs
        match_mode: Matching mode ("all", "any", "exact")
        
    Returns:
        Filtered data matching the specified criteria
        
    Raises:
        DataProcessingError: If filtering fails or invalid criteria provided
        
    Example:
        users = [
            {'name': 'John', 'age': 30, 'active': True, 'role': 'admin'},
            {'name': 'Jane', 'age': 25, 'active': True, 'role': 'user'},
            {'name': 'Bob', 'age': 35, 'active': False, 'role': 'admin'}
        ]
        
        # Filter active admin users
        active_admins = filter_data(
            users, 
            {'active': True, 'role': 'admin'}, 
            match_mode="all"
        )
        # Result: [{'name': 'John', 'age': 30, 'active': True, 'role': 'admin'}]
    """
    try:
        logger.debug("Starting data filtering operation",
                    data_type=type(data).__name__,
                    criteria_count=len(criteria),
                    match_mode=match_mode)
        
        valid_modes = {"all", "any", "exact"}
        if match_mode not in valid_modes:
            raise DataProcessingError(
                message=f"Invalid match mode: {match_mode}",
                error_code="INVALID_MATCH_MODE",
                processing_stage="data_filtering",
                context={
                    'provided_mode': match_mode,
                    'valid_modes': list(valid_modes)
                },
                severity=ErrorSeverity.MEDIUM
            )
        
        if not criteria:
            return data
        
        def matches_criteria(item: Dict[str, Any]) -> bool:
            """Check if item matches filtering criteria."""
            matches = []
            
            for key, expected_value in criteria.items():
                if key not in item:
                    matches.append(False)
                    continue
                
                actual_value = item[key]
                
                if match_mode == "exact":
                    matches.append(actual_value == expected_value)
                else:
                    # Support for pattern matching and type flexibility
                    if isinstance(expected_value, str) and isinstance(actual_value, str):
                        # Case-insensitive string matching
                        matches.append(expected_value.lower() in actual_value.lower())
                    else:
                        matches.append(actual_value == expected_value)
            
            if match_mode == "all":
                return all(matches)
            elif match_mode == "any":
                return any(matches)
            else:  # exact
                return all(matches)
        
        if isinstance(data, list):
            filtered = [item for item in data if isinstance(item, dict) and matches_criteria(item)]
            logger.debug("List filtering completed",
                        original_count=len(data),
                        filtered_count=len(filtered))
            return filtered
        elif isinstance(data, dict):
            if matches_criteria(data):
                return data
            else:
                return {}
        else:
            raise DataProcessingError(
                message="Data must be a list of dictionaries or a single dictionary",
                error_code="INVALID_FILTER_INPUT",
                processing_stage="data_filtering",
                data_type=type(data).__name__,
                severity=ErrorSeverity.MEDIUM
            )
            
    except Exception as e:
        if isinstance(e, BaseBusinessException):
            raise
        
        raise DataProcessingError(
            message="Data filtering operation failed",
            error_code="DATA_FILTER_FAILED",
            processing_stage="data_filtering",
            cause=e,
            severity=ErrorSeverity.MEDIUM
        )


# ============================================================================
# DATE/TIME PROCESSING UTILITIES
# ============================================================================

def parse_date(
    date_string: str, 
    timezone_info: Optional[Union[str, tz.tzinfo.StaticTzInfo]] = None,
    format_hint: Optional[str] = None
) -> datetime:
    """
    Parse date strings with comprehensive timezone handling.
    
    Provides robust date parsing capabilities equivalent to Node.js moment.js
    functionality using python-dateutil 2.8+. Supports multiple date formats,
    timezone conversion, and business date processing requirements per Section 5.2.4.
    
    Args:
        date_string: Date string to parse in various formats
        timezone_info: Target timezone for conversion (string name or tzinfo)
        format_hint: Optional format hint for faster parsing
        
    Returns:
        Parsed datetime object with timezone information
        
    Raises:
        DataValidationError: If date string cannot be parsed or invalid timezone
        
    Example:
        # Parse ISO date string
        dt1 = parse_date("2024-01-15T10:30:00Z")
        
        # Parse with timezone conversion
        dt2 = parse_date("2024-01-15 10:30:00", timezone_info="America/New_York")
        
        # Parse with format hint
        dt3 = parse_date("15/01/2024", format_hint="%d/%m/%Y")
    """
    try:
        logger.debug("Parsing date string",
                    date_string=date_string,
                    timezone_info=str(timezone_info),
                    format_hint=format_hint)
        
        if not isinstance(date_string, str) or not date_string.strip():
            raise DataValidationError(
                message="Date string must be a non-empty string",
                error_code="INVALID_DATE_STRING",
                context={'provided_value': str(date_string)[:50]},
                severity=ErrorSeverity.MEDIUM
            )
        
        # Parse using specific format if provided
        if format_hint:
            try:
                parsed_date = datetime.strptime(date_string, format_hint)
            except ValueError as format_error:
                raise DataValidationError(
                    message=f"Date string does not match format hint '{format_hint}'",
                    error_code="DATE_FORMAT_MISMATCH",
                    context={
                        'date_string': date_string,
                        'format_hint': format_hint
                    },
                    cause=format_error,
                    severity=ErrorSeverity.MEDIUM
                )
        else:
            # Use dateutil parser for flexible parsing
            try:
                parsed_date = date_parser.parse(date_string)
            except (ValueError, TypeError) as parse_error:
                raise DataValidationError(
                    message=f"Unable to parse date string: {date_string}",
                    error_code="DATE_PARSE_FAILED",
                    context={'date_string': date_string},
                    cause=parse_error,
                    severity=ErrorSeverity.MEDIUM
                )
        
        # Apply timezone conversion if specified
        if timezone_info:
            target_tz = _get_timezone(timezone_info)
            
            if parsed_date.tzinfo is None:
                # Naive datetime - assume it's in the target timezone
                parsed_date = parsed_date.replace(tzinfo=target_tz)
            else:
                # Convert to target timezone
                parsed_date = parsed_date.astimezone(target_tz)
        elif parsed_date.tzinfo is None:
            # No timezone specified, assume UTC for consistency
            parsed_date = parsed_date.replace(tzinfo=timezone.utc)
        
        logger.debug("Date parsing completed successfully",
                    parsed_date=parsed_date.isoformat())
        
        return parsed_date
        
    except Exception as e:
        if isinstance(e, BaseBusinessException):
            raise
        
        raise DataValidationError(
            message="Date parsing operation failed",
            error_code="DATE_PARSE_ERROR",
            context={'date_string': date_string},
            cause=e,
            severity=ErrorSeverity.MEDIUM
        )


def format_date(
    date_obj: DateTimeType, 
    format_type: str = "iso",
    timezone_info: Optional[Union[str, tz.tzinfo.StaticTzInfo]] = None
) -> str:
    """
    Format dates for API responses and business processing.
    
    Provides comprehensive date formatting capabilities for consistent date
    representation across API responses, business logic, and data export
    operations. Supports multiple output formats and timezone conversion.
    
    Args:
        date_obj: Date object to format (datetime, date, or string)
        format_type: Output format type ("iso", "date", "time", "datetime", "custom")
        timezone_info: Target timezone for conversion before formatting
        
    Returns:
        Formatted date string in the specified format
        
    Raises:
        DataValidationError: If date object is invalid or formatting fails
        
    Example:
        dt = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        
        # ISO format (default)
        iso_date = format_date(dt)  # "2024-01-15T10:30:00+00:00"
        
        # Date only
        date_only = format_date(dt, "date")  # "2024-01-15"
        
        # With timezone conversion
        local_time = format_date(dt, "datetime", "America/New_York")  # "2024-01-15 05:30:00"
    """
    try:
        logger.debug("Formatting date object",
                    date_type=type(date_obj).__name__,
                    format_type=format_type,
                    timezone_info=str(timezone_info))
        
        # Convert input to datetime if needed
        if isinstance(date_obj, str):
            date_obj = parse_date(date_obj)
        elif isinstance(date_obj, date) and not isinstance(date_obj, datetime):
            date_obj = datetime.combine(date_obj, datetime.min.time(), timezone.utc)
        elif not isinstance(date_obj, datetime):
            raise DataValidationError(
                message="Invalid date object type for formatting",
                error_code="INVALID_DATE_TYPE",
                context={
                    'provided_type': type(date_obj).__name__,
                    'supported_types': ['datetime', 'date', 'str']
                },
                severity=ErrorSeverity.MEDIUM
            )
        
        # Apply timezone conversion if specified
        if timezone_info:
            target_tz = _get_timezone(timezone_info)
            if date_obj.tzinfo is None:
                date_obj = date_obj.replace(tzinfo=timezone.utc)
            date_obj = date_obj.astimezone(target_tz)
        
        # Format based on type
        format_map = {
            "iso": lambda dt: dt.isoformat(),
            "date": lambda dt: dt.strftime("%Y-%m-%d"),
            "time": lambda dt: dt.strftime("%H:%M:%S"),
            "datetime": lambda dt: dt.strftime("%Y-%m-%d %H:%M:%S"),
            "timestamp": lambda dt: str(int(dt.timestamp())),
            "rfc2822": lambda dt: dt.strftime("%a, %d %b %Y %H:%M:%S %z"),
            "human": lambda dt: dt.strftime("%B %d, %Y at %I:%M %p")
        }
        
        if format_type not in format_map:
            raise DataValidationError(
                message=f"Unsupported format type: {format_type}",
                error_code="INVALID_FORMAT_TYPE",
                context={
                    'provided_format': format_type,
                    'supported_formats': list(format_map.keys())
                },
                severity=ErrorSeverity.MEDIUM
            )
        
        formatted = format_map[format_type](date_obj)
        
        logger.debug("Date formatting completed successfully",
                    formatted_date=formatted)
        
        return formatted
        
    except Exception as e:
        if isinstance(e, BaseBusinessException):
            raise
        
        raise DataValidationError(
            message="Date formatting operation failed",
            error_code="DATE_FORMAT_ERROR",
            context={'format_type': format_type},
            cause=e,
            severity=ErrorSeverity.MEDIUM
        )


def calculate_date_difference(
    start_date: DateTimeType, 
    end_date: DateTimeType,
    unit: str = "days"
) -> Union[int, float]:
    """
    Calculate time differences between dates with configurable units.
    
    Provides comprehensive date difference calculations for business logic
    operations including age calculations, duration measurements, and
    time-based business rule validation.
    
    Args:
        start_date: Starting date for calculation
        end_date: Ending date for calculation
        unit: Unit for result ("seconds", "minutes", "hours", "days", "weeks", "months", "years")
        
    Returns:
        Numeric difference in the specified unit
        
    Raises:
        DataValidationError: If dates are invalid or unit not supported
        
    Example:
        start = parse_date("2024-01-01")
        end = parse_date("2024-01-15")
        
        days_diff = calculate_date_difference(start, end, "days")  # 14
        hours_diff = calculate_date_difference(start, end, "hours")  # 336
    """
    try:
        logger.debug("Calculating date difference",
                    start_date=str(start_date),
                    end_date=str(end_date),
                    unit=unit)
        
        # Convert inputs to datetime objects
        if isinstance(start_date, str):
            start_date = parse_date(start_date)
        elif isinstance(start_date, date) and not isinstance(start_date, datetime):
            start_date = datetime.combine(start_date, datetime.min.time(), timezone.utc)
        
        if isinstance(end_date, str):
            end_date = parse_date(end_date)
        elif isinstance(end_date, date) and not isinstance(end_date, datetime):
            end_date = datetime.combine(end_date, datetime.min.time(), timezone.utc)
        
        if not isinstance(start_date, datetime) or not isinstance(end_date, datetime):
            raise DataValidationError(
                message="Invalid date types for difference calculation",
                error_code="INVALID_DATE_TYPES",
                context={
                    'start_type': type(start_date).__name__,
                    'end_type': type(end_date).__name__
                },
                severity=ErrorSeverity.MEDIUM
            )
        
        # Ensure both dates have timezone info
        if start_date.tzinfo is None:
            start_date = start_date.replace(tzinfo=timezone.utc)
        if end_date.tzinfo is None:
            end_date = end_date.replace(tzinfo=timezone.utc)
        
        # Calculate difference based on unit
        if unit in ["seconds", "minutes", "hours", "days", "weeks"]:
            # Use timedelta for precise calculations
            diff = end_date - start_date
            
            if unit == "seconds":
                result = diff.total_seconds()
            elif unit == "minutes":
                result = diff.total_seconds() / 60
            elif unit == "hours":
                result = diff.total_seconds() / 3600
            elif unit == "days":
                result = diff.days + (diff.seconds / 86400)
            elif unit == "weeks":
                result = diff.days / 7
                
        elif unit in ["months", "years"]:
            # Use relativedelta for accurate month/year calculations
            diff = relativedelta(end_date, start_date)
            
            if unit == "months":
                result = diff.years * 12 + diff.months + (diff.days / 30.44)  # Average month length
            elif unit == "years":
                result = diff.years + (diff.months / 12) + (diff.days / 365.25)  # Account for leap years
                
        else:
            raise DataValidationError(
                message=f"Unsupported time unit: {unit}",
                error_code="INVALID_TIME_UNIT",
                context={
                    'provided_unit': unit,
                    'supported_units': ['seconds', 'minutes', 'hours', 'days', 'weeks', 'months', 'years']
                },
                severity=ErrorSeverity.MEDIUM
            )
        
        logger.debug("Date difference calculation completed",
                    difference=result,
                    unit=unit)
        
        return result
        
    except Exception as e:
        if isinstance(e, BaseBusinessException):
            raise
        
        raise DataValidationError(
            message="Date difference calculation failed",
            error_code="DATE_DIFF_ERROR",
            context={'unit': unit},
            cause=e,
            severity=ErrorSeverity.MEDIUM
        )


def get_business_days(
    start_date: DateTimeType, 
    end_date: DateTimeType,
    exclude_weekends: bool = True,
    holidays: Optional[List[DateTimeType]] = None
) -> int:
    """
    Calculate business days between dates excluding weekends and holidays.
    
    Provides business day calculations for processing time estimations,
    SLA calculations, and business rule validation. Supports configurable
    weekend exclusion and holiday calendars.
    
    Args:
        start_date: Starting date for calculation
        end_date: Ending date for calculation
        exclude_weekends: Whether to exclude Saturday and Sunday
        holidays: Optional list of holiday dates to exclude
        
    Returns:
        Number of business days between the dates
        
    Raises:
        DataValidationError: If dates are invalid
        
    Example:
        start = parse_date("2024-01-01")  # Monday
        end = parse_date("2024-01-15")    # Monday
        
        holidays = [parse_date("2024-01-10")]  # Holiday on Wednesday
        
        business_days = get_business_days(start, end, holidays=holidays)  # 9 (excluding weekends and holiday)
    """
    try:
        logger.debug("Calculating business days",
                    start_date=str(start_date),
                    end_date=str(end_date),
                    exclude_weekends=exclude_weekends,
                    holiday_count=len(holidays) if holidays else 0)
        
        # Convert inputs to date objects
        if isinstance(start_date, str):
            start_date = parse_date(start_date).date()
        elif isinstance(start_date, datetime):
            start_date = start_date.date()
        
        if isinstance(end_date, str):
            end_date = parse_date(end_date).date()
        elif isinstance(end_date, datetime):
            end_date = end_date.date()
        
        if start_date > end_date:
            start_date, end_date = end_date, start_date
        
        # Convert holidays to date objects
        holiday_dates = set()
        if holidays:
            for holiday in holidays:
                if isinstance(holiday, str):
                    holiday_dates.add(parse_date(holiday).date())
                elif isinstance(holiday, datetime):
                    holiday_dates.add(holiday.date())
                elif isinstance(holiday, date):
                    holiday_dates.add(holiday)
        
        # Count business days
        business_days = 0
        current_date = start_date
        
        while current_date <= end_date:
            # Check if it's a weekend
            is_weekend = exclude_weekends and current_date.weekday() >= 5  # Saturday=5, Sunday=6
            
            # Check if it's a holiday
            is_holiday = current_date in holiday_dates
            
            if not is_weekend and not is_holiday:
                business_days += 1
            
            current_date += timedelta(days=1)
        
        logger.debug("Business days calculation completed",
                    business_days=business_days)
        
        return business_days
        
    except Exception as e:
        if isinstance(e, BaseBusinessException):
            raise
        
        raise DataValidationError(
            message="Business days calculation failed",
            error_code="BUSINESS_DAYS_ERROR",
            cause=e,
            severity=ErrorSeverity.MEDIUM
        )


def convert_timezone(
    date_obj: DateTimeType, 
    target_timezone: Union[str, tz.tzinfo.StaticTzInfo],
    source_timezone: Optional[Union[str, tz.tzinfo.StaticTzInfo]] = None
) -> datetime:
    """
    Convert dates between timezones with comprehensive timezone support.
    
    Provides robust timezone conversion capabilities for global business
    operations, supporting named timezones, UTC offsets, and business
    timezone processing requirements.
    
    Args:
        date_obj: Date object to convert
        target_timezone: Target timezone for conversion
        source_timezone: Source timezone (if date_obj is naive)
        
    Returns:
        Converted datetime object in target timezone
        
    Raises:
        DataValidationError: If timezone conversion fails
        
    Example:
        utc_time = parse_date("2024-01-15T10:30:00Z")
        
        # Convert to Eastern Time
        eastern_time = convert_timezone(utc_time, "America/New_York")
        
        # Convert naive datetime
        naive_time = datetime(2024, 1, 15, 10, 30, 0)
        local_time = convert_timezone(naive_time, "America/Los_Angeles", "UTC")
    """
    try:
        logger.debug("Converting timezone",
                    date_obj=str(date_obj),
                    target_timezone=str(target_timezone),
                    source_timezone=str(source_timezone))
        
        # Convert input to datetime if needed
        if isinstance(date_obj, str):
            date_obj = parse_date(date_obj)
        elif isinstance(date_obj, date) and not isinstance(date_obj, datetime):
            date_obj = datetime.combine(date_obj, datetime.min.time())
        
        if not isinstance(date_obj, datetime):
            raise DataValidationError(
                message="Invalid date object for timezone conversion",
                error_code="INVALID_DATE_FOR_TZ",
                context={'date_type': type(date_obj).__name__},
                severity=ErrorSeverity.MEDIUM
            )
        
        # Get target timezone
        target_tz = _get_timezone(target_timezone)
        
        # Handle naive datetime
        if date_obj.tzinfo is None:
            if source_timezone:
                source_tz = _get_timezone(source_timezone)
                date_obj = date_obj.replace(tzinfo=source_tz)
            else:
                # Assume UTC for naive datetime
                date_obj = date_obj.replace(tzinfo=timezone.utc)
        
        # Convert to target timezone
        converted = date_obj.astimezone(target_tz)
        
        logger.debug("Timezone conversion completed",
                    converted_date=converted.isoformat())
        
        return converted
        
    except Exception as e:
        if isinstance(e, BaseBusinessException):
            raise
        
        raise DataValidationError(
            message="Timezone conversion failed",
            error_code="TIMEZONE_CONVERT_ERROR",
            context={'target_timezone': str(target_timezone)},
            cause=e,
            severity=ErrorSeverity.MEDIUM
        )


def _get_timezone(timezone_info: Union[str, tz.tzinfo.StaticTzInfo]) -> tz.tzinfo.StaticTzInfo:
    """
    Internal helper to get timezone object from string or tzinfo.
    
    Args:
        timezone_info: Timezone identifier string or tzinfo object
        
    Returns:
        Timezone info object
        
    Raises:
        DataValidationError: If timezone is invalid
    """
    if isinstance(timezone_info, str):
        try:
            if timezone_info.upper() == 'UTC':
                return timezone.utc
            else:
                return tz.gettz(timezone_info)
        except Exception as tz_error:
            raise DataValidationError(
                message=f"Invalid timezone identifier: {timezone_info}",
                error_code="INVALID_TIMEZONE",
                context={'timezone': timezone_info},
                cause=tz_error,
                severity=ErrorSeverity.MEDIUM
            )
    elif hasattr(timezone_info, 'localize') or hasattr(timezone_info, 'utcoffset'):
        return timezone_info
    else:
        raise DataValidationError(
            message="Timezone must be a string identifier or tzinfo object",
            error_code="INVALID_TIMEZONE_TYPE",
            context={'timezone_type': type(timezone_info).__name__},
            severity=ErrorSeverity.MEDIUM
        )


# ============================================================================
# BUSINESS CALCULATION UTILITIES
# ============================================================================

def calculate_percentage(
    value: NumericType, 
    total: NumericType, 
    precision: int = 2
) -> decimal.Decimal:
    """
    Calculate percentage values with proper decimal precision.
    
    Provides accurate percentage calculations for business metrics,
    financial calculations, and statistical operations using decimal
    arithmetic to avoid floating-point precision issues.
    
    Args:
        value: Numerator value for percentage calculation
        total: Denominator value for percentage calculation
        precision: Number of decimal places for result
        
    Returns:
        Percentage value as Decimal with specified precision
        
    Raises:
        BusinessRuleViolationError: If total is zero or values are invalid
        
    Example:
        # Calculate completion percentage
        completed_tasks = 15
        total_tasks = 20
        
        completion_rate = calculate_percentage(completed_tasks, total_tasks)
        # Result: Decimal('75.00')
    """
    try:
        logger.debug("Calculating percentage",
                    value=str(value),
                    total=str(total),
                    precision=precision)
        
        # Convert to Decimal for precise arithmetic
        decimal_value = decimal.Decimal(str(value))
        decimal_total = decimal.Decimal(str(total))
        
        # Validate inputs
        if decimal_total == 0:
            raise BusinessRuleViolationError(
                message="Cannot calculate percentage with zero total",
                error_code="DIVISION_BY_ZERO",
                context={'value': str(value), 'total': str(total)},
                severity=ErrorSeverity.HIGH
            )
        
        if decimal_value < 0 or decimal_total < 0:
            raise BusinessRuleViolationError(
                message="Percentage calculation requires non-negative values",
                error_code="NEGATIVE_VALUES",
                context={'value': str(value), 'total': str(total)},
                severity=ErrorSeverity.MEDIUM
            )
        
        # Calculate percentage
        percentage = (decimal_value / decimal_total) * 100
        
        # Round to specified precision
        quantized = percentage.quantize(decimal.Decimal('0.' + '0' * precision))
        
        logger.debug("Percentage calculation completed",
                    percentage=str(quantized))
        
        return quantized
        
    except Exception as e:
        if isinstance(e, BaseBusinessException):
            raise
        
        raise BusinessRuleViolationError(
            message="Percentage calculation failed",
            error_code="PERCENTAGE_CALC_ERROR",
            context={'value': str(value), 'total': str(total)},
            cause=e,
            severity=ErrorSeverity.MEDIUM
        )


def apply_discount(
    original_amount: NumericType, 
    discount_rate: NumericType,
    discount_type: str = "percentage",
    max_discount: Optional[NumericType] = None
) -> decimal.Decimal:
    """
    Apply discount calculations with multiple discount types.
    
    Provides comprehensive discount calculation functionality for business
    pricing logic, promotional campaigns, and financial operations with
    support for percentage and fixed amount discounts.
    
    Args:
        original_amount: Original amount before discount
        discount_rate: Discount rate or fixed amount
        discount_type: Type of discount ("percentage" or "fixed")
        max_discount: Optional maximum discount amount
        
    Returns:
        Discounted amount as Decimal with proper precision
        
    Raises:
        BusinessRuleViolationError: If discount parameters are invalid
        
    Example:
        # Apply 15% discount
        original_price = decimal.Decimal('100.00')
        discounted_price = apply_discount(original_price, 15, "percentage")
        # Result: Decimal('85.00')
        
        # Apply fixed discount with maximum
        bulk_discount = apply_discount(original_price, 25, "fixed", max_discount=20)
        # Result: Decimal('80.00') (capped at max_discount)
    """
    try:
        logger.debug("Applying discount",
                    original_amount=str(original_amount),
                    discount_rate=str(discount_rate),
                    discount_type=discount_type,
                    max_discount=str(max_discount))
        
        # Convert to Decimal for precise arithmetic
        amount = decimal.Decimal(str(original_amount))
        rate = decimal.Decimal(str(discount_rate))
        
        # Validate inputs
        if amount < 0:
            raise BusinessRuleViolationError(
                message="Original amount cannot be negative",
                error_code="NEGATIVE_AMOUNT",
                context={'amount': str(amount)},
                severity=ErrorSeverity.MEDIUM
            )
        
        if rate < 0:
            raise BusinessRuleViolationError(
                message="Discount rate cannot be negative",
                error_code="NEGATIVE_DISCOUNT",
                context={'discount_rate': str(rate)},
                severity=ErrorSeverity.MEDIUM
            )
        
        # Calculate discount amount based on type
        if discount_type == "percentage":
            if rate > 100:
                raise BusinessRuleViolationError(
                    message="Percentage discount cannot exceed 100%",
                    error_code="INVALID_PERCENTAGE",
                    context={'discount_rate': str(rate)},
                    severity=ErrorSeverity.HIGH
                )
            
            discount_amount = amount * (rate / 100)
            
        elif discount_type == "fixed":
            discount_amount = rate
            
        else:
            raise BusinessRuleViolationError(
                message=f"Invalid discount type: {discount_type}",
                error_code="INVALID_DISCOUNT_TYPE",
                context={
                    'discount_type': discount_type,
                    'valid_types': ['percentage', 'fixed']
                },
                severity=ErrorSeverity.MEDIUM
            )
        
        # Apply maximum discount limit if specified
        if max_discount is not None:
            max_discount_decimal = decimal.Decimal(str(max_discount))
            if discount_amount > max_discount_decimal:
                discount_amount = max_discount_decimal
        
        # Ensure discount doesn't exceed original amount
        if discount_amount > amount:
            discount_amount = amount
        
        # Calculate final discounted amount
        discounted_amount = amount - discount_amount
        
        # Round to currency precision (2 decimal places)
        result = discounted_amount.quantize(decimal.Decimal('0.01'))
        
        logger.debug("Discount application completed",
                    discount_amount=str(discount_amount),
                    final_amount=str(result))
        
        return result
        
    except Exception as e:
        if isinstance(e, BaseBusinessException):
            raise
        
        raise BusinessRuleViolationError(
            message="Discount calculation failed",
            error_code="DISCOUNT_CALC_ERROR",
            context={'discount_type': discount_type},
            cause=e,
            severity=ErrorSeverity.MEDIUM
        )


def calculate_tax(
    amount: NumericType, 
    tax_rate: NumericType,
    tax_type: str = "inclusive"
) -> Tuple[decimal.Decimal, decimal.Decimal]:
    """
    Calculate tax amounts with inclusive/exclusive tax handling.
    
    Provides comprehensive tax calculation functionality for business
    financial operations, supporting both inclusive and exclusive tax
    calculations with proper decimal precision.
    
    Args:
        amount: Base amount for tax calculation
        tax_rate: Tax rate as percentage (e.g., 8.5 for 8.5%)
        tax_type: Tax calculation type ("inclusive" or "exclusive")
        
    Returns:
        Tuple of (tax_amount, total_amount) as Decimal values
        
    Raises:
        BusinessRuleViolationError: If tax parameters are invalid
        
    Example:
        # Exclusive tax calculation
        base_amount = decimal.Decimal('100.00')
        tax_amount, total = calculate_tax(base_amount, 8.5, "exclusive")
        # Result: (Decimal('8.50'), Decimal('108.50'))
        
        # Inclusive tax calculation
        inclusive_amount = decimal.Decimal('108.50')
        tax_amount, net = calculate_tax(inclusive_amount, 8.5, "inclusive")
        # Result: (Decimal('8.50'), Decimal('100.00'))
    """
    try:
        logger.debug("Calculating tax",
                    amount=str(amount),
                    tax_rate=str(tax_rate),
                    tax_type=tax_type)
        
        # Convert to Decimal for precise arithmetic
        base_amount = decimal.Decimal(str(amount))
        rate = decimal.Decimal(str(tax_rate))
        
        # Validate inputs
        if base_amount < 0:
            raise BusinessRuleViolationError(
                message="Amount cannot be negative for tax calculation",
                error_code="NEGATIVE_AMOUNT",
                context={'amount': str(amount)},
                severity=ErrorSeverity.MEDIUM
            )
        
        if rate < 0 or rate > 100:
            raise BusinessRuleViolationError(
                message="Tax rate must be between 0 and 100 percent",
                error_code="INVALID_TAX_RATE",
                context={'tax_rate': str(rate)},
                severity=ErrorSeverity.MEDIUM
            )
        
        if tax_type == "exclusive":
            # Tax is added to the base amount
            tax_amount = base_amount * (rate / 100)
            total_amount = base_amount + tax_amount
            
        elif tax_type == "inclusive":
            # Tax is included in the given amount, calculate backwards
            tax_multiplier = decimal.Decimal('1') + (rate / 100)
            net_amount = base_amount / tax_multiplier
            tax_amount = base_amount - net_amount
            total_amount = net_amount  # Net amount when tax is inclusive
            
        else:
            raise BusinessRuleViolationError(
                message=f"Invalid tax type: {tax_type}",
                error_code="INVALID_TAX_TYPE",
                context={
                    'tax_type': tax_type,
                    'valid_types': ['inclusive', 'exclusive']
                },
                severity=ErrorSeverity.MEDIUM
            )
        
        # Round to currency precision
        tax_amount = tax_amount.quantize(decimal.Decimal('0.01'))
        total_amount = total_amount.quantize(decimal.Decimal('0.01'))
        
        logger.debug("Tax calculation completed",
                    tax_amount=str(tax_amount),
                    total_amount=str(total_amount))
        
        return tax_amount, total_amount
        
    except Exception as e:
        if isinstance(e, BaseBusinessException):
            raise
        
        raise BusinessRuleViolationError(
            message="Tax calculation failed",
            error_code="TAX_CALC_ERROR",
            context={'tax_type': tax_type},
            cause=e,
            severity=ErrorSeverity.MEDIUM
        )


def round_currency(
    amount: NumericType, 
    currency: str = "USD",
    rounding_mode: str = "ROUND_HALF_UP"
) -> decimal.Decimal:
    """
    Round monetary values according to currency-specific rules.
    
    Provides proper currency rounding functionality for financial calculations,
    supporting different currencies and rounding modes to ensure compliance
    with financial standards and business requirements.
    
    Args:
        amount: Monetary amount to round
        currency: Currency code for rounding rules
        rounding_mode: Decimal rounding mode
        
    Returns:
        Rounded amount as Decimal with currency-appropriate precision
        
    Raises:
        BusinessRuleViolationError: If currency or rounding mode is invalid
        
    Example:
        # USD rounding (2 decimal places)
        usd_amount = round_currency(decimal.Decimal('123.456'), "USD")
        # Result: Decimal('123.46')
        
        # JPY rounding (no decimal places)
        jpy_amount = round_currency(decimal.Decimal('123.456'), "JPY")
        # Result: Decimal('123')
    """
    try:
        logger.debug("Rounding currency amount",
                    amount=str(amount),
                    currency=currency,
                    rounding_mode=rounding_mode)
        
        # Convert to Decimal
        decimal_amount = decimal.Decimal(str(amount))
        
        # Currency-specific precision rules
        precision_map = {
            'USD': 2, 'EUR': 2, 'GBP': 2, 'CAD': 2, 'AUD': 2,  # Standard 2 decimal places
            'JPY': 0, 'KRW': 0,  # No decimal places
            'BHD': 3, 'KWD': 3, 'OMR': 3,  # 3 decimal places
        }
        
        precision = precision_map.get(currency.upper(), 2)  # Default to 2 decimal places
        
        # Rounding mode mapping
        rounding_modes = {
            'ROUND_HALF_UP': decimal.ROUND_HALF_UP,
            'ROUND_HALF_DOWN': decimal.ROUND_HALF_DOWN,
            'ROUND_HALF_EVEN': decimal.ROUND_HALF_EVEN,
            'ROUND_UP': decimal.ROUND_UP,
            'ROUND_DOWN': decimal.ROUND_DOWN,
            'ROUND_CEILING': decimal.ROUND_CEILING,
            'ROUND_FLOOR': decimal.ROUND_FLOOR
        }
        
        if rounding_mode not in rounding_modes:
            raise BusinessRuleViolationError(
                message=f"Invalid rounding mode: {rounding_mode}",
                error_code="INVALID_ROUNDING_MODE",
                context={
                    'rounding_mode': rounding_mode,
                    'valid_modes': list(rounding_modes.keys())
                },
                severity=ErrorSeverity.MEDIUM
            )
        
        # Create quantization target based on precision
        if precision == 0:
            quantize_target = decimal.Decimal('1')
        else:
            quantize_target = decimal.Decimal('0.' + '0' * precision)
        
        # Apply rounding
        rounded_amount = decimal_amount.quantize(
            quantize_target,
            rounding=rounding_modes[rounding_mode]
        )
        
        logger.debug("Currency rounding completed",
                    rounded_amount=str(rounded_amount))
        
        return rounded_amount
        
    except Exception as e:
        if isinstance(e, BaseBusinessException):
            raise
        
        raise BusinessRuleViolationError(
            message="Currency rounding failed",
            error_code="CURRENCY_ROUND_ERROR",
            context={'currency': currency},
            cause=e,
            severity=ErrorSeverity.MEDIUM
        )


def validate_currency(
    amount: NumericType, 
    currency: str = "USD",
    min_amount: Optional[NumericType] = None,
    max_amount: Optional[NumericType] = None
) -> bool:
    """
    Validate currency amounts against business rules and constraints.
    
    Provides comprehensive currency validation for business financial operations,
    including range validation, precision checking, and currency-specific
    business rule enforcement.
    
    Args:
        amount: Currency amount to validate
        currency: Currency code for validation rules
        min_amount: Optional minimum allowed amount
        max_amount: Optional maximum allowed amount
        
    Returns:
        True if amount is valid, False otherwise
        
    Raises:
        BusinessRuleViolationError: If validation fails with detailed error information
        
    Example:
        # Validate payment amount
        is_valid = validate_currency(
            decimal.Decimal('99.99'),
            "USD",
            min_amount=1.00,
            max_amount=10000.00
        )  # True
    """
    try:
        logger.debug("Validating currency amount",
                    amount=str(amount),
                    currency=currency,
                    min_amount=str(min_amount),
                    max_amount=str(max_amount))
        
        # Convert to Decimal
        decimal_amount = decimal.Decimal(str(amount))
        
        # Basic validation - non-negative amounts
        if decimal_amount < 0:
            raise BusinessRuleViolationError(
                message="Currency amount cannot be negative",
                error_code="NEGATIVE_CURRENCY",
                context={'amount': str(amount), 'currency': currency},
                severity=ErrorSeverity.HIGH
            )
        
        # Range validation
        if min_amount is not None:
            min_decimal = decimal.Decimal(str(min_amount))
            if decimal_amount < min_decimal:
                raise BusinessRuleViolationError(
                    message=f"Amount {amount} is below minimum {min_amount} for {currency}",
                    error_code="AMOUNT_BELOW_MINIMUM",
                    context={
                        'amount': str(amount),
                        'min_amount': str(min_amount),
                        'currency': currency
                    },
                    severity=ErrorSeverity.HIGH
                )
        
        if max_amount is not None:
            max_decimal = decimal.Decimal(str(max_amount))
            if decimal_amount > max_decimal:
                raise BusinessRuleViolationError(
                    message=f"Amount {amount} exceeds maximum {max_amount} for {currency}",
                    error_code="AMOUNT_EXCEEDS_MAXIMUM",
                    context={
                        'amount': str(amount),
                        'max_amount': str(max_amount),
                        'currency': currency
                    },
                    severity=ErrorSeverity.HIGH
                )
        
        # Currency-specific precision validation
        precision_map = {
            'USD': 2, 'EUR': 2, 'GBP': 2, 'CAD': 2, 'AUD': 2,
            'JPY': 0, 'KRW': 0,
            'BHD': 3, 'KWD': 3, 'OMR': 3,
        }
        
        expected_precision = precision_map.get(currency.upper(), 2)
        
        # Check if amount has appropriate decimal places
        decimal_places = abs(decimal_amount.as_tuple().exponent)
        if decimal_places > expected_precision:
            raise BusinessRuleViolationError(
                message=f"Amount has too many decimal places for {currency}",
                error_code="INVALID_PRECISION",
                context={
                    'amount': str(amount),
                    'currency': currency,
                    'expected_precision': expected_precision,
                    'actual_precision': decimal_places
                },
                severity=ErrorSeverity.MEDIUM
            )
        
        logger.debug("Currency validation completed successfully")
        return True
        
    except Exception as e:
        if isinstance(e, BaseBusinessException):
            raise
        
        raise BusinessRuleViolationError(
            message="Currency validation failed",
            error_code="CURRENCY_VALIDATION_ERROR",
            context={'currency': currency},
            cause=e,
            severity=ErrorSeverity.MEDIUM
        )


# ============================================================================
# VALIDATION UTILITIES
# ============================================================================

def validate_email(email: str, strict: bool = True) -> bool:
    """
    Validate email addresses with configurable strictness levels.
    
    Provides comprehensive email validation for business user data processing,
    supporting both strict RFC compliance and relaxed business-friendly validation
    patterns for user registration and data import operations.
    
    Args:
        email: Email address string to validate
        strict: Whether to apply strict RFC 5322 compliance
        
    Returns:
        True if email is valid, False otherwise
        
    Raises:
        DataValidationError: If validation fails with detailed error information
        
    Example:
        # Basic email validation
        is_valid = validate_email("user@example.com")  # True
        
        # Strict validation
        is_valid = validate_email("user+tag@sub.example.com", strict=True)  # True
    """
    try:
        logger.debug("Validating email address",
                    email_length=len(email) if email else 0,
                    strict=strict)
        
        if not email or not isinstance(email, str):
            raise DataValidationError(
                message="Email must be a non-empty string",
                error_code="INVALID_EMAIL_TYPE",
                context={'email_type': type(email).__name__},
                severity=ErrorSeverity.MEDIUM
            )
        
        email = email.strip()
        
        # Basic length check
        if len(email) > 254:  # RFC 5321 limit
            raise DataValidationError(
                message="Email address is too long (maximum 254 characters)",
                error_code="EMAIL_TOO_LONG",
                context={'email_length': len(email)},
                severity=ErrorSeverity.MEDIUM
            )
        
        if len(email) < 5:  # Minimum reasonable email length
            raise DataValidationError(
                message="Email address is too short",
                error_code="EMAIL_TOO_SHORT",
                context={'email_length': len(email)},
                severity=ErrorSeverity.MEDIUM
            )
        
        # Split into local and domain parts
        if email.count('@') != 1:
            raise DataValidationError(
                message="Email must contain exactly one @ symbol",
                error_code="INVALID_EMAIL_FORMAT",
                context={'at_count': email.count('@')},
                severity=ErrorSeverity.MEDIUM
            )
        
        local_part, domain_part = email.rsplit('@', 1)
        
        # Validate local part
        if not local_part or len(local_part) > 64:
            raise DataValidationError(
                message="Email local part is invalid or too long",
                error_code="INVALID_LOCAL_PART",
                context={'local_length': len(local_part)},
                severity=ErrorSeverity.MEDIUM
            )
        
        # Validate domain part
        if not domain_part or len(domain_part) > 253:
            raise DataValidationError(
                message="Email domain part is invalid or too long",
                error_code="INVALID_DOMAIN_PART",
                context={'domain_length': len(domain_part)},
                severity=ErrorSeverity.MEDIUM
            )
        
        if strict:
            # Strict RFC 5322 compliance
            local_pattern = r'^[a-zA-Z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&\'*+/=?^_`{|}~-]+)*$'
            domain_pattern = r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        else:
            # Relaxed business-friendly validation
            local_pattern = r'^[a-zA-Z0-9._+-]+$'
            domain_pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(local_pattern, local_part):
            raise DataValidationError(
                message="Email local part contains invalid characters",
                error_code="INVALID_LOCAL_CHARS",
                context={'strict_mode': strict},
                severity=ErrorSeverity.MEDIUM
            )
        
        if not re.match(domain_pattern, domain_part):
            raise DataValidationError(
                message="Email domain part is invalid",
                error_code="INVALID_DOMAIN_FORMAT",
                context={'strict_mode': strict},
                severity=ErrorSeverity.MEDIUM
            )
        
        logger.debug("Email validation completed successfully")
        return True
        
    except Exception as e:
        if isinstance(e, BaseBusinessException):
            raise
        
        return False  # Return False for non-business exceptions to maintain compatibility


def validate_phone(
    phone: str, 
    country_code: Optional[str] = None,
    format_type: str = "international"
) -> bool:
    """
    Validate phone numbers with international format support.
    
    Provides comprehensive phone number validation for business contact data
    processing, supporting multiple international formats and country-specific
    validation rules for global business operations.
    
    Args:
        phone: Phone number string to validate
        country_code: Optional ISO country code for validation
        format_type: Expected format ("international", "national", "local")
        
    Returns:
        True if phone number is valid, False otherwise
        
    Raises:
        DataValidationError: If validation fails with detailed error information
        
    Example:
        # International format
        is_valid = validate_phone("+1-555-123-4567", format_type="international")  # True
        
        # National format with country
        is_valid = validate_phone("(555) 123-4567", country_code="US", format_type="national")  # True
    """
    try:
        logger.debug("Validating phone number",
                    phone_length=len(phone) if phone else 0,
                    country_code=country_code,
                    format_type=format_type)
        
        if not phone or not isinstance(phone, str):
            raise DataValidationError(
                message="Phone number must be a non-empty string",
                error_code="INVALID_PHONE_TYPE",
                context={'phone_type': type(phone).__name__},
                severity=ErrorSeverity.MEDIUM
            )
        
        # Clean phone number - remove common formatting
        cleaned_phone = re.sub(r'[^\d+()-.\s]', '', phone.strip())
        digits_only = re.sub(r'[^\d]', '', cleaned_phone)
        
        # Basic length validation
        if len(digits_only) < 7 or len(digits_only) > 15:
            raise DataValidationError(
                message="Phone number must contain 7-15 digits",
                error_code="INVALID_PHONE_LENGTH",
                context={'digit_count': len(digits_only)},
                severity=ErrorSeverity.MEDIUM
            )
        
        # Format-specific validation
        if format_type == "international":
            # Must start with + followed by country code
            if not cleaned_phone.startswith('+'):
                raise DataValidationError(
                    message="International phone number must start with '+'",
                    error_code="MISSING_PLUS_PREFIX",
                    severity=ErrorSeverity.MEDIUM
                )
            
            # Validate international format pattern
            intl_pattern = r'^\+\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{1,4}[\s.-]?\d{1,9}$'
            if not re.match(intl_pattern, cleaned_phone):
                raise DataValidationError(
                    message="Invalid international phone number format",
                    error_code="INVALID_INTL_FORMAT",
                    severity=ErrorSeverity.MEDIUM
                )
        
        elif format_type == "national":
            # National format validation (country-specific)
            if country_code == "US":
                # US national format: (XXX) XXX-XXXX or XXX-XXX-XXXX
                us_pattern = r'^(\(?\d{3}\)?[\s.-]?)?\d{3}[\s.-]?\d{4}$'
                if not re.match(us_pattern, cleaned_phone):
                    raise DataValidationError(
                        message="Invalid US national phone number format",
                        error_code="INVALID_US_FORMAT",
                        severity=ErrorSeverity.MEDIUM
                    )
                
                if len(digits_only) != 10:
                    raise DataValidationError(
                        message="US phone number must contain exactly 10 digits",
                        error_code="INVALID_US_LENGTH",
                        context={'digit_count': len(digits_only)},
                        severity=ErrorSeverity.MEDIUM
                    )
            else:
                # Generic national format validation
                if len(digits_only) < 7 or len(digits_only) > 12:
                    raise DataValidationError(
                        message="National phone number must contain 7-12 digits",
                        error_code="INVALID_NATIONAL_LENGTH",
                        context={'digit_count': len(digits_only)},
                        severity=ErrorSeverity.MEDIUM
                    )
        
        elif format_type == "local":
            # Local format validation
            if len(digits_only) < 7 or len(digits_only) > 10:
                raise DataValidationError(
                    message="Local phone number must contain 7-10 digits",
                    error_code="INVALID_LOCAL_LENGTH",
                    context={'digit_count': len(digits_only)},
                    severity=ErrorSeverity.MEDIUM
                )
        
        else:
            raise DataValidationError(
                message=f"Invalid phone format type: {format_type}",
                error_code="INVALID_FORMAT_TYPE",
                context={
                    'format_type': format_type,
                    'valid_types': ['international', 'national', 'local']
                },
                severity=ErrorSeverity.MEDIUM
            )
        
        logger.debug("Phone validation completed successfully")
        return True
        
    except Exception as e:
        if isinstance(e, BaseBusinessException):
            raise
        
        return False  # Return False for non-business exceptions


def validate_postal_code(
    postal_code: str, 
    country_code: str = "US"
) -> bool:
    """
    Validate postal codes with country-specific format rules.
    
    Provides comprehensive postal code validation for business address data
    processing, supporting multiple international postal code formats and
    country-specific validation patterns for global operations.
    
    Args:
        postal_code: Postal code string to validate
        country_code: ISO country code for format validation
        
    Returns:
        True if postal code is valid, False otherwise
        
    Raises:
        DataValidationError: If validation fails with detailed error information
        
    Example:
        # US ZIP code validation
        is_valid = validate_postal_code("12345", "US")  # True
        is_valid = validate_postal_code("12345-6789", "US")  # True
        
        # Canadian postal code validation
        is_valid = validate_postal_code("K1A 0A6", "CA")  # True
    """
    try:
        logger.debug("Validating postal code",
                    postal_code=postal_code,
                    country_code=country_code)
        
        if not postal_code or not isinstance(postal_code, str):
            raise DataValidationError(
                message="Postal code must be a non-empty string",
                error_code="INVALID_POSTAL_TYPE",
                context={'postal_type': type(postal_code).__name__},
                severity=ErrorSeverity.MEDIUM
            )
        
        cleaned_code = postal_code.strip().upper()
        
        # Country-specific postal code patterns
        patterns = {
            'US': r'^\d{5}(-\d{4})?$',  # 12345 or 12345-6789
            'CA': r'^[A-Z]\d[A-Z]\s?\d[A-Z]\d$',  # K1A 0A6 or K1A0A6
            'GB': r'^[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}$',  # SW1A 1AA
            'DE': r'^\d{5}$',  # 12345
            'FR': r'^\d{5}$',  # 75001
            'AU': r'^\d{4}$',  # 2000
            'JP': r'^\d{3}-\d{4}$',  # 123-4567
            'IN': r'^\d{6}$',  # 110001
            'BR': r'^\d{5}-?\d{3}$',  # 01234-567
            'MX': r'^\d{5}$',  # 12345
        }
        
        if country_code.upper() not in patterns:
            raise DataValidationError(
                message=f"Postal code validation not supported for country: {country_code}",
                error_code="UNSUPPORTED_COUNTRY",
                context={
                    'country_code': country_code,
                    'supported_countries': list(patterns.keys())
                },
                severity=ErrorSeverity.MEDIUM
            )
        
        pattern = patterns[country_code.upper()]
        
        if not re.match(pattern, cleaned_code):
            raise DataValidationError(
                message=f"Invalid postal code format for {country_code}",
                error_code="INVALID_POSTAL_FORMAT",
                context={
                    'postal_code': postal_code,
                    'country_code': country_code,
                    'expected_pattern': pattern
                },
                severity=ErrorSeverity.MEDIUM
            )
        
        logger.debug("Postal code validation completed successfully")
        return True
        
    except Exception as e:
        if isinstance(e, BaseBusinessException):
            raise
        
        return False  # Return False for non-business exceptions


def sanitize_input(
    input_data: str, 
    allow_html: bool = False,
    max_length: Optional[int] = None
) -> str:
    """
    Sanitize user input to prevent XSS and injection attacks.
    
    Provides comprehensive input sanitization for business data processing,
    removing potentially dangerous content while preserving legitimate user
    data for secure business operations.
    
    Args:
        input_data: Input string to sanitize
        allow_html: Whether to allow safe HTML tags
        max_length: Maximum allowed length for input
        
    Returns:
        Sanitized input string safe for processing
        
    Raises:
        DataValidationError: If input is invalid or sanitization fails
        
    Example:
        # Basic sanitization
        safe_text = sanitize_input("<script>alert('xss')</script>Hello World")
        # Result: "Hello World"
        
        # Allow safe HTML
        safe_html = sanitize_input("<p>Hello <b>World</b></p>", allow_html=True)
        # Result: "<p>Hello <b>World</b></p>"
    """
    try:
        logger.debug("Sanitizing input data",
                    input_length=len(input_data) if input_data else 0,
                    allow_html=allow_html,
                    max_length=max_length)
        
        if not isinstance(input_data, str):
            if input_data is None:
                return ""
            input_data = str(input_data)
        
        # Length validation
        if max_length and len(input_data) > max_length:
            raise DataValidationError(
                message=f"Input exceeds maximum length of {max_length} characters",
                error_code="INPUT_TOO_LONG",
                context={
                    'input_length': len(input_data),
                    'max_length': max_length
                },
                severity=ErrorSeverity.MEDIUM
            )
        
        # Import bleach for HTML sanitization
        try:
            import bleach
        except ImportError:
            raise ConfigurationError(
                message="bleach library required for input sanitization",
                error_code="MISSING_SANITIZATION_LIB",
                severity=ErrorSeverity.CRITICAL
            )
        
        if allow_html:
            # Allow safe HTML tags and attributes
            allowed_tags = [
                'p', 'br', 'strong', 'b', 'em', 'i', 'u', 'span',
                'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
                'ul', 'ol', 'li', 'blockquote',
                'a', 'img'
            ]
            allowed_attributes = {
                'a': ['href', 'title'],
                'img': ['src', 'alt', 'title', 'width', 'height'],
                'span': ['class'],
                '*': ['id', 'class']
            }
            
            sanitized = bleach.clean(
                input_data,
                tags=allowed_tags,
                attributes=allowed_attributes,
                strip=True
            )
        else:
            # Strip all HTML tags
            sanitized = bleach.clean(input_data, tags=[], strip=True)
        
        # Additional sanitization for common attack patterns
        # Remove null bytes
        sanitized = sanitized.replace('\x00', '')
        
        # Normalize whitespace
        sanitized = re.sub(r'\s+', ' ', sanitized).strip()
        
        logger.debug("Input sanitization completed",
                    original_length=len(input_data),
                    sanitized_length=len(sanitized))
        
        return sanitized
        
    except Exception as e:
        if isinstance(e, BaseBusinessException):
            raise
        
        raise DataValidationError(
            message="Input sanitization failed",
            error_code="SANITIZATION_ERROR",
            cause=e,
            severity=ErrorSeverity.HIGH
        )


def validate_json_schema(
    data: Dict[str, Any], 
    schema: Dict[str, Any]
) -> bool:
    """
    Validate JSON data against schema definitions.
    
    Provides comprehensive JSON schema validation for business data processing,
    ensuring data structure compliance and type safety for API requests,
    configuration validation, and data import operations.
    
    Args:
        data: JSON data to validate
        schema: JSON schema definition for validation
        
    Returns:
        True if data matches schema, False otherwise
        
    Raises:
        DataValidationError: If validation fails with detailed error information
        
    Example:
        schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string", "minLength": 1},
                "age": {"type": "number", "minimum": 0}
            },
            "required": ["name", "age"]
        }
        
        data = {"name": "John Doe", "age": 30}
        is_valid = validate_json_schema(data, schema)  # True
    """
    try:
        logger.debug("Validating JSON schema",
                    data_keys=list(data.keys()) if isinstance(data, dict) else [],
                    schema_type=schema.get('type') if isinstance(schema, dict) else None)
        
        # Import jsonschema for validation
        try:
            import jsonschema
            from jsonschema import validate, ValidationError
        except ImportError:
            raise ConfigurationError(
                message="jsonschema library required for JSON validation",
                error_code="MISSING_VALIDATION_LIB",
                severity=ErrorSeverity.CRITICAL
            )
        
        if not isinstance(data, dict):
            raise DataValidationError(
                message="Data must be a dictionary for JSON schema validation",
                error_code="INVALID_DATA_TYPE",
                context={'data_type': type(data).__name__},
                severity=ErrorSeverity.MEDIUM
            )
        
        if not isinstance(schema, dict):
            raise DataValidationError(
                message="Schema must be a dictionary",
                error_code="INVALID_SCHEMA_TYPE",
                context={'schema_type': type(schema).__name__},
                severity=ErrorSeverity.MEDIUM
            )
        
        try:
            validate(instance=data, schema=schema)
            logger.debug("JSON schema validation completed successfully")
            return True
            
        except ValidationError as validation_error:
            # Convert jsonschema ValidationError to business exception
            error_path = " -> ".join(str(p) for p in validation_error.absolute_path)
            
            raise DataValidationError(
                message=f"JSON schema validation failed: {validation_error.message}",
                error_code="SCHEMA_VALIDATION_FAILED",
                context={
                    'validation_path': error_path,
                    'failed_value': str(validation_error.instance)[:100],
                    'schema_rule': str(validation_error.schema)[:200]
                },
                cause=validation_error,
                severity=ErrorSeverity.MEDIUM
            )
        
    except Exception as e:
        if isinstance(e, BaseBusinessException):
            raise
        
        raise DataValidationError(
            message="JSON schema validation failed",
            error_code="SCHEMA_VALIDATION_ERROR",
            cause=e,
            severity=ErrorSeverity.MEDIUM
        )


# ============================================================================
# TYPE CONVERSION UTILITIES
# ============================================================================

def safe_int(
    value: Any, 
    default: Optional[int] = None,
    min_value: Optional[int] = None,
    max_value: Optional[int] = None
) -> Optional[int]:
    """
    Safely convert values to integers with validation and fallbacks.
    
    Provides robust integer conversion for business data processing with
    comprehensive error handling, range validation, and configurable
    default values for invalid inputs.
    
    Args:
        value: Value to convert to integer
        default: Default value for invalid conversions
        min_value: Optional minimum allowed value
        max_value: Optional maximum allowed value
        
    Returns:
        Converted integer value or default if conversion fails
        
    Raises:
        DataValidationError: If value is outside allowed range
        
    Example:
        # Basic conversion
        number = safe_int("123")  # 123
        
        # With default for invalid input
        number = safe_int("invalid", default=0)  # 0
        
        # With range validation
        number = safe_int("150", min_value=1, max_value=100)  # Raises exception
    """
    try:
        logger.debug("Converting to safe integer",
                    value=str(value)[:50],
                    value_type=type(value).__name__,
                    default=default,
                    min_value=min_value,
                    max_value=max_value)
        
        # Handle None input
        if value is None:
            return default
        
        # Handle already integer values
        if isinstance(value, int):
            result = value
        elif isinstance(value, float):
            # Check if float is a whole number
            if value.is_integer():
                result = int(value)
            else:
                if default is not None:
                    return default
                raise DataValidationError(
                    message=f"Float value {value} is not a whole number",
                    error_code="FLOAT_NOT_INTEGER",
                    context={'value': str(value)},
                    severity=ErrorSeverity.MEDIUM
                )
        elif isinstance(value, str):
            # Handle string conversion
            cleaned_value = value.strip()
            if not cleaned_value:
                return default
            
            try:
                # Handle different number formats
                if '.' in cleaned_value:
                    float_val = float(cleaned_value)
                    if float_val.is_integer():
                        result = int(float_val)
                    else:
                        if default is not None:
                            return default
                        raise ValueError(f"String '{value}' represents a non-integer")
                else:
                    result = int(cleaned_value)
            except ValueError:
                if default is not None:
                    return default
                raise DataValidationError(
                    message=f"Cannot convert '{value}' to integer",
                    error_code="INVALID_INTEGER_STRING",
                    context={'value': str(value)},
                    severity=ErrorSeverity.MEDIUM
                )
        elif isinstance(value, decimal.Decimal):
            # Handle Decimal conversion
            if value % 1 == 0:  # Check if it's a whole number
                result = int(value)
            else:
                if default is not None:
                    return default
                raise DataValidationError(
                    message=f"Decimal value {value} is not a whole number",
                    error_code="DECIMAL_NOT_INTEGER",
                    context={'value': str(value)},
                    severity=ErrorSeverity.MEDIUM
                )
        else:
            # Try generic conversion
            try:
                result = int(value)
            except (TypeError, ValueError):
                if default is not None:
                    return default
                raise DataValidationError(
                    message=f"Cannot convert {type(value).__name__} to integer",
                    error_code="UNSUPPORTED_TYPE",
                    context={'value_type': type(value).__name__},
                    severity=ErrorSeverity.MEDIUM
                )
        
        # Range validation
        if min_value is not None and result < min_value:
            raise DataValidationError(
                message=f"Integer value {result} is below minimum {min_value}",
                error_code="INTEGER_BELOW_MINIMUM",
                context={
                    'value': result,
                    'min_value': min_value
                },
                severity=ErrorSeverity.MEDIUM
            )
        
        if max_value is not None and result > max_value:
            raise DataValidationError(
                message=f"Integer value {result} exceeds maximum {max_value}",
                error_code="INTEGER_EXCEEDS_MAXIMUM",
                context={
                    'value': result,
                    'max_value': max_value
                },
                severity=ErrorSeverity.MEDIUM
            )
        
        logger.debug("Safe integer conversion completed",
                    result=result)
        
        return result
        
    except Exception as e:
        if isinstance(e, BaseBusinessException):
            raise
        
        logger.warning("Safe integer conversion failed",
                      value=str(value)[:50],
                      error=str(e))
        return default


def safe_float(
    value: Any, 
    default: Optional[float] = None,
    min_value: Optional[float] = None,
    max_value: Optional[float] = None,
    precision: Optional[int] = None
) -> Optional[float]:
    """
    Safely convert values to floats with validation and precision control.
    
    Provides robust float conversion for business data processing with
    comprehensive error handling, range validation, precision control,
    and configurable default values for invalid inputs.
    
    Args:
        value: Value to convert to float
        default: Default value for invalid conversions
        min_value: Optional minimum allowed value
        max_value: Optional maximum allowed value
        precision: Optional number of decimal places to round to
        
    Returns:
        Converted float value or default if conversion fails
        
    Raises:
        DataValidationError: If value is outside allowed range
        
    Example:
        # Basic conversion
        number = safe_float("123.45")  # 123.45
        
        # With precision control
        number = safe_float("123.456789", precision=2)  # 123.46
        
        # With range validation
        number = safe_float("150.5", min_value=0.0, max_value=100.0)  # Raises exception
    """
    try:
        logger.debug("Converting to safe float",
                    value=str(value)[:50],
                    value_type=type(value).__name__,
                    default=default,
                    min_value=min_value,
                    max_value=max_value,
                    precision=precision)
        
        # Handle None input
        if value is None:
            return default
        
        # Handle already numeric values
        if isinstance(value, (int, float)):
            result = float(value)
        elif isinstance(value, decimal.Decimal):
            result = float(value)
        elif isinstance(value, str):
            # Handle string conversion
            cleaned_value = value.strip()
            if not cleaned_value:
                return default
            
            try:
                result = float(cleaned_value)
            except ValueError:
                if default is not None:
                    return default
                raise DataValidationError(
                    message=f"Cannot convert '{value}' to float",
                    error_code="INVALID_FLOAT_STRING",
                    context={'value': str(value)},
                    severity=ErrorSeverity.MEDIUM
                )
        else:
            # Try generic conversion
            try:
                result = float(value)
            except (TypeError, ValueError):
                if default is not None:
                    return default
                raise DataValidationError(
                    message=f"Cannot convert {type(value).__name__} to float",
                    error_code="UNSUPPORTED_FLOAT_TYPE",
                    context={'value_type': type(value).__name__},
                    severity=ErrorSeverity.MEDIUM
                )
        
        # Check for infinity and NaN
        if not math.isfinite(result):
            if default is not None:
                return default
            raise DataValidationError(
                message="Float value is not finite (infinity or NaN)",
                error_code="NON_FINITE_FLOAT",
                context={'value': str(result)},
                severity=ErrorSeverity.MEDIUM
            )
        
        # Apply precision rounding
        if precision is not None:
            result = round(result, precision)
        
        # Range validation
        if min_value is not None and result < min_value:
            raise DataValidationError(
                message=f"Float value {result} is below minimum {min_value}",
                error_code="FLOAT_BELOW_MINIMUM",
                context={
                    'value': result,
                    'min_value': min_value
                },
                severity=ErrorSeverity.MEDIUM
            )
        
        if max_value is not None and result > max_value:
            raise DataValidationError(
                message=f"Float value {result} exceeds maximum {max_value}",
                error_code="FLOAT_EXCEEDS_MAXIMUM",
                context={
                    'value': result,
                    'max_value': max_value
                },
                severity=ErrorSeverity.MEDIUM
            )
        
        logger.debug("Safe float conversion completed",
                    result=result)
        
        return result
        
    except Exception as e:
        if isinstance(e, BaseBusinessException):
            raise
        
        logger.warning("Safe float conversion failed",
                      value=str(value)[:50],
                      error=str(e))
        return default


def safe_str(
    value: Any, 
    default: str = "",
    max_length: Optional[int] = None,
    strip_whitespace: bool = True
) -> str:
    """
    Safely convert values to strings with length control and formatting.
    
    Provides robust string conversion for business data processing with
    comprehensive error handling, length validation, whitespace control,
    and consistent formatting for display and storage operations.
    
    Args:
        value: Value to convert to string
        default: Default value for None input
        max_length: Optional maximum allowed string length
        strip_whitespace: Whether to strip leading/trailing whitespace
        
    Returns:
        Converted string value with proper formatting
        
    Raises:
        DataValidationError: If string exceeds maximum length
        
    Example:
        # Basic conversion
        text = safe_str(123)  # "123"
        
        # With length limit
        text = safe_str("Very long text...", max_length=10)  # May raise exception
        
        # With whitespace handling
        text = safe_str("  Hello World  ", strip_whitespace=True)  # "Hello World"
    """
    try:
        logger.debug("Converting to safe string",
                    value_type=type(value).__name__,
                    max_length=max_length,
                    strip_whitespace=strip_whitespace)
        
        # Handle None input
        if value is None:
            return default
        
        # Handle already string values
        if isinstance(value, str):
            result = value
        else:
            # Convert to string
            try:
                result = str(value)
            except Exception as convert_error:
                raise DataValidationError(
                    message=f"Cannot convert {type(value).__name__} to string",
                    error_code="STRING_CONVERSION_FAILED",
                    context={'value_type': type(value).__name__},
                    cause=convert_error,
                    severity=ErrorSeverity.MEDIUM
                )
        
        # Strip whitespace if requested
        if strip_whitespace:
            result = result.strip()
        
        # Length validation
        if max_length is not None and len(result) > max_length:
            raise DataValidationError(
                message=f"String length {len(result)} exceeds maximum {max_length}",
                error_code="STRING_TOO_LONG",
                context={
                    'string_length': len(result),
                    'max_length': max_length
                },
                severity=ErrorSeverity.MEDIUM
            )
        
        logger.debug("Safe string conversion completed",
                    result_length=len(result))
        
        return result
        
    except Exception as e:
        if isinstance(e, BaseBusinessException):
            raise
        
        logger.warning("Safe string conversion failed",
                      value_type=type(value).__name__,
                      error=str(e))
        return default


def normalize_boolean(
    value: Any, 
    default: Optional[bool] = None
) -> Optional[bool]:
    """
    Normalize various value types to boolean with flexible interpretation.
    
    Provides comprehensive boolean conversion for business data processing
    with support for multiple input formats including strings, numbers,
    and common boolean representations from various data sources.
    
    Args:
        value: Value to convert to boolean
        default: Default value for ambiguous inputs
        
    Returns:
        Normalized boolean value or default if conversion is ambiguous
        
    Example:
        # Standard boolean conversion
        result = normalize_boolean(True)  # True
        result = normalize_boolean("true")  # True
        result = normalize_boolean(1)  # True
        result = normalize_boolean("false")  # False
        result = normalize_boolean(0)  # False
        
        # Flexible string interpretation
        result = normalize_boolean("yes")  # True
        result = normalize_boolean("no")  # False
        result = normalize_boolean("on")  # True
        result = normalize_boolean("off")  # False
    """
    try:
        logger.debug("Normalizing boolean value",
                    value=str(value)[:50],
                    value_type=type(value).__name__,
                    default=default)
        
        # Handle None input
        if value is None:
            return default
        
        # Handle already boolean values
        if isinstance(value, bool):
            return value
        
        # Handle numeric values
        if isinstance(value, (int, float)):
            return bool(value)
        
        # Handle string values
        if isinstance(value, str):
            cleaned_value = value.strip().lower()
            
            # True values
            true_values = {
                'true', '1', 'yes', 'y', 'on', 'enable', 'enabled', 
                'active', 'ok', 'okay', 'success'
            }
            
            # False values
            false_values = {
                'false', '0', 'no', 'n', 'off', 'disable', 'disabled', 
                'inactive', 'fail', 'failed', 'error'
            }
            
            if cleaned_value in true_values:
                return True
            elif cleaned_value in false_values:
                return False
            else:
                # Ambiguous string value
                return default
        
        # Handle other types by checking truthiness
        return bool(value)
        
    except Exception as e:
        logger.warning("Boolean normalization failed",
                      value=str(value)[:50],
                      error=str(e))
        return default


def parse_json(
    json_string: str, 
    default: Optional[Dict[str, Any]] = None
) -> Optional[Dict[str, Any]]:
    """
    Safely parse JSON strings with error handling and validation.
    
    Provides robust JSON parsing for business data processing with
    comprehensive error handling, security validation, and configurable
    default values for malformed JSON input.
    
    Args:
        json_string: JSON string to parse
        default: Default value for invalid JSON
        
    Returns:
        Parsed JSON object or default if parsing fails
        
    Raises:
        DataValidationError: If JSON is malformed and no default provided
        
    Example:
        # Basic JSON parsing
        data = parse_json('{"name": "John", "age": 30}')
        # Result: {"name": "John", "age": 30}
        
        # With default for invalid JSON
        data = parse_json('invalid json', default={})
        # Result: {}
    """
    try:
        logger.debug("Parsing JSON string",
                    string_length=len(json_string) if json_string else 0,
                    has_default=default is not None)
        
        if not json_string or not isinstance(json_string, str):
            if default is not None:
                return default
            raise DataValidationError(
                message="JSON string must be a non-empty string",
                error_code="INVALID_JSON_INPUT",
                context={'input_type': type(json_string).__name__},
                severity=ErrorSeverity.MEDIUM
            )
        
        # Basic security check - prevent excessive nesting
        if json_string.count('{') > 100 or json_string.count('[') > 100:
            if default is not None:
                return default
            raise DataValidationError(
                message="JSON string has excessive nesting depth",
                error_code="JSON_TOO_COMPLEX",
                context={'nesting_level': max(json_string.count('{'), json_string.count('['))},
                severity=ErrorSeverity.HIGH
            )
        
        # Length check to prevent memory exhaustion
        if len(json_string) > 1_000_000:  # 1MB limit
            if default is not None:
                return default
            raise DataValidationError(
                message="JSON string is too large",
                error_code="JSON_TOO_LARGE",
                context={'size': len(json_string)},
                severity=ErrorSeverity.HIGH
            )
        
        try:
            parsed_data = json.loads(json_string)
            
            # Ensure we return a dictionary
            if not isinstance(parsed_data, dict):
                if default is not None:
                    return default
                raise DataValidationError(
                    message="JSON must represent a dictionary object",
                    error_code="JSON_NOT_OBJECT",
                    context={'parsed_type': type(parsed_data).__name__},
                    severity=ErrorSeverity.MEDIUM
                )
            
            logger.debug("JSON parsing completed successfully",
                        result_keys=len(parsed_data))
            
            return parsed_data
            
        except json.JSONDecodeError as json_error:
            if default is not None:
                return default
            raise DataValidationError(
                message=f"Invalid JSON format: {json_error.msg}",
                error_code="JSON_DECODE_ERROR",
                context={
                    'error_position': json_error.pos,
                    'error_line': json_error.lineno,
                    'error_column': json_error.colno
                },
                cause=json_error,
                severity=ErrorSeverity.MEDIUM
            )
        
    except Exception as e:
        if isinstance(e, BaseBusinessException):
            raise
        
        logger.warning("JSON parsing failed",
                      string_length=len(json_string) if json_string else 0,
                      error=str(e))
        return default


# ============================================================================
# UTILITY HELPER FUNCTIONS
# ============================================================================

def generate_unique_id(prefix: str = "", length: int = 8) -> str:
    """
    Generate unique identifiers for business operations.
    
    Provides consistent unique ID generation for business entities,
    transaction references, and correlation identifiers with
    configurable prefixes and length control.
    
    Args:
        prefix: Optional prefix for the generated ID
        length: Length of the random component (default: 8)
        
    Returns:
        Unique identifier string with optional prefix
        
    Example:
        # Basic unique ID
        id1 = generate_unique_id()  # "a1b2c3d4"
        
        # With prefix
        id2 = generate_unique_id("TXN", 12)  # "TXN_a1b2c3d4e5f6"
    """
    try:
        # Generate random component
        random_component = uuid.uuid4().hex[:length]
        
        # Combine with prefix if provided
        if prefix:
            unique_id = f"{prefix}_{random_component}"
        else:
            unique_id = random_component
        
        logger.debug("Generated unique ID",
                    unique_id=unique_id,
                    prefix=prefix,
                    length=length)
        
        return unique_id
        
    except Exception as e:
        logger.error("Failed to generate unique ID",
                    prefix=prefix,
                    length=length,
                    error=str(e))
        # Fallback to timestamp-based ID
        import time
        timestamp = str(int(time.time() * 1000))[-length:]
        return f"{prefix}_{timestamp}" if prefix else timestamp


def calculate_hash(
    data: Union[str, bytes, Dict[str, Any]], 
    algorithm: str = "sha256"
) -> str:
    """
    Calculate cryptographic hashes for data integrity and verification.
    
    Provides secure hash calculation for business data integrity verification,
    file checksums, and data change detection with support for multiple
    hash algorithms and data types.
    
    Args:
        data: Data to hash (string, bytes, or dictionary)
        algorithm: Hash algorithm to use ("md5", "sha1", "sha256", "sha512")
        
    Returns:
        Hexadecimal hash string
        
    Raises:
        DataProcessingError: If hashing fails or algorithm is unsupported
        
    Example:
        # Hash string data
        hash1 = calculate_hash("Hello World")  # SHA256 hash
        
        # Hash dictionary data
        data_dict = {"user": "john", "action": "login"}
        hash2 = calculate_hash(data_dict, "md5")
    """
    try:
        logger.debug("Calculating hash",
                    data_type=type(data).__name__,
                    algorithm=algorithm)
        
        # Validate algorithm
        supported_algorithms = {"md5", "sha1", "sha256", "sha512"}
        if algorithm.lower() not in supported_algorithms:
            raise DataProcessingError(
                message=f"Unsupported hash algorithm: {algorithm}",
                error_code="UNSUPPORTED_HASH_ALGORITHM",
                processing_stage="hash_calculation",
                context={
                    'algorithm': algorithm,
                    'supported_algorithms': list(supported_algorithms)
                },
                severity=ErrorSeverity.MEDIUM
            )
        
        # Convert data to bytes
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        elif isinstance(data, bytes):
            data_bytes = data
        elif isinstance(data, dict):
            # Convert dictionary to JSON string then bytes
            json_string = json.dumps(data, sort_keys=True, separators=(',', ':'))
            data_bytes = json_string.encode('utf-8')
        else:
            # Convert other types to string then bytes
            data_bytes = str(data).encode('utf-8')
        
        # Calculate hash
        hash_obj = hashlib.new(algorithm.lower())
        hash_obj.update(data_bytes)
        hash_value = hash_obj.hexdigest()
        
        logger.debug("Hash calculation completed",
                    hash_length=len(hash_value),
                    algorithm=algorithm)
        
        return hash_value
        
    except Exception as e:
        if isinstance(e, BaseBusinessException):
            raise
        
        raise DataProcessingError(
            message="Hash calculation failed",
            error_code="HASH_CALCULATION_ERROR",
            processing_stage="hash_calculation",
            cause=e,
            severity=ErrorSeverity.MEDIUM
        )


# Import math for isfinite check
import math

# Module initialization logging
logger.info("Business utils module initialized successfully",
           module_version="1.0.0",
           python_version=f"{3}.{8}+",
           dependencies_loaded=True)