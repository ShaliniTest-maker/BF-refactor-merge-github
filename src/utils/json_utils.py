"""
JSON serialization and deserialization utilities providing enhanced JSON processing 
with date/time handling, decimal precision, and custom encoding support.

Implements enterprise-grade JSON processing with comprehensive data type support 
and validation patterns maintaining compatibility with existing Node.js API formats.

This module implements:
- Enhanced JSON serialization maintaining data format compatibility per Section 0.1.4 data exchange formats
- JSON processing with date/time handling using python-dateutil integration per Section 3.2.3
- Decimal precision handling for financial and business data per Section 5.2.4
- Custom JSON encoders for enterprise data types per Section 5.4.1
- JSON validation utilities supporting jsonschema 4.19+ per Section 3.2.3
"""

import json
import uuid
from datetime import datetime, date, time, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP
from enum import Enum
from typing import Any, Dict, List, Optional, Union, Type, Callable, Tuple
from pathlib import Path
import logging

try:
    import jsonschema
    from jsonschema import validate, ValidationError, SchemaError
    from jsonschema.protocols import Validator
except ImportError as e:
    raise ImportError(
        "jsonschema 4.19+ is required for JSON validation utilities. "
        "Install with: pip install jsonschema>=4.19"
    ) from e

# Import datetime utilities for date/time processing
from .datetime_utils import (
    DateTimeProcessor, 
    to_iso, 
    parse as parse_datetime,
    is_valid_date,
    DateTimeError
)


# Configure logging for JSON processing
logger = logging.getLogger(__name__)


class JSONError(Exception):
    """Base exception for JSON processing errors."""
    pass


class JSONSerializationError(JSONError):
    """Exception raised when JSON serialization fails."""
    pass


class JSONDeserializationError(JSONError):
    """Exception raised when JSON deserialization fails."""
    pass


class JSONValidationError(JSONError):
    """Exception raised when JSON validation fails."""
    pass


class JSONSchemaError(JSONError):
    """Exception raised when JSON schema is invalid."""
    pass


class EnterpriseJSONEncoder(json.JSONEncoder):
    """
    Enterprise-grade JSON encoder supporting comprehensive data types including:
    - DateTime objects with ISO 8601 formatting
    - Decimal numbers with configurable precision
    - UUID objects as strings
    - Enum objects as values
    - Custom business objects with __json__ method
    - Sets and tuples as arrays
    - Path objects as strings
    
    Maintains compatibility with existing Node.js API data formats.
    """
    
    def __init__(self, *args, decimal_places: int = 2, 
                 ensure_ascii: bool = False, sort_keys: bool = False,
                 datetime_format: str = 'iso', include_microseconds: bool = False,
                 timezone_aware: bool = True, **kwargs):
        """
        Initialize enterprise JSON encoder with configurable options.
        
        Args:
            decimal_places: Number of decimal places for Decimal serialization
            ensure_ascii: Whether to escape non-ASCII characters
            sort_keys: Whether to sort dictionary keys
            datetime_format: Format for datetime serialization ('iso', 'timestamp')
            include_microseconds: Whether to include microseconds in datetime
            timezone_aware: Whether to ensure timezone awareness for datetime objects
        """
        super().__init__(*args, ensure_ascii=ensure_ascii, sort_keys=sort_keys, **kwargs)
        self.decimal_places = decimal_places
        self.datetime_format = datetime_format
        self.include_microseconds = include_microseconds
        self.timezone_aware = timezone_aware
        self._datetime_processor = DateTimeProcessor()
    
    def default(self, obj: Any) -> Any:
        """
        Convert objects to JSON-serializable types with enterprise data type support.
        
        Args:
            obj: Object to serialize
            
        Returns:
            JSON-serializable representation
            
        Raises:
            JSONSerializationError: If object cannot be serialized
        """
        try:
            # DateTime objects
            if isinstance(obj, (datetime, date, time)):
                return self._serialize_datetime(obj)
            
            # Decimal numbers with precision handling
            elif isinstance(obj, Decimal):
                return self._serialize_decimal(obj)
            
            # UUID objects
            elif isinstance(obj, uuid.UUID):
                return str(obj)
            
            # Enum objects
            elif isinstance(obj, Enum):
                return obj.value
            
            # Sets and frozensets
            elif isinstance(obj, (set, frozenset)):
                return list(obj)
            
            # Tuples as arrays
            elif isinstance(obj, tuple):
                return list(obj)
            
            # Path objects
            elif isinstance(obj, Path):
                return str(obj)
            
            # Custom business objects with __json__ method
            elif hasattr(obj, '__json__'):
                return obj.__json__()
            
            # Custom business objects with to_dict method
            elif hasattr(obj, 'to_dict'):
                return obj.to_dict()
            
            # Custom business objects with dict representation
            elif hasattr(obj, '__dict__'):
                # Filter out private attributes and methods
                return {
                    key: value for key, value in obj.__dict__.items()
                    if not key.startswith('_') and not callable(value)
                }
            
            # Timedelta objects
            elif isinstance(obj, timedelta):
                return {
                    'days': obj.days,
                    'seconds': obj.seconds,
                    'microseconds': obj.microseconds,
                    'total_seconds': obj.total_seconds()
                }
            
            # Complex numbers
            elif isinstance(obj, complex):
                return {'real': obj.real, 'imag': obj.imag}
            
            # Bytes objects
            elif isinstance(obj, (bytes, bytearray)):
                try:
                    return obj.decode('utf-8')
                except UnicodeDecodeError:
                    import base64
                    return base64.b64encode(obj).decode('ascii')
            
            # Range objects
            elif isinstance(obj, range):
                return list(obj)
            
            # Fall back to parent implementation
            return super().default(obj)
            
        except Exception as e:
            raise JSONSerializationError(
                f"Unable to serialize object of type {type(obj).__name__}: {str(e)}"
            ) from e
    
    def _serialize_datetime(self, obj: Union[datetime, date, time]) -> Union[str, int, float]:
        """
        Serialize datetime objects with configurable formatting.
        
        Args:
            obj: DateTime object to serialize
            
        Returns:
            Serialized datetime representation
        """
        try:
            if isinstance(obj, datetime):
                if self.timezone_aware and obj.tzinfo is None:
                    # Default to UTC for timezone-naive datetimes
                    obj = obj.replace(tzinfo=timezone.utc)
                
                if self.datetime_format == 'iso':
                    return to_iso(obj, include_microseconds=self.include_microseconds)
                elif self.datetime_format == 'timestamp':
                    return obj.timestamp()
                else:
                    return to_iso(obj, include_microseconds=self.include_microseconds)
            
            elif isinstance(obj, date):
                return obj.isoformat()
            
            elif isinstance(obj, time):
                if self.include_microseconds:
                    return obj.isoformat()
                else:
                    return obj.replace(microsecond=0).isoformat()
            
        except Exception as e:
            raise JSONSerializationError(f"Failed to serialize datetime: {str(e)}") from e
    
    def _serialize_decimal(self, obj: Decimal) -> Union[float, str]:
        """
        Serialize Decimal objects with precision handling.
        
        Args:
            obj: Decimal object to serialize
            
        Returns:
            Serialized decimal representation
        """
        try:
            # Round to specified decimal places
            quantizer = Decimal('0.1') ** self.decimal_places
            rounded = obj.quantize(quantizer, rounding=ROUND_HALF_UP)
            
            # Convert to float for JSON compatibility
            # Use string representation for high precision requirements
            if self.decimal_places > 15:  # IEEE 754 double precision limit
                return str(rounded)
            else:
                return float(rounded)
                
        except Exception as e:
            raise JSONSerializationError(f"Failed to serialize decimal: {str(e)}") from e


class EnterpriseJSONDecoder(json.JSONDecoder):
    """
    Enterprise-grade JSON decoder with enhanced data type recognition and parsing.
    
    Supports automatic parsing of:
    - ISO 8601 datetime strings
    - Decimal number strings with precision preservation
    - UUID strings
    - Custom object reconstruction
    """
    
    def __init__(self, *args, parse_datetime_strings: bool = True,
                 parse_decimal_strings: bool = True, parse_uuid_strings: bool = True,
                 strict_iso_parsing: bool = False, **kwargs):
        """
        Initialize enterprise JSON decoder with parsing options.
        
        Args:
            parse_datetime_strings: Whether to parse ISO datetime strings
            parse_decimal_strings: Whether to parse decimal number strings
            parse_uuid_strings: Whether to parse UUID strings
            strict_iso_parsing: Whether to require strict ISO 8601 format
        """
        super().__init__(*args, **kwargs)
        self.parse_datetime_strings = parse_datetime_strings
        self.parse_decimal_strings = parse_decimal_strings
        self.parse_uuid_strings = parse_uuid_strings
        self.strict_iso_parsing = strict_iso_parsing
        self._datetime_processor = DateTimeProcessor()
    
    def decode(self, s: str, **kwargs) -> Any:
        """
        Decode JSON string with enhanced data type parsing.
        
        Args:
            s: JSON string to decode
            
        Returns:
            Decoded Python object
            
        Raises:
            JSONDeserializationError: If decoding fails
        """
        try:
            # First decode normally
            obj = super().decode(s, **kwargs)
            
            # Then apply enhanced parsing
            return self._enhance_parsed_object(obj)
            
        except json.JSONDecodeError as e:
            raise JSONDeserializationError(f"Invalid JSON: {str(e)}") from e
        except Exception as e:
            raise JSONDeserializationError(f"JSON decoding failed: {str(e)}") from e
    
    def _enhance_parsed_object(self, obj: Any) -> Any:
        """
        Recursively enhance parsed object with type recognition.
        
        Args:
            obj: Parsed object to enhance
            
        Returns:
            Enhanced object with recognized types
        """
        if isinstance(obj, dict):
            return {key: self._enhance_parsed_object(value) for key, value in obj.items()}
        
        elif isinstance(obj, list):
            return [self._enhance_parsed_object(item) for item in obj]
        
        elif isinstance(obj, str):
            return self._parse_string_value(obj)
        
        else:
            return obj
    
    def _parse_string_value(self, value: str) -> Any:
        """
        Parse string value to recognize and convert data types.
        
        Args:
            value: String value to parse
            
        Returns:
            Parsed value or original string
        """
        # Parse datetime strings
        if self.parse_datetime_strings and self._looks_like_datetime(value):
            try:
                return self._datetime_processor.parse(
                    value, 
                    strict=self.strict_iso_parsing
                )
            except DateTimeError:
                pass  # Return original string if parsing fails
        
        # Parse UUID strings
        if self.parse_uuid_strings and self._looks_like_uuid(value):
            try:
                return uuid.UUID(value)
            except ValueError:
                pass  # Return original string if parsing fails
        
        # Parse decimal strings
        if self.parse_decimal_strings and self._looks_like_decimal(value):
            try:
                return Decimal(value)
            except (ValueError, TypeError):
                pass  # Return original string if parsing fails
        
        return value
    
    def _looks_like_datetime(self, value: str) -> bool:
        """Check if string looks like a datetime."""
        if len(value) < 10:  # Minimum length for YYYY-MM-DD
            return False
        
        # Check for ISO 8601 patterns
        iso_patterns = [
            'T',  # ISO datetime separator
            'Z',  # UTC timezone indicator
            '+',  # Timezone offset
            '-'   # Timezone offset or date separator
        ]
        
        return any(pattern in value for pattern in iso_patterns) and \
               any(char.isdigit() for char in value)
    
    def _looks_like_uuid(self, value: str) -> bool:
        """Check if string looks like a UUID."""
        return (len(value) == 36 and 
                value.count('-') == 4 and
                all(c in '0123456789abcdefABCDEF-' for c in value))
    
    def _looks_like_decimal(self, value: str) -> bool:
        """Check if string looks like a decimal number."""
        try:
            float(value)
            return '.' in value or 'e' in value.lower() or 'E' in value
        except ValueError:
            return False


class JSONProcessor:
    """
    Enterprise JSON processing class providing comprehensive serialization,
    deserialization, and validation capabilities with enterprise data type support.
    
    Features:
    - Enhanced data type support for business applications
    - JSON schema validation with comprehensive error reporting
    - Configurable precision and formatting options
    - Performance-optimized processing with caching
    - Thread-safe operations for concurrent applications
    """
    
    def __init__(self, 
                 decimal_places: int = 2,
                 datetime_format: str = 'iso',
                 include_microseconds: bool = False,
                 timezone_aware: bool = True,
                 parse_enhanced_types: bool = True,
                 strict_iso_parsing: bool = False,
                 sort_keys: bool = False,
                 ensure_ascii: bool = False):
        """
        Initialize JSON processor with configuration options.
        
        Args:
            decimal_places: Number of decimal places for Decimal serialization
            datetime_format: Format for datetime serialization ('iso', 'timestamp')
            include_microseconds: Whether to include microseconds in datetime
            timezone_aware: Whether to ensure timezone awareness for datetime objects
            parse_enhanced_types: Whether to parse enhanced types during deserialization
            strict_iso_parsing: Whether to require strict ISO 8601 format
            sort_keys: Whether to sort dictionary keys in output
            ensure_ascii: Whether to escape non-ASCII characters
        """
        self.decimal_places = decimal_places
        self.datetime_format = datetime_format
        self.include_microseconds = include_microseconds
        self.timezone_aware = timezone_aware
        self.parse_enhanced_types = parse_enhanced_types
        self.strict_iso_parsing = strict_iso_parsing
        self.sort_keys = sort_keys
        self.ensure_ascii = ensure_ascii
        
        # Initialize encoder and decoder
        self._encoder = EnterpriseJSONEncoder(
            decimal_places=decimal_places,
            datetime_format=datetime_format,
            include_microseconds=include_microseconds,
            timezone_aware=timezone_aware,
            sort_keys=sort_keys,
            ensure_ascii=ensure_ascii
        )
        
        self._decoder = EnterpriseJSONDecoder(
            parse_datetime_strings=parse_enhanced_types,
            parse_decimal_strings=parse_enhanced_types,
            parse_uuid_strings=parse_enhanced_types,
            strict_iso_parsing=strict_iso_parsing
        )
        
        # Schema cache for validation performance
        self._schema_cache: Dict[str, Validator] = {}
    
    def dumps(self, obj: Any, **kwargs) -> str:
        """
        Serialize object to JSON string with enterprise data type support.
        
        Args:
            obj: Object to serialize
            **kwargs: Additional arguments for json.dumps
            
        Returns:
            JSON string representation
            
        Raises:
            JSONSerializationError: If serialization fails
        """
        try:
            return json.dumps(obj, cls=EnterpriseJSONEncoder, 
                            decimal_places=self.decimal_places,
                            datetime_format=self.datetime_format,
                            include_microseconds=self.include_microseconds,
                            timezone_aware=self.timezone_aware,
                            sort_keys=self.sort_keys,
                            ensure_ascii=self.ensure_ascii,
                            **kwargs)
        except Exception as e:
            logger.error(f"JSON serialization failed: {str(e)}")
            raise JSONSerializationError(f"Serialization failed: {str(e)}") from e
    
    def loads(self, s: str, **kwargs) -> Any:
        """
        Deserialize JSON string with enhanced data type parsing.
        
        Args:
            s: JSON string to deserialize
            **kwargs: Additional arguments for json.loads
            
        Returns:
            Deserialized Python object
            
        Raises:
            JSONDeserializationError: If deserialization fails
        """
        try:
            if self.parse_enhanced_types:
                return self._decoder.decode(s, **kwargs)
            else:
                return json.loads(s, **kwargs)
        except Exception as e:
            logger.error(f"JSON deserialization failed: {str(e)}")
            raise JSONDeserializationError(f"Deserialization failed: {str(e)}") from e
    
    def dump(self, obj: Any, fp, **kwargs) -> None:
        """
        Serialize object to JSON file with enterprise data type support.
        
        Args:
            obj: Object to serialize
            fp: File-like object to write to
            **kwargs: Additional arguments for json.dump
            
        Raises:
            JSONSerializationError: If serialization fails
        """
        try:
            json.dump(obj, fp, cls=EnterpriseJSONEncoder,
                     decimal_places=self.decimal_places,
                     datetime_format=self.datetime_format,
                     include_microseconds=self.include_microseconds,
                     timezone_aware=self.timezone_aware,
                     sort_keys=self.sort_keys,
                     ensure_ascii=self.ensure_ascii,
                     **kwargs)
        except Exception as e:
            logger.error(f"JSON file serialization failed: {str(e)}")
            raise JSONSerializationError(f"File serialization failed: {str(e)}") from e
    
    def load(self, fp, **kwargs) -> Any:
        """
        Deserialize JSON file with enhanced data type parsing.
        
        Args:
            fp: File-like object to read from
            **kwargs: Additional arguments for json.load
            
        Returns:
            Deserialized Python object
            
        Raises:
            JSONDeserializationError: If deserialization fails
        """
        try:
            if self.parse_enhanced_types:
                content = fp.read()
                if isinstance(content, bytes):
                    content = content.decode('utf-8')
                return self._decoder.decode(content, **kwargs)
            else:
                return json.load(fp, **kwargs)
        except Exception as e:
            logger.error(f"JSON file deserialization failed: {str(e)}")
            raise JSONDeserializationError(f"File deserialization failed: {str(e)}") from e
    
    def validate(self, instance: Any, schema: Dict[str, Any], 
                 schema_id: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """
        Validate JSON data against JSON schema with comprehensive error reporting.
        
        Args:
            instance: Data to validate
            schema: JSON schema for validation
            schema_id: Optional schema identifier for caching
            
        Returns:
            Tuple of (is_valid, error_message)
            
        Raises:
            JSONSchemaError: If schema is invalid
        """
        try:
            # Get validator from cache or create new one
            validator = self._get_validator(schema, schema_id)
            
            # Validate the instance
            errors = list(validator.iter_errors(instance))
            
            if not errors:
                return True, None
            
            # Format comprehensive error message
            error_messages = []
            for error in errors:
                path = " -> ".join(str(p) for p in error.absolute_path)
                if path:
                    error_messages.append(f"Path '{path}': {error.message}")
                else:
                    error_messages.append(error.message)
            
            return False, "; ".join(error_messages)
            
        except SchemaError as e:
            raise JSONSchemaError(f"Invalid JSON schema: {str(e)}") from e
        except Exception as e:
            logger.error(f"JSON validation failed: {str(e)}")
            raise JSONValidationError(f"Validation failed: {str(e)}") from e
    
    def validate_strict(self, instance: Any, schema: Dict[str, Any],
                       schema_id: Optional[str] = None) -> None:
        """
        Strictly validate JSON data against schema, raising exception on failure.
        
        Args:
            instance: Data to validate
            schema: JSON schema for validation
            schema_id: Optional schema identifier for caching
            
        Raises:
            JSONValidationError: If validation fails
            JSONSchemaError: If schema is invalid
        """
        is_valid, error_message = self.validate(instance, schema, schema_id)
        if not is_valid:
            raise JSONValidationError(f"Validation failed: {error_message}")
    
    def _get_validator(self, schema: Dict[str, Any], 
                      schema_id: Optional[str] = None) -> Validator:
        """
        Get validator from cache or create new one.
        
        Args:
            schema: JSON schema
            schema_id: Optional schema identifier for caching
            
        Returns:
            JSON schema validator
        """
        if schema_id and schema_id in self._schema_cache:
            return self._schema_cache[schema_id]
        
        # Create new validator
        try:
            validator = jsonschema.Draft7Validator(schema)
            # Check schema validity
            validator.check_schema(schema)
            
            # Cache if schema_id provided
            if schema_id:
                self._schema_cache[schema_id] = validator
            
            return validator
            
        except Exception as e:
            raise JSONSchemaError(f"Failed to create validator: {str(e)}") from e
    
    def pretty_print(self, obj: Any, indent: int = 2) -> str:
        """
        Pretty print object as formatted JSON string.
        
        Args:
            obj: Object to format
            indent: Number of spaces for indentation
            
        Returns:
            Pretty-formatted JSON string
        """
        return self.dumps(obj, indent=indent, separators=(',', ': '))
    
    def minify(self, json_str: str) -> str:
        """
        Minify JSON string by removing whitespace.
        
        Args:
            json_str: JSON string to minify
            
        Returns:
            Minified JSON string
        """
        obj = self.loads(json_str)
        return self.dumps(obj, separators=(',', ':'))
    
    def merge(self, *objects: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deep merge multiple JSON objects.
        
        Args:
            *objects: JSON objects to merge
            
        Returns:
            Merged JSON object
        """
        result = {}
        
        for obj in objects:
            if not isinstance(obj, dict):
                continue
                
            for key, value in obj.items():
                if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                    result[key] = self.merge(result[key], value)
                else:
                    result[key] = value
        
        return result
    
    def extract_paths(self, obj: Any, path_prefix: str = '') -> Dict[str, Any]:
        """
        Extract all paths and values from nested JSON object.
        
        Args:
            obj: Object to extract paths from
            path_prefix: Prefix for path names
            
        Returns:
            Dictionary mapping paths to values
        """
        paths = {}
        
        if isinstance(obj, dict):
            for key, value in obj.items():
                new_path = f"{path_prefix}.{key}" if path_prefix else key
                if isinstance(value, (dict, list)):
                    paths.update(self.extract_paths(value, new_path))
                else:
                    paths[new_path] = value
        
        elif isinstance(obj, list):
            for i, value in enumerate(obj):
                new_path = f"{path_prefix}[{i}]"
                if isinstance(value, (dict, list)):
                    paths.update(self.extract_paths(value, new_path))
                else:
                    paths[new_path] = value
        
        else:
            paths[path_prefix] = obj
        
        return paths
    
    def filter_sensitive_data(self, obj: Any, 
                            sensitive_fields: List[str] = None,
                            mask_value: str = "***") -> Any:
        """
        Filter sensitive data from JSON object for logging/debugging.
        
        Args:
            obj: Object to filter
            sensitive_fields: List of field names to mask
            mask_value: Value to replace sensitive data with
            
        Returns:
            Filtered object with sensitive data masked
        """
        if sensitive_fields is None:
            sensitive_fields = [
                'password', 'secret', 'token', 'key', 'auth',
                'credential', 'private', 'confidential', 'ssn',
                'credit_card', 'cvv', 'pin', 'api_key'
            ]
        
        def _filter_recursive(item: Any) -> Any:
            if isinstance(item, dict):
                filtered = {}
                for key, value in item.items():
                    if any(field.lower() in key.lower() for field in sensitive_fields):
                        filtered[key] = mask_value
                    else:
                        filtered[key] = _filter_recursive(value)
                return filtered
            
            elif isinstance(item, list):
                return [_filter_recursive(i) for i in item]
            
            else:
                return item
        
        return _filter_recursive(obj)


# Global JSON processor instance for convenient access
_default_processor = JSONProcessor()

# Convenience functions using the default processor
def dumps(obj: Any, **kwargs) -> str:
    """Serialize object to JSON string using default processor."""
    return _default_processor.dumps(obj, **kwargs)


def loads(s: str, **kwargs) -> Any:
    """Deserialize JSON string using default processor."""
    return _default_processor.loads(s, **kwargs)


def dump(obj: Any, fp, **kwargs) -> None:
    """Serialize object to JSON file using default processor."""
    return _default_processor.dump(obj, fp, **kwargs)


def load(fp, **kwargs) -> Any:
    """Deserialize JSON file using default processor."""
    return _default_processor.load(fp, **kwargs)


def pretty_print(obj: Any, indent: int = 2) -> str:
    """Pretty print object as formatted JSON string using default processor."""
    return _default_processor.pretty_print(obj, indent)


def minify(json_str: str) -> str:
    """Minify JSON string using default processor."""
    return _default_processor.minify(json_str)


def validate_json(instance: Any, schema: Dict[str, Any],
                 schema_id: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """Validate JSON data against schema using default processor."""
    return _default_processor.validate(instance, schema, schema_id)


def validate_json_strict(instance: Any, schema: Dict[str, Any],
                        schema_id: Optional[str] = None) -> None:
    """Strictly validate JSON data against schema using default processor."""
    return _default_processor.validate_strict(instance, schema, schema_id)


def merge_json(*objects: Dict[str, Any]) -> Dict[str, Any]:
    """Deep merge multiple JSON objects using default processor."""
    return _default_processor.merge(*objects)


def extract_json_paths(obj: Any, path_prefix: str = '') -> Dict[str, Any]:
    """Extract all paths and values from nested JSON object using default processor."""
    return _default_processor.extract_paths(obj, path_prefix)


def filter_sensitive_json(obj: Any, 
                         sensitive_fields: List[str] = None,
                         mask_value: str = "***") -> Any:
    """Filter sensitive data from JSON object using default processor."""
    return _default_processor.filter_sensitive_data(obj, sensitive_fields, mask_value)


def is_valid_json(s: str) -> bool:
    """
    Check if string is valid JSON.
    
    Args:
        s: String to validate
        
    Returns:
        True if valid JSON, False otherwise
    """
    try:
        loads(s)
        return True
    except (JSONDeserializationError, json.JSONDecodeError):
        return False


def safe_loads(s: str, default: Any = None) -> Any:
    """
    Safely load JSON string, returning default value on failure.
    
    Args:
        s: JSON string to load
        default: Default value to return on failure
        
    Returns:
        Parsed object or default value
    """
    try:
        return loads(s)
    except (JSONDeserializationError, json.JSONDecodeError):
        return default


def safe_dumps(obj: Any, default: str = "{}") -> str:
    """
    Safely serialize object to JSON, returning default on failure.
    
    Args:
        obj: Object to serialize
        default: Default JSON string to return on failure
        
    Returns:
        JSON string or default value
    """
    try:
        return dumps(obj)
    except JSONSerializationError:
        return default


def to_json_compatible(obj: Any) -> Any:
    """
    Convert object to JSON-compatible types without serializing to string.
    
    Args:
        obj: Object to convert
        
    Returns:
        JSON-compatible representation
    """
    encoder = EnterpriseJSONEncoder()
    
    def _convert_recursive(item: Any) -> Any:
        if isinstance(item, (str, int, float, bool, type(None))):
            return item
        elif isinstance(item, dict):
            return {key: _convert_recursive(value) for key, value in item.items()}
        elif isinstance(item, list):
            return [_convert_recursive(i) for i in item]
        else:
            try:
                return encoder.default(item)
            except JSONSerializationError:
                return str(item)
    
    return _convert_recursive(obj)


def create_api_response(data: Any = None, success: bool = True, 
                       message: str = None, errors: List[str] = None,
                       meta: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Create standardized API response structure maintaining Node.js compatibility.
    
    Args:
        data: Response data
        success: Whether operation was successful
        message: Optional response message
        errors: List of error messages
        meta: Additional metadata
        
    Returns:
        Standardized API response dictionary
    """
    response = {
        'success': success,
        'timestamp': _default_processor._encoder._datetime_processor.to_iso(
            _default_processor._encoder._datetime_processor.utc_now()
        )
    }
    
    if data is not None:
        response['data'] = data
    
    if message:
        response['message'] = message
    
    if errors:
        response['errors'] = errors
    
    if meta:
        response['meta'] = meta
    
    return response


def create_error_response(message: str, errors: List[str] = None,
                         error_code: str = None, status_code: int = 400) -> Dict[str, Any]:
    """
    Create standardized error response structure.
    
    Args:
        message: Error message
        errors: List of detailed error messages
        error_code: Application-specific error code
        status_code: HTTP status code
        
    Returns:
        Standardized error response dictionary
    """
    response = create_api_response(
        success=False,
        message=message,
        errors=errors or []
    )
    
    if error_code:
        response['error_code'] = error_code
    
    response['status_code'] = status_code
    
    return response


def paginate_response(data: List[Any], page: int = 1, page_size: int = 20,
                     total_count: int = None) -> Dict[str, Any]:
    """
    Create paginated response structure.
    
    Args:
        data: List of data items
        page: Current page number (1-based)
        page_size: Number of items per page
        total_count: Total number of items (calculated if not provided)
        
    Returns:
        Paginated response dictionary
    """
    if total_count is None:
        total_count = len(data)
    
    start_index = (page - 1) * page_size
    end_index = start_index + page_size
    page_data = data[start_index:end_index]
    
    total_pages = (total_count + page_size - 1) // page_size
    has_next = page < total_pages
    has_prev = page > 1
    
    return create_api_response(
        data=page_data,
        meta={
            'pagination': {
                'page': page,
                'page_size': page_size,
                'total_count': total_count,
                'total_pages': total_pages,
                'has_next': has_next,
                'has_prev': has_prev,
                'next_page': page + 1 if has_next else None,
                'prev_page': page - 1 if has_prev else None
            }
        }
    )


# Common JSON schemas for validation
COMMON_SCHEMAS = {
    'pagination': {
        'type': 'object',
        'properties': {
            'page': {'type': 'integer', 'minimum': 1},
            'page_size': {'type': 'integer', 'minimum': 1, 'maximum': 1000},
            'sort_by': {'type': 'string'},
            'sort_order': {'type': 'string', 'enum': ['asc', 'desc']}
        },
        'required': ['page', 'page_size']
    },
    
    'api_response': {
        'type': 'object',
        'properties': {
            'success': {'type': 'boolean'},
            'timestamp': {'type': 'string', 'format': 'date-time'},
            'data': {},
            'message': {'type': 'string'},
            'errors': {'type': 'array', 'items': {'type': 'string'}},
            'meta': {'type': 'object'}
        },
        'required': ['success', 'timestamp']
    },
    
    'error_response': {
        'type': 'object',
        'properties': {
            'success': {'type': 'boolean', 'enum': [False]},
            'timestamp': {'type': 'string', 'format': 'date-time'},
            'message': {'type': 'string'},
            'errors': {'type': 'array', 'items': {'type': 'string'}},
            'error_code': {'type': 'string'},
            'status_code': {'type': 'integer', 'minimum': 400, 'maximum': 599}
        },
        'required': ['success', 'timestamp', 'message']
    }
}


# Export key classes and functions
__all__ = [
    # Main classes
    'JSONProcessor',
    'EnterpriseJSONEncoder',
    'EnterpriseJSONDecoder',
    
    # Exceptions
    'JSONError',
    'JSONSerializationError',
    'JSONDeserializationError',
    'JSONValidationError',
    'JSONSchemaError',
    
    # Core functions
    'dumps',
    'loads',
    'dump',
    'load',
    
    # Utility functions
    'pretty_print',
    'minify',
    'validate_json',
    'validate_json_strict',
    'merge_json',
    'extract_json_paths',
    'filter_sensitive_json',
    'is_valid_json',
    'safe_loads',
    'safe_dumps',
    'to_json_compatible',
    
    # API response functions
    'create_api_response',
    'create_error_response',
    'paginate_response',
    
    # Common schemas
    'COMMON_SCHEMAS',
]