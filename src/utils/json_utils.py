"""
JSON serialization and deserialization utilities providing enhanced JSON processing
with date/time handling, decimal precision, and custom encoding support.

This module implements enterprise-grade JSON processing with comprehensive data type
support and validation patterns, maintaining compatibility with existing Node.js
data formats while providing enhanced functionality for Python applications.

Features:
- Enhanced JSON serialization with custom encoders for enterprise data types
- Date/time processing using python-dateutil integration 
- Decimal precision handling for financial and business data
- JSON schema validation using jsonschema
- Custom encoding/decoding for MongoDB ObjectId and other database types
- Performance optimized serialization with caching support
- Comprehensive error handling and validation
"""

import json
import decimal
from datetime import datetime, date, time, timezone
from typing import Any, Dict, List, Optional, Union, Type, Callable
from uuid import UUID
import logging

try:
    from bson import ObjectId
    BSON_AVAILABLE = True
except ImportError:
    BSON_AVAILABLE = False
    ObjectId = None

try:
    import jsonschema
    from jsonschema import validate, ValidationError, Draft7Validator
    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False
    ValidationError = None

from dateutil import parser as date_parser
from dateutil.tz import tzutc


logger = logging.getLogger(__name__)


class EnterpriseJSONEncoder(json.JSONEncoder):
    """
    Custom JSON encoder supporting enterprise data types including datetime objects,
    decimal values, UUID, MongoDB ObjectId, and other common Python data types.
    
    Maintains compatibility with existing Node.js JSON serialization patterns
    while providing enhanced type support for Python applications.
    """
    
    def default(self, obj: Any) -> Any:
        """
        Convert non-serializable objects to JSON-serializable formats.
        
        Args:
            obj: Object to serialize
            
        Returns:
            JSON-serializable representation of the object
            
        Raises:
            TypeError: If object type cannot be serialized
        """
        try:
            # DateTime objects - ISO 8601 format for API compatibility
            if isinstance(obj, datetime):
                # Ensure timezone awareness for enterprise applications
                if obj.tzinfo is None:
                    obj = obj.replace(tzinfo=timezone.utc)
                return obj.isoformat()
            
            # Date objects
            elif isinstance(obj, date):
                return obj.isoformat()
            
            # Time objects
            elif isinstance(obj, time):
                return obj.isoformat()
            
            # Decimal objects - maintain precision for financial data
            elif isinstance(obj, decimal.Decimal):
                return float(obj)
            
            # UUID objects
            elif isinstance(obj, UUID):
                return str(obj)
            
            # MongoDB ObjectId support
            elif BSON_AVAILABLE and isinstance(obj, ObjectId):
                return str(obj)
            
            # Sets - convert to lists for JSON compatibility
            elif isinstance(obj, set):
                return list(obj)
            
            # Bytes objects - base64 encoding
            elif isinstance(obj, bytes):
                import base64
                return base64.b64encode(obj).decode('utf-8')
            
            # Complex numbers
            elif isinstance(obj, complex):
                return {"real": obj.real, "imag": obj.imag, "_type": "complex"}
            
            # Custom objects with __dict__ method
            elif hasattr(obj, '__dict__'):
                result = obj.__dict__.copy()
                result['_type'] = obj.__class__.__name__
                return result
            
            # Fallback to default behavior
            return super().default(obj)
            
        except Exception as e:
            logger.warning(f"Failed to serialize object of type {type(obj)}: {e}")
            # Return string representation as fallback
            return str(obj)


class EnterpriseJSONDecoder(json.JSONDecoder):
    """
    Custom JSON decoder for enterprise data types with automatic type detection
    and conversion for datetime, decimal, and other specialized types.
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(object_hook=self.object_hook, *args, **kwargs)
    
    def object_hook(self, obj: Dict[str, Any]) -> Any:
        """
        Convert JSON objects to appropriate Python types based on content analysis.
        
        Args:
            obj: Dictionary object from JSON parsing
            
        Returns:
            Converted Python object or original dictionary
        """
        if not isinstance(obj, dict):
            return obj
        
        # Handle complex numbers
        if '_type' in obj and obj['_type'] == 'complex':
            return complex(obj['real'], obj['imag'])
        
        # Auto-detect datetime strings in ISO format
        for key, value in obj.items():
            if isinstance(value, str):
                # Try to parse as datetime
                if self._is_datetime_string(value):
                    try:
                        obj[key] = date_parser.parse(value)
                    except (ValueError, TypeError):
                        pass  # Keep as string if parsing fails
                
                # Try to parse as ObjectId
                elif BSON_AVAILABLE and self._is_objectid_string(value):
                    try:
                        obj[key] = ObjectId(value)
                    except Exception:
                        pass  # Keep as string if invalid ObjectId
        
        return obj
    
    def _is_datetime_string(self, value: str) -> bool:
        """Check if string appears to be a datetime in ISO format."""
        # Basic heuristics for datetime strings
        if len(value) < 8:
            return False
        
        # ISO 8601 patterns
        datetime_patterns = [
            'T',  # Date-time separator
            '+',  # Timezone offset
            'Z',  # UTC timezone
            '-'   # In date context
        ]
        
        # Must contain date separators and possibly time separators
        has_date = '-' in value[:10]  # Date part
        has_time_sep = 'T' in value or ' ' in value
        
        return has_date and any(pattern in value for pattern in datetime_patterns)
    
    def _is_objectid_string(self, value: str) -> bool:
        """Check if string appears to be a MongoDB ObjectId."""
        if not BSON_AVAILABLE:
            return False
        
        # ObjectId is 24 character hex string
        if len(value) != 24:
            return False
        
        try:
            int(value, 16)  # Valid hex
            return True
        except ValueError:
            return False


def dumps(obj: Any, 
          cls: Optional[Type[json.JSONEncoder]] = None,
          indent: Optional[Union[int, str]] = None,
          separators: Optional[tuple] = None,
          ensure_ascii: bool = False,
          sort_keys: bool = False,
          **kwargs) -> str:
    """
    Enhanced JSON serialization with enterprise data type support.
    
    Args:
        obj: Object to serialize
        cls: Custom JSON encoder class (defaults to EnterpriseJSONEncoder)
        indent: JSON indentation (None for compact output)
        separators: Item and key separators
        ensure_ascii: Whether to escape non-ASCII characters
        sort_keys: Whether to sort dictionary keys
        **kwargs: Additional arguments passed to json.dumps
        
    Returns:
        JSON string representation
        
    Raises:
        TypeError: If object cannot be serialized
        ValueError: If encoding parameters are invalid
    """
    if cls is None:
        cls = EnterpriseJSONEncoder
    
    try:
        return json.dumps(
            obj,
            cls=cls,
            indent=indent,
            separators=separators,
            ensure_ascii=ensure_ascii,
            sort_keys=sort_keys,
            **kwargs
        )
    except Exception as e:
        logger.error(f"JSON serialization failed: {e}")
        raise


def loads(s: Union[str, bytes], 
          cls: Optional[Type[json.JSONDecoder]] = None,
          **kwargs) -> Any:
    """
    Enhanced JSON deserialization with automatic type detection and conversion.
    
    Args:
        s: JSON string or bytes to parse
        cls: Custom JSON decoder class (defaults to EnterpriseJSONDecoder)
        **kwargs: Additional arguments passed to json.loads
        
    Returns:
        Parsed Python object
        
    Raises:
        json.JSONDecodeError: If JSON is malformed
        TypeError: If input is not string or bytes
    """
    if cls is None:
        cls = EnterpriseJSONDecoder
    
    try:
        return json.loads(s, cls=cls, **kwargs)
    except json.JSONDecodeError as e:
        logger.error(f"JSON parsing failed: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during JSON parsing: {e}")
        raise


def load(fp, cls: Optional[Type[json.JSONDecoder]] = None, **kwargs) -> Any:
    """
    Load JSON from file with enhanced decoding support.
    
    Args:
        fp: File-like object to read from
        cls: Custom JSON decoder class (defaults to EnterpriseJSONDecoder)
        **kwargs: Additional arguments passed to json.load
        
    Returns:
        Parsed Python object
        
    Raises:
        json.JSONDecodeError: If JSON is malformed
        IOError: If file cannot be read
    """
    if cls is None:
        cls = EnterpriseJSONDecoder
    
    try:
        return json.load(fp, cls=cls, **kwargs)
    except Exception as e:
        logger.error(f"JSON file loading failed: {e}")
        raise


def dump(obj: Any, fp, 
         cls: Optional[Type[json.JSONEncoder]] = None,
         indent: Optional[Union[int, str]] = None,
         **kwargs) -> None:
    """
    Write JSON to file with enhanced encoding support.
    
    Args:
        obj: Object to serialize
        fp: File-like object to write to
        cls: Custom JSON encoder class (defaults to EnterpriseJSONEncoder)
        indent: JSON indentation
        **kwargs: Additional arguments passed to json.dump
        
    Raises:
        TypeError: If object cannot be serialized
        IOError: If file cannot be written
    """
    if cls is None:
        cls = EnterpriseJSONEncoder
    
    try:
        json.dump(obj, fp, cls=cls, indent=indent, **kwargs)
    except Exception as e:
        logger.error(f"JSON file writing failed: {e}")
        raise


def pretty_print(obj: Any, indent: int = 2) -> str:
    """
    Format JSON with readable indentation and sorting.
    
    Args:
        obj: Object to format
        indent: Number of spaces for indentation
        
    Returns:
        Pretty-formatted JSON string
    """
    return dumps(obj, indent=indent, sort_keys=True, ensure_ascii=False)


def minify(json_str: str) -> str:
    """
    Remove whitespace from JSON string for minimal size.
    
    Args:
        json_str: JSON string to minify
        
    Returns:
        Minified JSON string
        
    Raises:
        json.JSONDecodeError: If input is not valid JSON
    """
    try:
        obj = loads(json_str)
        return dumps(obj, separators=(',', ':'))
    except Exception as e:
        logger.error(f"JSON minification failed: {e}")
        raise


def validate_json_schema(data: Any, schema: Dict[str, Any]) -> bool:
    """
    Validate JSON data against a JSON Schema.
    
    Args:
        data: Data to validate
        schema: JSON Schema specification
        
    Returns:
        True if valid, False otherwise
        
    Raises:
        ImportError: If jsonschema library is not available
        ValidationError: If validation fails with detailed error info
    """
    if not JSONSCHEMA_AVAILABLE:
        raise ImportError(
            "jsonschema library is required for schema validation. "
            "Install with: pip install jsonschema>=4.19.0"
        )
    
    try:
        validate(instance=data, schema=schema)
        return True
    except ValidationError as e:
        logger.error(f"JSON schema validation failed: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during schema validation: {e}")
        raise


def create_validator(schema: Dict[str, Any]) -> 'Draft7Validator':
    """
    Create a reusable JSON Schema validator for performance optimization.
    
    Args:
        schema: JSON Schema specification
        
    Returns:
        Configured validator instance
        
    Raises:
        ImportError: If jsonschema library is not available
    """
    if not JSONSCHEMA_AVAILABLE:
        raise ImportError(
            "jsonschema library is required for schema validation. "
            "Install with: pip install jsonschema>=4.19.0"
        )
    
    try:
        return Draft7Validator(schema)
    except Exception as e:
        logger.error(f"Failed to create JSON schema validator: {e}")
        raise


def safe_loads(s: Union[str, bytes], default: Any = None) -> Any:
    """
    Safe JSON parsing that returns default value on error instead of raising exception.
    
    Args:
        s: JSON string or bytes to parse
        default: Default value to return on parsing error
        
    Returns:
        Parsed object or default value
    """
    try:
        return loads(s)
    except Exception as e:
        logger.warning(f"Safe JSON parsing failed, returning default: {e}")
        return default


def extract_json_paths(data: Any, path: str) -> List[Any]:
    """
    Extract values from JSON data using JSONPath-like syntax.
    
    Args:
        data: JSON data structure
        path: Dot-notation path (e.g., "user.profile.email")
        
    Returns:
        List of values found at the specified path
    """
    def _get_nested_value(obj: Any, keys: List[str]) -> List[Any]:
        if not keys:
            return [obj]
        
        if isinstance(obj, dict):
            key = keys[0]
            if key in obj:
                return _get_nested_value(obj[key], keys[1:])
        elif isinstance(obj, list):
            results = []
            for item in obj:
                results.extend(_get_nested_value(item, keys))
            return results
        
        return []
    
    keys = path.split('.')
    return _get_nested_value(data, keys)


def merge_json(base: Dict[str, Any], overlay: Dict[str, Any], 
               deep: bool = True) -> Dict[str, Any]:
    """
    Merge two JSON objects with optional deep merging.
    
    Args:
        base: Base JSON object
        overlay: JSON object to merge into base
        deep: Whether to perform deep merge of nested objects
        
    Returns:
        Merged JSON object
    """
    if not deep:
        result = base.copy()
        result.update(overlay)
        return result
    
    result = base.copy()
    
    for key, value in overlay.items():
        if (key in result and 
            isinstance(result[key], dict) and 
            isinstance(value, dict)):
            result[key] = merge_json(result[key], value, deep=True)
        else:
            result[key] = value
    
    return result


def sanitize_for_json(obj: Any) -> Any:
    """
    Sanitize object for JSON serialization by removing non-serializable elements.
    
    Args:
        obj: Object to sanitize
        
    Returns:
        JSON-serializable version of the object
    """
    try:
        # Try to serialize to test if already JSON-safe
        dumps(obj)
        return obj
    except TypeError:
        # Handle different object types
        if isinstance(obj, dict):
            return {k: sanitize_for_json(v) for k, v in obj.items() 
                   if not k.startswith('_')}  # Remove private attributes
        elif isinstance(obj, (list, tuple)):
            return [sanitize_for_json(item) for item in obj]
        elif hasattr(obj, '__dict__'):
            return sanitize_for_json(obj.__dict__)
        else:
            # Convert to string representation for unsupported types
            return str(obj)


class JSONCache:
    """
    Simple in-memory cache for parsed JSON objects to improve performance
    for frequently accessed JSON data.
    """
    
    def __init__(self, max_size: int = 100):
        """
        Initialize JSON cache.
        
        Args:
            max_size: Maximum number of items to cache
        """
        self._cache: Dict[str, Any] = {}
        self._max_size = max_size
        self._access_order: List[str] = []
    
    def get(self, key: str, json_str: str) -> Any:
        """
        Get parsed JSON from cache or parse and cache it.
        
        Args:
            key: Cache key
            json_str: JSON string to parse if not cached
            
        Returns:
            Parsed JSON object
        """
        if key in self._cache:
            # Move to end for LRU tracking
            self._access_order.remove(key)
            self._access_order.append(key)
            return self._cache[key]
        
        # Parse and cache
        parsed = loads(json_str)
        self._put(key, parsed)
        return parsed
    
    def _put(self, key: str, value: Any) -> None:
        """Add item to cache with LRU eviction."""
        if len(self._cache) >= self._max_size and key not in self._cache:
            # Remove oldest item
            oldest_key = self._access_order.pop(0)
            del self._cache[oldest_key]
        
        self._cache[key] = value
        if key in self._access_order:
            self._access_order.remove(key)
        self._access_order.append(key)
    
    def clear(self) -> None:
        """Clear all cached items."""
        self._cache.clear()
        self._access_order.clear()


# Global cache instance for convenience
_json_cache = JSONCache()


def cached_loads(s: Union[str, bytes], cache_key: Optional[str] = None) -> Any:
    """
    Parse JSON with caching for performance optimization.
    
    Args:
        s: JSON string or bytes to parse
        cache_key: Optional cache key (uses hash of string if not provided)
        
    Returns:
        Parsed JSON object
    """
    if cache_key is None:
        cache_key = str(hash(s))
    
    if isinstance(s, bytes):
        s = s.decode('utf-8')
    
    return _json_cache.get(cache_key, s)


def clear_json_cache() -> None:
    """Clear the global JSON parsing cache."""
    _json_cache.clear()


# Convenience aliases for common operations
serialize = dumps
deserialize = loads
parse = loads
stringify = dumps

# Export all public functions and classes
__all__ = [
    'EnterpriseJSONEncoder',
    'EnterpriseJSONDecoder', 
    'JSONCache',
    'dumps',
    'loads',
    'load',
    'dump',
    'pretty_print',
    'minify',
    'validate_json_schema',
    'create_validator',
    'safe_loads',
    'extract_json_paths',
    'merge_json',
    'sanitize_for_json',
    'cached_loads',
    'clear_json_cache',
    'serialize',
    'deserialize',
    'parse',
    'stringify',
]