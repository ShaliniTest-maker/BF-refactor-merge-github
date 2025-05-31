"""
HTML Sanitization and Input Sanitization Utilities

This module provides comprehensive HTML sanitization and input sanitization utilities using 
bleach 6.0+ for XSS prevention and secure input processing. Implements enterprise-grade 
input protection patterns with configurable security policies and comprehensive audit logging.

Features:
- HTML sanitization with configurable security policies
- Input sanitization equivalent to Node.js security patterns
- XSS prevention with context-aware sanitization
- Enterprise security compliance with audit logging
- Date/time sanitization with ISO 8601 validation
- Email sanitization and validation
- URL and filename sanitization
- JSON sanitization with nested object support
- Performance optimization with intelligent caching
- Integration with Flask-Talisman security framework

Security Standards:
- OWASP Top 10 compliance for XSS prevention
- SANS Top 25 software weakness coverage
- Enterprise security pattern alignment
- Comprehensive audit trail generation
- Input validation with detailed error reporting

Author: Flask Migration System
Version: 1.0.0
License: Enterprise
"""

import re
import json
import logging
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union, Set, Tuple
from urllib.parse import urlparse, quote, unquote
import unicodedata
from functools import lru_cache

import bleach
from email_validator import validate_email, EmailNotValidError
from dateutil import parser as dateutil_parser
from dateutil.relativedelta import relativedelta

# Import Flask-related modules for enterprise integration
try:
    from flask import current_app, g
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

# Import structlog for enterprise audit logging
try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False
    import logging as structlog


class SanitizationError(Exception):
    """Base exception for sanitization operations."""
    pass


class InvalidInputError(SanitizationError):
    """Exception raised when input fails validation."""
    pass


class SecurityPolicyViolationError(SanitizationError):
    """Exception raised when input violates security policy."""
    pass


class ConfigurationError(SanitizationError):
    """Exception raised when sanitizer configuration is invalid."""
    pass


class SecurityPolicyManager:
    """
    Manages configurable security policies for different sanitization contexts.
    
    Provides enterprise-grade security policy configuration with context-aware
    sanitization rules, threat detection capabilities, and comprehensive audit
    logging for security compliance and regulatory requirements.
    """
    
    def __init__(self):
        self.logger = self._get_logger()
        self._policies = self._initialize_default_policies()
        self._threat_patterns = self._initialize_threat_patterns()
        
    def _get_logger(self):
        """Get appropriate logger based on available libraries."""
        if STRUCTLOG_AVAILABLE:
            return structlog.get_logger("security.sanitization")
        else:
            logger = logging.getLogger("security.sanitization")
            if not logger.handlers:
                handler = logging.StreamHandler()
                formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
                handler.setFormatter(formatter)
                logger.addHandler(handler)
                logger.setLevel(logging.INFO)
            return logger
    
    def _initialize_default_policies(self) -> Dict[str, Dict[str, Any]]:
        """Initialize comprehensive default security policies."""
        return {
            'strict': {
                'html_tags': [],  # No HTML tags allowed
                'html_attributes': {},
                'protocols': ['https'],
                'max_length': 1000,
                'allow_unicode': False,
                'strip_comments': True,
                'strip_cdata': True,
                'description': 'Maximum security policy with minimal allowlist'
            },
            'basic': {
                'html_tags': ['p', 'br', 'strong', 'em', 'u'],
                'html_attributes': {
                    'p': ['class'],
                    'strong': ['class'],
                    'em': ['class'],
                    'u': ['class']
                },
                'protocols': ['https', 'http'],
                'max_length': 5000,
                'allow_unicode': True,
                'strip_comments': True,
                'strip_cdata': True,
                'description': 'Basic formatting with limited HTML tags'
            },
            'content': {
                'html_tags': [
                    'p', 'br', 'strong', 'em', 'u', 'ul', 'ol', 'li', 
                    'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote',
                    'a', 'img'
                ],
                'html_attributes': {
                    'a': ['href', 'title', 'rel'],
                    'img': ['src', 'alt', 'title', 'width', 'height'],
                    'p': ['class'],
                    'h1': ['class'], 'h2': ['class'], 'h3': ['class'],
                    'h4': ['class'], 'h5': ['class'], 'h6': ['class'],
                    'blockquote': ['class'],
                    'ul': ['class'], 'ol': ['class'], 'li': ['class']
                },
                'protocols': ['https', 'http', 'mailto'],
                'max_length': 50000,
                'allow_unicode': True,
                'strip_comments': True,
                'strip_cdata': True,
                'description': 'Rich content with safe HTML formatting and links'
            },
            'form': {
                'html_tags': [],
                'html_attributes': {},
                'protocols': ['https'],
                'max_length': 2000,
                'allow_unicode': True,
                'strip_comments': True,
                'strip_cdata': True,
                'normalize_whitespace': True,
                'description': 'Form input sanitization with no HTML allowed'
            },
            'json': {
                'max_depth': 10,
                'max_keys': 100,
                'max_string_length': 10000,
                'allow_null': True,
                'allowed_types': ['str', 'int', 'float', 'bool', 'list', 'dict'],
                'description': 'JSON object sanitization with structural validation'
            },
            'url': {
                'allowed_schemes': ['https', 'http', 'ftp'],
                'max_length': 2000,
                'validate_domain': True,
                'block_private_networks': True,
                'description': 'URL sanitization with domain validation'
            }
        }
    
    def _initialize_threat_patterns(self) -> Dict[str, List[str]]:
        """Initialize threat detection patterns for security monitoring."""
        return {
            'xss_patterns': [
                r'<script[\s\S]*?>[\s\S]*?</script>',
                r'javascript:',
                r'vbscript:',
                r'data:text/html',
                r'on\w+\s*=',  # Event handlers
                r'expression\s*\(',  # CSS expressions
                r'<iframe[\s\S]*?>',
                r'<object[\s\S]*?>',
                r'<embed[\s\S]*?>',
                r'<link[\s\S]*?>',
                r'<meta[\s\S]*?>'
            ],
            'sql_injection_patterns': [
                r"('|(\\'))+.*(-|#|--|;)",
                r"w*((%27)|')+.*((%6F)|(%6F)|(%4F)|o)+.*((%72)|(%72)|(%52)|r)",
                r"((\%3D)|(=))[^\n]*((\%27)|(\')|(--)|(\%3B)|(:))",
                r"\w*(((\%27)|(\'))+(\w|\s)*)((\%6F)|(\%6F)|(\%4F)|o)+",
                r"((\%3C)|<)((\%2F)|/)*((\%73)|s)+((\%63)|c)+",
                r"((\%3C)|<)((\%69)|i)+((\%6D)|m)+((\%67)|g)",
                r"((\%3C)|<)[^\n]+((\%3E)|>)"
            ],
            'path_traversal_patterns': [
                r'\.\.[/\\]',
                r'\.\.\\',
                r'\.\.\/',
                r'%2e%2e%2f',
                r'%2e%2e%5c',
                r'\.\.%2f',
                r'\.\.%5c'
            ],
            'command_injection_patterns': [
                r'[;&|`\$\(\)]',
                r'nc\s+-',
                r'telnet\s+',
                r'wget\s+',
                r'curl\s+',
                r'ping\s+-',
                r'nslookup\s+'
            ]
        }
    
    def get_policy(self, policy_name: str) -> Dict[str, Any]:
        """
        Retrieve security policy configuration by name.
        
        Args:
            policy_name: Name of the security policy to retrieve
            
        Returns:
            Dictionary containing policy configuration
            
        Raises:
            ConfigurationError: When policy does not exist
        """
        if policy_name not in self._policies:
            available_policies = list(self._policies.keys())
            raise ConfigurationError(
                f"Unknown security policy '{policy_name}'. "
                f"Available policies: {available_policies}"
            )
        
        return self._policies[policy_name].copy()
    
    def register_policy(
        self, 
        name: str, 
        policy: Dict[str, Any], 
        override: bool = False
    ) -> None:
        """
        Register a custom security policy.
        
        Args:
            name: Unique name for the security policy
            policy: Policy configuration dictionary
            override: Whether to override existing policy
            
        Raises:
            ConfigurationError: When policy name exists and override is False
        """
        if name in self._policies and not override:
            raise ConfigurationError(
                f"Security policy '{name}' already exists. "
                "Set override=True to replace existing policy."
            )
        
        # Validate policy structure
        self._validate_policy_structure(policy)
        
        self._policies[name] = policy.copy()
        
        self.logger.info(
            "Security policy registered",
            policy_name=name,
            override=override,
            policy_type=policy.get('description', 'Custom policy')
        )
    
    def _validate_policy_structure(self, policy: Dict[str, Any]) -> None:
        """Validate security policy structure for consistency."""
        required_fields = ['description']
        
        for field in required_fields:
            if field not in policy:
                raise ConfigurationError(
                    f"Security policy missing required field: {field}"
                )
    
    def detect_threats(self, input_data: str) -> List[Dict[str, Any]]:
        """
        Detect security threats in input data using pattern matching.
        
        Args:
            input_data: Input string to analyze for threats
            
        Returns:
            List of detected threats with details
        """
        detected_threats = []
        
        for threat_type, patterns in self._threat_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, input_data, re.IGNORECASE)
                for match in matches:
                    threat = {
                        'type': threat_type,
                        'pattern': pattern,
                        'match': match.group(),
                        'position': match.span(),
                        'severity': self._get_threat_severity(threat_type),
                        'timestamp': datetime.utcnow().isoformat()
                    }
                    detected_threats.append(threat)
        
        if detected_threats:
            self.logger.warning(
                "Security threats detected in input",
                threat_count=len(detected_threats),
                threat_types=[t['type'] for t in detected_threats]
            )
        
        return detected_threats
    
    def _get_threat_severity(self, threat_type: str) -> str:
        """Get severity level for threat type."""
        severity_mapping = {
            'xss_patterns': 'high',
            'sql_injection_patterns': 'critical',
            'path_traversal_patterns': 'high',
            'command_injection_patterns': 'critical'
        }
        return severity_mapping.get(threat_type, 'medium')


class HTMLSanitizer:
    """
    Enterprise-grade HTML sanitization using bleach 6.0+ with configurable policies.
    
    Provides comprehensive XSS prevention, context-aware sanitization, and enterprise
    security compliance with detailed audit logging and threat detection capabilities.
    """
    
    def __init__(self, policy_manager: Optional[SecurityPolicyManager] = None):
        self.policy_manager = policy_manager or SecurityPolicyManager()
        self.logger = self.policy_manager.logger
        self._cache = {}  # Simple cache for sanitized content
        
    @lru_cache(maxsize=1000)
    def _get_cached_policy_config(self, policy_name: str) -> str:
        """Get cached policy configuration for performance optimization."""
        policy = self.policy_manager.get_policy(policy_name)
        # Convert to string for caching
        return json.dumps(policy, sort_keys=True)
    
    def sanitize_html(
        self, 
        html_content: str, 
        policy: str = 'basic',
        context: Optional[str] = None,
        strict_validation: bool = True
    ) -> str:
        """
        Sanitize HTML content using specified security policy.
        
        Args:
            html_content: HTML content to sanitize
            policy: Security policy name to apply
            context: Additional context for logging and validation
            strict_validation: Whether to apply strict validation rules
            
        Returns:
            Sanitized HTML content safe for rendering
            
        Raises:
            InvalidInputError: When input fails validation
            SecurityPolicyViolationError: When input violates security policy
        """
        if not isinstance(html_content, str):
            raise InvalidInputError(
                f"HTML content must be string, got {type(html_content)}"
            )
        
        # Generate cache key
        cache_key = self._generate_cache_key(html_content, policy, strict_validation)
        
        # Check cache first
        if cache_key in self._cache:
            self.logger.debug("Returning cached sanitized content", cache_key=cache_key)
            return self._cache[cache_key]
        
        # Get policy configuration
        try:
            policy_config = self.policy_manager.get_policy(policy)
        except ConfigurationError as e:
            raise SecurityPolicyViolationError(f"Invalid security policy: {str(e)}")
        
        # Detect threats before sanitization
        threats = self.policy_manager.detect_threats(html_content)
        if threats and strict_validation:
            threat_types = [t['type'] for t in threats]
            raise SecurityPolicyViolationError(
                f"Security threats detected: {threat_types}"
            )
        
        # Validate content length
        max_length = policy_config.get('max_length', 50000)
        if len(html_content) > max_length:
            raise InvalidInputError(
                f"Content length {len(html_content)} exceeds policy limit {max_length}"
            )
        
        try:
            # Apply bleach sanitization
            sanitized_content = bleach.clean(
                html_content,
                tags=policy_config.get('html_tags', []),
                attributes=policy_config.get('html_attributes', {}),
                protocols=policy_config.get('protocols', ['https']),
                strip=True,
                strip_comments=policy_config.get('strip_comments', True)
            )
            
            # Apply additional policy-specific transformations
            if policy_config.get('normalize_whitespace', False):
                sanitized_content = self._normalize_whitespace(sanitized_content)
            
            if not policy_config.get('allow_unicode', True):
                sanitized_content = self._remove_unicode_characters(sanitized_content)
            
            # Cache the result
            self._cache[cache_key] = sanitized_content
            
            # Log sanitization event
            self.logger.info(
                "HTML content sanitized successfully",
                policy=policy,
                context=context,
                input_length=len(html_content),
                output_length=len(sanitized_content),
                threats_detected=len(threats) if threats else 0
            )
            
            return sanitized_content
            
        except Exception as e:
            self.logger.error(
                "HTML sanitization failed",
                error=str(e),
                policy=policy,
                context=context,
                input_length=len(html_content)
            )
            raise SanitizationError(f"HTML sanitization failed: {str(e)}")
    
    def sanitize_text_content(
        self, 
        text_content: str, 
        policy: str = 'form',
        max_length: Optional[int] = None
    ) -> str:
        """
        Sanitize plain text content removing all HTML.
        
        Args:
            text_content: Text content to sanitize
            policy: Security policy for validation rules
            max_length: Override maximum length from policy
            
        Returns:
            Clean text content with all HTML removed
        """
        if not isinstance(text_content, str):
            raise InvalidInputError(
                f"Text content must be string, got {type(text_content)}"
            )
        
        # Get policy for validation rules
        policy_config = self.policy_manager.get_policy(policy)
        effective_max_length = max_length or policy_config.get('max_length', 10000)
        
        if len(text_content) > effective_max_length:
            raise InvalidInputError(
                f"Content length {len(text_content)} exceeds limit {effective_max_length}"
            )
        
        # Remove all HTML tags and decode HTML entities
        clean_text = bleach.clean(text_content, tags=[], strip=True)
        
        # Normalize whitespace if specified in policy
        if policy_config.get('normalize_whitespace', False):
            clean_text = self._normalize_whitespace(clean_text)
        
        # Remove unicode if not allowed
        if not policy_config.get('allow_unicode', True):
            clean_text = self._remove_unicode_characters(clean_text)
        
        return clean_text.strip()
    
    def _generate_cache_key(
        self, 
        content: str, 
        policy: str, 
        strict_validation: bool
    ) -> str:
        """Generate cache key for sanitized content."""
        content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()[:16]
        return f"{policy}:{strict_validation}:{content_hash}"
    
    def _normalize_whitespace(self, text: str) -> str:
        """Normalize whitespace characters in text."""
        # Replace multiple whitespace with single space
        normalized = re.sub(r'\s+', ' ', text)
        # Remove leading/trailing whitespace
        return normalized.strip()
    
    def _remove_unicode_characters(self, text: str) -> str:
        """Remove or replace Unicode characters with ASCII equivalents."""
        # Normalize unicode characters
        normalized = unicodedata.normalize('NFKD', text)
        # Encode to ASCII, ignoring non-ASCII characters
        ascii_text = normalized.encode('ascii', 'ignore').decode('ascii')
        return ascii_text
    
    def clear_cache(self) -> None:
        """Clear sanitization cache."""
        self._cache.clear()
        self.logger.info("HTML sanitization cache cleared")


class InputSanitizer:
    """
    Comprehensive input sanitization utilities for various data types.
    
    Provides enterprise-grade input sanitization equivalent to Node.js security
    patterns with comprehensive validation, threat detection, and audit logging.
    """
    
    def __init__(self, policy_manager: Optional[SecurityPolicyManager] = None):
        self.policy_manager = policy_manager or SecurityPolicyManager()
        self.logger = self.policy_manager.logger
        self.html_sanitizer = HTMLSanitizer(self.policy_manager)
        
    def sanitize_email(
        self, 
        email: str, 
        check_deliverability: bool = False,
        normalize: bool = True
    ) -> str:
        """
        Sanitize and validate email addresses.
        
        Args:
            email: Email address to sanitize and validate
            check_deliverability: Whether to check email deliverability
            normalize: Whether to normalize email format
            
        Returns:
            Validated and sanitized email address
            
        Raises:
            InvalidInputError: When email is invalid
        """
        if not isinstance(email, str):
            raise InvalidInputError(f"Email must be string, got {type(email)}")
        
        # Basic length validation
        if len(email) > 254:  # RFC 5321 limit
            raise InvalidInputError("Email address too long (max 254 characters)")
        
        # Detect threats in email
        threats = self.policy_manager.detect_threats(email)
        if threats:
            threat_types = [t['type'] for t in threats]
            raise SecurityPolicyViolationError(
                f"Security threats detected in email: {threat_types}"
            )
        
        try:
            # Validate using email-validator
            validated_email = validate_email(
                email,
                check_deliverability=check_deliverability
            )
            
            sanitized_email = validated_email.email
            
            if normalize:
                # Apply additional normalization
                sanitized_email = sanitized_email.lower().strip()
            
            self.logger.info(
                "Email sanitized and validated",
                original_email=email[:20] + "..." if len(email) > 20 else email,
                sanitized_length=len(sanitized_email),
                check_deliverability=check_deliverability
            )
            
            return sanitized_email
            
        except EmailNotValidError as e:
            self.logger.warning(
                "Email validation failed",
                email=email[:20] + "..." if len(email) > 20 else email,
                error=str(e)
            )
            raise InvalidInputError(f"Invalid email address: {str(e)}")
    
    def sanitize_url(
        self, 
        url: str, 
        policy: str = 'url',
        validate_accessibility: bool = False
    ) -> str:
        """
        Sanitize and validate URLs with security checks.
        
        Args:
            url: URL to sanitize and validate
            policy: Security policy for URL validation
            validate_accessibility: Whether to check URL accessibility
            
        Returns:
            Sanitized and validated URL
            
        Raises:
            InvalidInputError: When URL is invalid
            SecurityPolicyViolationError: When URL violates security policy
        """
        if not isinstance(url, str):
            raise InvalidInputError(f"URL must be string, got {type(url)}")
        
        # Get URL policy configuration
        policy_config = self.policy_manager.get_policy(policy)
        
        # Validate URL length
        max_length = policy_config.get('max_length', 2000)
        if len(url) > max_length:
            raise InvalidInputError(f"URL length exceeds limit: {len(url)} > {max_length}")
        
        # Detect threats
        threats = self.policy_manager.detect_threats(url)
        if threats:
            threat_types = [t['type'] for t in threats]
            raise SecurityPolicyViolationError(
                f"Security threats detected in URL: {threat_types}"
            )
        
        try:
            # Parse URL
            parsed_url = urlparse(url)
            
            # Validate scheme
            allowed_schemes = policy_config.get('allowed_schemes', ['https', 'http'])
            if parsed_url.scheme.lower() not in allowed_schemes:
                raise InvalidInputError(
                    f"URL scheme '{parsed_url.scheme}' not allowed. "
                    f"Allowed schemes: {allowed_schemes}"
                )
            
            # Check for private networks if configured
            if policy_config.get('block_private_networks', False):
                self._validate_public_domain(parsed_url.hostname)
            
            # Reconstruct URL with proper encoding
            sanitized_url = self._reconstruct_safe_url(parsed_url)
            
            self.logger.info(
                "URL sanitized successfully",
                original_length=len(url),
                sanitized_length=len(sanitized_url),
                scheme=parsed_url.scheme,
                domain=parsed_url.hostname
            )
            
            return sanitized_url
            
        except Exception as e:
            self.logger.error(
                "URL sanitization failed",
                url=url[:50] + "..." if len(url) > 50 else url,
                error=str(e)
            )
            raise InvalidInputError(f"Invalid URL: {str(e)}")
    
    def sanitize_filename(
        self, 
        filename: str, 
        max_length: int = 255,
        preserve_extension: bool = True
    ) -> str:
        """
        Sanitize filenames for safe file system usage.
        
        Args:
            filename: Original filename to sanitize
            max_length: Maximum allowed filename length
            preserve_extension: Whether to preserve file extension
            
        Returns:
            Sanitized filename safe for file system usage
        """
        if not isinstance(filename, str):
            raise InvalidInputError(f"Filename must be string, got {type(filename)}")
        
        if not filename.strip():
            raise InvalidInputError("Filename cannot be empty")
        
        # Detect path traversal attempts
        threats = self.policy_manager.detect_threats(filename)
        path_traversal_threats = [t for t in threats if t['type'] == 'path_traversal_patterns']
        if path_traversal_threats:
            raise SecurityPolicyViolationError("Path traversal attempt detected in filename")
        
        # Remove directory separators and other dangerous characters
        dangerous_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '\0']
        sanitized = filename
        
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '_')
        
        # Remove leading/trailing dots and spaces
        sanitized = sanitized.strip('. ')
        
        # Handle reserved names on Windows
        reserved_names = [
            'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4',
            'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 
            'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
        ]
        
        name_part = sanitized.split('.')[0].upper()
        if name_part in reserved_names:
            sanitized = f"file_{sanitized}"
        
        # Truncate if too long while preserving extension
        if len(sanitized) > max_length:
            if preserve_extension and '.' in sanitized:
                name, ext = sanitized.rsplit('.', 1)
                name = name[:max_length - len(ext) - 1]
                sanitized = f"{name}.{ext}"
            else:
                sanitized = sanitized[:max_length]
        
        # Ensure not empty after sanitization
        if not sanitized:
            sanitized = "sanitized_file"
        
        self.logger.info(
            "Filename sanitized",
            original=filename,
            sanitized=sanitized,
            length_change=len(filename) - len(sanitized)
        )
        
        return sanitized
    
    def sanitize_json_data(
        self, 
        json_data: Union[str, Dict, List], 
        policy: str = 'json'
    ) -> Union[Dict, List]:
        """
        Sanitize JSON data with structural validation.
        
        Args:
            json_data: JSON data to sanitize (string, dict, or list)
            policy: Security policy for JSON validation
            
        Returns:
            Sanitized JSON data structure
        """
        # Parse JSON string if needed
        if isinstance(json_data, str):
            try:
                parsed_data = json.loads(json_data)
            except json.JSONDecodeError as e:
                raise InvalidInputError(f"Invalid JSON: {str(e)}")
        else:
            parsed_data = json_data
        
        # Get policy configuration
        policy_config = self.policy_manager.get_policy(policy)
        
        # Validate and sanitize recursively
        sanitized_data = self._sanitize_json_recursive(
            parsed_data, 
            policy_config, 
            depth=0
        )
        
        self.logger.info(
            "JSON data sanitized",
            input_type=type(json_data).__name__,
            output_type=type(sanitized_data).__name__
        )
        
        return sanitized_data
    
    def sanitize_datetime_string(
        self, 
        datetime_string: str,
        output_format: str = 'iso8601',
        timezone_aware: bool = True
    ) -> str:
        """
        Sanitize and validate datetime strings using python-dateutil.
        
        Args:
            datetime_string: DateTime string to sanitize
            output_format: Output format ('iso8601', 'timestamp')
            timezone_aware: Whether to ensure timezone awareness
            
        Returns:
            Sanitized datetime string in specified format
        """
        if not isinstance(datetime_string, str):
            raise InvalidInputError(
                f"DateTime string must be string, got {type(datetime_string)}"
            )
        
        try:
            # Parse using python-dateutil
            parsed_date = dateutil_parser.isoparse(datetime_string)
            
            # Ensure timezone awareness if required
            if timezone_aware and parsed_date.tzinfo is None:
                parsed_date = parsed_date.replace(tzinfo=timezone.utc)
            
            # Validate reasonable date range
            min_date = datetime(1900, 1, 1, tzinfo=timezone.utc)
            max_date = datetime(2100, 1, 1, tzinfo=timezone.utc)
            
            if not (min_date <= parsed_date <= max_date):
                raise InvalidInputError(
                    f"DateTime {parsed_date} outside valid range "
                    f"({min_date} to {max_date})"
                )
            
            # Format output
            if output_format == 'iso8601':
                sanitized_datetime = parsed_date.isoformat()
            elif output_format == 'timestamp':
                sanitized_datetime = str(int(parsed_date.timestamp()))
            else:
                raise InvalidInputError(f"Unknown output format: {output_format}")
            
            self.logger.info(
                "DateTime string sanitized",
                original=datetime_string,
                sanitized=sanitized_datetime,
                format=output_format,
                timezone_aware=timezone_aware
            )
            
            return sanitized_datetime
            
        except (ValueError, OverflowError, TypeError) as e:
            self.logger.warning(
                "DateTime sanitization failed",
                datetime_string=datetime_string,
                error=str(e)
            )
            raise InvalidInputError(f"Invalid datetime string: {str(e)}")
    
    def _validate_public_domain(self, hostname: Optional[str]) -> None:
        """Validate that hostname is not a private network address."""
        if not hostname:
            return
        
        # Simple check for private IP ranges and localhost
        private_patterns = [
            r'^127\.',  # Localhost
            r'^10\.',   # Private Class A
            r'^172\.(1[6-9]|2[0-9]|3[01])\.',  # Private Class B
            r'^192\.168\.',  # Private Class C
            r'^169\.254\.',  # Link-local
            r'^::1$',   # IPv6 localhost
            r'^fe80:',  # IPv6 link-local
            r'^localhost$',
            r'^0\.0\.0\.0$'
        ]
        
        for pattern in private_patterns:
            if re.match(pattern, hostname, re.IGNORECASE):
                raise SecurityPolicyViolationError(
                    f"Private network address not allowed: {hostname}"
                )
    
    def _reconstruct_safe_url(self, parsed_url) -> str:
        """Reconstruct URL with proper encoding and safety checks."""
        # Encode URL components safely
        scheme = parsed_url.scheme.lower()
        hostname = parsed_url.hostname.lower() if parsed_url.hostname else ''
        port = f":{parsed_url.port}" if parsed_url.port else ''
        path = quote(parsed_url.path.encode('utf-8'), safe='/')
        query = quote(parsed_url.query.encode('utf-8'), safe='&=')
        fragment = quote(parsed_url.fragment.encode('utf-8'), safe='')
        
        # Reconstruct URL
        url_parts = [f"{scheme}://{hostname}{port}"]
        
        if path:
            url_parts.append(path)
        if query:
            url_parts.append(f"?{query}")
        if fragment:
            url_parts.append(f"#{fragment}")
        
        return ''.join(url_parts)
    
    def _sanitize_json_recursive(
        self, 
        data: Any, 
        policy_config: Dict[str, Any], 
        depth: int
    ) -> Any:
        """Recursively sanitize JSON data structure."""
        max_depth = policy_config.get('max_depth', 10)
        if depth > max_depth:
            raise InvalidInputError(f"JSON depth exceeds limit: {depth} > {max_depth}")
        
        allowed_types = policy_config.get('allowed_types', [
            'str', 'int', 'float', 'bool', 'list', 'dict', 'NoneType'
        ])
        
        data_type = type(data).__name__
        if data_type not in allowed_types:
            raise InvalidInputError(f"Data type '{data_type}' not allowed in JSON")
        
        if isinstance(data, dict):
            max_keys = policy_config.get('max_keys', 100)
            if len(data) > max_keys:
                raise InvalidInputError(f"Dictionary has too many keys: {len(data)} > {max_keys}")
            
            return {
                str(key): self._sanitize_json_recursive(value, policy_config, depth + 1)
                for key, value in data.items()
            }
        
        elif isinstance(data, list):
            max_items = policy_config.get('max_items', 1000)
            if len(data) > max_items:
                raise InvalidInputError(f"List has too many items: {len(data)} > {max_items}")
            
            return [
                self._sanitize_json_recursive(item, policy_config, depth + 1)
                for item in data
            ]
        
        elif isinstance(data, str):
            max_string_length = policy_config.get('max_string_length', 10000)
            if len(data) > max_string_length:
                raise InvalidInputError(
                    f"String too long: {len(data)} > {max_string_length}"
                )
            
            # Sanitize string content for XSS
            return self.html_sanitizer.sanitize_text_content(data, policy='strict')
        
        elif data is None:
            if not policy_config.get('allow_null', True):
                raise InvalidInputError("Null values not allowed")
            return data
        
        else:
            # For primitive types (int, float, bool), return as-is
            return data


class EnterpriseSanitizationManager:
    """
    Enterprise-grade sanitization manager with comprehensive security policies.
    
    Provides centralized sanitization management, audit logging, performance
    monitoring, and integration with Flask-Talisman security framework.
    """
    
    def __init__(
        self, 
        enable_caching: bool = True,
        enable_audit_logging: bool = True,
        custom_policies: Optional[Dict[str, Dict[str, Any]]] = None
    ):
        self.policy_manager = SecurityPolicyManager()
        self.html_sanitizer = HTMLSanitizer(self.policy_manager)
        self.input_sanitizer = InputSanitizer(self.policy_manager)
        self.logger = self.policy_manager.logger
        
        self.enable_caching = enable_caching
        self.enable_audit_logging = enable_audit_logging
        
        # Register custom policies if provided
        if custom_policies:
            for name, policy in custom_policies.items():
                self.policy_manager.register_policy(name, policy, override=True)
        
        # Performance metrics
        self._sanitization_stats = {
            'total_requests': 0,
            'successful_sanitizations': 0,
            'failed_sanitizations': 0,
            'threats_detected': 0,
            'cache_hits': 0
        }
        
        self.logger.info(
            "Enterprise sanitization manager initialized",
            caching_enabled=enable_caching,
            audit_logging_enabled=enable_audit_logging,
            custom_policies_count=len(custom_policies) if custom_policies else 0
        )
    
    def sanitize_user_input(
        self, 
        input_data: Any, 
        input_type: str,
        policy: str = 'basic',
        context: Optional[str] = None,
        strict_validation: bool = True
    ) -> Any:
        """
        Universal sanitization method for various input types.
        
        Args:
            input_data: Data to sanitize
            input_type: Type of input ('html', 'text', 'email', 'url', 'json', 'datetime', 'filename')
            policy: Security policy to apply
            context: Additional context for logging
            strict_validation: Whether to apply strict validation
            
        Returns:
            Sanitized data appropriate for the input type
        """
        self._sanitization_stats['total_requests'] += 1
        
        try:
            if input_type == 'html':
                result = self.html_sanitizer.sanitize_html(
                    input_data, policy, context, strict_validation
                )
            elif input_type == 'text':
                result = self.html_sanitizer.sanitize_text_content(
                    input_data, policy
                )
            elif input_type == 'email':
                result = self.input_sanitizer.sanitize_email(input_data)
            elif input_type == 'url':
                result = self.input_sanitizer.sanitize_url(input_data, policy)
            elif input_type == 'json':
                result = self.input_sanitizer.sanitize_json_data(input_data, policy)
            elif input_type == 'datetime':
                result = self.input_sanitizer.sanitize_datetime_string(input_data)
            elif input_type == 'filename':
                result = self.input_sanitizer.sanitize_filename(input_data)
            else:
                raise InvalidInputError(f"Unknown input type: {input_type}")
            
            self._sanitization_stats['successful_sanitizations'] += 1
            
            if self.enable_audit_logging:
                self.logger.info(
                    "Input sanitization completed successfully",
                    input_type=input_type,
                    policy=policy,
                    context=context,
                    strict_validation=strict_validation
                )
            
            return result
            
        except Exception as e:
            self._sanitization_stats['failed_sanitizations'] += 1
            
            if self.enable_audit_logging:
                self.logger.error(
                    "Input sanitization failed",
                    input_type=input_type,
                    policy=policy,
                    context=context,
                    error=str(e)
                )
            
            raise
    
    def get_sanitization_stats(self) -> Dict[str, Any]:
        """Get sanitization performance statistics."""
        return self._sanitization_stats.copy()
    
    def clear_caches(self) -> None:
        """Clear all sanitization caches."""
        if self.enable_caching:
            self.html_sanitizer.clear_cache()
            self.logger.info("All sanitization caches cleared")
    
    def validate_security_policies(self) -> Dict[str, bool]:
        """Validate all registered security policies."""
        validation_results = {}
        
        for policy_name in ['strict', 'basic', 'content', 'form', 'json', 'url']:
            try:
                policy = self.policy_manager.get_policy(policy_name)
                # Basic validation - check required fields exist
                required_fields = ['description']
                is_valid = all(field in policy for field in required_fields)
                validation_results[policy_name] = is_valid
            except Exception as e:
                validation_results[policy_name] = False
                self.logger.error(
                    "Policy validation failed",
                    policy_name=policy_name,
                    error=str(e)
                )
        
        return validation_results


# Convenience functions for direct usage
def sanitize_html(
    html_content: str, 
    policy: str = 'basic',
    strict_validation: bool = True
) -> str:
    """
    Convenience function for HTML sanitization.
    
    Args:
        html_content: HTML content to sanitize
        policy: Security policy name ('strict', 'basic', 'content')
        strict_validation: Whether to apply strict validation
        
    Returns:
        Sanitized HTML content
    """
    sanitizer = HTMLSanitizer()
    return sanitizer.sanitize_html(html_content, policy, strict_validation=strict_validation)


def sanitize_text(text_content: str, policy: str = 'form') -> str:
    """
    Convenience function for text sanitization.
    
    Args:
        text_content: Text content to sanitize
        policy: Security policy name
        
    Returns:
        Sanitized text content with HTML removed
    """
    sanitizer = HTMLSanitizer()
    return sanitizer.sanitize_text_content(text_content, policy)


def sanitize_email(email: str, normalize: bool = True) -> str:
    """
    Convenience function for email sanitization.
    
    Args:
        email: Email address to sanitize
        normalize: Whether to normalize email format
        
    Returns:
        Validated and sanitized email address
    """
    sanitizer = InputSanitizer()
    return sanitizer.sanitize_email(email, normalize=normalize)


def sanitize_url(url: str, allow_private: bool = False) -> str:
    """
    Convenience function for URL sanitization.
    
    Args:
        url: URL to sanitize
        allow_private: Whether to allow private network addresses
        
    Returns:
        Sanitized and validated URL
    """
    sanitizer = InputSanitizer()
    policy = 'url' if not allow_private else 'url_permissive'
    return sanitizer.sanitize_url(url, policy)


def sanitize_filename(filename: str, max_length: int = 255) -> str:
    """
    Convenience function for filename sanitization.
    
    Args:
        filename: Filename to sanitize
        max_length: Maximum filename length
        
    Returns:
        Sanitized filename safe for file system usage
    """
    sanitizer = InputSanitizer()
    return sanitizer.sanitize_filename(filename, max_length)


# Export main classes and functions
__all__ = [
    'SecurityPolicyManager',
    'HTMLSanitizer', 
    'InputSanitizer',
    'EnterpriseSanitizationManager',
    'SanitizationError',
    'InvalidInputError',
    'SecurityPolicyViolationError',
    'ConfigurationError',
    'sanitize_html',
    'sanitize_text',
    'sanitize_email',
    'sanitize_url',
    'sanitize_filename'
]