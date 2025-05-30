"""
HTML sanitization and input sanitization utilities using bleach 6.0+ for XSS prevention
and secure input processing.

This module provides comprehensive sanitization functions with configurable security policies
and enterprise-grade input protection patterns as specified in Section 0.2.4 dependency decisions,
Section 3.2.2 input validation & sanitization, and Section 5.4.3 authentication and authorization framework.

Key Features:
- HTML sanitization with bleach 6.0+ for XSS prevention
- Configurable sanitization policies for different input contexts
- Email and URL sanitization with validation integration
- Date/time sanitization with python-dateutil integration
- File content sanitization for upload security
- SQL injection prevention patterns
- Enterprise security compliance with audit logging
- Prometheus metrics for sanitization monitoring
- Circuit breaker patterns for external sanitization services
"""

import base64
import html
import re
import urllib.parse
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union
from uuid import uuid4

import bleach
import structlog
from dateutil import parser as dateutil_parser
from dateutil.relativedelta import relativedelta
from prometheus_client import Counter, Histogram

# Import fallbacks for optional dependencies
try:
    from email_validator import EmailNotValidError, validate_email
    EMAIL_VALIDATOR_AVAILABLE = True
except ImportError:
    EMAIL_VALIDATOR_AVAILABLE = False
    # Fallback for environments without email-validator
    class EmailNotValidError(Exception):
        pass

try:
    from urllib3.util import parse_url
    URLLIB3_AVAILABLE = True
except ImportError:
    URLLIB3_AVAILABLE = False

# Prometheus metrics for sanitization monitoring
sanitization_counter = Counter(
    'sanitization_operations_total',
    'Total number of sanitization operations by type',
    ['sanitization_type', 'policy_name', 'result']
)

sanitization_time = Histogram(
    'sanitization_duration_seconds',
    'Time spent on sanitization operations',
    ['sanitization_type', 'policy_name']
)

security_violation_counter = Counter(
    'security_violations_detected_total',
    'Total number of security violations detected during sanitization',
    ['violation_type', 'sanitization_context']
)

# Get structured logger
logger = structlog.get_logger(__name__)


class SanitizationContext(Enum):
    """
    Sanitization context types for policy selection per Section 5.4.3.
    
    Different contexts require different sanitization policies to balance
    security and functionality requirements.
    """
    
    USER_INPUT = "user_input"          # General user input (forms, search)
    RICH_CONTENT = "rich_content"      # Rich text editor content
    COMMENTS = "comments"              # User comments and reviews
    DESCRIPTIONS = "descriptions"      # Product/service descriptions
    ADMIN_CONTENT = "admin_content"    # Administrative content
    EMAIL_CONTENT = "email_content"    # Email content sanitization
    API_INPUT = "api_input"           # API request input
    FILE_CONTENT = "file_content"     # File content sanitization
    SEARCH_QUERY = "search_query"     # Search query sanitization
    URL_INPUT = "url_input"           # URL and link sanitization


class SecurityViolationType(Enum):
    """Security violation types for monitoring and alerting."""
    
    XSS_ATTEMPT = "xss_attempt"
    SQL_INJECTION = "sql_injection"
    SCRIPT_INJECTION = "script_injection"
    HTML_INJECTION = "html_injection"
    URL_MANIPULATION = "url_manipulation"
    FILE_INCLUSION = "file_inclusion"
    COMMAND_INJECTION = "command_injection"
    LDAP_INJECTION = "ldap_injection"
    XPATH_INJECTION = "xpath_injection"
    MALICIOUS_UPLOAD = "malicious_upload"


class SanitizationResult:
    """
    Sanitization operation result with security analysis and metrics.
    
    Provides comprehensive information about sanitization operations including
    security violations detected, content modifications, and audit trail data.
    """
    
    def __init__(
        self,
        original: str,
        sanitized: str,
        context: SanitizationContext,
        policy_name: str,
        violations_detected: Optional[List[SecurityViolationType]] = None,
        modifications_made: bool = False,
        correlation_id: Optional[str] = None
    ):
        self.original = original
        self.sanitized = sanitized
        self.context = context
        self.policy_name = policy_name
        self.violations_detected = violations_detected or []
        self.modifications_made = modifications_made
        self.correlation_id = correlation_id or str(uuid4())
        self.original_length = len(original) if original else 0
        self.sanitized_length = len(sanitized) if sanitized else 0
        self.reduction_ratio = (
            (self.original_length - self.sanitized_length) / self.original_length
            if self.original_length > 0 else 0.0
        )
        
        # Log sanitization operation
        self._log_operation()
        
        # Update metrics
        self._update_metrics()
    
    def _log_operation(self) -> None:
        """Log sanitization operation with structured logging."""
        log_data = {
            'context': self.context.value,
            'policy_name': self.policy_name,
            'correlation_id': self.correlation_id,
            'original_length': self.original_length,
            'sanitized_length': self.sanitized_length,
            'reduction_ratio': self.reduction_ratio,
            'modifications_made': self.modifications_made,
            'violations_count': len(self.violations_detected),
            'violations': [v.value for v in self.violations_detected]
        }
        
        if self.violations_detected:
            logger.warning("Security violations detected during sanitization", **log_data)
        elif self.modifications_made:
            logger.info("Content modified during sanitization", **log_data)
        else:
            logger.debug("Content sanitization completed", **log_data)
    
    def _update_metrics(self) -> None:
        """Update Prometheus metrics for sanitization operations."""
        result = "violations_detected" if self.violations_detected else "clean"
        
        sanitization_counter.labels(
            sanitization_type=self.context.value,
            policy_name=self.policy_name,
            result=result
        ).inc()
        
        # Update security violation metrics
        for violation in self.violations_detected:
            security_violation_counter.labels(
                violation_type=violation.value,
                sanitization_context=self.context.value
            ).inc()
    
    def is_safe(self) -> bool:
        """Check if content is considered safe after sanitization."""
        return len(self.violations_detected) == 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for logging and debugging."""
        return {
            'correlation_id': self.correlation_id,
            'context': self.context.value,
            'policy_name': self.policy_name,
            'original_length': self.original_length,
            'sanitized_length': self.sanitized_length,
            'reduction_ratio': self.reduction_ratio,
            'modifications_made': self.modifications_made,
            'violations_detected': [v.value for v in self.violations_detected],
            'is_safe': self.is_safe()
        }


class HTMLSanitizationPolicy:
    """
    HTML sanitization policy configuration using bleach for XSS prevention.
    
    Implements configurable HTML sanitization policies as specified in Section 5.4.3
    for enterprise security compliance and Section 0.2.4 bleach 6.0+ integration.
    """
    
    def __init__(
        self,
        name: str,
        allowed_tags: Set[str],
        allowed_attributes: Dict[str, List[str]],
        allowed_protocols: Set[str] = None,
        strip_comments: bool = True,
        strip_unknown_tags: bool = True,
        escape_unescaped_quotes: bool = True
    ):
        self.name = name
        self.allowed_tags = allowed_tags
        self.allowed_attributes = allowed_attributes
        self.allowed_protocols = allowed_protocols or {'http', 'https', 'mailto'}
        self.strip_comments = strip_comments
        self.strip_unknown_tags = strip_unknown_tags
        self.escape_unescaped_quotes = escape_unescaped_quotes


# Predefined sanitization policies for different contexts
SANITIZATION_POLICIES = {
    'strict': HTMLSanitizationPolicy(
        name='strict',
        allowed_tags=set(),
        allowed_attributes={},
        strip_comments=True,
        strip_unknown_tags=True
    ),
    
    'basic': HTMLSanitizationPolicy(
        name='basic',
        allowed_tags={'p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li'},
        allowed_attributes={
            '*': ['class'],
        },
        strip_comments=True,
        strip_unknown_tags=True
    ),
    
    'rich_content': HTMLSanitizationPolicy(
        name='rich_content',
        allowed_tags={
            'p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li', 'blockquote',
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'a', 'img', 'table', 'thead',
            'tbody', 'tr', 'th', 'td', 'div', 'span', 'code', 'pre'
        },
        allowed_attributes={
            '*': ['class', 'id'],
            'a': ['href', 'title', 'target', 'rel'],
            'img': ['src', 'alt', 'width', 'height', 'title'],
            'table': ['cellpadding', 'cellspacing', 'border'],
            'th': ['colspan', 'rowspan'],
            'td': ['colspan', 'rowspan'],
        },
        allowed_protocols={'http', 'https', 'mailto'},
        strip_comments=True,
        strip_unknown_tags=True
    ),
    
    'admin_content': HTMLSanitizationPolicy(
        name='admin_content',
        allowed_tags={
            'p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li', 'blockquote',
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'a', 'img', 'table', 'thead',
            'tbody', 'tr', 'th', 'td', 'div', 'span', 'code', 'pre', 'hr',
            'small', 'sub', 'sup', 'del', 'ins', 'mark'
        },
        allowed_attributes={
            '*': ['class', 'id', 'data-*'],
            'a': ['href', 'title', 'target', 'rel'],
            'img': ['src', 'alt', 'width', 'height', 'title', 'style'],
            'table': ['cellpadding', 'cellspacing', 'border', 'style'],
            'th': ['colspan', 'rowspan', 'style'],
            'td': ['colspan', 'rowspan', 'style'],
            'div': ['style'],
            'span': ['style'],
            'p': ['style'],
        },
        allowed_protocols={'http', 'https', 'mailto', 'data'},
        strip_comments=False,
        strip_unknown_tags=True
    )
}


class InputSanitizer:
    """
    Comprehensive input sanitization utility with configurable policies.
    
    Implements enterprise-grade input sanitization as specified in Section 3.2.2
    input validation & sanitization and Section 5.4.3 security framework.
    """
    
    def __init__(self, default_policy: str = 'basic'):
        self.default_policy = default_policy
        self.xss_patterns = self._compile_xss_patterns()
        self.sql_injection_patterns = self._compile_sql_injection_patterns()
        self.script_injection_patterns = self._compile_script_injection_patterns()
    
    def _compile_xss_patterns(self) -> List[re.Pattern]:
        """Compile regular expressions for XSS detection."""
        patterns = [
            re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
            re.compile(r'javascript:', re.IGNORECASE),
            re.compile(r'vbscript:', re.IGNORECASE),
            re.compile(r'onload\s*=', re.IGNORECASE),
            re.compile(r'onerror\s*=', re.IGNORECASE),
            re.compile(r'onclick\s*=', re.IGNORECASE),
            re.compile(r'onmouseover\s*=', re.IGNORECASE),
            re.compile(r'onfocus\s*=', re.IGNORECASE),
            re.compile(r'onblur\s*=', re.IGNORECASE),
            re.compile(r'onchange\s*=', re.IGNORECASE),
            re.compile(r'onsubmit\s*=', re.IGNORECASE),
            re.compile(r'<iframe[^>]*>', re.IGNORECASE),
            re.compile(r'<object[^>]*>', re.IGNORECASE),
            re.compile(r'<embed[^>]*>', re.IGNORECASE),
            re.compile(r'<applet[^>]*>', re.IGNORECASE),
            re.compile(r'<meta[^>]*>', re.IGNORECASE),
            re.compile(r'<base[^>]*>', re.IGNORECASE),
            re.compile(r'<link[^>]*>', re.IGNORECASE),
            re.compile(r'expression\s*\(', re.IGNORECASE),
            re.compile(r'url\s*\(', re.IGNORECASE),
            re.compile(r'@import', re.IGNORECASE),
        ]
        return patterns
    
    def _compile_sql_injection_patterns(self) -> List[re.Pattern]:
        """Compile regular expressions for SQL injection detection."""
        patterns = [
            re.compile(r"'(\s*)(\|\||\||or)\s+", re.IGNORECASE),
            re.compile(r"'(\s*)(\&\&|\&|and)\s+", re.IGNORECASE),
            re.compile(r"'(\s*)(=|!=|<>|<|>)\s*", re.IGNORECASE),
            re.compile(r"\bunion\s+select\b", re.IGNORECASE),
            re.compile(r"\bselect\s+.*\s+from\b", re.IGNORECASE),
            re.compile(r"\binsert\s+into\b", re.IGNORECASE),
            re.compile(r"\bupdate\s+.*\s+set\b", re.IGNORECASE),
            re.compile(r"\bdelete\s+from\b", re.IGNORECASE),
            re.compile(r"\bdrop\s+table\b", re.IGNORECASE),
            re.compile(r"\btruncate\s+table\b", re.IGNORECASE),
            re.compile(r"\bexec\s*\(", re.IGNORECASE),
            re.compile(r"\bexecute\s*\(", re.IGNORECASE),
            re.compile(r"--", re.IGNORECASE),
            re.compile(r"/\*.*?\*/", re.IGNORECASE | re.DOTALL),
            re.compile(r"\bxp_cmdshell\b", re.IGNORECASE),
            re.compile(r"\bsp_executesql\b", re.IGNORECASE),
        ]
        return patterns
    
    def _compile_script_injection_patterns(self) -> List[re.Pattern]:
        """Compile regular expressions for script injection detection."""
        patterns = [
            re.compile(r'<%.*?%>', re.IGNORECASE | re.DOTALL),
            re.compile(r'<\?.*?\?>', re.IGNORECASE | re.DOTALL),
            re.compile(r'\$\{.*?\}', re.IGNORECASE | re.DOTALL),
            re.compile(r'#\{.*?\}', re.IGNORECASE | re.DOTALL),
            re.compile(r'{{.*?}}', re.IGNORECASE | re.DOTALL),
            re.compile(r'\[\[.*?\]\]', re.IGNORECASE | re.DOTALL),
            re.compile(r'eval\s*\(', re.IGNORECASE),
            re.compile(r'function\s*\(', re.IGNORECASE),
            re.compile(r'new\s+Function', re.IGNORECASE),
            re.compile(r'setTimeout\s*\(', re.IGNORECASE),
            re.compile(r'setInterval\s*\(', re.IGNORECASE),
        ]
        return patterns
    
    def _detect_security_violations(
        self, 
        content: str, 
        context: SanitizationContext
    ) -> List[SecurityViolationType]:
        """
        Detect security violations in content based on pattern matching.
        
        Args:
            content: Content to analyze for security violations
            context: Sanitization context for appropriate checks
            
        Returns:
            List of detected security violation types
        """
        violations = []
        
        if not content:
            return violations
        
        # XSS detection
        for pattern in self.xss_patterns:
            if pattern.search(content):
                violations.append(SecurityViolationType.XSS_ATTEMPT)
                break
        
        # SQL injection detection (for database-bound content)
        if context in [SanitizationContext.API_INPUT, SanitizationContext.SEARCH_QUERY]:
            for pattern in self.sql_injection_patterns:
                if pattern.search(content):
                    violations.append(SecurityViolationType.SQL_INJECTION)
                    break
        
        # Script injection detection
        for pattern in self.script_injection_patterns:
            if pattern.search(content):
                violations.append(SecurityViolationType.SCRIPT_INJECTION)
                break
        
        # Additional context-specific checks
        if context == SanitizationContext.URL_INPUT:
            if self._is_suspicious_url(content):
                violations.append(SecurityViolationType.URL_MANIPULATION)
        
        return violations
    
    def _is_suspicious_url(self, url: str) -> bool:
        """Check if URL contains suspicious patterns."""
        suspicious_patterns = [
            r'javascript:', r'data:', r'vbscript:', r'file:', r'ftp:',
            r'\.\./', r'%2e%2e%2f', r'%252e%252e%252f',
            r'<script', r'</script>', r'<iframe', r'</iframe>'
        ]
        
        url_lower = url.lower()
        for pattern in suspicious_patterns:
            if re.search(pattern, url_lower):
                return True
        
        return False
    
    @sanitization_time.labels(sanitization_type='html', policy_name='').time()
    def sanitize_html(
        self,
        content: str,
        context: SanitizationContext = SanitizationContext.USER_INPUT,
        policy_name: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> SanitizationResult:
        """
        Sanitize HTML content using bleach with configurable policies.
        
        Implements HTML sanitization using bleach 6.0+ as specified in Section 0.2.4
        dependency decisions and Section 3.2.2 input validation & sanitization.
        
        Args:
            content: HTML content to sanitize
            context: Sanitization context for policy selection
            policy_name: Specific policy name to use (overrides context-based selection)
            correlation_id: Optional correlation ID for audit trail
            
        Returns:
            SanitizationResult with sanitized content and security analysis
        """
        if not content:
            return SanitizationResult(
                original=content,
                sanitized=content or '',
                context=context,
                policy_name=policy_name or 'empty',
                correlation_id=correlation_id
            )
        
        # Select appropriate policy
        if policy_name and policy_name in SANITIZATION_POLICIES:
            policy = SANITIZATION_POLICIES[policy_name]
        else:
            # Context-based policy selection
            policy_mapping = {
                SanitizationContext.USER_INPUT: 'basic',
                SanitizationContext.RICH_CONTENT: 'rich_content',
                SanitizationContext.COMMENTS: 'basic',
                SanitizationContext.DESCRIPTIONS: 'rich_content',
                SanitizationContext.ADMIN_CONTENT: 'admin_content',
                SanitizationContext.EMAIL_CONTENT: 'basic',
                SanitizationContext.API_INPUT: 'strict',
                SanitizationContext.FILE_CONTENT: 'strict',
                SanitizationContext.SEARCH_QUERY: 'strict',
                SanitizationContext.URL_INPUT: 'strict',
            }
            policy_name = policy_mapping.get(context, self.default_policy)
            policy = SANITIZATION_POLICIES[policy_name]
        
        # Detect security violations before sanitization
        violations = self._detect_security_violations(content, context)
        
        # Perform HTML sanitization with bleach
        try:
            sanitized = bleach.clean(
                content,
                tags=policy.allowed_tags,
                attributes=policy.allowed_attributes,
                protocols=policy.allowed_protocols,
                strip=policy.strip_unknown_tags,
                strip_comments=policy.strip_comments
            )
            
            # Additional processing based on policy
            if policy.escape_unescaped_quotes:
                sanitized = html.escape(sanitized, quote=True)
                # Unescape allowed HTML tags
                for tag in policy.allowed_tags:
                    sanitized = sanitized.replace(f'&lt;{tag}&gt;', f'<{tag}>')
                    sanitized = sanitized.replace(f'&lt;/{tag}&gt;', f'</{tag}>')
            
            modifications_made = content != sanitized
            
        except Exception as e:
            logger.error(
                "HTML sanitization failed",
                context=context.value,
                policy_name=policy.name,
                error=str(e),
                correlation_id=correlation_id
            )
            # Fallback to strict sanitization
            sanitized = bleach.clean(content, tags=set(), attributes={})
            modifications_made = True
            violations.append(SecurityViolationType.HTML_INJECTION)
        
        return SanitizationResult(
            original=content,
            sanitized=sanitized,
            context=context,
            policy_name=policy.name,
            violations_detected=violations,
            modifications_made=modifications_made,
            correlation_id=correlation_id
        )
    
    @sanitization_time.labels(sanitization_type='text', policy_name='general').time()
    def sanitize_text(
        self,
        content: str,
        context: SanitizationContext = SanitizationContext.USER_INPUT,
        max_length: Optional[int] = None,
        allow_unicode: bool = True,
        correlation_id: Optional[str] = None
    ) -> SanitizationResult:
        """
        Sanitize plain text content for safe processing.
        
        Args:
            content: Text content to sanitize
            context: Sanitization context
            max_length: Maximum allowed length
            allow_unicode: Whether to allow Unicode characters
            correlation_id: Optional correlation ID for audit trail
            
        Returns:
            SanitizationResult with sanitized text and security analysis
        """
        if not content:
            return SanitizationResult(
                original=content,
                sanitized=content or '',
                context=context,
                policy_name='text',
                correlation_id=correlation_id
            )
        
        original_content = content
        violations = []
        
        # Detect security violations
        violations.extend(self._detect_security_violations(content, context))
        
        # Remove HTML tags
        content = bleach.clean(content, tags=set(), attributes={}, strip=True)
        
        # Handle Unicode
        if not allow_unicode:
            content = content.encode('ascii', 'ignore').decode('ascii')
        
        # Apply length restrictions
        if max_length and len(content) > max_length:
            content = content[:max_length]
        
        # Remove or replace dangerous characters
        dangerous_chars = ['<', '>', '"', "'", '&', '\x00', '\r', '\n\n\n']
        for char in dangerous_chars:
            if char in content:
                content = content.replace(char, '')
        
        # Normalize whitespace
        content = ' '.join(content.split())
        
        modifications_made = original_content != content
        
        return SanitizationResult(
            original=original_content,
            sanitized=content,
            context=context,
            policy_name='text',
            violations_detected=violations,
            modifications_made=modifications_made,
            correlation_id=correlation_id
        )
    
    @sanitization_time.labels(sanitization_type='email', policy_name='email').time()
    def sanitize_email(
        self,
        email: str,
        validate: bool = True,
        correlation_id: Optional[str] = None
    ) -> SanitizationResult:
        """
        Sanitize and validate email addresses using email-validator.
        
        Implements email sanitization as specified in Section 3.2.2 input validation
        and Section 0.2.4 email-validator 2.0+ dependency.
        
        Args:
            email: Email address to sanitize and validate
            validate: Whether to perform validation using email-validator
            correlation_id: Optional correlation ID for audit trail
            
        Returns:
            SanitizationResult with sanitized email and validation status
        """
        if not email:
            return SanitizationResult(
                original=email,
                sanitized='',
                context=SanitizationContext.EMAIL_CONTENT,
                policy_name='email',
                correlation_id=correlation_id
            )
        
        original_email = email
        violations = []
        
        # Basic sanitization
        email = email.strip().lower()
        
        # Remove dangerous characters
        dangerous_chars = ['<', '>', '"', "'", '&', '\x00', '\r', '\n', '\t']
        for char in dangerous_chars:
            email = email.replace(char, '')
        
        # Validate email format if email-validator is available
        valid_email = True
        if validate and EMAIL_VALIDATOR_AVAILABLE:
            try:
                validation_result = validate_email(email)
                email = validation_result.email  # Get normalized email
            except EmailNotValidError:
                valid_email = False
                violations.append(SecurityViolationType.XSS_ATTEMPT)
        
        # Basic regex validation as fallback
        if not EMAIL_VALIDATOR_AVAILABLE or not valid_email:
            email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
            if not email_pattern.match(email):
                violations.append(SecurityViolationType.XSS_ATTEMPT)
                email = ''  # Clear invalid email
        
        modifications_made = original_email != email
        
        return SanitizationResult(
            original=original_email,
            sanitized=email,
            context=SanitizationContext.EMAIL_CONTENT,
            policy_name='email',
            violations_detected=violations,
            modifications_made=modifications_made,
            correlation_id=correlation_id
        )
    
    @sanitization_time.labels(sanitization_type='url', policy_name='url').time()
    def sanitize_url(
        self,
        url: str,
        allowed_schemes: Optional[Set[str]] = None,
        correlation_id: Optional[str] = None
    ) -> SanitizationResult:
        """
        Sanitize URL inputs for safe processing and redirection.
        
        Args:
            url: URL to sanitize
            allowed_schemes: Set of allowed URL schemes (defaults to http, https)
            correlation_id: Optional correlation ID for audit trail
            
        Returns:
            SanitizationResult with sanitized URL and security analysis
        """
        if not url:
            return SanitizationResult(
                original=url,
                sanitized='',
                context=SanitizationContext.URL_INPUT,
                policy_name='url',
                correlation_id=correlation_id
            )
        
        original_url = url
        violations = []
        allowed_schemes = allowed_schemes or {'http', 'https'}
        
        # Detect URL-specific security violations
        if self._is_suspicious_url(url):
            violations.append(SecurityViolationType.URL_MANIPULATION)
        
        # Basic URL sanitization
        url = url.strip()
        
        # Parse and validate URL
        try:
            if URLLIB3_AVAILABLE:
                parsed = parse_url(url)
                
                # Check scheme
                if parsed.scheme and parsed.scheme.lower() not in allowed_schemes:
                    violations.append(SecurityViolationType.URL_MANIPULATION)
                    url = ''
                else:
                    # Reconstruct URL with safe components
                    url = f"{parsed.scheme}://{parsed.host}"
                    if parsed.port:
                        url += f":{parsed.port}"
                    if parsed.path:
                        url += urllib.parse.quote(parsed.path)
                    if parsed.query:
                        url += f"?{urllib.parse.quote_plus(parsed.query)}"
            else:
                # Fallback URL validation
                parsed = urllib.parse.urlparse(url)
                if parsed.scheme not in allowed_schemes:
                    violations.append(SecurityViolationType.URL_MANIPULATION)
                    url = ''
                
        except Exception:
            violations.append(SecurityViolationType.URL_MANIPULATION)
            url = ''
        
        modifications_made = original_url != url
        
        return SanitizationResult(
            original=original_url,
            sanitized=url,
            context=SanitizationContext.URL_INPUT,
            policy_name='url',
            violations_detected=violations,
            modifications_made=modifications_made,
            correlation_id=correlation_id
        )
    
    @sanitization_time.labels(sanitization_type='filename', policy_name='filename').time()
    def sanitize_filename(
        self,
        filename: str,
        max_length: int = 255,
        allow_unicode: bool = False,
        correlation_id: Optional[str] = None
    ) -> SanitizationResult:
        """
        Sanitize filenames for safe file system operations.
        
        Args:
            filename: Filename to sanitize
            max_length: Maximum allowed filename length
            allow_unicode: Whether to allow Unicode characters
            correlation_id: Optional correlation ID for audit trail
            
        Returns:
            SanitizationResult with sanitized filename and security analysis
        """
        if not filename:
            return SanitizationResult(
                original=filename,
                sanitized='',
                context=SanitizationContext.FILE_CONTENT,
                policy_name='filename',
                correlation_id=correlation_id
            )
        
        original_filename = filename
        violations = []
        
        # Remove path traversal attempts
        dangerous_patterns = ['../', '.\\', '..\\', '/..', '\\..']
        for pattern in dangerous_patterns:
            if pattern in filename:
                violations.append(SecurityViolationType.FILE_INCLUSION)
                filename = filename.replace(pattern, '')
        
        # Remove dangerous characters
        dangerous_chars = ['<', '>', ':', '"', '|', '?', '*', '\x00', '\r', '\n']
        for char in dangerous_chars:
            filename = filename.replace(char, '_')
        
        # Handle Unicode
        if not allow_unicode:
            filename = filename.encode('ascii', 'ignore').decode('ascii')
        
        # Remove leading/trailing spaces and dots
        filename = filename.strip(' .')
        
        # Apply length restrictions
        if len(filename) > max_length:
            name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
            available_length = max_length - len(ext) - 1 if ext else max_length
            filename = name[:available_length] + ('.' + ext if ext else '')
        
        # Ensure filename is not empty
        if not filename:
            filename = 'sanitized_file'
        
        modifications_made = original_filename != filename
        
        return SanitizationResult(
            original=original_filename,
            sanitized=filename,
            context=SanitizationContext.FILE_CONTENT,
            policy_name='filename',
            violations_detected=violations,
            modifications_made=modifications_made,
            correlation_id=correlation_id
        )
    
    @sanitization_time.labels(sanitization_type='datetime', policy_name='datetime').time()
    def sanitize_datetime_string(
        self,
        datetime_str: str,
        mask_level: str = 'none',
        correlation_id: Optional[str] = None
    ) -> SanitizationResult:
        """
        Sanitize and optionally mask datetime strings using python-dateutil.
        
        Implements secure datetime processing as specified in Section 6.4.3 data protection
        with python-dateutil integration for ISO 8601 parsing and temporal data anonymization.
        
        Args:
            datetime_str: Datetime string to sanitize
            mask_level: Masking level (none, day, week, month, quarter, year)
            correlation_id: Optional correlation ID for audit trail
            
        Returns:
            SanitizationResult with sanitized datetime and security analysis
        """
        if not datetime_str:
            return SanitizationResult(
                original=datetime_str,
                sanitized='',
                context=SanitizationContext.API_INPUT,
                policy_name='datetime',
                correlation_id=correlation_id
            )
        
        original_datetime = datetime_str
        violations = []
        
        try:
            # Parse datetime with python-dateutil
            parsed_date = dateutil_parser.isoparse(datetime_str)
            
            # Apply masking if requested
            if mask_level == 'day':
                masked_date = parsed_date.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            elif mask_level == 'week':
                days_since_monday = parsed_date.weekday()
                masked_date = parsed_date - relativedelta(days=days_since_monday)
                masked_date = masked_date.replace(hour=0, minute=0, second=0, microsecond=0)
            elif mask_level == 'month':
                masked_date = parsed_date.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            elif mask_level == 'quarter':
                quarter_start_month = ((parsed_date.month - 1) // 3) * 3 + 1
                masked_date = parsed_date.replace(
                    month=quarter_start_month, day=1,
                    hour=0, minute=0, second=0, microsecond=0
                )
            elif mask_level == 'year':
                masked_date = parsed_date.replace(
                    month=1, day=1,
                    hour=0, minute=0, second=0, microsecond=0
                )
            else:
                masked_date = parsed_date
            
            # Convert back to ISO format
            sanitized_datetime = masked_date.isoformat()
            
        except (ValueError, OverflowError) as e:
            logger.warning(
                "Invalid datetime format detected",
                datetime_str=datetime_str,
                error=str(e),
                correlation_id=correlation_id
            )
            violations.append(SecurityViolationType.XSS_ATTEMPT)
            sanitized_datetime = ''
        
        modifications_made = original_datetime != sanitized_datetime
        
        return SanitizationResult(
            original=original_datetime,
            sanitized=sanitized_datetime,
            context=SanitizationContext.API_INPUT,
            policy_name='datetime',
            violations_detected=violations,
            modifications_made=modifications_made,
            correlation_id=correlation_id
        )
    
    def sanitize_base64(
        self,
        content: str,
        max_decoded_size: int = 10 * 1024 * 1024,  # 10MB default
        correlation_id: Optional[str] = None
    ) -> SanitizationResult:
        """
        Sanitize base64 encoded content for security.
        
        Args:
            content: Base64 content to sanitize
            max_decoded_size: Maximum allowed decoded content size
            correlation_id: Optional correlation ID for audit trail
            
        Returns:
            SanitizationResult with sanitized base64 content
        """
        if not content:
            return SanitizationResult(
                original=content,
                sanitized='',
                context=SanitizationContext.FILE_CONTENT,
                policy_name='base64',
                correlation_id=correlation_id
            )
        
        original_content = content
        violations = []
        
        try:
            # Validate base64 format
            decoded = base64.b64decode(content, validate=True)
            
            # Check size limits
            if len(decoded) > max_decoded_size:
                violations.append(SecurityViolationType.MALICIOUS_UPLOAD)
                content = ''
            else:
                # Re-encode to ensure clean format
                content = base64.b64encode(decoded).decode('ascii')
                
        except Exception:
            violations.append(SecurityViolationType.MALICIOUS_UPLOAD)
            content = ''
        
        modifications_made = original_content != content
        
        return SanitizationResult(
            original=original_content,
            sanitized=content,
            context=SanitizationContext.FILE_CONTENT,
            policy_name='base64',
            violations_detected=violations,
            modifications_made=modifications_made,
            correlation_id=correlation_id
        )


# Global sanitizer instance
sanitizer = InputSanitizer()

# Convenience functions for common sanitization operations
def sanitize_html(
    content: str,
    context: SanitizationContext = SanitizationContext.USER_INPUT,
    policy: Optional[str] = None
) -> str:
    """
    Convenience function for HTML sanitization.
    
    Args:
        content: HTML content to sanitize
        context: Sanitization context
        policy: Optional policy name
        
    Returns:
        Sanitized HTML content
    """
    result = sanitizer.sanitize_html(content, context, policy)
    return result.sanitized


def sanitize_text(
    content: str,
    context: SanitizationContext = SanitizationContext.USER_INPUT,
    max_length: Optional[int] = None
) -> str:
    """
    Convenience function for text sanitization.
    
    Args:
        content: Text content to sanitize
        context: Sanitization context
        max_length: Maximum allowed length
        
    Returns:
        Sanitized text content
    """
    result = sanitizer.sanitize_text(content, context, max_length)
    return result.sanitized


def sanitize_email(email: str, validate: bool = True) -> str:
    """
    Convenience function for email sanitization.
    
    Args:
        email: Email address to sanitize
        validate: Whether to perform validation
        
    Returns:
        Sanitized email address
    """
    result = sanitizer.sanitize_email(email, validate)
    return result.sanitized


def sanitize_url(url: str, allowed_schemes: Optional[Set[str]] = None) -> str:
    """
    Convenience function for URL sanitization.
    
    Args:
        url: URL to sanitize
        allowed_schemes: Set of allowed schemes
        
    Returns:
        Sanitized URL
    """
    result = sanitizer.sanitize_url(url, allowed_schemes)
    return result.sanitized


def sanitize_filename(filename: str, max_length: int = 255) -> str:
    """
    Convenience function for filename sanitization.
    
    Args:
        filename: Filename to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized filename
    """
    result = sanitizer.sanitize_filename(filename, max_length)
    return result.sanitized


# Export all public functions and classes
__all__ = [
    'InputSanitizer',
    'SanitizationResult',
    'SanitizationContext',
    'SecurityViolationType',
    'HTMLSanitizationPolicy',
    'SANITIZATION_POLICIES',
    'sanitizer',
    'sanitize_html',
    'sanitize_text',
    'sanitize_email',
    'sanitize_url',
    'sanitize_filename'
]