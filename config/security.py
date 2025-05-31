"""
Flask Security Configuration Module

This module provides comprehensive security configuration implementing Flask-Talisman 1.1.0+ 
for HTTP security headers, CORS policies, rate limiting, input validation, and comprehensive 
security controls. Replaces Node.js helmet middleware and security configurations.

Key Security Features:
- Flask-Talisman 1.1.0+ for HTTP security header enforcement (Section 3.2.2)
- Flask-CORS 4.0+ for cross-origin request support (Section 3.2.1)  
- Flask-Limiter 3.5+ for request throttling (Section 3.2.1)
- HTTPS/TLS 1.3 enforcement and security headers (Section 6.4.3)
- Input validation using marshmallow 3.20+ and bleach 6.0+ (Section 3.2.2)
- Content Security Policy and HSTS enforcement (Section 6.4.3)
- Rate limiting with Redis backend and intelligent caching
- Comprehensive security monitoring and audit logging

Migrated from Node.js helmet middleware to Flask-Talisman maintaining identical 
security protections while enhancing enterprise-grade security controls.

Dependencies:
- Flask-Talisman 1.1.0+ for security header enforcement
- Flask-CORS 4.0+ for cross-origin request management
- Flask-Limiter 3.5+ for rate limiting and DoS protection
- marshmallow 3.20+ for input validation and schema enforcement
- bleach 6.0+ for HTML sanitization and XSS prevention
- redis-py 5.0+ for rate limiting backend storage

Author: Flask Migration Team
Version: 1.0.0
Migration Phase: Node.js to Python/Flask Security Migration (Section 0.1.1)
"""

import os
import logging
import secrets
import ipaddress
from typing import Dict, List, Any, Optional, Union, Callable
from datetime import timedelta
from urllib.parse import urlparse
import re

from flask import Flask, request, g, session, current_app
from flask_talisman import Talisman
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis
import bleach
from marshmallow import Schema, fields, ValidationError, validates_schema
from email_validator import validate_email, EmailNotValidError
import structlog

# Import configuration dependencies
from config.settings import get_config, BaseConfig
from config.database import RedisConfig


logger = structlog.get_logger(__name__)


class SecurityConfigurationError(Exception):
    """Custom exception for security configuration errors."""
    pass


class SecurityValidationError(Exception):
    """Custom exception for security validation failures."""
    pass


class ContentSecurityPolicyManager:
    """
    Content Security Policy (CSP) management with environment-specific policies
    and nonce generation for enhanced XSS protection as specified in Section 6.4.3.
    
    Implements comprehensive CSP policies replacing Node.js helmet CSP configuration
    with Flask-Talisman integration and dynamic nonce generation.
    """
    
    def __init__(self, flask_env: str = 'production'):
        """
        Initialize CSP manager with environment-specific policies.
        
        Args:
            flask_env: Flask environment (development, staging, production)
        """
        self.flask_env = flask_env
        self.logger = structlog.get_logger(f"{__name__}.{self.__class__.__name__}")
        self._base_csp_policy = self._get_base_csp_policy()
        
    def _get_base_csp_policy(self) -> Dict[str, Union[str, List[str]]]:
        """
        Get base Content Security Policy configuration.
        
        Returns:
            Base CSP policy dictionary with security directives
        """
        return {
            'default-src': "'self'",
            'script-src': [
                "'self'",
                "'unsafe-inline'",  # Required for some Flask operations
                "https://cdn.auth0.com",  # Auth0 integration
                "https://js.stripe.com",  # Payment processing (if applicable)
            ],
            'style-src': [
                "'self'",
                "'unsafe-inline'",  # Required for dynamic styles
                "https://fonts.googleapis.com"  # Web fonts
            ],
            'img-src': [
                "'self'",
                "data:",  # Data URLs for images
                "https:",  # HTTPS images
                "blob:",  # Blob URLs for file uploads
            ],
            'connect-src': [
                "'self'",
                "https://*.auth0.com",  # Auth0 API endpoints
                "https://*.amazonaws.com",  # AWS services
                "wss:",  # WebSocket connections (if applicable)
            ],
            'font-src': [
                "'self'",
                "https://fonts.gstatic.com",  # Google Fonts
                "data:"  # Data URLs for fonts
            ],
            'object-src': "'none'",  # Disable object/embed/applet
            'base-uri': "'self'",  # Restrict base tag URLs
            'frame-ancestors': "'none'",  # Prevent framing (clickjacking protection)
            'form-action': "'self'",  # Restrict form submissions
            'upgrade-insecure-requests': True,  # Force HTTPS
            'block-all-mixed-content': True,  # Block mixed content
        }
    
    def get_environment_csp_policy(self) -> Dict[str, Union[str, List[str]]]:
        """
        Get environment-specific CSP policy with appropriate security levels.
        
        Returns:
            Environment-tailored CSP policy configuration
        """
        csp_policy = self._base_csp_policy.copy()
        
        if self.flask_env == 'development':
            # Relaxed CSP for development with additional localhost sources
            csp_policy['script-src'].extend([
                "'unsafe-eval'",  # Allow eval for development tools
                "http://localhost:*",  # Localhost development servers
                "https://localhost:*",  # HTTPS localhost
                "ws://localhost:*",  # WebSocket for dev tools
            ])
            csp_policy['connect-src'].extend([
                "http://localhost:*",
                "https://localhost:*",
                "ws://localhost:*",
                "wss://localhost:*"
            ])
            csp_policy['img-src'].extend([
                "http://localhost:*",
                "https://localhost:*"
            ])
            
        elif self.flask_env == 'staging':
            # Staging-specific sources for testing
            csp_policy['script-src'].extend([
                "https://staging.company.com",
                "https://staging-admin.company.com"
            ])
            csp_policy['connect-src'].extend([
                "https://staging.company.com",
                "https://staging-admin.company.com"
            ])
            
        elif self.flask_env == 'production':
            # Strict production CSP policy
            csp_policy['script-src'] = [
                "'self'",
                "https://cdn.auth0.com",
                "https://js.stripe.com"
            ]
            # Remove unsafe-inline for production (may require code changes)
            # csp_policy['script-src'] = [src for src in csp_policy['script-src'] if src != "'unsafe-inline'"]
            
        # Add custom CSP sources from environment variables
        custom_script_src = os.getenv('CSP_SCRIPT_SRC_ADDITIONAL')
        if custom_script_src:
            additional_sources = [src.strip() for src in custom_script_src.split(',')]
            csp_policy['script-src'].extend(additional_sources)
        
        custom_connect_src = os.getenv('CSP_CONNECT_SRC_ADDITIONAL')
        if custom_connect_src:
            additional_sources = [src.strip() for src in custom_connect_src.split(',')]
            csp_policy['connect-src'].extend(additional_sources)
        
        self.logger.info(
            "CSP policy configured for environment",
            environment=self.flask_env,
            script_sources_count=len(csp_policy['script-src']),
            connect_sources_count=len(csp_policy['connect-src'])
        )
        
        return csp_policy
    
    def generate_nonce(self) -> str:
        """
        Generate cryptographically secure nonce for CSP.
        
        Returns:
            Base64-encoded nonce for script/style tags
        """
        import base64
        nonce_bytes = secrets.token_bytes(16)
        nonce_b64 = base64.b64encode(nonce_bytes).decode('utf-8')
        
        # Store nonce in Flask's g context for template access
        g.csp_nonce = nonce_b64
        
        return nonce_b64
    
    def add_nonce_to_csp(self, csp_policy: Dict[str, Any], nonce: str) -> Dict[str, Any]:
        """
        Add nonce to CSP policy for dynamic script/style execution.
        
        Args:
            csp_policy: Base CSP policy dictionary
            nonce: Generated nonce value
            
        Returns:
            Updated CSP policy with nonce directives
        """
        updated_policy = csp_policy.copy()
        nonce_directive = f"'nonce-{nonce}'"
        
        # Add nonce to script-src if it's a list
        if isinstance(updated_policy['script-src'], list):
            updated_policy['script-src'].append(nonce_directive)
        else:
            updated_policy['script-src'] = [updated_policy['script-src'], nonce_directive]
        
        # Add nonce to style-src if it's a list
        if isinstance(updated_policy['style-src'], list):
            updated_policy['style-src'].append(nonce_directive)
        else:
            updated_policy['style-src'] = [updated_policy['style-src'], nonce_directive]
        
        return updated_policy


class RateLimitManager:
    """
    Rate limiting management using Flask-Limiter 3.5+ with Redis backend
    and intelligent rate limiting strategies as specified in Section 3.2.1.
    
    Implements comprehensive rate limiting replacing express-rate-limit with
    Flask-Limiter for DoS protection and abuse prevention.
    """
    
    def __init__(self, redis_config: RedisConfig):
        """
        Initialize rate limiting manager with Redis backend.
        
        Args:
            redis_config: Redis configuration instance
        """
        self.redis_config = redis_config
        self.logger = structlog.get_logger(f"{__name__}.{self.__class__.__name__}")
        self._limiter: Optional[Limiter] = None
        
    def configure_rate_limiter(self, app: Flask) -> Limiter:
        """
        Configure Flask-Limiter with comprehensive rate limiting strategies.
        
        Args:
            app: Flask application instance
            
        Returns:
            Configured Flask-Limiter instance
        """
        try:
            # Get Redis client for rate limiting (separate DB)
            redis_client = self.redis_config.get_redis_client(
                db=int(os.getenv('REDIS_LIMITER_DB', 2))
            )
            
            # Create rate limiter with Redis backend
            self._limiter = Limiter(
                key_func=self._get_rate_limit_key,
                app=app,
                storage_uri=self._get_redis_storage_uri(),
                storage_options={
                    'connection_pool': redis_client.connection_pool
                },
                default_limits=[
                    "2000 per hour",    # Generous hourly limit
                    "200 per minute",   # Reasonable per-minute limit
                    "20 per second"     # Burst protection
                ],
                strategy="moving-window",  # More accurate than fixed-window
                headers_enabled=True,
                header_name_mapping={
                    "X-RateLimit-Limit": "X-RateLimit-Limit",
                    "X-RateLimit-Remaining": "X-RateLimit-Remaining", 
                    "X-RateLimit-Reset": "X-RateLimit-Reset"
                },
                swallow_errors=True,  # Don't break app if Redis is down
                in_memory_fallback_enabled=True  # Fallback for Redis outages
            )
            
            # Configure rate limit exceeded handler
            self._configure_rate_limit_handler(app)
            
            # Configure rate limit decorators for specific endpoints
            self._configure_endpoint_specific_limits()
            
            self.logger.info(
                "Rate limiter configured successfully",
                redis_host=self.redis_config.host,
                redis_db=int(os.getenv('REDIS_LIMITER_DB', 2)),
                strategy="moving-window"
            )
            
            return self._limiter
            
        except Exception as e:
            self.logger.error(
                "Failed to configure rate limiter",
                error=str(e),
                redis_host=self.redis_config.host
            )
            raise SecurityConfigurationError(f"Rate limiter configuration failed: {str(e)}")
    
    def _get_rate_limit_key(self) -> str:
        """
        Generate intelligent rate limiting key based on user and IP.
        
        Returns:
            Rate limiting key for request identification
        """
        # Try to get authenticated user ID first
        user_id = getattr(g, 'current_user_id', None)
        if user_id:
            return f"user:{user_id}"
        
        # Fall back to IP address for unauthenticated requests
        return f"ip:{get_remote_address()}"
    
    def _get_redis_storage_uri(self) -> str:
        """
        Generate Redis storage URI for rate limiting backend.
        
        Returns:
            Redis connection URI for Flask-Limiter
        """
        redis_password = self.redis_config.password
        password_part = f":{redis_password}@" if redis_password else ""
        limiter_db = int(os.getenv('REDIS_LIMITER_DB', 2))
        
        return f"redis://{password_part}{self.redis_config.host}:{self.redis_config.port}/{limiter_db}"
    
    def _configure_rate_limit_handler(self, app: Flask) -> None:
        """
        Configure custom rate limit exceeded handler with security logging.
        
        Args:
            app: Flask application instance
        """
        @app.errorhandler(429)
        def rate_limit_handler(e):
            """Handle rate limit exceeded responses."""
            user_id = getattr(g, 'current_user_id', 'anonymous')
            ip_address = get_remote_address()
            endpoint = request.endpoint or 'unknown'
            
            # Log rate limit violation for security monitoring
            self.logger.warning(
                "Rate limit exceeded",
                user_id=user_id,
                ip_address=ip_address,
                endpoint=endpoint,
                user_agent=request.headers.get('User-Agent', 'unknown'),
                limit_exceeded=str(e.description)
            )
            
            return {
                'error': 'Rate limit exceeded',
                'message': 'Too many requests. Please try again later.',
                'retry_after': e.retry_after
            }, 429
    
    def _configure_endpoint_specific_limits(self) -> None:
        """Configure specific rate limits for different endpoint categories."""
        if not self._limiter:
            return
        
        # Authentication endpoints - stricter limits
        @self._limiter.limit("20 per minute", key_func=lambda: f"auth:{get_remote_address()}")
        def auth_endpoint_limit():
            pass
        
        # API endpoints - moderate limits
        @self._limiter.limit("500 per hour; 50 per minute", key_func=self._get_rate_limit_key)
        def api_endpoint_limit():
            pass
        
        # Admin endpoints - very strict limits
        @self._limiter.limit("100 per hour; 10 per minute", key_func=lambda: f"admin:{getattr(g, 'current_user_id', get_remote_address())}")
        def admin_endpoint_limit():
            pass
        
        # File upload endpoints - restrictive limits
        @self._limiter.limit("50 per hour; 5 per minute", key_func=self._get_rate_limit_key)
        def upload_endpoint_limit():
            pass
    
    @property
    def limiter(self) -> Optional[Limiter]:
        """Get the configured Flask-Limiter instance."""
        return self._limiter


class InputValidationManager:
    """
    Input validation and sanitization using marshmallow 3.20+ and bleach 6.0+
    for comprehensive XSS prevention and input security as specified in Section 3.2.2.
    
    Implements enterprise-grade input validation replacing Node.js validation 
    libraries with marshmallow schema validation and bleach HTML sanitization.
    """
    
    def __init__(self):
        """Initialize input validation manager with security configurations."""
        self.logger = structlog.get_logger(f"{__name__}.{self.__class__.__name__}")
        
        # Configure bleach HTML sanitization settings
        self.allowed_tags = [
            'p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li', 
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote'
        ]
        self.allowed_attributes = {
            '*': ['class'],
            'a': ['href', 'title'],
            'img': ['src', 'alt', 'title', 'width', 'height']
        }
        self.allowed_protocols = ['http', 'https', 'mailto']
        
        # Email validation configuration
        self.email_check_deliverability = bool(os.getenv('EMAIL_CHECK_DELIVERABILITY', 'false').lower() == 'true')
        
    def sanitize_html(self, html_content: str, strip_tags: bool = False) -> str:
        """
        Sanitize HTML content to prevent XSS attacks.
        
        Args:
            html_content: Raw HTML content to sanitize
            strip_tags: Whether to strip all tags or allow safe ones
            
        Returns:
            Sanitized HTML content safe for display
        """
        if not html_content:
            return ""
        
        try:
            if strip_tags:
                # Strip all HTML tags
                sanitized = bleach.clean(
                    html_content, 
                    tags=[], 
                    attributes={}, 
                    strip=True
                )
            else:
                # Allow safe HTML tags and attributes
                sanitized = bleach.clean(
                    html_content,
                    tags=self.allowed_tags,
                    attributes=self.allowed_attributes,
                    protocols=self.allowed_protocols,
                    strip=True
                )
            
            # Additional URL validation for links
            sanitized = self._validate_urls_in_html(sanitized)
            
            return sanitized
            
        except Exception as e:
            self.logger.error(
                "HTML sanitization failed",
                error=str(e),
                content_length=len(html_content)
            )
            # Return empty string on sanitization failure for security
            return ""
    
    def validate_email(self, email: str) -> str:
        """
        Validate and normalize email addresses.
        
        Args:
            email: Email address to validate
            
        Returns:
            Normalized email address
            
        Raises:
            SecurityValidationError: When email validation fails
        """
        if not email:
            raise SecurityValidationError("Email address is required")
        
        try:
            # Use email-validator for comprehensive validation
            validation_result = validate_email(
                email,
                check_deliverability=self.email_check_deliverability
            )
            
            # Return normalized email
            normalized_email = validation_result.email
            
            self.logger.debug(
                "Email validation successful",
                original_email=email,
                normalized_email=normalized_email
            )
            
            return normalized_email
            
        except EmailNotValidError as e:
            self.logger.warning(
                "Email validation failed",
                email=email,
                error=str(e)
            )
            raise SecurityValidationError(f"Invalid email address: {str(e)}")
    
    def validate_url(self, url: str, allowed_schemes: Optional[List[str]] = None) -> str:
        """
        Validate URL for security and format compliance.
        
        Args:
            url: URL to validate
            allowed_schemes: List of allowed URL schemes (default: ['http', 'https'])
            
        Returns:
            Validated URL
            
        Raises:
            SecurityValidationError: When URL validation fails
        """
        if not url:
            raise SecurityValidationError("URL is required")
        
        allowed_schemes = allowed_schemes or ['http', 'https']
        
        try:
            parsed_url = urlparse(url)
            
            # Validate scheme
            if parsed_url.scheme.lower() not in allowed_schemes:
                raise SecurityValidationError(
                    f"URL scheme '{parsed_url.scheme}' not allowed. Allowed schemes: {allowed_schemes}"
                )
            
            # Validate domain is not localhost/private IP in production
            if os.getenv('FLASK_ENV') == 'production':
                if parsed_url.hostname:
                    try:
                        ip = ipaddress.ip_address(parsed_url.hostname)
                        if ip.is_private or ip.is_loopback:
                            raise SecurityValidationError("Private/localhost URLs not allowed in production")
                    except ValueError:
                        # Not an IP address, check for localhost
                        if parsed_url.hostname.lower() in ['localhost', '127.0.0.1', '::1']:
                            raise SecurityValidationError("Localhost URLs not allowed in production")
            
            # Basic URL structure validation
            if not parsed_url.netloc:
                raise SecurityValidationError("URL must have a valid domain")
            
            return url
            
        except Exception as e:
            if isinstance(e, SecurityValidationError):
                raise
            self.logger.warning(
                "URL validation failed",
                url=url,
                error=str(e)
            )
            raise SecurityValidationError(f"Invalid URL format: {str(e)}")
    
    def _validate_urls_in_html(self, html_content: str) -> str:
        """
        Validate URLs within HTML content for additional security.
        
        Args:
            html_content: HTML content with potential URLs
            
        Returns:
            HTML content with validated URLs
        """
        # Simple regex to find href attributes (basic implementation)
        href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
        
        def validate_href(match):
            url = match.group(1)
            try:
                validated_url = self.validate_url(url)
                return f'href="{validated_url}"'
            except SecurityValidationError:
                # Remove invalid URLs
                self.logger.warning("Removing invalid URL from HTML", url=url)
                return 'href="#"'
        
        return href_pattern.sub(validate_href, html_content)
    
    def create_base_schema(self) -> type:
        """
        Create base marshmallow schema with common validation patterns.
        
        Returns:
            Base schema class for input validation
        """
        class BaseValidationSchema(Schema):
            """Base schema with common validation patterns."""
            
            @validates_schema
            def validate_no_xss_patterns(self, data, **kwargs):
                """Validate that input doesn't contain common XSS patterns."""
                xss_patterns = [
                    r'<script[^>]*>.*?</script>',
                    r'javascript:',
                    r'vbscript:',
                    r'onload\s*=',
                    r'onerror\s*=',
                    r'onclick\s*=',
                    r'<iframe[^>]*>',
                    r'<object[^>]*>',
                    r'<embed[^>]*>'
                ]
                
                for field_name, field_value in data.items():
                    if isinstance(field_value, str):
                        for pattern in xss_patterns:
                            if re.search(pattern, field_value, re.IGNORECASE):
                                raise ValidationError(
                                    f"Potentially malicious content detected in {field_name}",
                                    field_name
                                )
        
        return BaseValidationSchema


class SecurityHeadersManager:
    """
    Security headers management using Flask-Talisman 1.1.0+ with comprehensive
    HTTP security header enforcement as specified in Section 6.4.3.
    
    Implements complete replacement of Node.js helmet middleware with Flask-Talisman
    providing HTTPS enforcement, HSTS, CSP, and additional security headers.
    """
    
    def __init__(self, app_config: BaseConfig, csp_manager: ContentSecurityPolicyManager):
        """
        Initialize security headers manager with configuration.
        
        Args:
            app_config: Application configuration instance
            csp_manager: Content Security Policy manager instance
        """
        self.app_config = app_config
        self.csp_manager = csp_manager
        self.logger = structlog.get_logger(f"{__name__}.{self.__class__.__name__}")
        
    def configure_talisman(self, app: Flask) -> Talisman:
        """
        Configure Flask-Talisman with comprehensive security headers.
        
        Args:
            app: Flask application instance
            
        Returns:
            Configured Flask-Talisman instance
        """
        try:
            # Get environment-specific CSP policy
            base_csp_policy = self.csp_manager.get_environment_csp_policy()
            
            # Configure Talisman with comprehensive security settings
            talisman = Talisman(
                app=app,
                
                # HTTPS enforcement
                force_https=self.app_config.FORCE_HTTPS,
                force_https_permanent=True,
                strict_transport_security=True,
                strict_transport_security_max_age=self.app_config.HSTS_MAX_AGE,
                strict_transport_security_include_subdomains=self.app_config.HSTS_INCLUDE_SUBDOMAINS,
                strict_transport_security_preload=self.app_config.HSTS_PRELOAD,
                
                # Content Security Policy
                content_security_policy=base_csp_policy,
                content_security_policy_nonce_in=['script-src', 'style-src'],
                content_security_policy_report_only=os.getenv('CSP_REPORT_ONLY', 'false').lower() == 'true',
                content_security_policy_report_uri=os.getenv('CSP_REPORT_URI'),
                
                # Referrer Policy
                referrer_policy=self.app_config.REFERRER_POLICY,
                
                # Feature Policy (Permissions Policy)
                feature_policy=self.app_config.FEATURE_POLICY,
                
                # Additional security headers
                force_file_save=False,  # Don't force file downloads
                
                # Session cookie security
                session_cookie_secure=self.app_config.SESSION_COOKIE_SECURE,
                session_cookie_http_only=self.app_config.SESSION_COOKIE_HTTPONLY,
                session_cookie_samesite=self.app_config.SESSION_COOKIE_SAMESITE,
                
                # Custom response handlers
                content_security_policy_nonce_in=['script-src', 'style-src']
            )
            
            # Configure CSP nonce generation
            self._configure_csp_nonce_generation(app)
            
            # Configure custom security headers
            self._configure_additional_headers(app)
            
            self.logger.info(
                "Flask-Talisman configured successfully",
                https_enforcement=self.app_config.FORCE_HTTPS,
                hsts_max_age=self.app_config.HSTS_MAX_AGE,
                csp_report_only=os.getenv('CSP_REPORT_ONLY', 'false'),
                environment=os.getenv('FLASK_ENV', 'production')
            )
            
            return talisman
            
        except Exception as e:
            self.logger.error(
                "Failed to configure Flask-Talisman",
                error=str(e),
                https_enforcement=self.app_config.FORCE_HTTPS
            )
            raise SecurityConfigurationError(f"Talisman configuration failed: {str(e)}")
    
    def _configure_csp_nonce_generation(self, app: Flask) -> None:
        """
        Configure CSP nonce generation for dynamic content.
        
        Args:
            app: Flask application instance
        """
        @app.before_request
        def generate_csp_nonce():
            """Generate CSP nonce for each request."""
            if request.endpoint and not request.endpoint.startswith('static'):
                self.csp_manager.generate_nonce()
    
    def _configure_additional_headers(self, app: Flask) -> None:
        """
        Configure additional custom security headers.
        
        Args:
            app: Flask application instance
        """
        @app.after_request
        def add_custom_security_headers(response):
            """Add custom security headers to all responses."""
            
            # X-Content-Type-Options
            response.headers['X-Content-Type-Options'] = 'nosniff'
            
            # X-Frame-Options (redundant with CSP frame-ancestors but provides fallback)
            response.headers['X-Frame-Options'] = self.app_config.X_FRAME_OPTIONS
            
            # X-XSS-Protection (legacy header but still useful)
            response.headers['X-XSS-Protection'] = self.app_config.X_XSS_PROTECTION
            
            # X-Download-Options (IE specific)
            response.headers['X-Download-Options'] = 'noopen'
            
            # X-Permitted-Cross-Domain-Policies (Flash/PDF)
            response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
            
            # Custom application header
            response.headers['X-Application'] = self.app_config.APP_NAME
            response.headers['X-Version'] = self.app_config.APP_VERSION
            
            # Security contact header
            security_contact = os.getenv('SECURITY_CONTACT_EMAIL')
            if security_contact:
                response.headers['X-Security-Contact'] = security_contact
            
            return response


class CORSManager:
    """
    CORS (Cross-Origin Resource Sharing) management using Flask-CORS 4.0+
    with environment-specific origin policies as specified in Section 3.2.1.
    
    Implements secure cross-origin request handling replacing Node.js cors
    middleware with Flask-CORS for comprehensive origin validation.
    """
    
    def __init__(self, app_config: BaseConfig):
        """
        Initialize CORS manager with application configuration.
        
        Args:
            app_config: Application configuration instance
        """
        self.app_config = app_config
        self.logger = structlog.get_logger(f"{__name__}.{self.__class__.__name__}")
        
    def configure_cors(self, app: Flask) -> CORS:
        """
        Configure Flask-CORS with security-focused policies.
        
        Args:
            app: Flask application instance
            
        Returns:
            Configured Flask-CORS instance
        """
        try:
            # Get environment-specific CORS origins
            allowed_origins = self._get_cors_origins()
            
            # Configure CORS with comprehensive settings
            cors = CORS(
                app=app,
                origins=allowed_origins,
                methods=self.app_config.CORS_METHODS,
                allow_headers=self.app_config.CORS_ALLOW_HEADERS,
                expose_headers=self.app_config.CORS_EXPOSE_HEADERS,
                supports_credentials=self.app_config.CORS_SUPPORTS_CREDENTIALS,
                max_age=self.app_config.CORS_MAX_AGE,
                send_wildcard=False,  # Never send wildcard in production
                vary_header=True,  # Add Vary: Origin header
                automatic_options=True,  # Handle OPTIONS requests automatically
                intercept_exceptions=False  # Let Flask handle exceptions
            )
            
            # Configure specific CORS policies for different routes
            self._configure_route_specific_cors(app, allowed_origins)
            
            # Configure CORS logging
            self._configure_cors_logging(app)
            
            self.logger.info(
                "Flask-CORS configured successfully",
                allowed_origins_count=len(allowed_origins),
                supports_credentials=self.app_config.CORS_SUPPORTS_CREDENTIALS,
                max_age=self.app_config.CORS_MAX_AGE,
                environment=os.getenv('FLASK_ENV', 'production')
            )
            
            return cors
            
        except Exception as e:
            self.logger.error(
                "Failed to configure Flask-CORS",
                error=str(e),
                origins_count=len(self.app_config.CORS_ORIGINS)
            )
            raise SecurityConfigurationError(f"CORS configuration failed: {str(e)}")
    
    def _get_cors_origins(self) -> List[str]:
        """
        Get environment-specific CORS origins with validation.
        
        Returns:
            List of validated CORS origins
        """
        # Start with base configuration origins
        origins = self.app_config.CORS_ORIGINS.copy()
        
        # Validate each origin
        validated_origins = []
        for origin in origins:
            if self._validate_cors_origin(origin):
                validated_origins.append(origin)
            else:
                self.logger.warning("Invalid CORS origin removed", origin=origin)
        
        # Add dynamic origins from environment (with validation)
        env_origins = os.getenv('ADDITIONAL_CORS_ORIGINS')
        if env_origins:
            for origin in env_origins.split(','):
                origin = origin.strip()
                if origin and self._validate_cors_origin(origin):
                    validated_origins.append(origin)
        
        return validated_origins
    
    def _validate_cors_origin(self, origin: str) -> bool:
        """
        Validate CORS origin for security compliance.
        
        Args:
            origin: CORS origin to validate
            
        Returns:
            True if origin is valid and secure
        """
        if not origin:
            return False
        
        # Parse origin URL
        try:
            parsed = urlparse(origin)
        except Exception:
            return False
        
        # Validate scheme
        if parsed.scheme not in ['http', 'https']:
            return False
        
        # Require HTTPS in production (except for localhost development)
        if os.getenv('FLASK_ENV') == 'production':
            if parsed.scheme != 'https':
                # Allow http only for localhost in staging/development
                if not (parsed.hostname and parsed.hostname.lower() in ['localhost', '127.0.0.1']):
                    return False
        
        # Validate hostname exists
        if not parsed.hostname:
            return False
        
        # Block obviously malicious patterns
        malicious_patterns = ['eval', 'script', 'javascript', 'vbscript', 'data:']
        origin_lower = origin.lower()
        if any(pattern in origin_lower for pattern in malicious_patterns):
            return False
        
        return True
    
    def _configure_route_specific_cors(self, app: Flask, allowed_origins: List[str]) -> None:
        """
        Configure route-specific CORS policies for enhanced security.
        
        Args:
            app: Flask application instance
            allowed_origins: List of allowed origins
        """
        from flask_cors import cross_origin
        
        # Admin routes - most restrictive CORS
        admin_origins = [origin for origin in allowed_origins if 'admin' in origin]
        
        # API routes - moderate CORS restrictions
        api_origins = [origin for origin in allowed_origins if not origin.startswith('file://')]
        
        # Public routes - broader CORS (but still restricted)
        public_origins = allowed_origins
        
        # Store CORS configurations for route decorators
        app.config['ADMIN_CORS_ORIGINS'] = admin_origins
        app.config['API_CORS_ORIGINS'] = api_origins
        app.config['PUBLIC_CORS_ORIGINS'] = public_origins
    
    def _configure_cors_logging(self, app: Flask) -> None:
        """
        Configure CORS request logging for security monitoring.
        
        Args:
            app: Flask application instance
        """
        @app.before_request
        def log_cors_requests():
            """Log CORS preflight and cross-origin requests."""
            origin = request.headers.get('Origin')
            if origin:
                self.logger.debug(
                    "Cross-origin request received",
                    origin=origin,
                    method=request.method,
                    endpoint=request.endpoint,
                    is_preflight=request.method == 'OPTIONS'
                )


class SecurityManager:
    """
    Centralized security manager orchestrating all security components
    for comprehensive Flask application security configuration.
    
    Coordinates Flask-Talisman, Flask-CORS, Flask-Limiter, and input validation
    to provide enterprise-grade security replacing Node.js security middleware.
    """
    
    def __init__(self, app_config: Optional[BaseConfig] = None):
        """
        Initialize security manager with configuration dependencies.
        
        Args:
            app_config: Application configuration (auto-loads if None)
        """
        self.app_config = app_config or get_config()
        self.logger = structlog.get_logger(f"{__name__}.{self.__class__.__name__}")
        
        # Initialize component managers
        self.csp_manager = ContentSecurityPolicyManager(
            flask_env=getattr(self.app_config, 'FLASK_ENV', 'production')
        )
        self.headers_manager = SecurityHeadersManager(self.app_config, self.csp_manager)
        self.cors_manager = CORSManager(self.app_config)
        self.input_validator = InputValidationManager()
        
        # Initialize rate limiting if Redis is available
        try:
            redis_config = RedisConfig()
            self.rate_limit_manager = RateLimitManager(redis_config)
        except Exception as e:
            self.logger.warning(
                "Rate limiting disabled - Redis configuration failed",
                error=str(e)
            )
            self.rate_limit_manager = None
        
        # Component instances
        self._talisman: Optional[Talisman] = None
        self._cors: Optional[CORS] = None
        self._limiter: Optional[Limiter] = None
    
    def configure_security(self, app: Flask) -> Dict[str, Any]:
        """
        Configure comprehensive security for Flask application.
        
        Args:
            app: Flask application instance
            
        Returns:
            Dictionary containing configured security components
        """
        try:
            security_components = {}
            
            # Configure Flask-Talisman security headers
            self._talisman = self.headers_manager.configure_talisman(app)
            security_components['talisman'] = self._talisman
            
            # Configure Flask-CORS
            self._cors = self.cors_manager.configure_cors(app)
            security_components['cors'] = self._cors
            
            # Configure Flask-Limiter (if available)
            if self.rate_limit_manager:
                self._limiter = self.rate_limit_manager.configure_rate_limiter(app)
                security_components['limiter'] = self._limiter
            
            # Configure error handlers
            self._configure_security_error_handlers(app)
            
            # Configure security middleware
            self._configure_security_middleware(app)
            
            # Configure security monitoring
            self._configure_security_monitoring(app)
            
            # Store security manager in app context
            app.security_manager = self
            
            self.logger.info(
                "Security configuration completed successfully",
                components_configured=list(security_components.keys()),
                https_enforcement=getattr(self.app_config, 'FORCE_HTTPS', False),
                environment=getattr(self.app_config, 'FLASK_ENV', 'production')
            )
            
            return security_components
            
        except Exception as e:
            self.logger.error(
                "Security configuration failed",
                error=str(e),
                component_failures=str(e)
            )
            raise SecurityConfigurationError(f"Security configuration failed: {str(e)}")
    
    def _configure_security_error_handlers(self, app: Flask) -> None:
        """
        Configure security-specific error handlers.
        
        Args:
            app: Flask application instance
        """
        @app.errorhandler(403)
        def forbidden_handler(error):
            """Handle forbidden access attempts."""
            self.logger.warning(
                "Forbidden access attempt",
                ip_address=get_remote_address(),
                user_agent=request.headers.get('User-Agent'),
                endpoint=request.endpoint,
                method=request.method
            )
            return {
                'error': 'Forbidden',
                'message': 'Access denied. Insufficient permissions.'
            }, 403
        
        @app.errorhandler(400)
        def bad_request_handler(error):
            """Handle bad request with security logging."""
            self.logger.warning(
                "Bad request received",
                ip_address=get_remote_address(),
                endpoint=request.endpoint,
                method=request.method,
                error_description=str(error)
            )
            return {
                'error': 'Bad Request',
                'message': 'Invalid request format or parameters.'
            }, 400
    
    def _configure_security_middleware(self, app: Flask) -> None:
        """
        Configure security middleware for request processing.
        
        Args:
            app: Flask application instance
        """
        @app.before_request
        def security_request_handler():
            """Process security checks for each request."""
            
            # Skip security checks for static files
            if request.endpoint and request.endpoint.startswith('static'):
                return
            
            # Log security-relevant request information
            self.logger.debug(
                "Request security check",
                ip_address=get_remote_address(),
                user_agent=request.headers.get('User-Agent', 'unknown'),
                endpoint=request.endpoint,
                method=request.method,
                content_length=request.content_length or 0
            )
            
            # Check for obviously malicious request patterns
            if self._is_suspicious_request():
                self.logger.warning(
                    "Suspicious request detected",
                    ip_address=get_remote_address(),
                    user_agent=request.headers.get('User-Agent', 'unknown'),
                    path=request.path,
                    method=request.method
                )
                # Could implement additional blocking logic here
    
    def _configure_security_monitoring(self, app: Flask) -> None:
        """
        Configure security monitoring and metrics collection.
        
        Args:
            app: Flask application instance
        """
        @app.after_request
        def security_response_handler(response):
            """Process security monitoring for responses."""
            
            # Log security response information
            if response.status_code >= 400:
                self.logger.info(
                    "Security response",
                    status_code=response.status_code,
                    ip_address=get_remote_address(),
                    endpoint=request.endpoint,
                    method=request.method
                )
            
            # Add security headers validation
            required_headers = [
                'X-Content-Type-Options',
                'X-Frame-Options',
                'Strict-Transport-Security'
            ]
            
            missing_headers = [
                header for header in required_headers 
                if header not in response.headers
            ]
            
            if missing_headers and response.status_code < 400:
                self.logger.warning(
                    "Missing security headers",
                    missing_headers=missing_headers,
                    endpoint=request.endpoint
                )
            
            return response
    
    def _is_suspicious_request(self) -> bool:
        """
        Check if request contains suspicious patterns.
        
        Returns:
            True if request appears suspicious
        """
        # Check for common attack patterns in URL
        suspicious_patterns = [
            '../', '..\\',  # Directory traversal
            '<script', 'javascript:',  # XSS attempts
            'union select', 'drop table',  # SQL injection
            'eval(', 'exec(',  # Code injection
            '%3cscript', '%2e%2e',  # URL-encoded attacks
        ]
        
        request_path = request.path.lower()
        query_string = request.query_string.decode('utf-8', errors='ignore').lower()
        
        for pattern in suspicious_patterns:
            if pattern in request_path or pattern in query_string:
                return True
        
        # Check for oversized requests
        max_content_length = getattr(self.app_config, 'MAX_CONTENT_LENGTH', 16 * 1024 * 1024)
        if request.content_length and request.content_length > max_content_length:
            return True
        
        return False
    
    @property
    def talisman(self) -> Optional[Talisman]:
        """Get the configured Flask-Talisman instance."""
        return self._talisman
    
    @property
    def cors(self) -> Optional[CORS]:
        """Get the configured Flask-CORS instance."""
        return self._cors
    
    @property
    def limiter(self) -> Optional[Limiter]:
        """Get the configured Flask-Limiter instance."""
        return self._limiter
    
    def get_input_validator(self) -> InputValidationManager:
        """Get the input validation manager."""
        return self.input_validator


def init_security_config(app: Flask, app_config: Optional[BaseConfig] = None) -> SecurityManager:
    """
    Initialize comprehensive security configuration for Flask application.
    
    This function serves as the main entry point for configuring all security
    components including Flask-Talisman, Flask-CORS, Flask-Limiter, and input
    validation as specified in the migration requirements.
    
    Args:
        app: Flask application instance
        app_config: Optional application configuration (auto-loads if None)
        
    Returns:
        Configured SecurityManager instance
        
    Raises:
        SecurityConfigurationError: When security configuration fails
    """
    try:
        # Initialize security manager
        security_manager = SecurityManager(app_config)
        
        # Configure all security components
        security_components = security_manager.configure_security(app)
        
        # Log successful initialization
        logger.info(
            "Security configuration initialized successfully",
            components=list(security_components.keys()),
            app_name=getattr(app_config or get_config(), 'APP_NAME', 'Flask App'),
            environment=os.getenv('FLASK_ENV', 'production')
        )
        
        return security_manager
        
    except Exception as e:
        logger.error(
            "Failed to initialize security configuration",
            error=str(e),
            app_name=getattr(app_config or get_config(), 'APP_NAME', 'Flask App')
        )
        raise SecurityConfigurationError(f"Security initialization failed: {str(e)}")


# Export all security components for external use
__all__ = [
    'SecurityManager',
    'ContentSecurityPolicyManager',
    'RateLimitManager', 
    'InputValidationManager',
    'SecurityHeadersManager',
    'CORSManager',
    'init_security_config',
    'SecurityConfigurationError',
    'SecurityValidationError'
]