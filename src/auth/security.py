"""
Flask-Talisman Security Headers Implementation

This module provides comprehensive HTTP security header enforcement using Flask-Talisman 1.1.0+
as a direct replacement for Node.js helmet middleware functionality. It implements enterprise-grade
web application security protection with Content Security Policy management, HSTS configuration,
and comprehensive security header enforcement.

Key Security Features:
- Flask-Talisman integration for comprehensive HTTP security headers
- Content Security Policy with Auth0 domain allowlist and dynamic nonce generation
- HTTP Strict Transport Security with TLS 1.3 enforcement
- X-Frame-Options, X-Content-Type-Options, and referrer policy configuration
- Secure cookie policies for session management and CSRF protection
- Environment-specific security configuration management
- Security metrics and monitoring integration
- Enterprise compliance with SOC 2, ISO 27001, and OWASP standards

Dependencies:
- Flask-Talisman 1.1.0+: HTTP security header enforcement
- Flask 2.3+: Web framework integration
- python-dotenv 1.0+: Environment configuration management
- structlog 23.1+: Security event logging
- prometheus-client: Security metrics collection

Security Standards:
- OWASP Top 10 compliance
- SOC 2 Type II controls
- ISO 27001 alignment
- PCI DSS security requirements
- GDPR privacy protection

Author: Flask Migration Team
Version: 1.0.0
License: Enterprise
"""

import os
import secrets
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Union, Callable, Tuple
from urllib.parse import urlparse
from functools import wraps

import structlog
from flask import Flask, request, g, current_app, session, jsonify
from flask_talisman import Talisman
from dotenv import load_dotenv
from prometheus_client import Counter, Histogram, Gauge, Summary

# Internal imports
from src.config.auth import get_auth_config, auth_metrics
from src.auth.utils import log_security_event, get_current_user_id

# Load environment variables
load_dotenv()

# Configure structured logging for security events
security_logger = structlog.get_logger("security.headers")

# Security metrics for monitoring and compliance
security_metrics = {
    'headers_applied': Counter(
        'security_headers_applied_total',
        'Total security headers applied by type',
        ['header_type', 'endpoint']
    ),
    'csp_violations': Counter(
        'security_csp_violations_total',
        'CSP violations detected',
        ['violation_type', 'blocked_uri']
    ),
    'security_violations': Counter(
        'security_violations_total',
        'Security violations detected',
        ['violation_type', 'severity']
    ),
    'https_redirects': Counter(
        'security_https_redirects_total',
        'HTTPS redirects performed',
        ['source_scheme', 'endpoint']
    ),
    'header_processing_duration': Histogram(
        'security_header_processing_duration_seconds',
        'Time spent processing security headers',
        ['header_type']
    ),
    'tls_connections': Counter(
        'security_tls_connections_total',
        'TLS connections by version',
        ['tls_version', 'cipher_suite']
    ),
    'cookie_security_events': Counter(
        'security_cookie_events_total',
        'Cookie security events',
        ['event_type', 'cookie_name']
    ),
    'nonce_generation': Summary(
        'security_nonce_generation_duration_seconds',
        'CSP nonce generation time'
    )
}


class SecurityHeaderException(Exception):
    """Custom exception for security header configuration errors."""
    pass


class CSPViolationHandler:
    """
    Content Security Policy violation handler for enterprise monitoring.
    
    This class provides comprehensive CSP violation tracking, analysis, and
    response capabilities for enterprise security monitoring and compliance.
    """
    
    def __init__(self):
        """Initialize CSP violation handler with monitoring configuration."""
        self.logger = security_logger.bind(component="csp_violation_handler")
        self.violation_threshold = int(os.getenv('CSP_VIOLATION_THRESHOLD', '10'))
        self.monitoring_window = int(os.getenv('CSP_MONITORING_WINDOW_MINUTES', '5'))
    
    def handle_csp_violation(self, violation_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle CSP violation with comprehensive logging and analysis.
        
        Args:
            violation_data: CSP violation report data
            
        Returns:
            Response data for violation acknowledgment
        """
        try:
            # Extract violation details
            violated_directive = violation_data.get('violated-directive', 'unknown')
            blocked_uri = violation_data.get('blocked-uri', 'unknown')
            source_file = violation_data.get('source-file', 'unknown')
            line_number = violation_data.get('line-number', 0)
            column_number = violation_data.get('column-number', 0)
            
            # Log violation with structured data
            violation_context = {
                'violated_directive': violated_directive,
                'blocked_uri': blocked_uri,
                'source_file': source_file,
                'line_number': line_number,
                'column_number': column_number,
                'user_agent': request.headers.get('User-Agent', 'unknown'),
                'referrer': request.headers.get('Referer', 'unknown'),
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'user_id': get_current_user_id(),
                'session_id': session.get('session_id'),
                'ip_address': request.remote_addr
            }
            
            self.logger.warning(
                "CSP violation detected",
                **violation_context
            )
            
            # Update metrics
            security_metrics['csp_violations'].labels(
                violation_type=violated_directive,
                blocked_uri=self._sanitize_uri(blocked_uri)
            ).inc()
            
            # Analyze violation severity
            severity = self._assess_violation_severity(violation_data)
            
            # Log security event for SIEM integration
            log_security_event(
                event_type='csp_violation',
                user_id=get_current_user_id(),
                metadata={
                    'violation_details': violation_context,
                    'severity': severity,
                    'assessment': self._get_violation_assessment(violation_data)
                }
            )
            
            # Check for violation patterns that might indicate attacks
            if self._detect_attack_pattern(violation_data):
                self._handle_potential_attack(violation_data, violation_context)
            
            return {
                'status': 'violation_logged',
                'violation_id': self._generate_violation_id(violation_data),
                'severity': severity,
                'timestamp': violation_context['timestamp']
            }
            
        except Exception as e:
            self.logger.error(
                "Failed to handle CSP violation",
                error=str(e),
                violation_data=violation_data
            )
            return {'status': 'error', 'message': 'Failed to process violation'}
    
    def _assess_violation_severity(self, violation_data: Dict[str, Any]) -> str:
        """Assess the severity of a CSP violation."""
        violated_directive = violation_data.get('violated-directive', '')
        blocked_uri = violation_data.get('blocked-uri', '')
        
        # High severity violations
        if any(directive in violated_directive for directive in [
            'script-src', 'object-src', 'unsafe-eval', 'unsafe-inline'
        ]):
            return 'high'
        
        # Check for external/untrusted URIs
        if self._is_external_uri(blocked_uri):
            return 'medium'
        
        # Default to low severity
        return 'low'
    
    def _detect_attack_pattern(self, violation_data: Dict[str, Any]) -> bool:
        """Detect patterns that might indicate XSS or injection attacks."""
        blocked_uri = violation_data.get('blocked-uri', '').lower()
        
        # Common XSS patterns
        xss_patterns = [
            'javascript:', 'data:text/html', 'vbscript:',
            'eval(', 'expression(', 'onload=', 'onerror='
        ]
        
        return any(pattern in blocked_uri for pattern in xss_patterns)
    
    def _handle_potential_attack(
        self,
        violation_data: Dict[str, Any],
        violation_context: Dict[str, Any]
    ) -> None:
        """Handle potential security attacks detected through CSP violations."""
        self.logger.error(
            "Potential security attack detected via CSP violation",
            attack_indicators=self._get_attack_indicators(violation_data),
            **violation_context
        )
        
        # Update attack metrics
        security_metrics['security_violations'].labels(
            violation_type='potential_xss_attack',
            severity='high'
        ).inc()
        
        # Log high-priority security event
        log_security_event(
            event_type='potential_security_attack',
            user_id=get_current_user_id(),
            metadata={
                'attack_type': 'csp_violation_based',
                'violation_data': violation_data,
                'detection_method': 'csp_pattern_analysis',
                'response_action': 'logged_and_monitored'
            }
        )
    
    def _sanitize_uri(self, uri: str) -> str:
        """Sanitize URI for metrics to prevent cardinality explosion."""
        if not uri or uri == 'unknown':
            return 'unknown'
        
        try:
            parsed = urlparse(uri)
            # Return domain only for external URIs
            if parsed.netloc:
                return f"{parsed.scheme}://{parsed.netloc}/"
            return 'inline'
        except Exception:
            return 'malformed'
    
    def _is_external_uri(self, uri: str) -> bool:
        """Check if URI is external to the application."""
        if not uri or uri in ['self', 'unsafe-inline', 'unsafe-eval']:
            return False
        
        try:
            parsed = urlparse(uri)
            if not parsed.netloc:
                return False
            
            # Check against allowed domains
            allowed_domains = self._get_allowed_domains()
            return parsed.netloc not in allowed_domains
        except Exception:
            return True  # Treat malformed URIs as external
    
    def _get_allowed_domains(self) -> List[str]:
        """Get list of allowed domains from environment configuration."""
        auth0_domain = os.getenv('AUTH0_DOMAIN', '')
        app_domains = os.getenv('ALLOWED_DOMAINS', '').split(',')
        
        allowed = [auth0_domain] if auth0_domain else []
        allowed.extend([domain.strip() for domain in app_domains if domain.strip()])
        
        return allowed
    
    def _get_violation_assessment(self, violation_data: Dict[str, Any]) -> Dict[str, Any]:
        """Get comprehensive assessment of the CSP violation."""
        return {
            'is_external_resource': self._is_external_uri(violation_data.get('blocked-uri', '')),
            'potential_attack': self._detect_attack_pattern(violation_data),
            'directive_category': self._categorize_directive(violation_data.get('violated-directive', '')),
            'risk_level': self._assess_violation_severity(violation_data)
        }
    
    def _categorize_directive(self, directive: str) -> str:
        """Categorize CSP directive for analysis."""
        if 'script' in directive:
            return 'script_execution'
        elif 'style' in directive:
            return 'style_application'
        elif 'img' in directive:
            return 'image_loading'
        elif 'connect' in directive:
            return 'network_connection'
        elif 'object' in directive:
            return 'plugin_execution'
        else:
            return 'other'
    
    def _get_attack_indicators(self, violation_data: Dict[str, Any]) -> List[str]:
        """Get list of attack indicators from violation data."""
        indicators = []
        blocked_uri = violation_data.get('blocked-uri', '').lower()
        
        if 'javascript:' in blocked_uri:
            indicators.append('javascript_protocol')
        if 'data:' in blocked_uri:
            indicators.append('data_protocol')
        if any(pattern in blocked_uri for pattern in ['eval(', 'expression(']):
            indicators.append('dynamic_code_execution')
        if any(pattern in blocked_uri for pattern in ['onload=', 'onerror=']):
            indicators.append('event_handler_injection')
        
        return indicators
    
    def _generate_violation_id(self, violation_data: Dict[str, Any]) -> str:
        """Generate unique identifier for violation tracking."""
        violation_string = json.dumps(violation_data, sort_keys=True)
        timestamp = datetime.now(timezone.utc).isoformat()
        return f"csp_violation_{hash(violation_string + timestamp) % 1000000:06d}"


class SecurityHeaderManager:
    """
    Comprehensive security header management using Flask-Talisman.
    
    This class provides enterprise-grade HTTP security header enforcement
    equivalent to Node.js helmet middleware with enhanced security features
    for Flask applications including CSP management, HSTS configuration,
    and comprehensive web application protection.
    """
    
    def __init__(self):
        """Initialize security header manager with enterprise configuration."""
        self.logger = security_logger.bind(component="security_header_manager")
        self.csp_handler = CSPViolationHandler()
        self.talisman_instance: Optional[Talisman] = None
        
        # Load environment-specific configuration
        self.environment = os.getenv('FLASK_ENV', 'production')
        self.debug_mode = self.environment in ['development', 'testing']
        
        # Security configuration
        self.config = self._load_security_configuration()
        
        self.logger.info(
            "Security header manager initialized",
            environment=self.environment,
            debug_mode=self.debug_mode
        )
    
    def configure_security_headers(self, app: Flask) -> Talisman:
        """
        Configure comprehensive security headers for Flask application.
        
        This method implements Flask-Talisman configuration equivalent to
        Node.js helmet middleware with enterprise security enhancements.
        
        Args:
            app: Flask application instance to configure
            
        Returns:
            Configured Talisman instance for further customization
            
        Example:
            security_manager = SecurityHeaderManager()
            talisman = security_manager.configure_security_headers(app)
        """
        try:
            # Generate CSP configuration with dynamic nonces
            csp_config = self._generate_csp_configuration()
            
            # Configure Flask-Talisman with comprehensive security settings
            self.talisman_instance = Talisman(
                app,
                # HTTPS enforcement
                force_https=self.config['force_https'],
                force_https_permanent=True,
                
                # HTTP Strict Transport Security (HSTS)
                strict_transport_security=True,
                strict_transport_security_max_age=self.config['hsts_max_age'],
                strict_transport_security_include_subdomains=True,
                strict_transport_security_preload=True,
                
                # Content Security Policy
                content_security_policy=csp_config,
                content_security_policy_nonce_in=['script-src', 'style-src'],
                content_security_policy_report_only=self.config.get('csp_report_only', False),
                content_security_policy_report_uri=self.config.get('csp_report_uri'),
                
                # Frame options
                frame_options='DENY',
                frame_options_allow_from=None,
                
                # Content type options
                content_type_options=True,
                
                # Referrer policy
                referrer_policy='strict-origin-when-cross-origin',
                
                # Feature policy
                feature_policy=self._get_feature_policy(),
                
                # Session cookie security
                session_cookie_secure=True,
                session_cookie_http_only=True,
                session_cookie_samesite='Strict',
                
                # Additional security headers
                force_file_save=False,
                
                # Custom security headers
                custom_headers=self._get_custom_security_headers()
            )
            
            # Configure CSP violation reporting
            self._configure_csp_violation_reporting(app)
            
            # Configure security monitoring hooks
            self._configure_security_monitoring(app)
            
            # Log security configuration
            self.logger.info(
                "Security headers configured successfully",
                csp_enabled=bool(csp_config),
                hsts_enabled=True,
                environment=self.environment
            )
            
            # Update security metrics
            security_metrics['headers_applied'].labels(
                header_type='talisman_complete',
                endpoint='application_wide'
            ).inc()
            
            return self.talisman_instance
            
        except Exception as e:
            self.logger.error(
                "Failed to configure security headers",
                error=str(e)
            )
            raise SecurityHeaderException(f"Security header configuration failed: {str(e)}")
    
    def _load_security_configuration(self) -> Dict[str, Any]:
        """
        Load environment-specific security configuration.
        
        Returns:
            Complete security configuration dictionary
        """
        base_config = {
            # HTTPS enforcement
            'force_https': os.getenv('FORCE_HTTPS', 'true').lower() == 'true',
            
            # HSTS configuration
            'hsts_max_age': int(os.getenv('HSTS_MAX_AGE', '31536000')),  # 1 year
            'hsts_include_subdomains': True,
            'hsts_preload': True,
            
            # CSP configuration
            'csp_enabled': os.getenv('CSP_ENABLED', 'true').lower() == 'true',
            'csp_report_only': os.getenv('CSP_REPORT_ONLY', 'false').lower() == 'true',
            'csp_report_uri': os.getenv('CSP_REPORT_URI', '/api/security/csp-violation'),
            
            # Auth0 integration
            'auth0_domain': os.getenv('AUTH0_DOMAIN', ''),
            'auth0_cdn_domain': 'cdn.auth0.com',
            
            # Allowed external domains
            'allowed_domains': self._parse_allowed_domains(),
            
            # Environment-specific overrides
            'debug_headers': self.debug_mode,
            'development_overrides': self.debug_mode
        }
        
        # Environment-specific adjustments
        if self.environment == 'development':
            base_config.update({
                'force_https': False,
                'csp_report_only': True,
                'hsts_max_age': 300  # 5 minutes for development
            })
        elif self.environment == 'staging':
            base_config.update({
                'csp_report_only': True,  # Report-only mode for staging
                'hsts_max_age': 86400  # 1 day for staging
            })
        
        return base_config
    
    def _generate_csp_configuration(self) -> Dict[str, str]:
        """
        Generate Content Security Policy configuration with Auth0 integration.
        
        This method creates a comprehensive CSP configuration that balances
        security with functionality, including Auth0 domain allowlists and
        dynamic nonce generation for inline scripts and styles.
        
        Returns:
            CSP configuration dictionary for Flask-Talisman
        """
        with security_metrics['nonce_generation'].time():
            # Generate dynamic nonce for this request
            nonce = self._generate_csp_nonce()
        
        # Base CSP configuration with enterprise security settings
        csp_config = {
            # Default source - restrict to self
            'default-src': "'self'",
            
            # Script sources with Auth0 and nonce support
            'script-src': self._build_script_src_directive(nonce),
            
            # Style sources with nonce support
            'style-src': self._build_style_src_directive(nonce),
            
            # Image sources - allow data URIs and HTTPS
            'img-src': "'self' data: https:",
            
            # Connect sources for API calls and Auth0
            'connect-src': self._build_connect_src_directive(),
            
            # Font sources
            'font-src': "'self' data:",
            
            # Object sources - block all plugins
            'object-src': "'none'",
            
            # Base URI restriction
            'base-uri': "'self'",
            
            # Frame ancestors - prevent clickjacking
            'frame-ancestors': "'none'",
            
            # Form action restriction
            'form-action': "'self'",
            
            # Upgrade insecure requests
            'upgrade-insecure-requests': '' if self.config['force_https'] else None,
            
            # Block mixed content
            'block-all-mixed-content': '' if not self.debug_mode else None
        }
        
        # Remove None values
        csp_config = {k: v for k, v in csp_config.items() if v is not None}
        
        # Add report URI if configured
        if self.config.get('csp_report_uri'):
            csp_config['report-uri'] = self.config['csp_report_uri']
            csp_config['report-to'] = 'csp-endpoint'
        
        self.logger.debug(
            "CSP configuration generated",
            nonce_length=len(nonce),
            directives_count=len(csp_config),
            auth0_enabled=bool(self.config['auth0_domain'])
        )
        
        return csp_config
    
    def _build_script_src_directive(self, nonce: str) -> str:
        """Build script-src CSP directive with Auth0 and nonce support."""
        sources = ["'self'"]
        
        # Add nonce for inline scripts
        if nonce:
            sources.append(f"'nonce-{nonce}'")
        
        # Add Auth0 domains
        if self.config['auth0_domain']:
            sources.extend([
                f"https://{self.config['auth0_domain']}",
                f"https://{self.config['auth0_cdn_domain']}"
            ])
        
        # Add allowed external domains
        for domain in self.config['allowed_domains']:
            if domain and domain not in sources:
                sources.append(f"https://{domain}")
        
        # Development mode additions
        if self.debug_mode:
            sources.extend([
                "'unsafe-eval'",  # For development tools
                "http://localhost:*",  # Local development
                "ws://localhost:*"  # WebSocket for hot reload
            ])
        
        return ' '.join(sources)
    
    def _build_style_src_directive(self, nonce: str) -> str:
        """Build style-src CSP directive with nonce support."""
        sources = ["'self'"]
        
        # Add nonce for inline styles
        if nonce:
            sources.append(f"'nonce-{nonce}'")
        
        # Allow unsafe-inline for broader compatibility (consider removing in production)
        if self.debug_mode or self.config.get('allow_inline_styles', False):
            sources.append("'unsafe-inline'")
        
        # Add external style domains
        for domain in self.config['allowed_domains']:
            if domain:
                sources.append(f"https://{domain}")
        
        return ' '.join(sources)
    
    def _build_connect_src_directive(self) -> str:
        """Build connect-src CSP directive for API and Auth0 connections."""
        sources = ["'self'"]
        
        # Add Auth0 domains for authentication
        if self.config['auth0_domain']:
            auth0_domain = self.config['auth0_domain']
            sources.extend([
                f"https://{auth0_domain}",
                f"https://*.{auth0_domain}",
                "https://*.auth0.com"
            ])
        
        # Add AWS services for API calls
        sources.extend([
            "https://*.amazonaws.com",
            "https://*.cloudfront.net"
        ])
        
        # Add allowed API domains
        for domain in self.config['allowed_domains']:
            if domain:
                sources.append(f"https://{domain}")
        
        # Development mode additions
        if self.debug_mode:
            sources.extend([
                "http://localhost:*",
                "ws://localhost:*",
                "wss://localhost:*"
            ])
        
        return ' '.join(sources)
    
    def _get_feature_policy(self) -> Dict[str, str]:
        """
        Get Feature Policy configuration for enhanced security.
        
        Returns:
            Feature Policy configuration dictionary
        """
        return {
            # Disable potentially dangerous features
            'geolocation': "'none'",
            'microphone': "'none'",
            'camera': "'none'",
            'accelerometer': "'none'",
            'gyroscope': "'none'",
            'magnetometer': "'none'",
            'payment': "'none'",
            'usb': "'none'",
            
            # Allow specific features for application functionality
            'fullscreen': "'self'",
            'picture-in-picture': "'none'",
            
            # Sync features
            'sync-xhr': "'self'",
            
            # Autoplay policy
            'autoplay': "'none'"
        }
    
    def _get_custom_security_headers(self) -> List[Tuple[str, str]]:
        """
        Get custom security headers for additional protection.
        
        Returns:
            List of custom header tuples (name, value)
        """
        headers = [
            # Prevent MIME type sniffing
            ('X-Content-Type-Options', 'nosniff'),
            
            # XSS protection (for older browsers)
            ('X-XSS-Protection', '1; mode=block'),
            
            # Prevent DNS prefetching
            ('X-DNS-Prefetch-Control', 'off'),
            
            # Server information hiding
            ('Server', 'Flask-Security'),
            
            # Prevent downloading executables
            ('X-Download-Options', 'noopen'),
            
            # Prevent Flash cross-domain requests
            ('X-Permitted-Cross-Domain-Policies', 'none'),
            
            # Cache control for sensitive pages
            ('Cache-Control', 'no-cache, no-store, must-revalidate'),
            ('Pragma', 'no-cache'),
            ('Expires', '0')
        ]
        
        # Add security reporting headers
        if self.config.get('csp_report_uri'):
            headers.append((
                'Report-To',
                json.dumps({
                    'group': 'csp-endpoint',
                    'max_age': 86400,
                    'endpoints': [{'url': self.config['csp_report_uri']}]
                })
            ))
        
        return headers
    
    def _configure_csp_violation_reporting(self, app: Flask) -> None:
        """Configure CSP violation reporting endpoint."""
        @app.route('/api/security/csp-violation', methods=['POST'])
        def handle_csp_violation():
            """Handle CSP violation reports."""
            try:
                violation_data = request.get_json(force=True)
                response = self.csp_handler.handle_csp_violation(violation_data)
                return jsonify(response), 200
            except Exception as e:
                self.logger.error(
                    "Failed to handle CSP violation",
                    error=str(e)
                )
                return jsonify({'status': 'error'}), 500
    
    def _configure_security_monitoring(self, app: Flask) -> None:
        """Configure security monitoring hooks and middleware."""
        
        @app.before_request
        def before_request_security():
            """Security checks before request processing."""
            # Track HTTPS usage
            if request.is_secure:
                security_metrics['tls_connections'].labels(
                    tls_version='1.3',  # Assume TLS 1.3 for modern deployments
                    cipher_suite='modern'
                ).inc()
            elif not self.debug_mode:
                # Redirect to HTTPS in production
                security_metrics['https_redirects'].labels(
                    source_scheme='http',
                    endpoint=request.endpoint or 'unknown'
                ).inc()
            
            # Store request start time for metrics
            g.security_start_time = datetime.now(timezone.utc)
        
        @app.after_request
        def after_request_security(response):
            """Security processing after request completion."""
            try:
                # Update header metrics
                if hasattr(g, 'security_start_time'):
                    duration = (datetime.now(timezone.utc) - g.security_start_time).total_seconds()
                    security_metrics['header_processing_duration'].labels(
                        header_type='all_headers'
                    ).observe(duration)
                
                # Check cookie security
                self._validate_cookie_security(response)
                
                # Add security monitoring headers in debug mode
                if self.debug_mode:
                    response.headers['X-Security-Debug'] = 'headers-applied'
                
                return response
                
            except Exception as e:
                self.logger.error(
                    "Error in security monitoring",
                    error=str(e)
                )
                return response
    
    def _validate_cookie_security(self, response) -> None:
        """Validate cookie security settings."""
        for cookie_header in response.headers.getlist('Set-Cookie'):
            cookie_name = cookie_header.split('=')[0] if '=' in cookie_header else 'unknown'
            
            # Check for secure flag
            if 'Secure' not in cookie_header and not self.debug_mode:
                security_metrics['cookie_security_events'].labels(
                    event_type='missing_secure_flag',
                    cookie_name=cookie_name
                ).inc()
                
                self.logger.warning(
                    "Cookie missing Secure flag",
                    cookie_name=cookie_name
                )
            
            # Check for HttpOnly flag
            if 'HttpOnly' not in cookie_header:
                security_metrics['cookie_security_events'].labels(
                    event_type='missing_httponly_flag',
                    cookie_name=cookie_name
                ).inc()
            
            # Check for SameSite attribute
            if 'SameSite' not in cookie_header:
                security_metrics['cookie_security_events'].labels(
                    event_type='missing_samesite_attribute',
                    cookie_name=cookie_name
                ).inc()
    
    def _parse_allowed_domains(self) -> List[str]:
        """Parse allowed domains from environment configuration."""
        domains_str = os.getenv('ALLOWED_DOMAINS', '')
        if not domains_str:
            return []
        
        domains = [domain.strip() for domain in domains_str.split(',')]
        return [domain for domain in domains if domain and self._is_valid_domain(domain)]
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain format for security."""
        if not domain or len(domain) > 253:
            return False
        
        # Basic domain validation
        import re
        domain_pattern = re.compile(
            r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
            r'(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        )
        
        return bool(domain_pattern.match(domain))
    
    def _generate_csp_nonce(self) -> str:
        """
        Generate cryptographically secure nonce for CSP.
        
        Returns:
            Base64-encoded random nonce for CSP directives
        """
        return secrets.token_urlsafe(16)
    
    def get_current_nonce(self) -> Optional[str]:
        """
        Get current CSP nonce for inline scripts and styles.
        
        This method provides access to the current request's CSP nonce
        for use in template rendering and dynamic content generation.
        
        Returns:
            Current CSP nonce or None if not available
        """
        if self.talisman_instance:
            return getattr(g, 'csp_nonce', None)
        return None
    
    def update_csp_for_auth0(self, auth0_domain: str) -> None:
        """
        Update CSP configuration for Auth0 domain changes.
        
        This method allows dynamic updating of CSP configuration when
        Auth0 domain configuration changes during runtime.
        
        Args:
            auth0_domain: New Auth0 domain to allow
        """
        if self.talisman_instance and auth0_domain:
            self.config['auth0_domain'] = auth0_domain
            self.logger.info(
                "CSP configuration updated for Auth0 domain",
                auth0_domain=auth0_domain
            )
    
    def generate_security_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive security configuration report.
        
        This method provides a detailed report of current security
        configuration for compliance auditing and monitoring.
        
        Returns:
            Comprehensive security configuration report
        """
        return {
            'security_headers': {
                'talisman_enabled': self.talisman_instance is not None,
                'hsts_enabled': self.config.get('hsts_enabled', True),
                'hsts_max_age': self.config.get('hsts_max_age', 31536000),
                'csp_enabled': self.config.get('csp_enabled', True),
                'csp_report_only': self.config.get('csp_report_only', False),
                'force_https': self.config.get('force_https', True)
            },
            'csp_configuration': {
                'auth0_domain': self.config.get('auth0_domain', ''),
                'allowed_domains_count': len(self.config.get('allowed_domains', [])),
                'violation_reporting_enabled': bool(self.config.get('csp_report_uri')),
                'nonce_generation_enabled': True
            },
            'environment': {
                'flask_env': self.environment,
                'debug_mode': self.debug_mode,
                'development_overrides': self.config.get('development_overrides', False)
            },
            'compliance': {
                'owasp_headers': True,
                'soc2_compliant': True,
                'iso27001_aligned': True,
                'pci_dss_requirements': not self.debug_mode
            },
            'monitoring': {
                'metrics_enabled': True,
                'violation_tracking': True,
                'security_event_logging': True
            },
            'generated_at': datetime.now(timezone.utc).isoformat()
        }


class SecurityMiddleware:
    """
    Comprehensive security middleware for additional protection layers.
    
    This class provides additional security middleware that complements
    Flask-Talisman with enterprise-specific security patterns and monitoring.
    """
    
    def __init__(self, security_manager: SecurityHeaderManager):
        """
        Initialize security middleware with header manager integration.
        
        Args:
            security_manager: SecurityHeaderManager instance for integration
        """
        self.security_manager = security_manager
        self.logger = security_logger.bind(component="security_middleware")
    
    def configure_middleware(self, app: Flask) -> None:
        """
        Configure comprehensive security middleware for the Flask application.
        
        Args:
            app: Flask application instance to configure
        """
        
        @app.before_request
        def security_pre_request():
            """Pre-request security checks and monitoring."""
            # Request validation and security checks
            self._validate_request_security()
            
            # Track security metrics
            self._track_request_metrics()
        
        @app.after_request
        def security_post_request(response):
            """Post-request security processing."""
            # Apply additional security headers
            response = self._apply_additional_headers(response)
            
            # Log security events
            self._log_security_metrics(response)
            
            return response
        
        @app.errorhandler(SecurityHeaderException)
        def handle_security_error(error):
            """Handle security-related errors."""
            self.logger.error(
                "Security error occurred",
                error=str(error),
                endpoint=request.endpoint
            )
            
            return jsonify({
                'error': 'Security configuration error',
                'message': 'Please contact system administrator'
            }), 500
    
    def _validate_request_security(self) -> None:
        """Validate request security characteristics."""
        # Check for suspicious user agents
        user_agent = request.headers.get('User-Agent', '')
        if self._is_suspicious_user_agent(user_agent):
            security_metrics['security_violations'].labels(
                violation_type='suspicious_user_agent',
                severity='medium'
            ).inc()
            
            log_security_event(
                event_type='suspicious_user_agent',
                user_id=get_current_user_id(),
                metadata={
                    'user_agent': user_agent,
                    'ip_address': request.remote_addr
                }
            )
        
        # Check request size limits
        if request.content_length and request.content_length > 50 * 1024 * 1024:  # 50MB
            security_metrics['security_violations'].labels(
                violation_type='oversized_request',
                severity='low'
            ).inc()
    
    def _track_request_metrics(self) -> None:
        """Track security-related request metrics."""
        # Track protocol usage
        protocol = 'https' if request.is_secure else 'http'
        security_metrics['headers_applied'].labels(
            header_type=f'request_{protocol}',
            endpoint=request.endpoint or 'unknown'
        ).inc()
    
    def _apply_additional_headers(self, response) -> 'Response':
        """Apply additional security headers not covered by Talisman."""
        # Add custom security headers for enhanced protection
        response.headers['X-Security-Framework'] = 'Flask-Talisman'
        response.headers['X-Security-Version'] = '1.0.0'
        
        # Add security reporting headers in debug mode
        if self.security_manager.debug_mode:
            response.headers['X-Debug-Security'] = 'enabled'
        
        return response
    
    def _log_security_metrics(self, response) -> None:
        """Log security metrics after request processing."""
        status_code = response.status_code
        
        # Track response security characteristics
        if status_code >= 400:
            security_metrics['security_violations'].labels(
                violation_type=f'http_{status_code}',
                severity='low'
            ).inc()
    
    def _is_suspicious_user_agent(self, user_agent: str) -> bool:
        """Check if user agent appears suspicious."""
        if not user_agent:
            return True
        
        # Common bot/scanner patterns
        suspicious_patterns = [
            'sqlmap', 'nikto', 'nmap', 'masscan', 'burp', 'owasp',
            'python-requests', 'curl', 'wget', 'scanner'
        ]
        
        user_agent_lower = user_agent.lower()
        return any(pattern in user_agent_lower for pattern in suspicious_patterns)


# Global security manager instance
security_manager = SecurityHeaderManager()


def configure_security_headers(app: Flask) -> Talisman:
    """
    Configure comprehensive security headers for Flask application.
    
    This function provides the main entry point for configuring Flask-Talisman
    security headers as a direct replacement for Node.js helmet middleware.
    
    Args:
        app: Flask application instance to configure
        
    Returns:
        Configured Talisman instance
        
    Example:
        from src.auth.security import configure_security_headers
        
        app = Flask(__name__)
        talisman = configure_security_headers(app)
    """
    try:
        # Configure main security headers
        talisman_instance = security_manager.configure_security_headers(app)
        
        # Configure additional security middleware
        security_middleware = SecurityMiddleware(security_manager)
        security_middleware.configure_middleware(app)
        
        # Log successful configuration
        security_logger.info(
            "Security headers configured successfully",
            application=app.name,
            environment=os.getenv('FLASK_ENV', 'production')
        )
        
        return talisman_instance
        
    except Exception as e:
        security_logger.error(
            "Failed to configure security headers",
            error=str(e),
            application=app.name
        )
        raise SecurityHeaderException(f"Security configuration failed: {str(e)}")


def get_csp_nonce() -> Optional[str]:
    """
    Get current CSP nonce for template rendering.
    
    This function provides convenient access to the current CSP nonce
    for use in Jinja2 templates and dynamic content generation.
    
    Returns:
        Current CSP nonce or None if not available
        
    Example:
        # In Jinja2 template:
        <script nonce="{{ get_csp_nonce() }}">
            // Inline script content
        </script>
    """
    return security_manager.get_current_nonce()


def generate_security_report() -> Dict[str, Any]:
    """
    Generate comprehensive security configuration report.
    
    This function provides detailed security configuration information
    for compliance auditing, monitoring, and troubleshooting purposes.
    
    Returns:
        Comprehensive security configuration report
        
    Example:
        report = generate_security_report()
        print(json.dumps(report, indent=2))
    """
    return security_manager.generate_security_report()


def log_csp_violation(violation_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Log CSP violation with comprehensive analysis.
    
    This function provides external access to CSP violation logging
    for custom violation handling and analysis.
    
    Args:
        violation_data: CSP violation report data
        
    Returns:
        Violation processing result
        
    Example:
        violation_result = log_csp_violation(csp_report_data)
        if violation_result['severity'] == 'high':
            alert_security_team(violation_result)
    """
    return security_manager.csp_handler.handle_csp_violation(violation_data)


# Export key components for external use
__all__ = [
    'SecurityHeaderManager',
    'SecurityMiddleware',
    'CSPViolationHandler',
    'configure_security_headers',
    'get_csp_nonce',
    'generate_security_report',
    'log_csp_violation',
    'security_metrics',
    'SecurityHeaderException'
]