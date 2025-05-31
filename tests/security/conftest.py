"""
Security Testing Configuration and Fixtures

This module provides comprehensive security testing fixtures, mock attack scenarios, security validation
utilities, and enterprise-grade security testing framework setup for Flask application security validation.
Implements security testing requirements as specified in Section 6.4 and 6.6.1 of the technical specification.

Key Components:
- Security testing fixtures for authentication and authorization validation per Section 6.6.1
- Mock attack scenarios for penetration testing automation per Section 6.4.5
- Security validation utilities for comprehensive security assessment per Section 6.4
- Enterprise-grade security testing framework setup per Section 6.4.5
- Flask-Talisman security header validation fixtures per Section 6.4.1
- PyJWT token security testing with Auth0 integration per Section 6.4.1
- Security audit logging and monitoring fixtures per Section 6.4.2
- Performance monitoring for security operations per Section 0.1.1

Architecture Integration:
- Section 6.4.1: Authentication Framework with Auth0, PyJWT, Flask-Login integration
- Section 6.4.2: Authorization System with RBAC and permission validation
- Section 6.4.3: Data Protection with encryption and secure communication
- Section 6.4.5: Security Controls Matrix with comprehensive security validation
- Section 6.6.1: Testing Strategy with security test automation and coverage
- Section 6.4.5: CI/CD Security Checks with automated vulnerability scanning

Security Testing Coverage:
- Authentication security (JWT validation, Auth0 integration, session management)
- Authorization security (RBAC, permissions, resource access control)
- Input validation security (XSS prevention, injection attacks, data sanitization)
- Session security (Flask-Session with Redis, encryption, secure cookies)
- Transport security (HTTPS/TLS enforcement, security headers, CORS)
- Infrastructure security (container scanning, dependency validation)

Author: Flask Migration Team
Version: 1.0.0
Coverage Target: 95% security test coverage per Section 6.6.3
Dependencies: pytest 7.4+, pytest-mock, bandit 1.7+, safety 3.0+, Flask-Talisman 1.1+
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sys
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Generator, Callable, Union
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from urllib.parse import quote, unquote

import pytest
import pytest_asyncio
from flask import Flask, request, session, g
from flask.testing import FlaskClient
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.test import Client

# Security testing imports
import jwt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Import base test fixtures and configuration
from tests.conftest import (
    flask_app,
    client,
    app_context,
    request_context,
    comprehensive_test_environment,
    performance_monitoring
)
from tests.test_config import (
    JWTTestConfig,
    MockServiceConfig,
    TestEnvironmentIsolationConfig,
    IntegratedTestConfig
)

# Configure security testing logger
logging.basicConfig(level=logging.INFO)
security_logger = logging.getLogger(__name__)


# =============================================================================
# Security Testing Configuration Classes
# =============================================================================

class SecurityTestConfig:
    """
    Comprehensive security testing configuration providing enterprise-grade security
    testing parameters, attack simulation settings, and validation thresholds.
    """
    
    # Security Testing Framework Configuration
    SECURITY_TESTING_ENABLED = True
    SECURITY_VALIDATION_STRICT = True
    SECURITY_AUDIT_LOGGING_ENABLED = True
    SECURITY_PERFORMANCE_MONITORING = True
    
    # Authentication Security Testing
    AUTH_SECURITY_TESTING = True
    AUTH_BRUTE_FORCE_SIMULATION = True
    AUTH_TOKEN_MANIPULATION_TESTING = True
    AUTH_SESSION_HIJACKING_SIMULATION = True
    AUTH_CSRF_PROTECTION_TESTING = True
    
    # Authorization Security Testing
    AUTHZ_PRIVILEGE_ESCALATION_TESTING = True
    AUTHZ_ACCESS_CONTROL_BYPASS_TESTING = True
    AUTHZ_RESOURCE_ENUMERATION_TESTING = True
    AUTHZ_PERMISSION_BOUNDARY_TESTING = True
    
    # Input Validation Security Testing
    INPUT_XSS_TESTING = True
    INPUT_SQL_INJECTION_TESTING = True
    INPUT_COMMAND_INJECTION_TESTING = True
    INPUT_PATH_TRAVERSAL_TESTING = True
    INPUT_DESERIALIZATION_TESTING = True
    
    # Session Security Testing
    SESSION_FIXATION_TESTING = True
    SESSION_REPLAY_TESTING = True
    SESSION_ENCRYPTION_TESTING = True
    SESSION_TIMEOUT_TESTING = True
    
    # Transport Security Testing
    TRANSPORT_TLS_TESTING = True
    TRANSPORT_HEADER_TESTING = True
    TRANSPORT_CORS_TESTING = True
    TRANSPORT_REDIRECT_TESTING = True
    
    # Security Performance Thresholds
    SECURITY_OPERATION_MAX_TIME = 500  # milliseconds
    AUTH_REQUEST_MAX_TIME = 200  # milliseconds
    ENCRYPTION_OPERATION_MAX_TIME = 100  # milliseconds
    HASH_OPERATION_MAX_TIME = 50  # milliseconds
    
    # Attack Simulation Configuration
    ATTACK_SIMULATION_ENABLED = True
    ATTACK_RATE_LIMIT_TESTING = True
    ATTACK_PAYLOAD_FUZZING = True
    ATTACK_TIMING_ANALYSIS = True
    
    # Security Audit Configuration
    AUDIT_ALL_SECURITY_EVENTS = True
    AUDIT_FAILED_ATTEMPTS = True
    AUDIT_PRIVILEGE_CHANGES = True
    AUDIT_SECURITY_VIOLATIONS = True
    
    # Vulnerability Scanning Configuration
    DEPENDENCY_SCANNING_ENABLED = True
    STATIC_ANALYSIS_ENABLED = True
    DYNAMIC_ANALYSIS_ENABLED = True
    CONTAINER_SCANNING_ENABLED = True


class SecurityPayloads:
    """
    Comprehensive security payload collection for penetration testing automation.
    
    Provides categorized attack payloads for various security testing scenarios
    as specified in Section 6.4.5 for automated penetration testing.
    """
    
    # XSS Payloads for Input Validation Testing
    XSS_PAYLOADS = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        'javascript:alert("XSS")',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<body onload=alert("XSS")>',
        '<div style="background:url(javascript:alert(\'XSS\'))">',
        '<input type="text" value="" onfocus="alert(\'XSS\')" autofocus>',
        '<textarea onfocus="alert(\'XSS\')" autofocus>',
        '<select onfocus="alert(\'XSS\')" autofocus>',
        '<details open ontoggle="alert(\'XSS\')">',
        '<marquee onstart="alert(\'XSS\')">',
        '"><script>alert("XSS")</script>',
        "';alert('XSS');//",
        "\"><svg/onload=alert('XSS')>",
        "<script>alert(String.fromCharCode(88,83,83))</script>"
    ]
    
    # SQL Injection Payloads
    SQL_INJECTION_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "admin'--",
        "admin'#",
        "admin'/*",
        "' OR '1'='1'--",
        "' OR '1'='1'#",
        "' OR '1'='1'/*",
        "1' OR '1'='1",
        "1' OR 1=1--",
        "1' OR 1=1#",
        "'; DROP TABLE users; --",
        "1; INSERT INTO users VALUES('hacker','password');--",
        "' UNION SELECT * FROM users--"
    ]
    
    # Command Injection Payloads
    COMMAND_INJECTION_PAYLOADS = [
        "; ls -la",
        "| ls -la", 
        "&& ls -la",
        "|| ls -la",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "&& cat /etc/passwd",
        "; ping -c 1 127.0.0.1",
        "| ping -c 1 127.0.0.1",
        "; whoami",
        "| whoami",
        "; id",
        "| id",
        "; uname -a",
        "| uname -a",
        "\n cat /etc/passwd",
        "\r cat /etc/passwd"
    ]
    
    # Path Traversal Payloads
    PATH_TRAVERSAL_PAYLOADS = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//etc/passwd",
        "....\\\\....\\\\....\\\\windows\\system32\\drivers\\etc\\hosts",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
        "..%2f..%2f..%2fetc%2fpasswd",
        "..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
        "../../../../../../etc/passwd",
        "..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "/etc/passwd",
        "\\windows\\system32\\drivers\\etc\\hosts",
        "file:///etc/passwd",
        "file:///c:/windows/system32/drivers/etc/hosts"
    ]
    
    # LDAP Injection Payloads
    LDAP_INJECTION_PAYLOADS = [
        "*",
        "*)(&",
        "*))%00",
        "*()|&'",
        "*(|(mail=*))",
        "*(|(objectclass=*))",
        "*)(uid=*",
        "*)(uid=*))",
        "*)(|(objectClass=*)",
        "admin*",
        "admin*)((|userPassword=*)",
        "*)(|(cn=*))"
    ]
    
    # Header Injection Payloads
    HEADER_INJECTION_PAYLOADS = [
        "\r\nSet-Cookie: sessionid=malicious",
        "\r\nLocation: http://evil.com",
        "\n\rSet-Cookie: admin=true",
        "%0d%0aSet-Cookie: malicious=true",
        "%0a%0dLocation: javascript:alert('XSS')",
        "\r\n\r\n<script>alert('XSS')</script>",
        "%0d%0a%0d%0a<script>alert('XSS')</script>",
        "\r\nContent-Type: text/html\r\n\r\n<script>alert('XSS')</script>"
    ]
    
    # Authentication Bypass Payloads
    AUTH_BYPASS_PAYLOADS = [
        {"username": "admin", "password": ""},
        {"username": "", "password": ""},
        {"username": "admin'--", "password": "anything"},
        {"username": "admin", "password": "' OR '1'='1"},
        {"username": "admin'; --", "password": ""},
        {"username": "admin' OR '1'='1'--", "password": ""},
        {"username": "admin", "password": "admin"},
        {"username": "administrator", "password": "administrator"},
        {"username": "root", "password": "root"},
        {"username": "test", "password": "test"},
        {"username": "guest", "password": "guest"},
        {"username": "admin", "password": "password"}
    ]


# =============================================================================
# Security Testing Fixtures
# =============================================================================

@pytest.fixture(scope="function")
def security_config():
    """
    Function-scoped fixture providing security testing configuration.
    
    Creates comprehensive security testing configuration with enterprise-grade
    security testing parameters and validation thresholds per Section 6.4.5
    security controls matrix requirements.
    
    Returns:
        SecurityTestConfig: Security testing configuration instance
    """
    config = SecurityTestConfig()
    
    security_logger.info(
        "Security testing configuration created",
        security_testing_enabled=config.SECURITY_TESTING_ENABLED,
        strict_validation=config.SECURITY_VALIDATION_STRICT,
        audit_logging=config.SECURITY_AUDIT_LOGGING_ENABLED
    )
    
    return config


@pytest.fixture(scope="function")
def security_payloads():
    """
    Function-scoped fixture providing security testing payloads for attack simulation.
    
    Creates comprehensive collection of security testing payloads for penetration
    testing automation per Section 6.4.5 automated penetration testing requirements.
    
    Returns:
        SecurityPayloads: Security payload collection for testing
    """
    payloads = SecurityPayloads()
    
    security_logger.info(
        "Security testing payloads loaded",
        xss_payloads=len(payloads.XSS_PAYLOADS),
        sql_injection_payloads=len(payloads.SQL_INJECTION_PAYLOADS),
        command_injection_payloads=len(payloads.COMMAND_INJECTION_PAYLOADS),
        path_traversal_payloads=len(payloads.PATH_TRAVERSAL_PAYLOADS)
    )
    
    return payloads


@pytest.fixture(scope="function")
def security_audit_logger():
    """
    Function-scoped fixture providing security audit logging for comprehensive tracking.
    
    Creates structured security audit logging system for tracking security events,
    violations, and testing activities per Section 6.4.2 audit logging requirements.
    
    Returns:
        SecurityAuditLogger: Security audit logging utility
    """
    
    class SecurityAuditLogger:
        def __init__(self):
            self.events = []
            self.violations = []
            self.security_tests = []
            self.performance_metrics = []
        
        def log_security_event(self, event_type: str, details: Dict[str, Any], 
                             severity: str = "INFO", user_id: str = None):
            """Log security event with comprehensive details"""
            event = {
                'timestamp': datetime.utcnow().isoformat(),
                'event_id': str(uuid.uuid4()),
                'event_type': event_type,
                'severity': severity,
                'user_id': user_id,
                'details': details,
                'source_ip': getattr(request, 'remote_addr', 'test_environment'),
                'user_agent': getattr(request, 'user_agent', 'pytest_security_testing')
            }
            self.events.append(event)
            
            security_logger.log(
                getattr(logging, severity, logging.INFO),
                f"Security event: {event_type}",
                extra={
                    'event_id': event['event_id'],
                    'details': details,
                    'user_id': user_id
                }
            )
        
        def log_security_violation(self, violation_type: str, details: Dict[str, Any],
                                 risk_level: str = "MEDIUM", remediation: str = None):
            """Log security violation with risk assessment"""
            violation = {
                'timestamp': datetime.utcnow().isoformat(),
                'violation_id': str(uuid.uuid4()),
                'violation_type': violation_type,
                'risk_level': risk_level,
                'details': details,
                'remediation': remediation,
                'source_ip': getattr(request, 'remote_addr', 'test_environment')
            }
            self.violations.append(violation)
            
            security_logger.warning(
                f"Security violation: {violation_type}",
                extra={
                    'violation_id': violation['violation_id'],
                    'risk_level': risk_level,
                    'details': details
                }
            )
        
        def log_security_test(self, test_name: str, test_type: str, result: str,
                            duration: float = 0.0, payload: str = None):
            """Log security test execution and results"""
            test = {
                'timestamp': datetime.utcnow().isoformat(),
                'test_id': str(uuid.uuid4()),
                'test_name': test_name,
                'test_type': test_type,
                'result': result,
                'duration': duration,
                'payload': payload
            }
            self.security_tests.append(test)
            
            security_logger.info(
                f"Security test executed: {test_name}",
                extra={
                    'test_id': test['test_id'],
                    'test_type': test_type,
                    'result': result,
                    'duration': duration
                }
            )
        
        def log_performance_metric(self, operation: str, duration: float,
                                 baseline: float = None, threshold: float = None):
            """Log security operation performance metrics"""
            metric = {
                'timestamp': datetime.utcnow().isoformat(),
                'operation': operation,
                'duration': duration,
                'baseline': baseline,
                'threshold': threshold,
                'within_threshold': threshold is None or duration <= threshold,
                'variance_percentage': (
                    ((duration - baseline) / baseline * 100) 
                    if baseline and baseline > 0 else None
                )
            }
            self.performance_metrics.append(metric)
            
            if not metric['within_threshold']:
                security_logger.warning(
                    f"Security operation performance threshold exceeded: {operation}",
                    extra={
                        'duration': duration,
                        'threshold': threshold,
                        'variance': metric['variance_percentage']
                    }
                )
        
        def get_security_summary(self) -> Dict[str, Any]:
            """Get comprehensive security testing summary"""
            return {
                'total_events': len(self.events),
                'total_violations': len(self.violations),
                'total_security_tests': len(self.security_tests),
                'total_performance_metrics': len(self.performance_metrics),
                'violation_types': list(set(v['violation_type'] for v in self.violations)),
                'test_types': list(set(t['test_type'] for t in self.security_tests)),
                'high_risk_violations': len([v for v in self.violations if v['risk_level'] == 'HIGH']),
                'failed_security_tests': len([t for t in self.security_tests if t['result'] == 'FAILED']),
                'performance_violations': len([m for m in self.performance_metrics if not m['within_threshold']])
            }
    
    audit_logger = SecurityAuditLogger()
    
    security_logger.info("Security audit logger initialized")
    return audit_logger


@pytest.fixture(scope="function")
def mock_auth0_security_service():
    """
    Function-scoped fixture providing comprehensive Auth0 security service mocking.
    
    Creates realistic Auth0 service mock with security features including JWT validation,
    user management, and security event logging per Section 6.4.1 authentication
    framework requirements.
    
    Returns:
        Mock: Auth0 security service mock with comprehensive functionality
    """
    
    class MockAuth0SecurityService:
        def __init__(self):
            self.users = {}
            self.tokens = {}
            self.security_events = []
            self.failed_attempts = {}
            self.locked_accounts = set()
            
            # JWT configuration
            self.jwt_secret = "test-auth0-secret-key"
            self.jwt_algorithm = "HS256"
            self.token_expiry = 3600  # 1 hour
            
            # Security policies
            self.max_failed_attempts = 5
            self.lockout_duration = 300  # 5 minutes
            self.password_policy = {
                'min_length': 8,
                'require_uppercase': True,
                'require_lowercase': True,
                'require_numbers': True,
                'require_special': True
            }
        
        def authenticate_user(self, email: str, password: str) -> Dict[str, Any]:
            """Authenticate user with security controls"""
            user_id = f"auth0|{email.split('@')[0]}"
            
            # Check account lockout
            if email in self.locked_accounts:
                self._log_security_event('authentication_blocked', {
                    'email': email,
                    'reason': 'account_locked'
                })
                raise Exception("Account locked due to multiple failed attempts")
            
            # Check failed attempts
            if email in self.failed_attempts:
                if self.failed_attempts[email]['count'] >= self.max_failed_attempts:
                    self.locked_accounts.add(email)
                    self._log_security_event('account_locked', {
                        'email': email,
                        'failed_attempts': self.failed_attempts[email]['count']
                    })
                    raise Exception("Account locked due to multiple failed attempts")
            
            # Simulate authentication
            if email in self.users and self.users[email]['password'] == password:
                # Reset failed attempts on successful authentication
                if email in self.failed_attempts:
                    del self.failed_attempts[email]
                
                self._log_security_event('authentication_success', {
                    'email': email,
                    'user_id': user_id
                })
                
                return {
                    'user_id': user_id,
                    'email': email,
                    'name': self.users[email].get('name', 'Test User'),
                    'roles': self.users[email].get('roles', ['user']),
                    'permissions': self.users[email].get('permissions', [])
                }
            else:
                # Track failed attempt
                if email not in self.failed_attempts:
                    self.failed_attempts[email] = {'count': 0, 'last_attempt': time.time()}
                
                self.failed_attempts[email]['count'] += 1
                self.failed_attempts[email]['last_attempt'] = time.time()
                
                self._log_security_event('authentication_failed', {
                    'email': email,
                    'failed_attempt_count': self.failed_attempts[email]['count']
                })
                
                raise Exception("Invalid credentials")
        
        def create_jwt_token(self, user_info: Dict[str, Any]) -> str:
            """Create JWT token with security claims"""
            now = datetime.utcnow()
            claims = {
                'sub': user_info['user_id'],
                'email': user_info['email'],
                'name': user_info.get('name', ''),
                'roles': user_info.get('roles', []),
                'permissions': user_info.get('permissions', []),
                'iss': 'https://test-tenant.auth0.com/',
                'aud': 'test-api-audience',
                'iat': now,
                'exp': now + timedelta(seconds=self.token_expiry),
                'nbf': now,
                'jti': str(uuid.uuid4())
            }
            
            token = jwt.encode(claims, self.jwt_secret, algorithm=self.jwt_algorithm)
            
            # Store token for validation
            self.tokens[claims['jti']] = {
                'user_id': user_info['user_id'],
                'created_at': now,
                'expires_at': claims['exp']
            }
            
            self._log_security_event('token_created', {
                'user_id': user_info['user_id'],
                'token_id': claims['jti'],
                'expires_at': claims['exp'].isoformat()
            })
            
            return token
        
        def validate_jwt_token(self, token: str) -> Dict[str, Any]:
            """Validate JWT token with comprehensive security checks"""
            try:
                # Decode and validate token
                claims = jwt.decode(
                    token, 
                    self.jwt_secret, 
                    algorithms=[self.jwt_algorithm],
                    audience='test-api-audience',
                    issuer='https://test-tenant.auth0.com/'
                )
                
                # Check if token is revoked
                token_id = claims.get('jti')
                if token_id and token_id not in self.tokens:
                    self._log_security_event('token_validation_failed', {
                        'token_id': token_id,
                        'reason': 'token_revoked'
                    })
                    raise Exception("Token has been revoked")
                
                self._log_security_event('token_validation_success', {
                    'user_id': claims['sub'],
                    'token_id': token_id
                })
                
                return claims
                
            except jwt.ExpiredSignatureError:
                self._log_security_event('token_validation_failed', {
                    'reason': 'token_expired'
                })
                raise Exception("Token has expired")
            except jwt.InvalidTokenError as e:
                self._log_security_event('token_validation_failed', {
                    'reason': 'invalid_token',
                    'error': str(e)
                })
                raise Exception(f"Invalid token: {str(e)}")
        
        def revoke_token(self, token_id: str):
            """Revoke JWT token"""
            if token_id in self.tokens:
                del self.tokens[token_id]
                self._log_security_event('token_revoked', {
                    'token_id': token_id
                })
        
        def create_user(self, email: str, password: str, **kwargs) -> Dict[str, Any]:
            """Create user with password policy validation"""
            if not self._validate_password(password):
                raise Exception("Password does not meet security requirements")
            
            user_id = f"auth0|{email.split('@')[0]}"
            user_data = {
                'email': email,
                'password': password,  # In real implementation, this would be hashed
                'name': kwargs.get('name', email.split('@')[0]),
                'roles': kwargs.get('roles', ['user']),
                'permissions': kwargs.get('permissions', []),
                'created_at': datetime.utcnow().isoformat(),
                'email_verified': kwargs.get('email_verified', False)
            }
            
            self.users[email] = user_data
            
            self._log_security_event('user_created', {
                'user_id': user_id,
                'email': email
            })
            
            return {
                'user_id': user_id,
                **user_data
            }
        
        def _validate_password(self, password: str) -> bool:
            """Validate password against security policy"""
            policy = self.password_policy
            
            if len(password) < policy['min_length']:
                return False
            
            if policy['require_uppercase'] and not any(c.isupper() for c in password):
                return False
            
            if policy['require_lowercase'] and not any(c.islower() for c in password):
                return False
            
            if policy['require_numbers'] and not any(c.isdigit() for c in password):
                return False
            
            if policy['require_special'] and not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
                return False
            
            return True
        
        def _log_security_event(self, event_type: str, details: Dict[str, Any]):
            """Log security event"""
            event = {
                'timestamp': datetime.utcnow().isoformat(),
                'event_type': event_type,
                'details': details
            }
            self.security_events.append(event)
        
        def get_security_events(self) -> List[Dict[str, Any]]:
            """Get all security events"""
            return self.security_events
    
    mock_service = MockAuth0SecurityService()
    
    # Create test users
    mock_service.create_user(
        'test@example.com',
        'SecurePass123!',
        name='Test User',
        roles=['user'],
        permissions=['read:profile', 'update:profile']
    )
    
    mock_service.create_user(
        'admin@example.com',
        'AdminPass456!',
        name='Admin User',
        roles=['admin'],
        permissions=['read:users', 'write:users', 'delete:users', 'admin:all']
    )
    
    security_logger.info(
        "Mock Auth0 security service created",
        test_users=len(mock_service.users),
        security_policies_enabled=True
    )
    
    return mock_service


@pytest.fixture(scope="function")
def security_validation_tools():
    """
    Function-scoped fixture providing security validation utilities.
    
    Creates comprehensive security validation tools for testing authentication,
    authorization, input validation, and security headers per Section 6.4
    security architecture requirements.
    
    Returns:
        SecurityValidationTools: Security validation utility collection
    """
    
    class SecurityValidationTools:
        def __init__(self):
            self.validation_results = []
        
        def validate_jwt_security(self, token: str, expected_claims: Dict[str, Any] = None) -> Dict[str, Any]:
            """Validate JWT token security properties"""
            result = {
                'test_type': 'jwt_security_validation',
                'timestamp': datetime.utcnow().isoformat(),
                'passed': False,
                'issues': [],
                'token_analysis': {}
            }
            
            try:
                # Decode without verification to analyze structure
                header = jwt.get_unverified_header(token)
                payload = jwt.decode(token, options={"verify_signature": False})
                
                result['token_analysis'] = {
                    'header': header,
                    'payload': payload
                }
                
                # Check algorithm security
                if header.get('alg') == 'none':
                    result['issues'].append("Algorithm 'none' is not secure")
                elif header.get('alg') not in ['HS256', 'HS512', 'RS256', 'RS512']:
                    result['issues'].append(f"Weak algorithm detected: {header.get('alg')}")
                
                # Check required claims
                required_claims = ['sub', 'iat', 'exp', 'iss', 'aud']
                missing_claims = [claim for claim in required_claims if claim not in payload]
                if missing_claims:
                    result['issues'].append(f"Missing required claims: {missing_claims}")
                
                # Check expiration
                if 'exp' in payload:
                    exp_time = datetime.fromtimestamp(payload['exp'])
                    if exp_time < datetime.utcnow():
                        result['issues'].append("Token has expired")
                    elif exp_time > datetime.utcnow() + timedelta(days=1):
                        result['issues'].append("Token expiration is too far in the future")
                
                # Check issuer
                if 'iss' in payload and not payload['iss'].startswith('https://'):
                    result['issues'].append("Issuer should use HTTPS")
                
                # Validate expected claims if provided
                if expected_claims:
                    for key, expected_value in expected_claims.items():
                        if key not in payload:
                            result['issues'].append(f"Missing expected claim: {key}")
                        elif payload[key] != expected_value:
                            result['issues'].append(f"Claim {key} mismatch: expected {expected_value}, got {payload[key]}")
                
                result['passed'] = len(result['issues']) == 0
                
            except Exception as e:
                result['issues'].append(f"Token validation error: {str(e)}")
            
            self.validation_results.append(result)
            return result
        
        def validate_password_security(self, password: str) -> Dict[str, Any]:
            """Validate password security strength"""
            result = {
                'test_type': 'password_security_validation',
                'timestamp': datetime.utcnow().isoformat(),
                'passed': False,
                'issues': [],
                'strength_score': 0,
                'recommendations': []
            }
            
            # Length check
            if len(password) < 8:
                result['issues'].append("Password is too short (minimum 8 characters)")
            else:
                result['strength_score'] += 1
            
            # Character diversity checks
            if not any(c.isupper() for c in password):
                result['issues'].append("Password should contain uppercase letters")
            else:
                result['strength_score'] += 1
            
            if not any(c.islower() for c in password):
                result['issues'].append("Password should contain lowercase letters")
            else:
                result['strength_score'] += 1
            
            if not any(c.isdigit() for c in password):
                result['issues'].append("Password should contain numbers")
            else:
                result['strength_score'] += 1
            
            if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
                result['issues'].append("Password should contain special characters")
            else:
                result['strength_score'] += 1
            
            # Common password checks
            common_passwords = ['password', '123456', 'admin', 'letmein', 'welcome']
            if password.lower() in common_passwords:
                result['issues'].append("Password is too common")
            
            # Sequential characters check
            if any(password[i:i+3] in '123456789' for i in range(len(password)-2)):
                result['issues'].append("Password contains sequential numbers")
            
            # Recommendations
            if result['strength_score'] < 3:
                result['recommendations'].append("Use a mix of uppercase, lowercase, numbers, and special characters")
            if len(password) < 12:
                result['recommendations'].append("Consider using a longer password (12+ characters)")
            
            result['passed'] = len(result['issues']) == 0 and result['strength_score'] >= 4
            
            self.validation_results.append(result)
            return result
        
        def validate_session_security(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
            """Validate session security configuration"""
            result = {
                'test_type': 'session_security_validation',
                'timestamp': datetime.utcnow().isoformat(),
                'passed': False,
                'issues': [],
                'security_features': []
            }
            
            # Check session ID entropy
            session_id = session_data.get('session_id', '')
            if len(session_id) < 32:
                result['issues'].append("Session ID is too short")
            else:
                result['security_features'].append("Adequate session ID length")
            
            # Check secure flag
            if not session_data.get('secure', False):
                result['issues'].append("Session should have secure flag set")
            else:
                result['security_features'].append("Secure flag enabled")
            
            # Check HttpOnly flag
            if not session_data.get('httponly', False):
                result['issues'].append("Session should have HttpOnly flag set")
            else:
                result['security_features'].append("HttpOnly flag enabled")
            
            # Check SameSite attribute
            samesite = session_data.get('samesite', '')
            if samesite not in ['Strict', 'Lax']:
                result['issues'].append("Session should have SameSite attribute set")
            else:
                result['security_features'].append(f"SameSite {samesite} enabled")
            
            # Check expiration
            if 'expires' not in session_data:
                result['issues'].append("Session should have explicit expiration")
            else:
                result['security_features'].append("Session expiration configured")
            
            result['passed'] = len(result['issues']) == 0
            
            self.validation_results.append(result)
            return result
        
        def validate_input_sanitization(self, input_value: str, expected_output: str = None) -> Dict[str, Any]:
            """Validate input sanitization effectiveness"""
            result = {
                'test_type': 'input_sanitization_validation',
                'timestamp': datetime.utcnow().isoformat(),
                'passed': False,
                'issues': [],
                'sanitization_analysis': {}
            }
            
            # Check for XSS patterns
            xss_patterns = ['<script', 'javascript:', 'onload=', 'onerror=', 'onclick=']
            detected_xss = [pattern for pattern in xss_patterns if pattern.lower() in input_value.lower()]
            
            if detected_xss:
                result['issues'].append(f"Potential XSS patterns detected: {detected_xss}")
                result['sanitization_analysis']['xss_risk'] = True
            else:
                result['sanitization_analysis']['xss_risk'] = False
            
            # Check for SQL injection patterns
            sql_patterns = ["'", '"', ';', '--', '/*', '*/', 'union', 'select', 'drop', 'insert']
            detected_sql = [pattern for pattern in sql_patterns if pattern.lower() in input_value.lower()]
            
            if detected_sql:
                result['issues'].append(f"Potential SQL injection patterns detected: {detected_sql}")
                result['sanitization_analysis']['sql_injection_risk'] = True
            else:
                result['sanitization_analysis']['sql_injection_risk'] = False
            
            # Check for command injection patterns
            cmd_patterns = [';', '|', '&', '$', '`', 'cat ', 'ls ', 'rm ', 'wget ', 'curl ']
            detected_cmd = [pattern for pattern in cmd_patterns if pattern.lower() in input_value.lower()]
            
            if detected_cmd:
                result['issues'].append(f"Potential command injection patterns detected: {detected_cmd}")
                result['sanitization_analysis']['command_injection_risk'] = True
            else:
                result['sanitization_analysis']['command_injection_risk'] = False
            
            result['passed'] = len(result['issues']) == 0
            
            self.validation_results.append(result)
            return result
        
        def validate_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
            """Validate HTTP security headers"""
            result = {
                'test_type': 'security_headers_validation',
                'timestamp': datetime.utcnow().isoformat(),
                'passed': False,
                'issues': [],
                'present_headers': [],
                'missing_headers': []
            }
            
            # Required security headers
            required_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': None,  # Any value acceptable
                'Content-Security-Policy': None
            }
            
            for header, expected_value in required_headers.items():
                header_value = headers.get(header, '')
                
                if not header_value:
                    result['missing_headers'].append(header)
                    result['issues'].append(f"Missing security header: {header}")
                else:
                    result['present_headers'].append(header)
                    
                    # Validate specific values if required
                    if expected_value:
                        if isinstance(expected_value, list):
                            if header_value not in expected_value:
                                result['issues'].append(f"Invalid {header} value: {header_value}")
                        elif header_value != expected_value:
                            result['issues'].append(f"Invalid {header} value: {header_value}")
            
            # Check HSTS configuration
            hsts = headers.get('Strict-Transport-Security', '')
            if hsts:
                if 'max-age=' not in hsts:
                    result['issues'].append("HSTS header missing max-age directive")
                elif 'includeSubDomains' not in hsts:
                    result['issues'].append("HSTS header should include includeSubDomains")
            
            # Check CSP configuration
            csp = headers.get('Content-Security-Policy', '')
            if csp:
                if 'unsafe-eval' in csp:
                    result['issues'].append("CSP contains unsafe-eval which is not recommended")
                if 'unsafe-inline' in csp and 'script-src' in csp:
                    result['issues'].append("CSP allows unsafe-inline scripts which is not recommended")
            
            result['passed'] = len(result['issues']) == 0
            
            self.validation_results.append(result)
            return result
        
        def get_validation_summary(self) -> Dict[str, Any]:
            """Get comprehensive validation summary"""
            total_validations = len(self.validation_results)
            passed_validations = len([r for r in self.validation_results if r['passed']])
            
            return {
                'total_validations': total_validations,
                'passed_validations': passed_validations,
                'failed_validations': total_validations - passed_validations,
                'success_rate': (passed_validations / total_validations * 100) if total_validations > 0 else 0,
                'validation_types': list(set(r['test_type'] for r in self.validation_results)),
                'all_issues': [issue for r in self.validation_results for issue in r.get('issues', [])]
            }
    
    tools = SecurityValidationTools()
    
    security_logger.info("Security validation tools initialized")
    return tools


@pytest.fixture(scope="function")
def mock_attack_scenarios(security_payloads, security_audit_logger):
    """
    Function-scoped fixture providing mock attack scenario simulation.
    
    Creates comprehensive attack scenario simulation for penetration testing
    automation per Section 6.4.5 automated security testing requirements.
    
    Args:
        security_payloads: Security testing payload collection
        security_audit_logger: Security audit logging utility
        
    Returns:
        MockAttackScenarios: Attack scenario simulation utilities
    """
    
    class MockAttackScenarios:
        def __init__(self, payloads, audit_logger):
            self.payloads = payloads
            self.audit_logger = audit_logger
            self.attack_results = []
        
        def simulate_brute_force_attack(self, target_endpoint: str, username: str,
                                      password_list: List[str] = None) -> Dict[str, Any]:
            """Simulate brute force attack against authentication endpoint"""
            if password_list is None:
                password_list = ['password', '123456', 'admin', 'letmein', 'welcome']
            
            attack_result = {
                'attack_type': 'brute_force',
                'target_endpoint': target_endpoint,
                'username': username,
                'attempts': [],
                'success': False,
                'start_time': datetime.utcnow().isoformat(),
                'duration': 0
            }
            
            start_time = time.time()
            
            for password in password_list:
                attempt = {
                    'password': password,
                    'timestamp': datetime.utcnow().isoformat(),
                    'success': False,
                    'response_code': None,
                    'response_time': 0
                }
                
                # Simulate attack attempt timing
                attempt_start = time.time()
                
                # Log security event
                self.audit_logger.log_security_event(
                    'brute_force_attempt',
                    {
                        'target_endpoint': target_endpoint,
                        'username': username,
                        'password': password[:3] + '*' * (len(password) - 3)
                    },
                    severity='WARNING'
                )
                
                # Simulate response (would be actual HTTP request in real scenario)
                if password == 'admin' and username == 'admin':
                    attempt['success'] = True
                    attempt['response_code'] = 200
                    attack_result['success'] = True
                else:
                    attempt['response_code'] = 401
                
                attempt['response_time'] = time.time() - attempt_start
                attack_result['attempts'].append(attempt)
                
                # Break if successful
                if attempt['success']:
                    break
                
                # Simulate delay between attempts
                time.sleep(0.1)
            
            attack_result['duration'] = time.time() - start_time
            
            if attack_result['success']:
                self.audit_logger.log_security_violation(
                    'brute_force_success',
                    {
                        'target_endpoint': target_endpoint,
                        'username': username,
                        'attempts': len(attack_result['attempts'])
                    },
                    risk_level='HIGH',
                    remediation='Implement account lockout and rate limiting'
                )
            
            self.attack_results.append(attack_result)
            return attack_result
        
        def simulate_xss_attack(self, target_endpoint: str, input_fields: List[str]) -> Dict[str, Any]:
            """Simulate XSS attack against input fields"""
            attack_result = {
                'attack_type': 'xss',
                'target_endpoint': target_endpoint,
                'input_fields': input_fields,
                'payloads_tested': [],
                'successful_payloads': [],
                'start_time': datetime.utcnow().isoformat(),
                'duration': 0
            }
            
            start_time = time.time()
            
            for field in input_fields:
                for payload in self.payloads.XSS_PAYLOADS:
                    payload_test = {
                        'field': field,
                        'payload': payload,
                        'timestamp': datetime.utcnow().isoformat(),
                        'detected': False,
                        'blocked': False
                    }
                    
                    # Log security event
                    self.audit_logger.log_security_event(
                        'xss_attack_attempt',
                        {
                            'target_endpoint': target_endpoint,
                            'field': field,
                            'payload': payload[:50] + '...' if len(payload) > 50 else payload
                        },
                        severity='WARNING'
                    )
                    
                    # Simulate XSS detection (would be actual testing in real scenario)
                    if '<script>' in payload.lower() or 'javascript:' in payload.lower():
                        payload_test['detected'] = True
                        if 'alert' in payload.lower():
                            payload_test['blocked'] = False  # Assume not blocked for testing
                            attack_result['successful_payloads'].append(payload_test)
                            
                            self.audit_logger.log_security_violation(
                                'xss_vulnerability_detected',
                                {
                                    'target_endpoint': target_endpoint,
                                    'field': field,
                                    'payload': payload
                                },
                                risk_level='HIGH',
                                remediation='Implement input validation and output encoding'
                            )
                    
                    attack_result['payloads_tested'].append(payload_test)
            
            attack_result['duration'] = time.time() - start_time
            
            self.attack_results.append(attack_result)
            return attack_result
        
        def simulate_sql_injection_attack(self, target_endpoint: str, 
                                        parameters: List[str]) -> Dict[str, Any]:
            """Simulate SQL injection attack against parameters"""
            attack_result = {
                'attack_type': 'sql_injection',
                'target_endpoint': target_endpoint,
                'parameters': parameters,
                'payloads_tested': [],
                'vulnerable_parameters': [],
                'start_time': datetime.utcnow().isoformat(),
                'duration': 0
            }
            
            start_time = time.time()
            
            for parameter in parameters:
                for payload in self.payloads.SQL_INJECTION_PAYLOADS:
                    payload_test = {
                        'parameter': parameter,
                        'payload': payload,
                        'timestamp': datetime.utcnow().isoformat(),
                        'vulnerable': False,
                        'error_detected': False
                    }
                    
                    # Log security event
                    self.audit_logger.log_security_event(
                        'sql_injection_attempt',
                        {
                            'target_endpoint': target_endpoint,
                            'parameter': parameter,
                            'payload': payload
                        },
                        severity='WARNING'
                    )
                    
                    # Simulate SQL injection detection
                    if "'" in payload or '"' in payload or '--' in payload:
                        payload_test['error_detected'] = True
                        if 'OR' in payload.upper() or 'UNION' in payload.upper():
                            payload_test['vulnerable'] = True
                            attack_result['vulnerable_parameters'].append(parameter)
                            
                            self.audit_logger.log_security_violation(
                                'sql_injection_vulnerability',
                                {
                                    'target_endpoint': target_endpoint,
                                    'parameter': parameter,
                                    'payload': payload
                                },
                                risk_level='CRITICAL',
                                remediation='Use parameterized queries and input validation'
                            )
                    
                    attack_result['payloads_tested'].append(payload_test)
            
            attack_result['duration'] = time.time() - start_time
            
            self.attack_results.append(attack_result)
            return attack_result
        
        def simulate_session_hijacking(self, session_id: str) -> Dict[str, Any]:
            """Simulate session hijacking attack"""
            attack_result = {
                'attack_type': 'session_hijacking',
                'session_id': session_id,
                'hijack_attempts': [],
                'success': False,
                'start_time': datetime.utcnow().isoformat(),
                'duration': 0
            }
            
            start_time = time.time()
            
            # Simulate various hijacking techniques
            techniques = [
                'session_fixation',
                'session_prediction',
                'session_sniffing',
                'xss_session_theft'
            ]
            
            for technique in techniques:
                attempt = {
                    'technique': technique,
                    'timestamp': datetime.utcnow().isoformat(),
                    'success': False,
                    'details': {}
                }
                
                # Log security event
                self.audit_logger.log_security_event(
                    'session_hijacking_attempt',
                    {
                        'session_id': session_id[:8] + '...',
                        'technique': technique
                    },
                    severity='CRITICAL'
                )
                
                # Simulate technique-specific logic
                if technique == 'session_prediction':
                    # Check if session ID is predictable
                    if len(session_id) < 32 or session_id.isdigit():
                        attempt['success'] = True
                        attempt['details']['weakness'] = 'Predictable session ID'
                        attack_result['success'] = True
                elif technique == 'session_fixation':
                    # Check if session ID changes after authentication
                    attempt['details']['test'] = 'Session ID rotation check'
                
                attack_result['hijack_attempts'].append(attempt)
            
            attack_result['duration'] = time.time() - start_time
            
            if attack_result['success']:
                self.audit_logger.log_security_violation(
                    'session_hijacking_success',
                    {
                        'session_id': session_id[:8] + '...',
                        'successful_techniques': [
                            a['technique'] for a in attack_result['hijack_attempts'] 
                            if a['success']
                        ]
                    },
                    risk_level='CRITICAL',
                    remediation='Implement secure session management with proper entropy'
                )
            
            self.attack_results.append(attack_result)
            return attack_result
        
        def simulate_privilege_escalation(self, user_role: str, target_role: str) -> Dict[str, Any]:
            """Simulate privilege escalation attack"""
            attack_result = {
                'attack_type': 'privilege_escalation',
                'initial_role': user_role,
                'target_role': target_role,
                'escalation_attempts': [],
                'success': False,
                'start_time': datetime.utcnow().isoformat(),
                'duration': 0
            }
            
            start_time = time.time()
            
            # Simulate various escalation techniques
            techniques = [
                'parameter_tampering',
                'direct_object_reference',
                'function_level_access',
                'token_manipulation'
            ]
            
            for technique in techniques:
                attempt = {
                    'technique': technique,
                    'timestamp': datetime.utcnow().isoformat(),
                    'success': False,
                    'details': {}
                }
                
                # Log security event
                self.audit_logger.log_security_event(
                    'privilege_escalation_attempt',
                    {
                        'initial_role': user_role,
                        'target_role': target_role,
                        'technique': technique
                    },
                    severity='HIGH'
                )
                
                # Simulate technique-specific logic
                if technique == 'parameter_tampering':
                    # Check if role parameters can be manipulated
                    attempt['details']['test'] = 'Role parameter manipulation'
                    if user_role == 'user' and target_role == 'admin':
                        # Simulate weak authorization check
                        attempt['success'] = True
                        attack_result['success'] = True
                
                attack_result['escalation_attempts'].append(attempt)
            
            attack_result['duration'] = time.time() - start_time
            
            if attack_result['success']:
                self.audit_logger.log_security_violation(
                    'privilege_escalation_success',
                    {
                        'initial_role': user_role,
                        'target_role': target_role,
                        'successful_techniques': [
                            a['technique'] for a in attack_result['escalation_attempts'] 
                            if a['success']
                        ]
                    },
                    risk_level='CRITICAL',
                    remediation='Implement proper authorization checks and role validation'
                )
            
            self.attack_results.append(attack_result)
            return attack_result
        
        def get_attack_summary(self) -> Dict[str, Any]:
            """Get comprehensive attack simulation summary"""
            total_attacks = len(self.attack_results)
            successful_attacks = len([a for a in self.attack_results if a.get('success', False)])
            
            return {
                'total_attacks': total_attacks,
                'successful_attacks': successful_attacks,
                'attack_success_rate': (successful_attacks / total_attacks * 100) if total_attacks > 0 else 0,
                'attack_types': list(set(a['attack_type'] for a in self.attack_results)),
                'vulnerabilities_found': successful_attacks,
                'total_payloads_tested': sum(
                    len(a.get('payloads_tested', [])) 
                    for a in self.attack_results
                ),
                'attack_duration_total': sum(
                    a.get('duration', 0) 
                    for a in self.attack_results
                )
            }
    
    scenarios = MockAttackScenarios(security_payloads, security_audit_logger)
    
    security_logger.info("Mock attack scenarios initialized")
    return scenarios


@pytest.fixture(scope="function")
def security_performance_monitor(performance_monitoring):
    """
    Function-scoped fixture providing security operation performance monitoring.
    
    Creates performance monitoring specifically for security operations to ensure
    security controls don't impact performance beyond ≤10% variance threshold
    per Section 0.1.1 performance requirements.
    
    Args:
        performance_monitoring: Base performance monitoring context
        
    Returns:
        SecurityPerformanceMonitor: Security-specific performance monitoring
    """
    
    class SecurityPerformanceMonitor:
        def __init__(self, base_monitor):
            self.base_monitor = base_monitor
            self.security_metrics = []
            self.security_thresholds = {
                'jwt_validation': 50,  # milliseconds
                'password_hashing': 100,
                'encryption_operation': 75,
                'auth_request': 200,
                'permission_check': 25,
                'session_operation': 30,
                'security_header_processing': 10
            }
        
        @contextmanager
        def measure_security_operation(self, operation_name: str):
            """Context manager for measuring security operation performance"""
            start_time = time.perf_counter()
            start_memory = None
            
            try:
                # Get memory usage if available
                try:
                    import psutil
                    process = psutil.Process()
                    start_memory = process.memory_info().rss
                except ImportError:
                    pass
                
                yield
                
            finally:
                end_time = time.perf_counter()
                duration_ms = (end_time - start_time) * 1000
                
                end_memory = None
                memory_delta = None
                
                if start_memory:
                    try:
                        import psutil
                        process = psutil.Process()
                        end_memory = process.memory_info().rss
                        memory_delta = end_memory - start_memory
                    except ImportError:
                        pass
                
                # Create metric record
                metric = {
                    'operation': operation_name,
                    'duration_ms': duration_ms,
                    'timestamp': datetime.utcnow().isoformat(),
                    'memory_delta_bytes': memory_delta,
                    'within_threshold': True,
                    'threshold_ms': self.security_thresholds.get(operation_name),
                    'performance_impact': None
                }
                
                # Check threshold
                threshold = self.security_thresholds.get(operation_name)
                if threshold and duration_ms > threshold:
                    metric['within_threshold'] = False
                    metric['performance_impact'] = (duration_ms / threshold - 1) * 100
                    
                    security_logger.warning(
                        f"Security operation exceeded performance threshold: {operation_name}",
                        extra={
                            'duration_ms': duration_ms,
                            'threshold_ms': threshold,
                            'impact_percentage': metric['performance_impact']
                        }
                    )
                
                self.security_metrics.append(metric)
                
                # Also record in base monitor
                if hasattr(self.base_monitor, 'measure_operation'):
                    with self.base_monitor.measure_operation(f"security_{operation_name}"):
                        pass  # Already measured above
        
        def get_security_performance_summary(self) -> Dict[str, Any]:
            """Get comprehensive security performance summary"""
            if not self.security_metrics:
                return {
                    'total_operations': 0,
                    'average_duration_ms': 0,
                    'threshold_violations': 0,
                    'performance_compliant': True
                }
            
            total_operations = len(self.security_metrics)
            threshold_violations = len([m for m in self.security_metrics if not m['within_threshold']])
            
            durations = [m['duration_ms'] for m in self.security_metrics]
            average_duration = sum(durations) / len(durations)
            
            # Group by operation type
            operations_by_type = {}
            for metric in self.security_metrics:
                op_type = metric['operation']
                if op_type not in operations_by_type:
                    operations_by_type[op_type] = []
                operations_by_type[op_type].append(metric['duration_ms'])
            
            operation_summaries = {}
            for op_type, durations in operations_by_type.items():
                operation_summaries[op_type] = {
                    'count': len(durations),
                    'average_duration_ms': sum(durations) / len(durations),
                    'max_duration_ms': max(durations),
                    'min_duration_ms': min(durations),
                    'threshold_ms': self.security_thresholds.get(op_type),
                    'violations': len([d for d in durations if 
                                     self.security_thresholds.get(op_type) and 
                                     d > self.security_thresholds.get(op_type)])
                }
            
            return {
                'total_operations': total_operations,
                'average_duration_ms': average_duration,
                'max_duration_ms': max(durations),
                'min_duration_ms': min(durations),
                'threshold_violations': threshold_violations,
                'violation_percentage': (threshold_violations / total_operations * 100) if total_operations > 0 else 0,
                'performance_compliant': threshold_violations == 0,
                'operations_by_type': operation_summaries,
                'total_memory_impact_bytes': sum(
                    m.get('memory_delta_bytes', 0) or 0 
                    for m in self.security_metrics
                )
            }
    
    monitor = SecurityPerformanceMonitor(performance_monitoring)
    
    security_logger.info(
        "Security performance monitor initialized",
        security_thresholds=len(monitor.security_thresholds)
    )
    
    return monitor


@pytest.fixture(scope="function")
def comprehensive_security_environment(
    security_config,
    security_payloads,
    security_audit_logger,
    mock_auth0_security_service,
    security_validation_tools,
    mock_attack_scenarios,
    security_performance_monitor,
    flask_app,
    client
):
    """
    Function-scoped fixture providing comprehensive security testing environment.
    
    Integrates all security testing components for complete security validation
    per Section 6.4 security architecture and Section 6.6.1 testing strategy
    requirements.
    
    Args:
        security_config: Security testing configuration
        security_payloads: Security testing payload collection
        security_audit_logger: Security audit logging utility
        mock_auth0_security_service: Auth0 security service mock
        security_validation_tools: Security validation utilities
        mock_attack_scenarios: Attack scenario simulation
        security_performance_monitor: Security performance monitoring
        flask_app: Flask application instance
        client: Flask test client
        
    Returns:
        Dict: Comprehensive security testing environment
    """
    environment = {
        'config': security_config,
        'payloads': security_payloads,
        'audit_logger': security_audit_logger,
        'auth0_service': mock_auth0_security_service,
        'validation_tools': security_validation_tools,
        'attack_scenarios': mock_attack_scenarios,
        'performance_monitor': security_performance_monitor,
        'flask_app': flask_app,
        'client': client,
        'session_info': {
            'session_id': str(uuid.uuid4()),
            'started_at': datetime.utcnow().isoformat(),
            'security_level': 'enterprise'
        }
    }
    
    # Initialize security test session
    start_time = time.time()
    
    security_audit_logger.log_security_event(
        'security_test_session_started',
        {
            'session_id': environment['session_info']['session_id'],
            'security_level': environment['session_info']['security_level'],
            'testing_components': list(environment.keys())
        },
        severity='INFO'
    )
    
    security_logger.info(
        "Comprehensive security testing environment initialized",
        session_id=environment['session_info']['session_id'],
        components_available=len(environment),
        auth0_service_available=bool(environment['auth0_service']),
        attack_scenarios_available=bool(environment['attack_scenarios']),
        performance_monitoring_enabled=bool(environment['performance_monitor'])
    )
    
    yield environment
    
    # Security test session cleanup and reporting
    end_time = time.time()
    session_duration = end_time - start_time
    
    # Collect final security metrics
    security_summary = security_audit_logger.get_security_summary()
    validation_summary = security_validation_tools.get_validation_summary()
    attack_summary = mock_attack_scenarios.get_attack_summary()
    performance_summary = security_performance_monitor.get_security_performance_summary()
    
    # Log final security session summary
    security_audit_logger.log_security_event(
        'security_test_session_completed',
        {
            'session_id': environment['session_info']['session_id'],
            'duration': session_duration,
            'security_events': security_summary['total_events'],
            'security_violations': security_summary['total_violations'],
            'validations_performed': validation_summary['total_validations'],
            'attacks_simulated': attack_summary['total_attacks'],
            'performance_compliant': performance_summary['performance_compliant']
        },
        severity='INFO'
    )
    
    security_logger.info(
        "Security testing environment session completed",
        session_id=environment['session_info']['session_id'],
        duration=round(session_duration, 3),
        security_events_logged=security_summary['total_events'],
        security_violations_detected=security_summary['total_violations'],
        security_tests_passed=validation_summary['passed_validations'],
        performance_violations=performance_summary['threshold_violations']
    )


# =============================================================================
# Security Testing Utility Functions
# =============================================================================

def create_test_jwt_token(claims: Dict[str, Any] = None, algorithm: str = 'HS256', 
                         secret: str = 'test-secret') -> str:
    """
    Create JWT token for security testing.
    
    Args:
        claims: JWT claims dictionary
        algorithm: JWT algorithm
        secret: JWT secret key
        
    Returns:
        str: Encoded JWT token for testing
    """
    default_claims = {
        'sub': 'test_user_123',
        'email': 'test@example.com',
        'iss': 'https://test-tenant.auth0.com/',
        'aud': 'test-api-audience',
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=1),
        'scope': 'openid profile email'
    }
    
    if claims:
        default_claims.update(claims)
    
    return jwt.encode(default_claims, secret, algorithm=algorithm)


def generate_secure_session_id(length: int = 32) -> str:
    """
    Generate cryptographically secure session ID.
    
    Args:
        length: Session ID length
        
    Returns:
        str: Secure session ID
    """
    return secrets.token_urlsafe(length)


def hash_password_securely(password: str) -> str:
    """
    Hash password using secure algorithm.
    
    Args:
        password: Plain text password
        
    Returns:
        str: Hashed password
    """
    return generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)


def validate_password_hash(password: str, password_hash: str) -> bool:
    """
    Validate password against hash.
    
    Args:
        password: Plain text password
        password_hash: Hashed password
        
    Returns:
        bool: True if password matches hash
    """
    return check_password_hash(password_hash, password)


def encrypt_data(data: str, key: bytes = None) -> Tuple[bytes, bytes]:
    """
    Encrypt data using Fernet symmetric encryption.
    
    Args:
        data: Data to encrypt
        key: Encryption key (generated if None)
        
    Returns:
        Tuple[bytes, bytes]: (encrypted_data, encryption_key)
    """
    if key is None:
        key = Fernet.generate_key()
    
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data.encode())
    
    return encrypted_data, key


def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """
    Decrypt data using Fernet symmetric encryption.
    
    Args:
        encrypted_data: Encrypted data
        key: Encryption key
        
    Returns:
        str: Decrypted data
    """
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)
    
    return decrypted_data.decode()


def generate_csrf_token() -> str:
    """
    Generate CSRF token for form protection.
    
    Returns:
        str: CSRF token
    """
    return secrets.token_urlsafe(32)


def validate_csrf_token(token: str, session_token: str) -> bool:
    """
    Validate CSRF token.
    
    Args:
        token: CSRF token to validate
        session_token: Session CSRF token
        
    Returns:
        bool: True if token is valid
    """
    return hmac.compare_digest(token, session_token)


# Export all security testing fixtures and utilities
__all__ = [
    # Configuration classes
    'SecurityTestConfig',
    'SecurityPayloads',
    
    # Main fixtures
    'security_config',
    'security_payloads',
    'security_audit_logger',
    'mock_auth0_security_service',
    'security_validation_tools',
    'mock_attack_scenarios',
    'security_performance_monitor',
    'comprehensive_security_environment',
    
    # Utility functions
    'create_test_jwt_token',
    'generate_secure_session_id',
    'hash_password_securely',
    'validate_password_hash',
    'encrypt_data',
    'decrypt_data',
    'generate_csrf_token',
    'validate_csrf_token'
]