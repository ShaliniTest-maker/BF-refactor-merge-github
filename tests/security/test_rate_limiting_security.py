"""
Rate Limiting Security Testing

This module implements comprehensive Flask-Limiter security validation, abuse prevention testing,
and rate limiting bypass attempt detection ensuring DoS protection and resource exhaustion prevention
per Section 6.4.2 Authorization System rate limiting requirements.

Key Security Validations:
- Flask-Limiter rate limiting security validation per Section 6.4.2
- Rate limiting for authorization endpoints with user-specific limits per Section 6.4.2
- DoS attack prevention through intelligent rate limiting per Section 6.4.2
- Zero tolerance for rate limiting bypass vulnerabilities per Section 6.4.5
- Rate limiting bypass attempt detection tests per Section 6.4.2
- Authorization endpoint throttling security tests per Section 6.4.2
- Burst and sustained rate limiting security validation per Section 6.4.2
- Rate limiting cache security and integrity validation per Section 6.4.2

Test Coverage Areas:
- Rate limiting configuration validation and security hardening
- Authorization endpoint specific rate limiting with user context
- DoS attack simulation and protection effectiveness
- Rate limiting bypass attempts using various attack vectors
- Burst vs sustained rate limiting pattern validation
- Rate limiting cache manipulation and security validation
- Circuit breaker integration during rate limiting scenarios
- Performance impact validation maintaining ≤10% variance requirement

Security Integration:
- Flask-Limiter 3.12+ integration with Redis backend security
- Rate limiting key generation security and collision resistance
- User-specific rate limiting with session validation
- Rate limiting metrics collection for security monitoring
- Prometheus integration for rate limiting violation alerts
- Structured audit logging for rate limiting security events

Dependencies:
- pytest: Testing framework with comprehensive fixtures
- Flask: Web framework for rate limiting endpoint testing
- Flask-Limiter: Rate limiting implementation and security validation
- redis: Cache backend for rate limiting storage security
- time: Timing utilities for rate limiting validation
- concurrent.futures: Concurrent request testing for DoS simulation
- threading: Multi-threaded rate limiting testing

Author: Flask Migration Team
Version: 1.0.0
Compliance: OWASP Top 10, DoS Prevention, SOC 2
Security Level: Zero tolerance for rate limiting bypass per Section 6.4.5
"""

import asyncio
import json
import random
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Callable
from unittest.mock import Mock, patch, MagicMock

import pytest
import redis
from flask import Flask, request, jsonify, g, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import TooManyRequests

# Import test dependencies with fallback handling
try:
    from tests.conftest import (
        comprehensive_test_environment,
        performance_monitoring,
        test_metrics_collector
    )
    from src.auth.decorators import (
        rate_limited_authorization,
        require_permissions,
        AuthenticatedUser,
        DecoratorConfig
    )
    from src.config.rate_limiting import (
        RateLimitConfig,
        RateLimitingManager,
        create_rate_limiter
    )
    IMPORTS_AVAILABLE = True
except ImportError:
    IMPORTS_AVAILABLE = False
    
    # Fallback implementations for isolated testing
    class RateLimitConfig:
        DEFAULT_RATE_LIMIT = "100 per minute"
        HIGH_SECURITY_RATE_LIMIT = "20 per minute"
        ADMIN_RATE_LIMIT = "10 per minute"
        BURST_PROTECTION_LIMIT = "10 per second"
    
    class DecoratorConfig:
        DEFAULT_RATE_LIMIT = "100 per minute"
        HIGH_SECURITY_RATE_LIMIT = "20 per minute"
        ADMIN_RATE_LIMIT = "10 per minute"
        BURST_PROTECTION_LIMIT = "10 per second"

# Configure test logging
import logging
logger = logging.getLogger(__name__)


# =============================================================================
# Rate Limiting Security Test Configuration
# =============================================================================

class RateLimitingSecurityConfig:
    """
    Configuration for rate limiting security testing with comprehensive DoS protection
    and bypass attempt detection per Section 6.4.2 security requirements.
    """
    
    # Rate Limiting Test Thresholds
    MAX_REQUESTS_PER_SECOND = 10
    MAX_REQUESTS_PER_MINUTE = 100
    MAX_REQUESTS_PER_HOUR = 1000
    
    # DoS Attack Simulation Parameters
    DOS_ATTACK_REQUEST_COUNT = 500
    DOS_ATTACK_CONCURRENT_THREADS = 50
    DOS_ATTACK_BURST_DURATION = 5.0  # seconds
    
    # Rate Limiting Bypass Test Parameters
    BYPASS_ATTEMPT_COUNT = 100
    BYPASS_ATTACK_VECTORS = [
        'header_manipulation',
        'ip_rotation',
        'user_agent_rotation',
        'session_manipulation',
        'cache_poisoning',
        'distributed_attack'
    ]
    
    # Authorization Endpoint Rate Limiting
    AUTH_ENDPOINT_LIMITS = {
        'login': "5 per minute",
        'logout': "10 per minute", 
        'refresh': "20 per minute",
        'permissions': "50 per minute",
        'admin': "10 per minute"
    }
    
    # Performance Requirements
    MAX_RATE_LIMITING_OVERHEAD_MS = 5.0  # Maximum acceptable overhead
    PERFORMANCE_VARIANCE_THRESHOLD = 0.10  # ≤10% variance requirement
    
    # Security Monitoring Thresholds
    RATE_LIMIT_VIOLATION_ALERT_THRESHOLD = 10
    BYPASS_ATTEMPT_ALERT_THRESHOLD = 5
    SUSPICIOUS_PATTERN_ALERT_THRESHOLD = 3


class RateLimitingTestHelper:
    """
    Helper class for rate limiting security testing with comprehensive attack simulation
    and bypass detection capabilities per Section 6.4.2 requirements.
    """
    
    def __init__(self, app: Flask, limiter: Limiter, redis_client: redis.Redis):
        self.app = app
        self.limiter = limiter
        self.redis_client = redis_client
        self.security_violations = []
        self.bypass_attempts = []
        self.dos_protection_events = []
    
    def simulate_burst_requests(
        self, 
        endpoint: str, 
        request_count: int,
        burst_duration: float = 1.0,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Simulate burst request pattern for rate limiting validation.
        
        Args:
            endpoint: Target endpoint for burst testing
            request_count: Number of requests in burst
            burst_duration: Duration of burst in seconds
            headers: Optional headers for requests
            
        Returns:
            Burst test results with rate limiting validation
        """
        results = {
            'total_requests': request_count,
            'successful_requests': 0,
            'rate_limited_requests': 0,
            'error_requests': 0,
            'response_times': [],
            'rate_limit_triggered': False,
            'burst_duration': burst_duration,
            'requests_per_second': request_count / burst_duration
        }
        
        start_time = time.perf_counter()
        
        with self.app.test_client() as client:
            for i in range(request_count):
                request_start = time.perf_counter()
                
                try:
                    response = client.get(
                        endpoint, 
                        headers=headers or {'User-Agent': f'BurstTest-{i}'}
                    )
                    
                    request_end = time.perf_counter()
                    response_time = request_end - request_start
                    results['response_times'].append(response_time)
                    
                    if response.status_code == 429:  # Too Many Requests
                        results['rate_limited_requests'] += 1
                        results['rate_limit_triggered'] = True
                        
                        # Log rate limiting event
                        self.dos_protection_events.append({
                            'timestamp': datetime.utcnow().isoformat(),
                            'event_type': 'rate_limit_triggered',
                            'endpoint': endpoint,
                            'request_number': i + 1,
                            'total_requests': request_count,
                            'response_time': response_time
                        })
                        
                    elif response.status_code == 200:
                        results['successful_requests'] += 1
                    else:
                        results['error_requests'] += 1
                
                except Exception as e:
                    results['error_requests'] += 1
                    logger.warning(f"Burst request failed: {e}")
                
                # Maintain burst timing
                elapsed = time.perf_counter() - start_time
                expected_elapsed = (i + 1) * (burst_duration / request_count)
                if elapsed < expected_elapsed:
                    time.sleep(expected_elapsed - elapsed)
        
        total_time = time.perf_counter() - start_time
        results['actual_duration'] = total_time
        results['actual_rps'] = request_count / total_time if total_time > 0 else 0
        
        return results
    
    def simulate_sustained_requests(
        self,
        endpoint: str,
        requests_per_second: int,
        duration_seconds: int,
        user_rotation: bool = False
    ) -> Dict[str, Any]:
        """
        Simulate sustained request pattern for DoS protection validation.
        
        Args:
            endpoint: Target endpoint for sustained testing
            requests_per_second: Rate of requests per second
            duration_seconds: Duration of sustained testing
            user_rotation: Whether to rotate user context
            
        Returns:
            Sustained test results with DoS protection validation
        """
        results = {
            'total_requests': requests_per_second * duration_seconds,
            'successful_requests': 0,
            'rate_limited_requests': 0,
            'error_requests': 0,
            'average_response_time': 0.0,
            'rate_limiting_effectiveness': 0.0,
            'dos_protection_triggered': False,
            'sustained_duration': duration_seconds,
            'target_rps': requests_per_second
        }
        
        response_times = []
        start_time = time.perf_counter()
        
        with self.app.test_client() as client:
            for second in range(duration_seconds):
                second_start = time.perf_counter()
                
                for request_in_second in range(requests_per_second):
                    request_start = time.perf_counter()
                    
                    # Generate headers with user rotation if enabled
                    headers = {'User-Agent': 'SustainedTest'}
                    if user_rotation:
                        user_id = f"user_{request_in_second % 10}"
                        headers['X-User-ID'] = user_id
                    
                    try:
                        response = client.get(endpoint, headers=headers)
                        
                        request_end = time.perf_counter()
                        response_time = request_end - request_start
                        response_times.append(response_time)
                        
                        if response.status_code == 429:
                            results['rate_limited_requests'] += 1
                            results['dos_protection_triggered'] = True
                        elif response.status_code == 200:
                            results['successful_requests'] += 1
                        else:
                            results['error_requests'] += 1
                    
                    except Exception as e:
                        results['error_requests'] += 1
                        logger.warning(f"Sustained request failed: {e}")
                
                # Pace requests to maintain target RPS
                second_elapsed = time.perf_counter() - second_start
                if second_elapsed < 1.0:
                    time.sleep(1.0 - second_elapsed)
        
        if response_times:
            results['average_response_time'] = sum(response_times) / len(response_times)
        
        # Calculate rate limiting effectiveness
        total_requests = results['total_requests']
        rate_limited = results['rate_limited_requests']
        
        if total_requests > 0:
            results['rate_limiting_effectiveness'] = rate_limited / total_requests
        
        return results
    
    def attempt_rate_limit_bypass(
        self,
        endpoint: str,
        attack_vector: str,
        attempt_count: int = 50
    ) -> Dict[str, Any]:
        """
        Attempt rate limiting bypass using various attack vectors.
        
        Args:
            endpoint: Target endpoint for bypass attempts
            attack_vector: Type of bypass attack to attempt
            attempt_count: Number of bypass attempts
            
        Returns:
            Bypass attempt results with security validation
        """
        results = {
            'attack_vector': attack_vector,
            'total_attempts': attempt_count,
            'successful_bypasses': 0,
            'blocked_attempts': 0,
            'error_attempts': 0,
            'bypass_success_rate': 0.0,
            'security_effective': True,
            'detected_patterns': []
        }
        
        with self.app.test_client() as client:
            for i in range(attempt_count):
                headers = self._generate_bypass_headers(attack_vector, i)
                
                try:
                    response = client.get(endpoint, headers=headers)
                    
                    if response.status_code == 200:
                        results['successful_bypasses'] += 1
                        
                        # Log potential bypass
                        self.bypass_attempts.append({
                            'timestamp': datetime.utcnow().isoformat(),
                            'attack_vector': attack_vector,
                            'attempt_number': i + 1,
                            'headers': headers,
                            'response_code': response.status_code,
                            'bypass_successful': True
                        })
                        
                    elif response.status_code == 429:
                        results['blocked_attempts'] += 1
                    else:
                        results['error_attempts'] += 1
                
                except Exception as e:
                    results['error_attempts'] += 1
                    logger.warning(f"Bypass attempt failed: {e}")
        
        # Calculate bypass success rate
        if attempt_count > 0:
            results['bypass_success_rate'] = results['successful_bypasses'] / attempt_count
        
        # Security is effective if bypass rate is below threshold (5%)
        results['security_effective'] = results['bypass_success_rate'] < 0.05
        
        return results
    
    def _generate_bypass_headers(self, attack_vector: str, attempt_number: int) -> Dict[str, str]:
        """Generate headers for specific bypass attack vectors."""
        base_headers = {'User-Agent': f'BypassTest-{attempt_number}'}
        
        if attack_vector == 'header_manipulation':
            # Attempt various header manipulations
            bypass_headers = {
                'X-Forwarded-For': f'192.168.1.{random.randint(1, 254)}',
                'X-Real-IP': f'10.0.0.{random.randint(1, 254)}',
                'X-Originating-IP': f'172.16.0.{random.randint(1, 254)}',
                'CF-Connecting-IP': f'203.0.113.{random.randint(1, 254)}',
                'True-Client-IP': f'198.51.100.{random.randint(1, 254)}'
            }
            base_headers.update(bypass_headers)
            
        elif attack_vector == 'user_agent_rotation':
            user_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X)',
                'Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/88.0'
            ]
            base_headers['User-Agent'] = random.choice(user_agents)
            
        elif attack_vector == 'session_manipulation':
            base_headers['Cookie'] = f'session_id=bypass_session_{uuid.uuid4()}'
            base_headers['X-Session-Token'] = f'token_{uuid.uuid4()}'
            
        elif attack_vector == 'cache_poisoning':
            base_headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            base_headers['Pragma'] = 'no-cache'
            base_headers['Expires'] = '0'
            base_headers['X-Cache-Bypass'] = f'bypass_{attempt_number}'
            
        elif attack_vector == 'distributed_attack':
            # Simulate distributed attack patterns
            base_headers['X-Forwarded-For'] = f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}'
            base_headers['Via'] = f'1.1 proxy{random.randint(1, 100)}.example.com'
            
        return base_headers
    
    def validate_rate_limiting_cache_security(self) -> Dict[str, Any]:
        """
        Validate rate limiting cache security and integrity.
        
        Returns:
            Cache security validation results
        """
        results = {
            'cache_accessible': False,
            'cache_keys_exposed': [],
            'cache_manipulation_possible': False,
            'cache_encryption_validated': False,
            'security_violations': [],
            'cache_integrity_maintained': True
        }
        
        try:
            # Test cache key enumeration
            cache_keys = self.redis_client.keys('*rate_limit*')
            results['cache_keys_exposed'] = [key.decode() if isinstance(key, bytes) else key for key in cache_keys]
            results['cache_accessible'] = len(cache_keys) > 0
            
            if cache_keys:
                # Test cache key structure for security
                for key in cache_keys[:5]:  # Test first 5 keys
                    try:
                        cache_value = self.redis_client.get(key)
                        if cache_value:
                            # Check if cache value contains sensitive information
                            value_str = cache_value.decode() if isinstance(cache_value, bytes) else str(cache_value)
                            
                            # Look for potential security issues
                            if any(sensitive in value_str.lower() for sensitive in ['password', 'token', 'secret', 'key']):
                                results['security_violations'].append({
                                    'type': 'sensitive_data_in_cache',
                                    'key': key,
                                    'issue': 'Potentially sensitive data found in rate limiting cache'
                                })
                    
                    except Exception as e:
                        logger.warning(f"Cache validation error for key {key}: {e}")
            
            # Test cache manipulation attempts
            manipulation_key = 'test_manipulation_key'
            original_value = self.redis_client.get(manipulation_key)
            
            try:
                # Attempt to set a test value
                self.redis_client.setex(manipulation_key, 60, 'manipulation_test')
                manipulated_value = self.redis_client.get(manipulation_key)
                
                if manipulated_value and manipulated_value.decode() == 'manipulation_test':
                    results['cache_manipulation_possible'] = True
                    results['security_violations'].append({
                        'type': 'cache_manipulation_possible',
                        'issue': 'Rate limiting cache can be directly manipulated'
                    })
                
                # Clean up test
                self.redis_client.delete(manipulation_key)
                
            except Exception as e:
                logger.debug(f"Cache manipulation test failed (good): {e}")
            
            # Restore original value if it existed
            if original_value:
                self.redis_client.set(manipulation_key, original_value)
        
        except Exception as e:
            logger.error(f"Cache security validation failed: {e}")
            results['cache_integrity_maintained'] = False
        
        return results
    
    def measure_rate_limiting_performance_impact(
        self,
        endpoint: str,
        baseline_requests: int = 100,
        rate_limited_requests: int = 100
    ) -> Dict[str, Any]:
        """
        Measure performance impact of rate limiting implementation.
        
        Args:
            endpoint: Endpoint to test
            baseline_requests: Number of baseline requests
            rate_limited_requests: Number of rate limited requests
            
        Returns:
            Performance impact analysis results
        """
        results = {
            'baseline_avg_response_time': 0.0,
            'rate_limited_avg_response_time': 0.0,
            'performance_overhead': 0.0,
            'variance_percentage': 0.0,
            'compliant_with_requirements': False,
            'overhead_threshold_ms': RateLimitingSecurityConfig.MAX_RATE_LIMITING_OVERHEAD_MS
        }
        
        # Measure baseline performance (without rate limiting pressure)
        baseline_times = []
        
        with self.app.test_client() as client:
            # Baseline measurement with spacing
            for i in range(baseline_requests):
                start_time = time.perf_counter()
                response = client.get(endpoint)
                end_time = time.perf_counter()
                
                if response.status_code == 200:
                    baseline_times.append(end_time - start_time)
                
                # Small delay to avoid rate limiting
                time.sleep(0.1)
        
        if baseline_times:
            results['baseline_avg_response_time'] = sum(baseline_times) / len(baseline_times)
        
        # Measure performance under rate limiting pressure
        rate_limited_times = []
        
        with self.app.test_client() as client:
            # Rapid requests to trigger rate limiting
            for i in range(rate_limited_requests):
                start_time = time.perf_counter()
                response = client.get(endpoint)
                end_time = time.perf_counter()
                
                # Include all response times (both 200 and 429)
                rate_limited_times.append(end_time - start_time)
        
        if rate_limited_times:
            results['rate_limited_avg_response_time'] = sum(rate_limited_times) / len(rate_limited_times)
        
        # Calculate performance overhead
        if results['baseline_avg_response_time'] > 0:
            overhead = results['rate_limited_avg_response_time'] - results['baseline_avg_response_time']
            results['performance_overhead'] = overhead
            results['variance_percentage'] = (overhead / results['baseline_avg_response_time']) * 100
            
            # Check compliance with ≤10% variance requirement
            results['compliant_with_requirements'] = (
                results['variance_percentage'] <= RateLimitingSecurityConfig.PERFORMANCE_VARIANCE_THRESHOLD * 100 and
                overhead * 1000 <= results['overhead_threshold_ms']  # Convert to ms
            )
        
        return results


# =============================================================================
# Rate Limiting Security Test Fixtures
# =============================================================================

@pytest.fixture(scope="function")
def rate_limiting_test_app():
    """
    Create Flask application with comprehensive rate limiting configuration for testing.
    
    Returns:
        Flask application with rate limiting configured for security testing
    """
    app = Flask(__name__)
    app.config.update({
        'TESTING': True,
        'SECRET_KEY': 'test-secret-key',
        'RATELIMIT_STORAGE_URL': 'redis://localhost:6379/15',
        'RATELIMIT_STRATEGY': 'moving-window',
        'RATELIMIT_HEADERS_ENABLED': True,
    })
    
    # Configure Redis client for rate limiting
    redis_client = redis.Redis(
        host='localhost',
        port=6379,
        db=15,
        decode_responses=True
    )
    
    # Create rate limiter with security configuration
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        storage_uri='redis://localhost:6379/15',
        strategy='moving-window',
        headers_enabled=True,
        default_limits=["1000 per hour", "100 per minute", "10 per second"]
    )
    
    # Define test endpoints with various rate limiting configurations
    
    @app.route('/test/basic')
    @limiter.limit("5 per minute")
    def basic_endpoint():
        return jsonify({'message': 'Basic endpoint', 'timestamp': time.time()})
    
    @app.route('/test/burst')  
    @limiter.limit("10 per second; 50 per minute")
    def burst_protected_endpoint():
        return jsonify({'message': 'Burst protected endpoint', 'timestamp': time.time()})
    
    @app.route('/test/auth/login', methods=['POST'])
    @limiter.limit("5 per minute")
    def auth_login():
        return jsonify({'message': 'Auth login endpoint', 'timestamp': time.time()})
    
    @app.route('/test/auth/permissions')
    @limiter.limit("20 per minute")
    def auth_permissions():
        return jsonify({'message': 'Auth permissions endpoint', 'timestamp': time.time()})
    
    @app.route('/test/admin')
    @limiter.limit("10 per minute")
    def admin_endpoint():
        return jsonify({'message': 'Admin endpoint', 'timestamp': time.time()})
    
    @app.route('/test/high-security')
    @limiter.limit("3 per minute")
    def high_security_endpoint():
        return jsonify({'message': 'High security endpoint', 'timestamp': time.time()})
    
    @app.route('/test/no-limit')
    def no_limit_endpoint():
        return jsonify({'message': 'No rate limiting', 'timestamp': time.time()})
    
    # Error handler for rate limiting
    @app.errorhandler(429)
    def handle_rate_limit_exceeded(e):
        return jsonify({
            'error': 'Rate limit exceeded',
            'message': 'Too many requests',
            'retry_after': getattr(e, 'retry_after', None)
        }), 429
    
    app.limiter = limiter
    app.redis_client = redis_client
    
    return app


@pytest.fixture(scope="function") 
def rate_limiting_helper(rate_limiting_test_app):
    """
    Create rate limiting test helper with security testing utilities.
    
    Args:
        rate_limiting_test_app: Flask application with rate limiting
        
    Returns:
        RateLimitingTestHelper instance for security testing
    """
    return RateLimitingTestHelper(
        app=rate_limiting_test_app,
        limiter=rate_limiting_test_app.limiter,
        redis_client=rate_limiting_test_app.redis_client
    )


@pytest.fixture(scope="function")
def mock_authenticated_users():
    """
    Create mock authenticated users for rate limiting testing.
    
    Returns:
        Dictionary of mock users with different permission levels
    """
    users = {
        'regular_user': {
            'user_id': 'user_001',
            'email': 'user@example.com',
            'permissions': ['read:profile', 'update:profile'],
            'roles': ['user'],
            'rate_limit_tier': 'standard'
        },
        'admin_user': {
            'user_id': 'admin_001', 
            'email': 'admin@example.com',
            'permissions': ['admin:all', 'read:all', 'write:all'],
            'roles': ['admin', 'user'],
            'rate_limit_tier': 'elevated'
        },
        'api_user': {
            'user_id': 'api_001',
            'email': 'api@example.com', 
            'permissions': ['api:access'],
            'roles': ['api_user'],
            'rate_limit_tier': 'api'
        },
        'suspicious_user': {
            'user_id': 'suspicious_001',
            'email': 'suspicious@example.com',
            'permissions': ['read:profile'],
            'roles': ['user'],
            'rate_limit_tier': 'restricted'
        }
    }
    
    return users


# =============================================================================
# Flask-Limiter Security Validation Tests
# =============================================================================

class TestFlaskLimiterSecurityValidation:
    """
    Test Flask-Limiter security validation ensuring proper configuration and
    protection against abuse per Section 6.4.2 requirements.
    """
    
    def test_rate_limiter_initialization_security(self, rate_limiting_test_app):
        """
        Test Flask-Limiter initialization with security-focused configuration.
        
        Validates that rate limiter is properly configured with secure defaults,
        Redis backend integration, and comprehensive security headers.
        """
        app = rate_limiting_test_app
        limiter = app.limiter
        
        # Validate limiter configuration
        assert limiter is not None, "Rate limiter should be initialized"
        assert limiter.enabled, "Rate limiter should be enabled"
        assert limiter._strategy == 'moving-window', "Should use moving-window strategy for security"
        
        # Test Redis backend connectivity
        assert app.redis_client.ping(), "Redis backend should be accessible"
        
        # Validate security headers are enabled
        with app.test_client() as client:
            response = client.get('/test/basic')
            
            # Check for rate limiting headers
            assert 'X-RateLimit-Limit' in response.headers, "Rate limit headers should be present"
            assert 'X-RateLimit-Remaining' in response.headers, "Remaining requests header should be present"
            assert 'X-RateLimit-Reset' in response.headers, "Reset time header should be present"
        
        logger.info("Flask-Limiter security configuration validated successfully")
    
    def test_rate_limiting_key_generation_security(self, rate_limiting_test_app, rate_limiting_helper):
        """
        Test rate limiting key generation for security and collision resistance.
        
        Validates that rate limiting keys are generated securely and resist
        collision attacks that could bypass rate limiting controls.
        """
        app = rate_limiting_test_app
        redis_client = app.redis_client
        
        # Clear any existing rate limiting data
        redis_client.flushdb()
        
        # Generate requests with different sources
        test_scenarios = [
            {'headers': {'X-Forwarded-For': '192.168.1.1'}, 'expected_key_contains': 'remote_addr'},
            {'headers': {'X-Real-IP': '10.0.0.1'}, 'expected_key_contains': 'remote_addr'},
            {'headers': {'User-Agent': 'TestAgent'}, 'expected_key_contains': 'remote_addr'},
        ]
        
        generated_keys = set()
        
        with app.test_client() as client:
            for scenario in test_scenarios:
                response = client.get('/test/basic', headers=scenario['headers'])
                assert response.status_code == 200, f"Request should succeed: {scenario}"
                
                # Check generated cache keys
                cache_keys = redis_client.keys('*')
                assert len(cache_keys) > 0, "Rate limiting keys should be generated"
                
                for key in cache_keys:
                    key_str = key.decode() if isinstance(key, bytes) else key
                    generated_keys.add(key_str)
                    
                    # Validate key structure for security
                    assert 'rate_limit' in key_str.lower() or 'limiter' in key_str.lower(), \
                        f"Key should contain rate limiting identifier: {key_str}"
                    
                    # Ensure keys don't expose sensitive information
                    sensitive_patterns = ['password', 'secret', 'key', 'token']
                    for pattern in sensitive_patterns:
                        assert pattern not in key_str.lower(), \
                            f"Rate limiting key should not contain sensitive data: {key_str}"
        
        # Validate key uniqueness and collision resistance
        assert len(generated_keys) > 0, "Should generate rate limiting keys"
        
        logger.info(f"Rate limiting key security validated with {len(generated_keys)} unique keys")
    
    def test_rate_limiting_cache_manipulation_resistance(self, rate_limiting_test_app, rate_limiting_helper):
        """
        Test resistance to rate limiting cache manipulation attacks.
        
        Validates that rate limiting cache cannot be directly manipulated to
        bypass rate limiting controls per Section 6.4.5 zero tolerance requirement.
        """
        cache_security_results = rate_limiting_helper.validate_rate_limiting_cache_security()
        
        # Validate cache security findings
        assert cache_security_results['cache_integrity_maintained'], \
            "Rate limiting cache integrity should be maintained"
        
        # Check for critical security violations
        critical_violations = [
            violation for violation in cache_security_results['security_violations']
            if violation['type'] in ['sensitive_data_in_cache', 'cache_manipulation_possible']
        ]
        
        assert len(critical_violations) == 0, \
            f"Critical cache security violations detected: {critical_violations}"
        
        # Validate cache access is properly restricted
        if cache_security_results['cache_accessible']:
            # If cache is accessible, ensure no sensitive data is exposed
            sensitive_keys = [
                key for key in cache_security_results['cache_keys_exposed']
                if any(sensitive in key.lower() for sensitive in ['password', 'secret', 'token'])
            ]
            
            assert len(sensitive_keys) == 0, \
                f"Sensitive data found in rate limiting cache keys: {sensitive_keys}"
        
        logger.info("Rate limiting cache manipulation resistance validated")
    
    def test_rate_limiting_configuration_hardening(self, rate_limiting_test_app):
        """
        Test rate limiting configuration hardening and security settings.
        
        Validates that rate limiting is configured with security-focused settings
        including proper timeouts, limits, and error handling.
        """
        app = rate_limiting_test_app
        limiter = app.limiter
        
        # Test configuration security
        with app.test_client() as client:
            # Test that rate limiting is enforced
            for i in range(7):  # Exceed 5 per minute limit
                response = client.get('/test/basic')
                
                if i < 5:
                    assert response.status_code == 200, f"Request {i+1} should succeed"
                else:
                    assert response.status_code == 429, f"Request {i+1} should be rate limited"
                    
                    # Validate error response structure
                    error_data = response.get_json()
                    assert 'error' in error_data, "Error response should contain error field"
                    assert 'rate limit' in error_data['error'].lower(), "Should indicate rate limiting"
        
        # Test burst protection configuration
        with app.test_client() as client:
            burst_responses = []
            start_time = time.perf_counter()
            
            # Send rapid requests to test burst protection
            for i in range(12):  # Exceed 10 per second limit
                response = client.get('/test/burst')
                burst_responses.append(response.status_code)
            
            elapsed_time = time.perf_counter() - start_time
            
            # Should hit rate limit within burst window
            rate_limited_count = sum(1 for status in burst_responses if status == 429)
            assert rate_limited_count > 0, "Burst protection should trigger rate limiting"
            
            # Should be fast (not waiting for window reset)
            assert elapsed_time < 2.0, "Burst protection should respond quickly"
        
        logger.info("Rate limiting configuration hardening validated")


# =============================================================================
# DoS Attack Prevention Tests
# =============================================================================

class TestDoSAttackPrevention:
    """
    Test DoS attack prevention through intelligent rate limiting per Section 6.4.2
    requirements ensuring effective protection against resource exhaustion.
    """
    
    def test_burst_dos_attack_prevention(self, rate_limiting_test_app, rate_limiting_helper, performance_monitoring):
        """
        Test prevention of burst DoS attacks through rate limiting.
        
        Simulates high-intensity burst attacks and validates that rate limiting
        effectively prevents resource exhaustion and maintains service availability.
        """
        endpoint = '/test/basic'
        
        with performance_monitoring['measure_operation']('burst_dos_test', 'api_response_time'):
            # Simulate burst DoS attack
            burst_results = rate_limiting_helper.simulate_burst_requests(
                endpoint=endpoint,
                request_count=RateLimitingSecurityConfig.DOS_ATTACK_REQUEST_COUNT,
                burst_duration=RateLimitingSecurityConfig.DOS_ATTACK_BURST_DURATION
            )
        
        # Validate DoS protection effectiveness
        assert burst_results['rate_limit_triggered'], "Rate limiting should trigger during burst attack"
        assert burst_results['rate_limited_requests'] > 0, "Some requests should be rate limited"
        
        # Calculate protection effectiveness
        protection_rate = burst_results['rate_limited_requests'] / burst_results['total_requests']
        assert protection_rate >= 0.8, f"DoS protection should block ≥80% of attack requests, got {protection_rate:.2%}"
        
        # Validate response times remain reasonable under attack
        if burst_results['response_times']:
            avg_response_time = sum(burst_results['response_times']) / len(burst_results['response_times'])
            assert avg_response_time < 1.0, f"Response times should remain reasonable under attack: {avg_response_time:.3f}s"
        
        # Validate service availability is maintained
        assert burst_results['successful_requests'] > 0, "Some legitimate requests should still succeed"
        
        logger.info(
            f"Burst DoS attack prevention validated: {protection_rate:.2%} blocking rate, "
            f"{burst_results['successful_requests']} legitimate requests preserved"
        )
    
    def test_sustained_dos_attack_prevention(self, rate_limiting_test_app, rate_limiting_helper, performance_monitoring):
        """
        Test prevention of sustained DoS attacks through rate limiting.
        
        Simulates sustained attack patterns and validates that rate limiting
        maintains protection over extended periods without degrading legitimate traffic.
        """
        endpoint = '/test/basic'
        
        with performance_monitoring['measure_operation']('sustained_dos_test', 'api_response_time'):
            # Simulate sustained DoS attack
            sustained_results = rate_limiting_helper.simulate_sustained_requests(
                endpoint=endpoint,
                requests_per_second=20,  # Well above 5 per minute limit
                duration_seconds=10,
                user_rotation=False
            )
        
        # Validate sustained DoS protection
        assert sustained_results['dos_protection_triggered'], "DoS protection should trigger during sustained attack"
        assert sustained_results['rate_limiting_effectiveness'] >= 0.7, \
            f"Rate limiting should be ≥70% effective, got {sustained_results['rate_limiting_effectiveness']:.2%}"
        
        # Validate that some legitimate requests can still get through
        legitimate_rate = sustained_results['successful_requests'] / sustained_results['total_requests']
        assert 0.1 <= legitimate_rate <= 0.3, \
            f"Should allow 10-30% legitimate traffic through, got {legitimate_rate:.2%}"
        
        # Validate average response time remains acceptable
        assert sustained_results['average_response_time'] < 0.5, \
            f"Average response time should remain reasonable: {sustained_results['average_response_time']:.3f}s"
        
        logger.info(
            f"Sustained DoS attack prevention validated: {sustained_results['rate_limiting_effectiveness']:.2%} blocking rate, "
            f"{legitimate_rate:.2%} legitimate traffic preserved"
        )
    
    def test_distributed_dos_attack_prevention(self, rate_limiting_test_app, rate_limiting_helper):
        """
        Test prevention of distributed DoS attacks with multiple source IPs.
        
        Simulates distributed attacks from multiple sources and validates that
        rate limiting can detect and prevent coordinated attack patterns.
        """
        endpoint = '/test/basic'
        
        # Simulate distributed attack from multiple IPs
        concurrent_attacks = []
        
        def attack_from_ip(ip_suffix):
            """Simulate attack from specific IP"""
            headers = {'X-Forwarded-For': f'192.168.1.{ip_suffix}'}
            return rate_limiting_helper.simulate_burst_requests(
                endpoint=endpoint,
                request_count=20,
                burst_duration=2.0,
                headers=headers
            )
        
        # Launch concurrent attacks from different IPs
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(attack_from_ip, ip_suffix) 
                for ip_suffix in range(1, 21)  # 20 different IPs
            ]
            
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=10)
                    concurrent_attacks.append(result)
                except Exception as e:
                    logger.warning(f"Distributed attack simulation failed: {e}")
        
        # Analyze distributed attack results
        total_requests = sum(attack['total_requests'] for attack in concurrent_attacks)
        total_blocked = sum(attack['rate_limited_requests'] for attack in concurrent_attacks)
        total_successful = sum(attack['successful_requests'] for attack in concurrent_attacks)
        
        # Validate distributed DoS protection
        assert total_requests > 0, "Distributed attack should generate requests"
        
        blocking_rate = total_blocked / total_requests if total_requests > 0 else 0
        assert blocking_rate >= 0.5, f"Should block ≥50% of distributed attack requests, got {blocking_rate:.2%}"
        
        # Validate that legitimate traffic is still possible
        legitimate_rate = total_successful / total_requests if total_requests > 0 else 0
        assert legitimate_rate <= 0.5, f"Should limit distributed attack success to ≤50%, got {legitimate_rate:.2%}"
        
        logger.info(
            f"Distributed DoS attack prevention validated: {blocking_rate:.2%} blocking rate across {len(concurrent_attacks)} sources"
        )
    
    def test_resource_exhaustion_prevention(self, rate_limiting_test_app, rate_limiting_helper, performance_monitoring):
        """
        Test prevention of resource exhaustion through rate limiting.
        
        Validates that rate limiting prevents attacks from exhausting server
        resources and maintains performance within acceptable thresholds.
        """
        endpoint = '/test/basic'
        
        # Measure performance impact of rate limiting
        performance_results = rate_limiting_helper.measure_rate_limiting_performance_impact(
            endpoint=endpoint,
            baseline_requests=50,
            rate_limited_requests=200
        )
        
        # Validate performance requirements
        assert performance_results['compliant_with_requirements'], \
            f"Rate limiting should meet performance requirements: {performance_results}"
        
        assert performance_results['variance_percentage'] <= 10.0, \
            f"Performance variance should be ≤10%, got {performance_results['variance_percentage']:.1f}%"
        
        overhead_ms = performance_results['performance_overhead'] * 1000
        assert overhead_ms <= RateLimitingSecurityConfig.MAX_RATE_LIMITING_OVERHEAD_MS, \
            f"Rate limiting overhead should be ≤{RateLimitingSecurityConfig.MAX_RATE_LIMITING_OVERHEAD_MS}ms, got {overhead_ms:.2f}ms"
        
        # Test memory usage stability under attack
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Simulate memory exhaustion attack
        with rate_limiting_test_app.test_client() as client:
            for i in range(100):
                response = client.get(endpoint)
                # Memory should not grow excessively
        
        final_memory = process.memory_info().rss
        memory_growth = final_memory - initial_memory
        memory_growth_mb = memory_growth / (1024 * 1024)
        
        # Memory growth should be reasonable (< 50MB for this test)
        assert memory_growth_mb < 50, f"Memory growth should be limited, got {memory_growth_mb:.2f}MB"
        
        logger.info(
            f"Resource exhaustion prevention validated: {overhead_ms:.2f}ms overhead, "
            f"{memory_growth_mb:.2f}MB memory growth"
        )


# =============================================================================
# Rate Limiting Bypass Attempt Detection Tests
# =============================================================================

class TestRateLimitingBypassDetection:
    """
    Test rate limiting bypass attempt detection ensuring zero tolerance for
    security circumvention per Section 6.4.5 requirements.
    """
    
    def test_header_manipulation_bypass_detection(self, rate_limiting_test_app, rate_limiting_helper):
        """
        Test detection and prevention of header manipulation bypass attempts.
        
        Validates that attempts to bypass rate limiting through header manipulation
        (IP spoofing, proxy headers, etc.) are detected and blocked.
        """
        endpoint = '/test/basic'
        
        # Test header manipulation bypass attempts
        bypass_results = rate_limiting_helper.attempt_rate_limit_bypass(
            endpoint=endpoint,
            attack_vector='header_manipulation',
            attempt_count=50
        )
        
        # Validate zero tolerance for bypass attempts
        assert bypass_results['security_effective'], \
            f"Header manipulation bypass should be prevented: {bypass_results['bypass_success_rate']:.2%} success rate"
        
        assert bypass_results['bypass_success_rate'] < 0.05, \
            f"Bypass success rate should be <5%, got {bypass_results['bypass_success_rate']:.2%}"
        
        # Validate that most attempts are properly blocked
        block_rate = bypass_results['blocked_attempts'] / bypass_results['total_attempts']
        assert block_rate >= 0.9, f"Should block ≥90% of bypass attempts, got {block_rate:.2%}"
        
        # Check for logged bypass attempts
        assert len(rate_limiting_helper.bypass_attempts) > 0, "Bypass attempts should be logged for monitoring"
        
        # Validate header manipulation detection
        header_bypass_attempts = [
            attempt for attempt in rate_limiting_helper.bypass_attempts
            if attempt['attack_vector'] == 'header_manipulation'
        ]
        
        # Should detect suspicious header patterns
        for attempt in header_bypass_attempts[:5]:  # Check first 5 attempts
            headers = attempt['headers']
            suspicious_headers = ['X-Forwarded-For', 'X-Real-IP', 'X-Originating-IP']
            
            has_suspicious_headers = any(header in headers for header in suspicious_headers)
            if has_suspicious_headers and attempt['bypass_successful']:
                pytest.fail(f"Suspicious header manipulation succeeded: {headers}")
        
        logger.info(f"Header manipulation bypass detection validated: {block_rate:.2%} block rate")
    
    def test_session_manipulation_bypass_detection(self, rate_limiting_test_app, rate_limiting_helper):
        """
        Test detection and prevention of session manipulation bypass attempts.
        
        Validates that attempts to bypass rate limiting through session token
        manipulation or cookie forgery are detected and blocked.
        """
        endpoint = '/test/basic'
        
        # Test session manipulation bypass attempts
        bypass_results = rate_limiting_helper.attempt_rate_limit_bypass(
            endpoint=endpoint,
            attack_vector='session_manipulation',
            attempt_count=30
        )
        
        # Validate session manipulation is prevented
        assert bypass_results['security_effective'], \
            f"Session manipulation bypass should be prevented: {bypass_results['bypass_success_rate']:.2%} success rate"
        
        assert bypass_results['bypass_success_rate'] < 0.1, \
            f"Session bypass success rate should be <10%, got {bypass_results['bypass_success_rate']:.2%}"
        
        # Validate session manipulation detection
        session_bypass_attempts = [
            attempt for attempt in rate_limiting_helper.bypass_attempts
            if attempt['attack_vector'] == 'session_manipulation'
        ]
        
        for attempt in session_bypass_attempts:
            headers = attempt['headers']
            
            # Check for session manipulation indicators
            if 'Cookie' in headers or 'X-Session-Token' in headers:
                if attempt['bypass_successful']:
                    pytest.fail(f"Session manipulation should not succeed: {headers}")
        
        logger.info(f"Session manipulation bypass detection validated")
    
    def test_cache_poisoning_bypass_detection(self, rate_limiting_test_app, rate_limiting_helper):
        """
        Test detection and prevention of cache poisoning bypass attempts.
        
        Validates that attempts to bypass rate limiting through cache manipulation
        or cache poisoning techniques are detected and blocked.
        """
        endpoint = '/test/basic'
        
        # Test cache poisoning bypass attempts
        bypass_results = rate_limiting_helper.attempt_rate_limit_bypass(
            endpoint=endpoint,
            attack_vector='cache_poisoning',
            attempt_count=40
        )
        
        # Validate cache poisoning is prevented
        assert bypass_results['security_effective'], \
            f"Cache poisoning bypass should be prevented: {bypass_results['bypass_success_rate']:.2%} success rate"
        
        assert bypass_results['bypass_success_rate'] < 0.05, \
            f"Cache poisoning success rate should be <5%, got {bypass_results['bypass_success_rate']:.2%}"
        
        # Validate cache integrity is maintained
        cache_security = rate_limiting_helper.validate_rate_limiting_cache_security()
        assert cache_security['cache_integrity_maintained'], "Cache integrity should be maintained during attacks"
        
        # Check for cache poisoning attempts in logs
        cache_bypass_attempts = [
            attempt for attempt in rate_limiting_helper.bypass_attempts
            if attempt['attack_vector'] == 'cache_poisoning'
        ]
        
        # Validate cache poisoning indicators are detected
        for attempt in cache_bypass_attempts:
            headers = attempt['headers']
            cache_headers = ['Cache-Control', 'Pragma', 'Expires', 'X-Cache-Bypass']
            
            has_cache_manipulation = any(header in headers for header in cache_headers)
            if has_cache_manipulation and attempt['bypass_successful']:
                pytest.fail(f"Cache poisoning should not succeed: {headers}")
        
        logger.info(f"Cache poisoning bypass detection validated")
    
    def test_user_agent_rotation_bypass_detection(self, rate_limiting_test_app, rate_limiting_helper):
        """
        Test detection and prevention of user agent rotation bypass attempts.
        
        Validates that attempts to bypass rate limiting through user agent
        rotation or spoofing are detected and blocked.
        """
        endpoint = '/test/basic'
        
        # Test user agent rotation bypass attempts
        bypass_results = rate_limiting_helper.attempt_rate_limit_bypass(
            endpoint=endpoint,
            attack_vector='user_agent_rotation',
            attempt_count=25
        )
        
        # Validate user agent rotation is prevented
        assert bypass_results['security_effective'], \
            f"User agent rotation bypass should be prevented: {bypass_results['bypass_success_rate']:.2%} success rate"
        
        # User agent rotation might be somewhat effective since it doesn't change the source IP
        # But rate limiting should still mostly work based on IP address
        assert bypass_results['bypass_success_rate'] < 0.2, \
            f"User agent rotation success rate should be <20%, got {bypass_results['bypass_success_rate']:.2%}"
        
        # Validate that rate limiting is primarily IP-based, not user-agent-based
        ua_bypass_attempts = [
            attempt for attempt in rate_limiting_helper.bypass_attempts
            if attempt['attack_vector'] == 'user_agent_rotation'
        ]
        
        # Check that different user agents from same IP are still rate limited
        unique_user_agents = set()
        for attempt in ua_bypass_attempts:
            if 'User-Agent' in attempt['headers']:
                unique_user_agents.add(attempt['headers']['User-Agent'])
        
        assert len(unique_user_agents) > 1, "Should test multiple different user agents"
        
        logger.info(f"User agent rotation bypass detection validated with {len(unique_user_agents)} different agents")
    
    def test_distributed_bypass_attempt_detection(self, rate_limiting_test_app, rate_limiting_helper):
        """
        Test detection and prevention of distributed bypass attempts.
        
        Validates that coordinated bypass attempts from multiple sources
        are detected and appropriate countermeasures are applied.
        """
        endpoint = '/test/basic'
        
        # Test distributed bypass attempts
        bypass_results = rate_limiting_helper.attempt_rate_limit_bypass(
            endpoint=endpoint,
            attack_vector='distributed_attack',
            attempt_count=60
        )
        
        # Validate distributed bypass attempts are mitigated
        assert bypass_results['security_effective'], \
            f"Distributed bypass should be prevented: {bypass_results['bypass_success_rate']:.2%} success rate"
        
        # Distributed attacks might have higher success rate due to IP distribution
        # But should still be significantly limited
        assert bypass_results['bypass_success_rate'] < 0.3, \
            f"Distributed bypass success rate should be <30%, got {bypass_results['bypass_success_rate']:.2%}"
        
        # Validate distributed attack detection
        distributed_attempts = [
            attempt for attempt in rate_limiting_helper.bypass_attempts
            if attempt['attack_vector'] == 'distributed_attack'
        ]
        
        # Check for distributed attack patterns
        unique_ips = set()
        for attempt in distributed_attempts:
            if 'X-Forwarded-For' in attempt['headers']:
                unique_ips.add(attempt['headers']['X-Forwarded-For'])
        
        assert len(unique_ips) > 10, f"Should simulate distributed attack from multiple IPs, got {len(unique_ips)}"
        
        # Validate that attack coordination is limited
        successful_attempts = [attempt for attempt in distributed_attempts if attempt['bypass_successful']]
        success_rate_per_ip = len(successful_attempts) / len(unique_ips) if unique_ips else 0
        
        assert success_rate_per_ip < 2.0, \
            f"Should limit successful attempts per IP to <2, got {success_rate_per_ip:.1f}"
        
        logger.info(f"Distributed bypass attempt detection validated across {len(unique_ips)} simulated IPs")


# =============================================================================
# Authorization Endpoint Rate Limiting Tests  
# =============================================================================

class TestAuthorizationEndpointRateLimiting:
    """
    Test rate limiting for authorization endpoints with user-specific limits
    per Section 6.4.2 requirements ensuring proper authentication flow protection.
    """
    
    def test_authentication_endpoint_rate_limiting(self, rate_limiting_test_app, mock_authenticated_users):
        """
        Test rate limiting for authentication endpoints.
        
        Validates that authentication endpoints (login, refresh, etc.) have
        appropriate rate limiting to prevent brute force attacks.
        """
        app = rate_limiting_test_app
        
        # Test login endpoint rate limiting
        with app.test_client() as client:
            login_responses = []
            
            # Attempt multiple login requests
            for i in range(8):  # Exceed 5 per minute limit
                response = client.post('/test/auth/login', json={
                    'username': f'user_{i}',
                    'password': 'test_password'
                })
                login_responses.append(response.status_code)
            
            # Validate rate limiting is applied
            successful_logins = sum(1 for status in login_responses if status == 200)
            rate_limited_logins = sum(1 for status in login_responses if status == 429)
            
            assert rate_limited_logins > 0, "Login attempts should be rate limited"
            assert successful_logins <= 6, f"Should allow limited login attempts, got {successful_logins}"
            
            # Validate that legitimate users can still authenticate (some requests succeed)
            assert successful_logins >= 4, f"Should allow some legitimate logins, got {successful_logins}"
        
        logger.info(f"Authentication endpoint rate limiting validated: {rate_limited_logins} blocked, {successful_logins} allowed")
    
    def test_permission_endpoint_rate_limiting(self, rate_limiting_test_app, mock_authenticated_users):
        """
        Test rate limiting for permission validation endpoints.
        
        Validates that permission checking endpoints have appropriate rate
        limiting to prevent authorization system abuse.
        """
        app = rate_limiting_test_app
        
        # Test permissions endpoint rate limiting
        with app.test_client() as client:
            permission_responses = []
            
            # Simulate user checking permissions rapidly
            for i in range(25):  # Exceed 20 per minute limit
                response = client.get('/test/auth/permissions', headers={
                    'Authorization': f'Bearer token_{i}',
                    'X-User-ID': 'user_001'
                })
                permission_responses.append(response.status_code)
            
            # Validate permission endpoint rate limiting
            successful_checks = sum(1 for status in permission_responses if status == 200)
            rate_limited_checks = sum(1 for status in permission_responses if status == 429)
            
            assert rate_limited_checks > 0, "Permission checks should be rate limited"
            assert successful_checks <= 22, f"Should limit permission checks, got {successful_checks}"
            
            # Validate reasonable access is still allowed
            assert successful_checks >= 18, f"Should allow reasonable permission checks, got {successful_checks}"
        
        logger.info(f"Permission endpoint rate limiting validated: {rate_limited_checks} blocked, {successful_checks} allowed")
    
    def test_user_specific_rate_limiting(self, rate_limiting_test_app, mock_authenticated_users):
        """
        Test user-specific rate limiting implementation.
        
        Validates that rate limiting can be applied per user context and that
        different users have independent rate limiting quotas.
        """
        app = rate_limiting_test_app
        users = mock_authenticated_users
        
        # Test multiple users accessing same endpoint
        user_results = {}
        
        with app.test_client() as client:
            for user_type, user_data in users.items():
                user_responses = []
                
                # Each user makes requests to the same endpoint
                for i in range(7):  # Test against 5 per minute limit
                    response = client.get('/test/basic', headers={
                        'Authorization': f'Bearer {user_data["user_id"]}_token',
                        'X-User-ID': user_data['user_id'],
                        'X-User-Type': user_type
                    })
                    user_responses.append(response.status_code)
                
                successful = sum(1 for status in user_responses if status == 200)
                rate_limited = sum(1 for status in user_responses if status == 429)
                
                user_results[user_type] = {
                    'successful': successful,
                    'rate_limited': rate_limited,
                    'user_id': user_data['user_id']
                }
        
        # Validate user isolation
        for user_type, results in user_results.items():
            assert results['rate_limited'] > 0, f"User {user_type} should be rate limited"
            assert results['successful'] <= 6, f"User {user_type} should have limited access"
            
            # Each user should be rate limited independently
            assert results['successful'] >= 4, f"User {user_type} should have some access"
        
        # Validate that different users don't interfere with each other
        total_successful = sum(results['successful'] for results in user_results.values())
        expected_min_total = len(user_results) * 4  # Each user should get at least 4 requests
        
        assert total_successful >= expected_min_total, \
            f"Users should have independent quotas, got {total_successful} total successful requests"
        
        logger.info(f"User-specific rate limiting validated for {len(user_results)} users")
    
    def test_admin_endpoint_rate_limiting(self, rate_limiting_test_app, mock_authenticated_users):
        """
        Test rate limiting for administrative endpoints.
        
        Validates that admin endpoints have stricter rate limiting to prevent
        abuse of high-privilege operations.
        """
        app = rate_limiting_test_app
        admin_user = mock_authenticated_users['admin_user']
        
        # Test admin endpoint with stricter limits
        with app.test_client() as client:
            admin_responses = []
            
            # Test admin endpoint (10 per minute limit)
            for i in range(15):  # Exceed limit
                response = client.get('/test/admin', headers={
                    'Authorization': f'Bearer {admin_user["user_id"]}_admin_token',
                    'X-User-ID': admin_user['user_id'],
                    'X-Admin-Role': 'true'
                })
                admin_responses.append(response.status_code)
            
            successful_admin = sum(1 for status in admin_responses if status == 200)
            rate_limited_admin = sum(1 for status in admin_responses if status == 429)
            
            # Validate stricter admin rate limiting
            assert rate_limited_admin > 0, "Admin endpoints should be rate limited"
            assert successful_admin <= 12, f"Admin access should be strictly limited, got {successful_admin}"
            
            # Should still allow reasonable admin access
            assert successful_admin >= 8, f"Should allow reasonable admin access, got {successful_admin}"
        
        # Test high-security endpoint with very strict limits
        with app.test_client() as client:
            security_responses = []
            
            # Test high-security endpoint (3 per minute limit)
            for i in range(6):  # Exceed strict limit
                response = client.get('/test/high-security', headers={
                    'Authorization': f'Bearer {admin_user["user_id"]}_admin_token',
                    'X-User-ID': admin_user['user_id']
                })
                security_responses.append(response.status_code)
            
            successful_security = sum(1 for status in security_responses if status == 200)
            rate_limited_security = sum(1 for status in security_responses if status == 429)
            
            # Validate very strict security endpoint limiting
            assert rate_limited_security > 0, "High-security endpoints should be strictly rate limited"
            assert successful_security <= 4, f"High-security access should be very limited, got {successful_security}"
        
        logger.info(f"Admin endpoint rate limiting validated: {rate_limited_admin} admin blocked, {rate_limited_security} security blocked")


# =============================================================================
# Burst and Sustained Rate Limiting Tests
# =============================================================================

class TestBurstAndSustainedRateLimiting:
    """
    Test burst and sustained rate limiting security validation per Section 6.4.2
    ensuring comprehensive protection against different attack patterns.
    """
    
    def test_burst_rate_limiting_validation(self, rate_limiting_test_app, rate_limiting_helper, performance_monitoring):
        """
        Test burst rate limiting effectiveness and security.
        
        Validates that burst rate limiting can handle sudden spikes in traffic
        while maintaining security and performance requirements.
        """
        endpoint = '/test/burst'  # 10 per second; 50 per minute
        
        # Test short burst protection
        with performance_monitoring['measure_operation']('burst_rate_limiting', 'api_response_time'):
            burst_results = rate_limiting_helper.simulate_burst_requests(
                endpoint=endpoint,
                request_count=15,  # Exceed 10 per second
                burst_duration=1.0
            )
        
        # Validate burst protection effectiveness
        assert burst_results['rate_limit_triggered'], "Burst rate limiting should trigger"
        assert burst_results['rate_limited_requests'] >= 5, "Should block excess burst requests"
        
        # Validate burst window behavior
        burst_success_rate = burst_results['successful_requests'] / burst_results['total_requests']
        assert 0.4 <= burst_success_rate <= 0.8, \
            f"Burst success rate should be 40-80%, got {burst_success_rate:.2%}"
        
        # Test burst recovery - requests should succeed after burst window
        time.sleep(2.0)  # Wait for burst window to reset
        
        with rate_limiting_test_app.test_client() as client:
            recovery_responses = []
            for i in range(5):  # Test normal traffic after burst
                response = client.get(endpoint)
                recovery_responses.append(response.status_code)
                time.sleep(0.2)  # Space out requests
            
            recovery_success = sum(1 for status in recovery_responses if status == 200)
            assert recovery_success >= 4, f"Should recover after burst, got {recovery_success}/5 successful"
        
        # Validate response time consistency during burst
        if burst_results['response_times']:
            max_response_time = max(burst_results['response_times'])
            assert max_response_time < 0.5, f"Response times should remain reasonable during burst: {max_response_time:.3f}s"
        
        logger.info(f"Burst rate limiting validated: {burst_success_rate:.2%} success rate, {len(burst_results['response_times'])} responses measured")
    
    def test_sustained_rate_limiting_validation(self, rate_limiting_test_app, rate_limiting_helper, performance_monitoring):
        """
        Test sustained rate limiting effectiveness and security.
        
        Validates that sustained rate limiting provides consistent protection
        over extended periods without performance degradation.
        """
        endpoint = '/test/basic'  # 5 per minute limit
        
        # Test sustained traffic over time
        with performance_monitoring['measure_operation']('sustained_rate_limiting', 'api_response_time'):
            sustained_results = rate_limiting_helper.simulate_sustained_requests(
                endpoint=endpoint,
                requests_per_second=2,  # Moderate sustained load
                duration_seconds=15,
                user_rotation=False
            )
        
        # Validate sustained protection
        assert sustained_results['dos_protection_triggered'], "Sustained rate limiting should trigger"
        
        # Calculate expected vs actual blocking
        total_requests = sustained_results['total_requests']
        expected_allowed = 5  # 5 per minute limit for 15 seconds should allow ~1-2 requests
        actual_successful = sustained_results['successful_requests']
        
        assert actual_successful <= expected_allowed + 3, \
            f"Sustained rate limiting should limit requests to ~{expected_allowed}, got {actual_successful}"
        
        # Validate consistent response times
        assert sustained_results['average_response_time'] < 0.3, \
            f"Average response time should remain low: {sustained_results['average_response_time']:.3f}s"
        
        # Test sustained protection effectiveness
        protection_rate = sustained_results['rate_limiting_effectiveness']
        assert protection_rate >= 0.8, f"Sustained protection should be ≥80% effective, got {protection_rate:.2%}"
        
        logger.info(f"Sustained rate limiting validated: {protection_rate:.2%} effectiveness over {sustained_results['sustained_duration']}s")
    
    def test_combined_burst_and_sustained_protection(self, rate_limiting_test_app, rate_limiting_helper):
        """
        Test combined burst and sustained rate limiting protection.
        
        Validates that endpoints with both burst and sustained limits can
        handle complex attack patterns effectively.
        """
        endpoint = '/test/burst'  # 10 per second; 50 per minute
        
        # Phase 1: Initial burst attack
        initial_burst = rate_limiting_helper.simulate_burst_requests(
            endpoint=endpoint,
            request_count=20,
            burst_duration=2.0
        )
        
        # Phase 2: Sustained attack after burst
        time.sleep(1.0)  # Brief pause
        sustained_attack = rate_limiting_helper.simulate_sustained_requests(
            endpoint=endpoint,
            requests_per_second=3,
            duration_seconds=20,
            user_rotation=False
        )
        
        # Phase 3: Second burst attack
        time.sleep(1.0)  # Brief pause
        second_burst = rate_limiting_helper.simulate_burst_requests(
            endpoint=endpoint,
            request_count=15,
            burst_duration=1.5
        )
        
        # Validate combined protection effectiveness
        total_requests = (initial_burst['total_requests'] + 
                         sustained_attack['total_requests'] + 
                         second_burst['total_requests'])
        
        total_successful = (initial_burst['successful_requests'] + 
                           sustained_attack['successful_requests'] + 
                           second_burst['successful_requests'])
        
        total_blocked = (initial_burst['rate_limited_requests'] + 
                        sustained_attack['rate_limited_requests'] + 
                        second_burst['rate_limited_requests'])
        
        overall_protection_rate = total_blocked / total_requests if total_requests > 0 else 0
        overall_success_rate = total_successful / total_requests if total_requests > 0 else 0
        
        # Validate multi-phase attack protection
        assert overall_protection_rate >= 0.7, \
            f"Combined protection should be ≥70% effective, got {overall_protection_rate:.2%}"
        
        assert overall_success_rate <= 0.4, \
            f"Combined attack success should be ≤40%, got {overall_success_rate:.2%}"
        
        # Validate that burst limits are enforced independently of sustained limits
        assert initial_burst['rate_limit_triggered'], "Initial burst should trigger rate limiting"
        assert second_burst['rate_limit_triggered'], "Second burst should also trigger rate limiting"
        assert sustained_attack['dos_protection_triggered'], "Sustained attack should trigger protection"
        
        logger.info(
            f"Combined burst and sustained protection validated: {overall_protection_rate:.2%} overall blocking rate "
            f"across {total_requests} total requests in multi-phase attack"
        )
    
    def test_rate_limiting_window_behavior(self, rate_limiting_test_app):
        """
        Test rate limiting window behavior and reset mechanics.
        
        Validates that rate limiting windows behave correctly and reset
        as expected to maintain consistent protection.
        """
        app = rate_limiting_test_app
        endpoint = '/test/basic'  # 5 per minute limit
        
        # Phase 1: Fill the rate limit quota
        with app.test_client() as client:
            phase1_responses = []
            for i in range(6):  # Exceed 5 per minute limit
                response = client.get(endpoint)
                phase1_responses.append(response.status_code)
            
            successful_phase1 = sum(1 for status in phase1_responses if status == 200)
            blocked_phase1 = sum(1 for status in phase1_responses if status == 429)
            
            assert blocked_phase1 > 0, "Should hit rate limit in phase 1"
            assert successful_phase1 <= 5, "Should not exceed quota in phase 1"
        
        # Phase 2: Immediate retry should still be blocked
        with app.test_client() as client:
            immediate_response = client.get(endpoint)
            assert immediate_response.status_code == 429, "Immediate retry should be blocked"
        
        # Phase 3: Wait for window reset and test recovery
        logger.info("Waiting for rate limit window to reset...")
        time.sleep(61)  # Wait just over 1 minute for window reset
        
        with app.test_client() as client:
            phase3_responses = []
            for i in range(3):  # Test normal requests after reset
                response = client.get(endpoint)
                phase3_responses.append(response.status_code)
                time.sleep(0.5)  # Space out requests
            
            successful_phase3 = sum(1 for status in phase3_responses if status == 200)
            assert successful_phase3 >= 2, f"Should recover after window reset, got {successful_phase3}/3 successful"
        
        logger.info("Rate limiting window behavior validated successfully")


# =============================================================================
# Integration Tests
# =============================================================================

class TestRateLimitingSecurityIntegration:
    """
    Integration tests for rate limiting security with comprehensive validation
    of end-to-end security effectiveness per Section 6.4.2 requirements.
    """
    
    def test_comprehensive_rate_limiting_security_validation(
        self, 
        rate_limiting_test_app, 
        rate_limiting_helper, 
        mock_authenticated_users,
        performance_monitoring,
        test_metrics_collector
    ):
        """
        Comprehensive integration test validating all rate limiting security aspects.
        
        Tests complete rate limiting security stack including configuration,
        bypass prevention, DoS protection, and performance requirements.
        """
        test_metrics_collector['record_security_test']('rate_limiting_comprehensive')
        
        # Test Configuration Security
        with performance_monitoring['measure_operation']('config_validation', 'api_response_time'):
            limiter = rate_limiting_test_app.limiter
            redis_client = rate_limiting_test_app.redis_client
            
            assert limiter.enabled, "Rate limiter should be enabled"
            assert redis_client.ping(), "Redis backend should be accessible"
        
        # Test DoS Protection
        with performance_monitoring['measure_operation']('dos_protection', 'api_response_time'):
            dos_results = rate_limiting_helper.simulate_burst_requests(
                endpoint='/test/basic',
                request_count=100,
                burst_duration=5.0
            )
            
            dos_protection_rate = dos_results['rate_limited_requests'] / dos_results['total_requests']
            assert dos_protection_rate >= 0.8, f"DoS protection should be ≥80% effective, got {dos_protection_rate:.2%}"
        
        # Test Bypass Prevention
        bypass_test_vectors = ['header_manipulation', 'session_manipulation', 'cache_poisoning']
        bypass_effectiveness = []
        
        for vector in bypass_test_vectors:
            with performance_monitoring['measure_operation'](f'bypass_test_{vector}', 'api_response_time'):
                bypass_results = rate_limiting_helper.attempt_rate_limit_bypass(
                    endpoint='/test/basic',
                    attack_vector=vector,
                    attempt_count=20
                )
                
                assert bypass_results['security_effective'], f"Bypass prevention should be effective for {vector}"
                bypass_effectiveness.append(1 - bypass_results['bypass_success_rate'])
        
        avg_bypass_effectiveness = sum(bypass_effectiveness) / len(bypass_effectiveness)
        assert avg_bypass_effectiveness >= 0.9, \
            f"Average bypass prevention should be ≥90%, got {avg_bypass_effectiveness:.2%}"
        
        # Test Performance Requirements
        with performance_monitoring['measure_operation']('performance_validation', 'api_response_time'):
            performance_results = rate_limiting_helper.measure_rate_limiting_performance_impact(
                endpoint='/test/basic',
                baseline_requests=50,
                rate_limited_requests=100
            )
            
            assert performance_results['compliant_with_requirements'], \
                f"Performance requirements should be met: {performance_results}"
        
        # Test Cache Security
        cache_security = rate_limiting_helper.validate_rate_limiting_cache_security()
        assert cache_security['cache_integrity_maintained'], "Cache integrity should be maintained"
        assert len(cache_security['security_violations']) == 0, \
            f"No cache security violations should be found: {cache_security['security_violations']}"
        
        # Generate Final Security Report
        security_report = {
            'dos_protection_effectiveness': dos_protection_rate,
            'bypass_prevention_effectiveness': avg_bypass_effectiveness,
            'performance_compliant': performance_results['compliant_with_requirements'],
            'cache_security_maintained': cache_security['cache_integrity_maintained'],
            'total_bypass_attempts_logged': len(rate_limiting_helper.bypass_attempts),
            'total_dos_events_logged': len(rate_limiting_helper.dos_protection_events),
            'security_violations_detected': len(rate_limiting_helper.security_violations)
        }
        
        # Validate Zero Tolerance Security Requirements
        assert security_report['dos_protection_effectiveness'] >= 0.8, "DoS protection must be highly effective"
        assert security_report['bypass_prevention_effectiveness'] >= 0.9, "Bypass prevention must be very effective"
        assert security_report['performance_compliant'], "Performance requirements must be met"
        assert security_report['cache_security_maintained'], "Cache security must be maintained"
        
        test_metrics_collector['record_security_test']('rate_limiting_validation_complete')
        
        logger.info(f"Comprehensive rate limiting security validation completed successfully: {security_report}")
    
    def test_rate_limiting_monitoring_and_alerting(self, rate_limiting_test_app, rate_limiting_helper):
        """
        Test rate limiting monitoring and alerting capabilities.
        
        Validates that rate limiting violations and security events are properly
        logged and can trigger appropriate security alerts.
        """
        # Simulate various security events
        endpoint = '/test/basic'
        
        # Generate rate limiting violations
        violation_results = rate_limiting_helper.simulate_burst_requests(
            endpoint=endpoint,
            request_count=50,
            burst_duration=2.0
        )
        
        # Generate bypass attempts
        bypass_results = rate_limiting_helper.attempt_rate_limit_bypass(
            endpoint=endpoint,
            attack_vector='header_manipulation',
            attempt_count=20
        )
        
        # Validate monitoring data collection
        assert len(rate_limiting_helper.dos_protection_events) > 0, "DoS protection events should be logged"
        assert len(rate_limiting_helper.bypass_attempts) > 0, "Bypass attempts should be logged"
        
        # Validate event data quality
        for event in rate_limiting_helper.dos_protection_events[:5]:  # Check first 5 events
            required_fields = ['timestamp', 'event_type', 'endpoint']
            for field in required_fields:
                assert field in event, f"DoS event should contain {field}: {event}"
            
            # Validate timestamp format
            try:
                datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
            except ValueError:
                pytest.fail(f"Invalid timestamp format in DoS event: {event['timestamp']}")
        
        for attempt in rate_limiting_helper.bypass_attempts[:5]:  # Check first 5 attempts
            required_fields = ['timestamp', 'attack_vector', 'headers', 'response_code']
            for field in required_fields:
                assert field in attempt, f"Bypass attempt should contain {field}: {attempt}"
        
        # Simulate alert thresholds
        violation_count = len(rate_limiting_helper.dos_protection_events)
        bypass_count = len(rate_limiting_helper.bypass_attempts)
        
        if violation_count > RateLimitingSecurityConfig.RATE_LIMIT_VIOLATION_ALERT_THRESHOLD:
            logger.warning(f"ALERT: Rate limit violations exceed threshold: {violation_count}")
        
        if bypass_count > RateLimitingSecurityConfig.BYPASS_ATTEMPT_ALERT_THRESHOLD:
            logger.warning(f"ALERT: Bypass attempts exceed threshold: {bypass_count}")
        
        logger.info(f"Rate limiting monitoring validated: {violation_count} violations, {bypass_count} bypass attempts logged")
    
    def test_rate_limiting_circuit_breaker_integration(self, rate_limiting_test_app, rate_limiting_helper):
        """
        Test integration between rate limiting and circuit breaker patterns.
        
        Validates that rate limiting and circuit breakers work together
        effectively to provide comprehensive protection.
        """
        endpoint = '/test/basic'
        
        # Simulate high load to trigger both rate limiting and potential circuit breaking
        circuit_breaker_test_results = {
            'rate_limiting_triggered': False,
            'circuit_breaker_activated': False,
            'combined_protection_effective': False
        }
        
        # Phase 1: Generate sustained load
        sustained_results = rate_limiting_helper.simulate_sustained_requests(
            endpoint=endpoint,
            requests_per_second=10,  # High load
            duration_seconds=8,
            user_rotation=False
        )
        
        if sustained_results['dos_protection_triggered']:
            circuit_breaker_test_results['rate_limiting_triggered'] = True
        
        # Phase 2: Test circuit breaker behavior under rate limiting
        with rate_limiting_test_app.test_client() as client:
            # Rapid sequential requests to test circuit breaker
            cb_responses = []
            for i in range(20):
                try:
                    response = client.get(endpoint, timeout=1.0)
                    cb_responses.append(response.status_code)
                except Exception as e:
                    # Circuit breaker might cause connection failures
                    cb_responses.append(500)
                    if 'circuit' in str(e).lower():
                        circuit_breaker_test_results['circuit_breaker_activated'] = True
        
        # Analyze combined protection effectiveness
        total_requests = sustained_results['total_requests'] + len(cb_responses)
        total_blocked = sustained_results['rate_limited_requests'] + sum(1 for s in cb_responses if s in [429, 500])
        
        combined_protection_rate = total_blocked / total_requests if total_requests > 0 else 0
        
        if combined_protection_rate >= 0.8:
            circuit_breaker_test_results['combined_protection_effective'] = True
        
        # Validate integration effectiveness
        assert circuit_breaker_test_results['rate_limiting_triggered'], "Rate limiting should trigger under load"
        
        # Combined protection should be highly effective
        assert circuit_breaker_test_results['combined_protection_effective'], \
            f"Combined protection should be ≥80% effective, got {combined_protection_rate:.2%}"
        
        logger.info(f"Rate limiting and circuit breaker integration validated: {combined_protection_rate:.2%} combined effectiveness")


# =============================================================================
# Performance and Compliance Tests
# =============================================================================

class TestRateLimitingPerformanceCompliance:
    """
    Test rate limiting performance compliance ensuring ≤10% variance requirement
    per Section 0.1.1 and maintaining security effectiveness.
    """
    
    def test_rate_limiting_performance_overhead(self, rate_limiting_test_app, rate_limiting_helper, performance_monitoring):
        """
        Test rate limiting performance overhead compliance.
        
        Validates that rate limiting implementation meets performance requirements
        and maintains ≤10% variance from baseline performance.
        """
        endpoint = '/test/no-limit'  # Endpoint without rate limiting
        rate_limited_endpoint = '/test/basic'  # Endpoint with rate limiting
        
        # Measure baseline performance (no rate limiting)
        baseline_times = []
        
        with performance_monitoring['measure_operation']('baseline_performance', 'api_response_time'):
            with rate_limiting_test_app.test_client() as client:
                for i in range(50):
                    start_time = time.perf_counter()
                    response = client.get(endpoint)
                    end_time = time.perf_counter()
                    
                    if response.status_code == 200:
                        baseline_times.append(end_time - start_time)
                    
                    time.sleep(0.1)  # Avoid overwhelming the system
        
        baseline_avg = sum(baseline_times) / len(baseline_times) if baseline_times else 0
        
        # Measure rate limited performance
        rate_limited_times = []
        
        with performance_monitoring['measure_operation']('rate_limited_performance', 'api_response_time'):
            with rate_limiting_test_app.test_client() as client:
                for i in range(50):
                    start_time = time.perf_counter()
                    response = client.get(rate_limited_endpoint)
                    end_time = time.perf_counter()
                    
                    # Include all response times (both allowed and rate limited)
                    rate_limited_times.append(end_time - start_time)
                    
                    time.sleep(0.1)  # Avoid overwhelming the system
        
        rate_limited_avg = sum(rate_limited_times) / len(rate_limited_times) if rate_limited_times else 0
        
        # Calculate performance variance
        if baseline_avg > 0:
            performance_overhead = rate_limited_avg - baseline_avg
            variance_percentage = (performance_overhead / baseline_avg) * 100
            overhead_ms = performance_overhead * 1000
            
            # Validate performance requirements
            assert variance_percentage <= 10.0, \
                f"Performance variance should be ≤10%, got {variance_percentage:.2f}%"
            
            assert overhead_ms <= RateLimitingSecurityConfig.MAX_RATE_LIMITING_OVERHEAD_MS, \
                f"Rate limiting overhead should be ≤{RateLimitingSecurityConfig.MAX_RATE_LIMITING_OVERHEAD_MS}ms, got {overhead_ms:.2f}ms"
            
            # Log performance metrics
            logger.info(
                f"Rate limiting performance validated: {variance_percentage:.2f}% variance, "
                f"{overhead_ms:.2f}ms overhead, baseline: {baseline_avg*1000:.2f}ms, "
                f"rate limited: {rate_limited_avg*1000:.2f}ms"
            )
        else:
            pytest.fail("Unable to establish baseline performance metrics")
    
    def test_rate_limiting_scalability_under_load(self, rate_limiting_test_app, rate_limiting_helper, performance_monitoring):
        """
        Test rate limiting scalability and performance under load.
        
        Validates that rate limiting maintains performance and effectiveness
        under high concurrent load scenarios.
        """
        endpoint = '/test/basic'
        
        # Test scalability with concurrent requests
        concurrent_results = []
        
        def concurrent_client_test(client_id: int):
            """Simulate concurrent client load"""
            with rate_limiting_test_app.test_client() as client:
                client_times = []
                client_success = 0
                client_blocked = 0
                
                for i in range(10):
                    start_time = time.perf_counter()
                    response = client.get(endpoint, headers={'X-Client-ID': f'client_{client_id}'})
                    end_time = time.perf_counter()
                    
                    client_times.append(end_time - start_time)
                    
                    if response.status_code == 200:
                        client_success += 1
                    elif response.status_code == 429:
                        client_blocked += 1
                
                return {
                    'client_id': client_id,
                    'avg_response_time': sum(client_times) / len(client_times),
                    'successful_requests': client_success,
                    'blocked_requests': client_blocked,
                    'total_requests': len(client_times)
                }
        
        # Run concurrent load test
        with performance_monitoring['measure_operation']('concurrent_load_test', 'api_response_time'):
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = [
                    executor.submit(concurrent_client_test, client_id)
                    for client_id in range(20)
                ]
                
                for future in as_completed(futures, timeout=30):
                    try:
                        result = future.result()
                        concurrent_results.append(result)
                    except Exception as e:
                        logger.warning(f"Concurrent client test failed: {e}")
        
        # Analyze scalability results
        if concurrent_results:
            avg_response_times = [result['avg_response_time'] for result in concurrent_results]
            total_successful = sum(result['successful_requests'] for result in concurrent_results)
            total_blocked = sum(result['blocked_requests'] for result in concurrent_results)
            total_requests = sum(result['total_requests'] for result in concurrent_results)
            
            overall_avg_response_time = sum(avg_response_times) / len(avg_response_times)
            blocking_rate = total_blocked / total_requests if total_requests > 0 else 0
            
            # Validate scalability requirements
            assert overall_avg_response_time < 1.0, \
                f"Average response time under load should be <1s, got {overall_avg_response_time:.3f}s"
            
            assert blocking_rate >= 0.7, \
                f"Rate limiting should maintain ≥70% effectiveness under load, got {blocking_rate:.2%}"
            
            # Validate consistent performance across clients
            max_response_time = max(avg_response_times)
            min_response_time = min(avg_response_times)
            response_time_variance = (max_response_time - min_response_time) / min_response_time if min_response_time > 0 else 0
            
            assert response_time_variance < 2.0, \
                f"Response time variance across clients should be reasonable, got {response_time_variance:.2f}"
            
            logger.info(
                f"Rate limiting scalability validated: {overall_avg_response_time*1000:.2f}ms avg response time, "
                f"{blocking_rate:.2%} blocking rate, {len(concurrent_results)} concurrent clients"
            )
        else:
            pytest.fail("No concurrent test results available for scalability validation")
    
    def test_rate_limiting_memory_efficiency(self, rate_limiting_test_app, rate_limiting_helper):
        """
        Test rate limiting memory efficiency and resource usage.
        
        Validates that rate limiting implementation is memory efficient and
        doesn't cause memory leaks or excessive resource consumption.
        """
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        endpoint = '/test/basic'
        
        # Generate significant rate limiting activity
        memory_test_iterations = 5
        
        for iteration in range(memory_test_iterations):
            # Burst requests to generate rate limiting data
            rate_limiting_helper.simulate_burst_requests(
                endpoint=endpoint,
                request_count=100,
                burst_duration=2.0
            )
            
            # Bypass attempts to generate security logs
            rate_limiting_helper.attempt_rate_limit_bypass(
                endpoint=endpoint,
                attack_vector='header_manipulation',
                attempt_count=30
            )
            
            # Check memory usage periodically
            current_memory = process.memory_info().rss
            memory_growth = current_memory - initial_memory
            memory_growth_mb = memory_growth / (1024 * 1024)
            
            # Memory growth should be reasonable (< 100MB for this test)
            assert memory_growth_mb < 100, \
                f"Memory growth should be limited during iteration {iteration}, got {memory_growth_mb:.2f}MB"
        
        # Final memory check
        final_memory = process.memory_info().rss
        total_memory_growth = final_memory - initial_memory
        total_growth_mb = total_memory_growth / (1024 * 1024)
        
        # Total memory growth should be reasonable
        assert total_growth_mb < 150, f"Total memory growth should be limited, got {total_growth_mb:.2f}MB"
        
        # Test Redis cache memory usage
        redis_client = rate_limiting_test_app.redis_client
        redis_memory_info = redis_client.info('memory')
        
        redis_used_memory_mb = redis_memory_info.get('used_memory', 0) / (1024 * 1024)
        assert redis_used_memory_mb < 50, f"Redis memory usage should be reasonable, got {redis_used_memory_mb:.2f}MB"
        
        logger.info(
            f"Rate limiting memory efficiency validated: {total_growth_mb:.2f}MB Python memory growth, "
            f"{redis_used_memory_mb:.2f}MB Redis memory usage"
        )


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])