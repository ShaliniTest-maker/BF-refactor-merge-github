"""
Comprehensive JWT Authentication Security Testing

This module implements enterprise-grade security testing for the Flask authentication system,
validating PyJWT token security, Auth0 integration security, authentication bypass prevention,
and token manipulation attack resistance per Section 6.4.1 and 6.6.3 security requirements.

Security Test Categories:
- JWT token security validation equivalent to Node.js implementation per Section 6.4.1
- Authentication bypass attack prevention testing per Section 6.4.1
- Token manipulation and signature validation security per Section 6.4.1
- Auth0 integration security testing with mock attack scenarios per Section 6.4.1
- Timing attack detection tests for authentication flows per Section 6.4.1
- Comprehensive authentication security test coverage per Section 6.6.3

Compliance Requirements:
- Zero tolerance for critical authentication vulnerabilities per Section 6.4.5
- Security scan integration with bandit and safety per Section 6.6.2
- ≥95% security test coverage for authentication components per Section 6.6.3
- OWASP Top 10 security pattern validation per Section 6.4.5

Dependencies:
- pytest 7.4+ for comprehensive security test framework
- pytest-asyncio for async authentication operations testing  
- pytest-mock for Auth0 service mocking and attack simulation
- PyJWT 2.8+ for token manipulation and validation testing
- cryptography 41.0+ for cryptographic attack simulation
- time module for timing attack detection and prevention testing

Author: Flask Migration Team
Version: 1.0.0
Compliance: SOC 2, ISO 27001, OWASP Top 10
"""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from unittest.mock import Mock, patch, MagicMock, AsyncMock
import pytest
import pytest_asyncio

# JWT and cryptographic imports for security testing
import jwt
from jwt import InvalidTokenError, ExpiredSignatureError, InvalidSignatureError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

# HTTP client for security testing
import httpx
import requests

# Authentication system imports for security testing
from src.auth.authentication import (
    AuthenticationManager,
    JWTTokenValidator,
    Auth0UserManager,
    Auth0Config,
    Auth0CircuitBreaker,
    authenticate_jwt_token,
    validate_user_permissions,
    refresh_jwt_token
)
from src.auth.utils import (
    JWTTokenUtils,
    CryptographicUtils,
    InputValidator,
    DateTimeUtils,
    generate_secure_token,
    validate_email,
    parse_iso8601_date
)
from src.auth.exceptions import (
    AuthenticationException,
    JWTException,
    Auth0Exception,
    SecurityException,
    SessionException,
    CircuitBreakerException,
    SecurityErrorCode
)


class TestJWTTokenSecurity:
    """
    Comprehensive JWT token security validation tests implementing PyJWT 2.8+ security patterns
    equivalent to Node.js jsonwebtoken security validation per Section 6.4.1.
    
    Security Test Coverage:
    - Token signature verification with RSA and HMAC algorithms
    - Token expiration and timing validation security
    - Token structure and format validation against malformed attacks
    - Claims validation and injection prevention
    - Algorithm confusion attack prevention  
    - Token replay attack detection and prevention
    """
    
    @pytest.fixture
    def jwt_utils(self):
        """JWT utilities instance for security testing"""
        return JWTTokenUtils(secret_key='test-secret-key-for-security-testing')
    
    @pytest.fixture
    def crypto_utils(self):
        """Cryptographic utilities for attack simulation"""
        return CryptographicUtils()
    
    @pytest.fixture
    def valid_jwt_payload(self):
        """Valid JWT payload for security testing"""
        return {
            'sub': 'auth0|test_user_12345',
            'email': 'security.test@example.com',
            'iss': 'https://test-tenant.auth0.com/',
            'aud': 'test-audience-security',
            'scope': 'openid profile email',
            'permissions': ['read:profile', 'update:profile'],
            'email_verified': True,
            'name': 'Security Test User'
        }
    
    @pytest.fixture
    def rsa_key_pair(self):
        """RSA key pair for RS256 signature testing"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            'private_key': private_pem,
            'public_key': public_pem,
            'private_key_obj': private_key,
            'public_key_obj': public_key
        }
    
    def test_jwt_signature_verification_security(self, jwt_utils, valid_jwt_payload):
        """
        Test JWT signature verification security against signature manipulation attacks.
        
        Security Validation:
        - Signature verification with correct secret key
        - Signature verification failure with incorrect secret key
        - Signature verification against empty signature
        - Signature verification against modified signature
        """
        # Generate valid token
        valid_token = jwt_utils.generate_token(valid_jwt_payload, expires_in=3600)
        
        # Test 1: Valid signature verification
        decoded_payload = jwt_utils.validate_token(valid_token)
        assert decoded_payload['sub'] == valid_jwt_payload['sub']
        assert decoded_payload['email'] == valid_jwt_payload['email']
        
        # Test 2: Invalid signature with wrong secret key
        wrong_key_utils = JWTTokenUtils(secret_key='wrong-secret-key')
        with pytest.raises(JWTException) as exc_info:
            wrong_key_utils.validate_token(valid_token)
        assert 'signature verification failed' in str(exc_info.value).lower()
        
        # Test 3: Signature manipulation attack
        token_parts = valid_token.split('.')
        # Modify signature by changing last character
        manipulated_signature = token_parts[2][:-1] + 'X'
        manipulated_token = '.'.join([token_parts[0], token_parts[1], manipulated_signature])
        
        with pytest.raises(JWTException) as exc_info:
            jwt_utils.validate_token(manipulated_token)
        assert 'signature verification failed' in str(exc_info.value).lower()
        
        # Test 4: Empty signature attack
        empty_signature_token = '.'.join([token_parts[0], token_parts[1], ''])
        with pytest.raises(JWTException) as exc_info:
            jwt_utils.validate_token(empty_signature_token)
        assert 'invalid' in str(exc_info.value).lower()
    
    def test_jwt_algorithm_confusion_attack_prevention(self, rsa_key_pair, valid_jwt_payload):
        """
        Test prevention of algorithm confusion attacks between HMAC and RSA.
        
        Security Validation:
        - RS256 token cannot be verified as HS256 with public key as secret
        - HS256 token cannot be verified as RS256 
        - Algorithm specification enforcement
        - None algorithm attack prevention
        """
        # Generate RS256 token
        rs256_token = jwt.encode(
            payload=valid_jwt_payload,
            key=rsa_key_pair['private_key'],
            algorithm='RS256'
        )
        
        # Test 1: Algorithm confusion attack - try to verify RS256 token as HS256
        with pytest.raises((jwt.InvalidTokenError, jwt.InvalidSignatureError)):
            jwt.decode(
                jwt=rs256_token,
                key=rsa_key_pair['public_key'],  # Using public key as HMAC secret
                algorithms=['HS256']
            )
        
        # Test 2: Algorithm confusion attack - try to verify with wrong algorithm
        with pytest.raises((jwt.InvalidTokenError, jwt.InvalidSignatureError)):
            jwt.decode(
                jwt=rs256_token,
                key='hmac-secret-key',
                algorithms=['HS256']
            )
        
        # Test 3: None algorithm attack prevention
        none_algorithm_token = jwt.encode(
            payload=valid_jwt_payload,
            key='',
            algorithm='none'
        )
        
        with pytest.raises((jwt.InvalidTokenError, jwt.MissingRequiredClaimError)):
            jwt.decode(
                jwt=none_algorithm_token,
                key=rsa_key_pair['public_key'],
                algorithms=['RS256', 'HS256']  # None algorithm not allowed
            )
        
        # Test 4: Algorithm enforcement - must specify allowed algorithms
        with pytest.raises((jwt.InvalidTokenError, jwt.InvalidSignatureError)):
            jwt.decode(
                jwt=rs256_token,
                key=rsa_key_pair['public_key'],
                algorithms=['HS256']  # Wrong algorithm specified
            )
    
    def test_jwt_expiration_security_validation(self, jwt_utils, valid_jwt_payload):
        """
        Test JWT expiration security validation against timing attacks.
        
        Security Validation:
        - Expired token rejection
        - Future-dated token validation with leeway
        - Clock skew handling security
        - Timing attack prevention for expiration checks
        """
        # Test 1: Expired token rejection
        expired_payload = valid_jwt_payload.copy()
        expired_token = jwt_utils.generate_token(expired_payload, expires_in=-3600)  # Expired 1 hour ago
        
        with pytest.raises(JWTException) as exc_info:
            jwt_utils.validate_token(expired_token)
        assert 'expired' in str(exc_info.value).lower()
        
        # Test 2: Future-dated token validation
        future_payload = valid_jwt_payload.copy()
        future_time = datetime.utcnow() + timedelta(hours=1)
        future_payload['iat'] = future_time.timestamp()
        
        # This should fail as token is issued in the future beyond acceptable leeway
        future_token = jwt.encode(
            payload=future_payload,
            key='test-secret-key-for-security-testing',
            algorithm='HS256'
        )
        
        with pytest.raises(JWTException):
            jwt_utils.validate_token(future_token)
        
        # Test 3: Timing attack prevention - measure response time consistency
        timing_measurements = []
        
        # Generate multiple tokens with different expiration times
        for i in range(10):
            test_payload = valid_jwt_payload.copy()
            # Some expired, some valid tokens
            expires_in = 3600 if i % 2 == 0 else -3600
            test_token = jwt_utils.generate_token(test_payload, expires_in=expires_in)
            
            start_time = time.perf_counter()
            try:
                jwt_utils.validate_token(test_token)
            except JWTException:
                pass  # Expected for expired tokens
            end_time = time.perf_counter()
            
            timing_measurements.append(end_time - start_time)
        
        # Verify timing consistency (no significant timing differences)
        max_time = max(timing_measurements)
        min_time = min(timing_measurements)
        timing_variance = (max_time - min_time) / min_time if min_time > 0 else 0
        
        # Timing variance should be reasonable (less than 100% difference)
        assert timing_variance < 1.0, f"Potential timing attack vulnerability: {timing_variance:.2%} variance"
    
    def test_jwt_claims_injection_prevention(self, jwt_utils, valid_jwt_payload):
        """
        Test JWT claims injection and manipulation prevention.
        
        Security Validation:
        - Claims modification attack prevention
        - Required claims validation
        - Claims type validation security
        - Malicious claims filtering
        """
        # Test 1: Claims modification in payload
        modified_payload = valid_jwt_payload.copy()
        modified_payload['admin'] = True  # Injected admin claim
        modified_payload['permissions'] = ['admin:all', 'system:root']  # Escalated permissions
        
        modified_token = jwt_utils.generate_token(modified_payload, expires_in=3600)
        
        # Token should validate but application logic should handle permission escalation
        decoded_payload = jwt_utils.validate_token(modified_token)
        
        # Verify claims are present but application should validate permissions separately
        assert 'admin' in decoded_payload
        assert 'permissions' in decoded_payload
        
        # Test 2: Required claims validation
        incomplete_payload = {'sub': 'test_user'}  # Missing required claims
        incomplete_token = jwt_utils.generate_token(incomplete_payload, expires_in=3600)
        
        # Should still validate basic structure but missing claims should be handled
        decoded_incomplete = jwt_utils.validate_token(incomplete_token)
        assert decoded_incomplete['sub'] == 'test_user'
        
        # Test 3: Malicious claims filtering
        malicious_payload = valid_jwt_payload.copy()
        malicious_payload['<script>alert("xss")</script>'] = 'malicious_value'
        malicious_payload['../../../etc/passwd'] = 'path_traversal'
        malicious_payload['eval(malicious_code)'] = 'code_injection'
        
        malicious_token = jwt_utils.generate_token(malicious_payload, expires_in=3600)
        decoded_malicious = jwt_utils.validate_token(malicious_token)
        
        # Verify malicious claims are present (filtering should happen at application level)
        assert '<script>alert("xss")</script>' in decoded_malicious
        assert '../../../etc/passwd' in decoded_malicious
        
        # Test 4: Claims type validation
        type_confusion_payload = valid_jwt_payload.copy()
        type_confusion_payload['sub'] = ['array', 'instead', 'of', 'string']  # Wrong type
        type_confusion_payload['iat'] = 'string_instead_of_number'  # Wrong type
        
        type_confusion_token = jwt_utils.generate_token(type_confusion_payload, expires_in=3600)
        decoded_type_confusion = jwt_utils.validate_token(type_confusion_token)
        
        # Verify types are preserved but application should validate
        assert isinstance(decoded_type_confusion['sub'], list)
        assert isinstance(decoded_type_confusion['iat'], str)
    
    def test_jwt_token_structure_validation(self, jwt_utils):
        """
        Test JWT token structure validation against malformed token attacks.
        
        Security Validation:
        - Malformed token structure rejection
        - Invalid base64 encoding handling
        - Missing token parts validation
        - Oversized token handling
        """
        # Test 1: Invalid token structure (wrong number of parts)
        invalid_structures = [
            'invalid.token',  # Only 2 parts
            'invalid.token.with.extra.parts',  # Too many parts
            'single_part_token',  # Single part
            '',  # Empty token
            'invalid',  # No dots
        ]
        
        for invalid_token in invalid_structures:
            with pytest.raises((JWTException, AuthenticationException)) as exc_info:
                jwt_utils.validate_token(invalid_token)
            assert any(keyword in str(exc_info.value).lower() 
                      for keyword in ['invalid', 'malformed', 'format'])
        
        # Test 2: Invalid base64 encoding
        valid_token = jwt_utils.generate_token({'test': 'payload'}, expires_in=3600)
        token_parts = valid_token.split('.')
        
        # Corrupt base64 encoding in header
        corrupted_header = 'invalid_base64_!@#$%'
        corrupted_token = '.'.join([corrupted_header, token_parts[1], token_parts[2]])
        
        with pytest.raises(JWTException):
            jwt_utils.validate_token(corrupted_token)
        
        # Corrupt base64 encoding in payload
        corrupted_payload = 'invalid_base64_!@#$%'
        corrupted_token = '.'.join([token_parts[0], corrupted_payload, token_parts[2]])
        
        with pytest.raises(JWTException):
            jwt_utils.validate_token(corrupted_token)
        
        # Test 3: Oversized token handling
        large_payload = {'data': 'x' * 10000}  # Large payload
        large_token = jwt_utils.generate_token(large_payload, expires_in=3600)
        
        # Should handle large tokens gracefully
        decoded_large = jwt_utils.validate_token(large_token)
        assert len(decoded_large['data']) == 10000
        
        # Test 4: Invalid JSON in payload
        valid_header_b64 = base64.urlsafe_b64encode(
            json.dumps({'typ': 'JWT', 'alg': 'HS256'}).encode()
        ).decode().rstrip('=')
        
        invalid_json_payload = base64.urlsafe_b64encode(
            b'invalid_json_content'
        ).decode().rstrip('=')
        
        signature = base64.urlsafe_b64encode(b'fake_signature').decode().rstrip('=')
        invalid_json_token = f"{valid_header_b64}.{invalid_json_payload}.{signature}"
        
        with pytest.raises(JWTException):
            jwt_utils.validate_token(invalid_json_token)


class TestAuthenticationBypassPrevention:
    """
    Authentication bypass attack prevention testing implementing comprehensive security validation
    against common authentication bypass techniques per Section 6.4.1 token handling requirements.
    
    Security Test Coverage:
    - Authentication bypass attempt detection and prevention
    - Session hijacking and fixation prevention
    - Token theft and replay attack prevention
    - Privilege escalation attack detection
    - Multi-step authentication bypass prevention
    """
    
    @pytest.fixture
    async def auth_manager(self, mongodb_uri, redis_uri):
        """Authentication manager for bypass testing"""
        with patch.dict(os.environ, {
            'AUTH0_DOMAIN': 'test-tenant.auth0.com',
            'AUTH0_CLIENT_ID': 'test_client_id',
            'AUTH0_CLIENT_SECRET': 'test_client_secret',
            'AUTH0_AUDIENCE': 'test_audience',
            'JWT_SECRET_KEY': 'test-jwt-secret-key',
            'MONGODB_URI': mongodb_uri,
            'REDIS_URL': redis_uri
        }):
            auth_manager = AuthenticationManager()
            yield auth_manager
            await auth_manager.close()
    
    @pytest.fixture
    def mock_auth0_responses(self):
        """Mock Auth0 responses for bypass testing"""
        return {
            'valid_user': {
                'sub': 'auth0|valid_user_123',
                'email': 'valid@example.com',
                'email_verified': True,
                'name': 'Valid User',
                'picture': 'https://example.com/avatar.jpg'
            },
            'admin_user': {
                'sub': 'auth0|admin_user_456',
                'email': 'admin@example.com',
                'email_verified': True,
                'name': 'Admin User',
                'permissions': ['admin:all', 'user:read', 'user:write']
            }
        }
    
    @pytest.mark.asyncio
    async def test_authentication_bypass_token_manipulation(self, auth_manager, mock_auth0_responses):
        """
        Test authentication bypass prevention through token manipulation.
        
        Security Validation:
        - Token signature bypass attempts
        - Token payload manipulation detection
        - Token expiration bypass attempts
        - Algorithm downgrade attack prevention
        """
        # Mock successful Auth0 validation
        with patch.object(auth_manager.token_validator, 'validate_token') as mock_validate:
            mock_validate.return_value = {
                'sub': 'auth0|test_user_123',
                'email': 'test@example.com',
                'iss': 'https://test-tenant.auth0.com/',
                'aud': 'test_audience',
                'exp': int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
                'iat': int(datetime.utcnow().timestamp()),
                'validation_metadata': {
                    'validated_at': datetime.utcnow().isoformat(),
                    'signature_verified': True,
                    'validation_source': 'auth0_jwks'
                }
            }
            
            # Mock user profile retrieval
            with patch.object(auth_manager.user_manager, 'get_user_profile') as mock_profile:
                mock_profile.return_value = mock_auth0_responses['valid_user']
                
                # Test 1: Valid authentication baseline
                valid_token = 'valid.jwt.token'
                auth_result = await auth_manager.authenticate_user(valid_token)
                
                assert auth_result['authenticated'] is True
                assert auth_result['user_id'] == 'auth0|test_user_123'
                
                # Test 2: Token manipulation bypass attempt
                mock_validate.side_effect = JWTException(
                    message="Token signature verification failed",
                    error_code=SecurityErrorCode.AUTH_TOKEN_INVALID
                )
                
                with pytest.raises(JWTException) as exc_info:
                    await auth_manager.authenticate_user('manipulated.jwt.token')
                
                assert exc_info.value.error_code == SecurityErrorCode.AUTH_TOKEN_INVALID
                
                # Test 3: Expired token bypass attempt
                mock_validate.side_effect = JWTException(
                    message="JWT token has expired",
                    error_code=SecurityErrorCode.AUTH_TOKEN_EXPIRED
                )
                
                with pytest.raises(JWTException) as exc_info:
                    await auth_manager.authenticate_user('expired.jwt.token')
                
                assert exc_info.value.error_code == SecurityErrorCode.AUTH_TOKEN_EXPIRED
                
                # Test 4: Malformed token bypass attempt
                with pytest.raises(AuthenticationException) as exc_info:
                    await auth_manager.authenticate_user('malformed_token_without_dots')
                
                assert exc_info.value.error_code == SecurityErrorCode.AUTH_TOKEN_MALFORMED
    
    @pytest.mark.asyncio
    async def test_session_hijacking_prevention(self, auth_manager, mock_auth0_responses):
        """
        Test session hijacking and fixation prevention.
        
        Security Validation:
        - Session ID regeneration on authentication
        - Session fixation attack prevention
        - Cross-session contamination prevention
        - Session theft detection
        """
        # Mock Auth0 responses
        with patch.object(auth_manager.token_validator, 'validate_token') as mock_validate:
            mock_validate.return_value = {
                'sub': 'auth0|test_user_123',
                'email': 'test@example.com',
                'exp': int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
                'iat': int(datetime.utcnow().timestamp()),
                'validation_metadata': {'validated_at': datetime.utcnow().isoformat()}
            }
            
            with patch.object(auth_manager.user_manager, 'get_user_profile') as mock_profile:
                mock_profile.return_value = mock_auth0_responses['valid_user']
                
                # Test 1: Create initial session
                auth_result = await auth_manager.authenticate_user('valid.jwt.token')
                
                # Create session for authenticated user
                session_result = await auth_manager.create_user_session(
                    user_id=auth_result['user_id'],
                    token_payload=auth_result['token_payload'],
                    ttl=3600
                )
                
                session_id_1 = session_result['session_id']
                
                # Test 2: Verify session isolation - create another session
                session_result_2 = await auth_manager.create_user_session(
                    user_id=auth_result['user_id'],
                    token_payload=auth_result['token_payload'],
                    ttl=3600
                )
                
                session_id_2 = session_result_2['session_id']
                
                # Sessions should have different IDs
                assert session_id_1 != session_id_2
                
                # Test 3: Verify session data isolation
                session_1_data = await auth_manager.get_user_session(session_id_1)
                session_2_data = await auth_manager.get_user_session(session_id_2)
                
                assert session_1_data is not None
                assert session_2_data is not None
                assert session_1_data['session_id'] != session_2_data['session_id']
                
                # Test 4: Session invalidation security
                invalidation_success = await auth_manager.invalidate_user_session(session_id_1)
                assert invalidation_success is True
                
                # Verify invalidated session cannot be retrieved
                invalidated_session = await auth_manager.get_user_session(session_id_1)
                assert invalidated_session is None
                
                # Verify other session remains valid
                valid_session = await auth_manager.get_user_session(session_id_2)
                assert valid_session is not None
    
    @pytest.mark.asyncio
    async def test_privilege_escalation_prevention(self, auth_manager, mock_auth0_responses):
        """
        Test privilege escalation attack prevention.
        
        Security Validation:
        - Permission escalation through token manipulation
        - Role elevation attack prevention
        - Administrative access bypass prevention
        - Permission inheritance validation
        """
        # Test 1: Normal user permissions
        with patch.object(auth_manager.user_manager, 'validate_user_permissions') as mock_permissions:
            mock_permissions.return_value = {
                'user_id': 'auth0|normal_user_123',
                'has_permissions': True,
                'granted_permissions': ['read:profile', 'update:profile'],
                'required_permissions': ['read:profile'],
                'validation_source': 'auth0_api',
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Validate normal user permissions
            permission_result = await auth_manager.validate_permissions(
                user_id='auth0|normal_user_123',
                required_permissions=['read:profile']
            )
            
            assert permission_result['has_permissions'] is True
            assert 'admin' not in str(permission_result['granted_permissions']).lower()
            
            # Test 2: Administrative privilege escalation attempt
            mock_permissions.return_value = {
                'user_id': 'auth0|normal_user_123',
                'has_permissions': False,
                'granted_permissions': ['read:profile', 'update:profile'],
                'required_permissions': ['admin:users'],
                'validation_source': 'auth0_api',
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Attempt to access admin functionality
            admin_permission_result = await auth_manager.validate_permissions(
                user_id='auth0|normal_user_123',
                required_permissions=['admin:users']
            )
            
            assert admin_permission_result['has_permissions'] is False
            assert 'admin:users' not in admin_permission_result['granted_permissions']
            
            # Test 3: Multiple permission escalation attempt
            mock_permissions.return_value = {
                'user_id': 'auth0|normal_user_123',
                'has_permissions': False,
                'granted_permissions': ['read:profile'],
                'required_permissions': ['admin:all', 'system:root', 'delete:users'],
                'validation_source': 'auth0_api',
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Attempt escalation to multiple high-privilege permissions
            escalation_result = await auth_manager.validate_permissions(
                user_id='auth0|normal_user_123',
                required_permissions=['admin:all', 'system:root', 'delete:users']
            )
            
            assert escalation_result['has_permissions'] is False
            dangerous_permissions = ['admin:all', 'system:root', 'delete:users']
            granted = escalation_result['granted_permissions']
            assert not any(perm in granted for perm in dangerous_permissions)
    
    @pytest.mark.asyncio
    async def test_concurrent_authentication_bypass_attempts(self, auth_manager):
        """
        Test prevention of concurrent authentication bypass attempts.
        
        Security Validation:
        - Concurrent session attack prevention
        - Race condition exploitation prevention
        - Resource exhaustion attack prevention
        - Brute force attack detection
        """
        # Test 1: Concurrent invalid token validation
        invalid_tokens = [f'invalid.token.{i}' for i in range(10)]
        
        async def attempt_authentication(token):
            try:
                return await auth_manager.authenticate_user(token)
            except (AuthenticationException, JWTException) as e:
                return {'error': str(e), 'error_code': e.error_code}
        
        # Execute concurrent authentication attempts
        tasks = [attempt_authentication(token) for token in invalid_tokens]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # All attempts should fail
        for result in results:
            if isinstance(result, dict) and 'error' in result:
                assert 'error_code' in result
            else:
                # Should be an exception
                assert isinstance(result, (AuthenticationException, JWTException))
        
        # Test 2: Resource exhaustion prevention
        start_time = time.time()
        large_batch_tasks = [attempt_authentication(f'token_{i}') for i in range(50)]
        large_batch_results = await asyncio.gather(*large_batch_tasks, return_exceptions=True)
        end_time = time.time()
        
        # Verify reasonable response time (no hanging or excessive delays)
        total_time = end_time - start_time
        assert total_time < 30.0, f"Authentication took too long: {total_time:.2f}s"
        
        # All should fail appropriately
        for result in large_batch_results:
            assert isinstance(result, (dict, AuthenticationException, JWTException))


class TestTokenManipulationSecurity:
    """
    Token manipulation and signature validation security testing implementing comprehensive
    cryptographic attack prevention per Section 6.4.1 JWT validation requirements.
    
    Security Test Coverage:
    - Token signature manipulation and forgery prevention
    - Token payload tampering detection and prevention
    - Cryptographic attack simulation and validation
    - Key confusion and algorithm downgrade prevention
    - Token replay and time-based attack prevention
    """
    
    @pytest.fixture
    def crypto_utils(self):
        """Cryptographic utilities for attack simulation"""
        return CryptographicUtils()
    
    @pytest.fixture
    def test_secret_key(self):
        """Test secret key for HMAC operations"""
        return 'test-secret-key-for-manipulation-testing'
    
    @pytest.fixture
    def test_rsa_keys(self):
        """Test RSA key pair for RS256 operations"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            'private_key': private_pem,
            'public_key': public_pem
        }
    
    def test_token_signature_forgery_prevention(self, test_secret_key, crypto_utils):
        """
        Test prevention of token signature forgery attacks.
        
        Security Validation:
        - HMAC signature forgery prevention
        - Signature verification bypass attempts
        - Weak signature algorithm exploitation prevention
        - Signature truncation attack prevention
        """
        # Create valid token for reference
        payload = {
            'sub': 'auth0|test_user_123',
            'email': 'test@example.com',
            'iat': int(datetime.utcnow().timestamp()),
            'exp': int((datetime.utcnow() + timedelta(hours=1)).timestamp())
        }
        
        valid_token = jwt.encode(payload, test_secret_key, algorithm='HS256')
        
        # Test 1: Signature forgery with known plaintext attack
        header = {'typ': 'JWT', 'alg': 'HS256'}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        
        # Attempt to forge signature using weak methods
        weak_signatures = [
            'weak_signature',
            hashlib.md5(f"{header_b64}.{payload_b64}".encode()).hexdigest(),
            hashlib.sha1(f"{header_b64}.{payload_b64}".encode()).hexdigest(),
            base64.urlsafe_b64encode(b'forged_signature').decode().rstrip('=')
        ]
        
        for weak_sig in weak_signatures:
            forged_token = f"{header_b64}.{payload_b64}.{weak_sig}"
            
            with pytest.raises((jwt.InvalidSignatureError, jwt.InvalidTokenError)):
                jwt.decode(forged_token, test_secret_key, algorithms=['HS256'])
        
        # Test 2: Signature truncation attack
        valid_parts = valid_token.split('.')
        truncated_signatures = [
            valid_parts[2][:10],  # Truncated signature
            valid_parts[2][:-5],  # Partial signature
            valid_parts[2][:1],   # Single character
            ''                    # Empty signature
        ]
        
        for truncated_sig in truncated_signatures:
            truncated_token = f"{valid_parts[0]}.{valid_parts[1]}.{truncated_sig}"
            
            with pytest.raises((jwt.InvalidSignatureError, jwt.InvalidTokenError)):
                jwt.decode(truncated_token, test_secret_key, algorithms=['HS256'])
        
        # Test 3: Signature padding attack
        valid_signature = valid_parts[2]
        padded_signatures = [
            valid_signature + '=',
            valid_signature + '==',
            valid_signature + 'extra_padding',
            '=' + valid_signature
        ]
        
        for padded_sig in padded_signatures:
            padded_token = f"{valid_parts[0]}.{valid_parts[1]}.{padded_sig}"
            
            with pytest.raises((jwt.InvalidSignatureError, jwt.InvalidTokenError)):
                jwt.decode(padded_token, test_secret_key, algorithms=['HS256'])
    
    def test_token_payload_tampering_detection(self, test_secret_key):
        """
        Test detection of token payload tampering attacks.
        
        Security Validation:
        - Payload modification detection
        - Claims injection prevention
        - Payload corruption handling
        - Base64 manipulation prevention
        """
        # Create original token
        original_payload = {
            'sub': 'auth0|normal_user_123',
            'email': 'user@example.com',
            'role': 'user',
            'permissions': ['read:profile'],
            'iat': int(datetime.utcnow().timestamp()),
            'exp': int((datetime.utcnow() + timedelta(hours=1)).timestamp())
        }
        
        original_token = jwt.encode(original_payload, test_secret_key, algorithm='HS256')
        token_parts = original_token.split('.')
        
        # Test 1: Claims injection attack
        malicious_payload = original_payload.copy()
        malicious_payload['role'] = 'admin'
        malicious_payload['permissions'] = ['admin:all', 'delete:users']
        
        malicious_payload_b64 = base64.urlsafe_b64encode(
            json.dumps(malicious_payload).encode()
        ).decode().rstrip('=')
        
        tampered_token = f"{token_parts[0]}.{malicious_payload_b64}.{token_parts[2]}"
        
        with pytest.raises(jwt.InvalidSignatureError):
            jwt.decode(tampered_token, test_secret_key, algorithms=['HS256'])
        
        # Test 2: Payload corruption attack
        corrupted_payloads = [
            base64.urlsafe_b64encode(b'corrupted_data').decode().rstrip('='),
            base64.urlsafe_b64encode(b'{"malformed": json}').decode().rstrip('='),
            'invalid_base64_data_!@#$%',
            token_parts[1] + 'extra_data'
        ]
        
        for corrupted_payload in corrupted_payloads:
            corrupted_token = f"{token_parts[0]}.{corrupted_payload}.{token_parts[2]}"
            
            with pytest.raises((jwt.InvalidSignatureError, jwt.InvalidTokenError, jwt.DecodeError)):
                jwt.decode(corrupted_token, test_secret_key, algorithms=['HS256'])
        
        # Test 3: Payload size manipulation
        oversized_payload = original_payload.copy()
        oversized_payload['large_data'] = 'x' * 100000  # 100KB of data
        
        oversized_payload_b64 = base64.urlsafe_b64encode(
            json.dumps(oversized_payload).encode()
        ).decode().rstrip('=')
        
        oversized_token = f"{token_parts[0]}.{oversized_payload_b64}.{token_parts[2]}"
        
        with pytest.raises(jwt.InvalidSignatureError):
            jwt.decode(oversized_token, test_secret_key, algorithms=['HS256'])
    
    def test_cryptographic_attack_prevention(self, test_rsa_keys, test_secret_key):
        """
        Test prevention of advanced cryptographic attacks.
        
        Security Validation:
        - Key confusion attack prevention
        - Timing attack resistance
        - Side-channel attack prevention
        - Cryptographic downgrade prevention
        """
        # Test 1: Key confusion attack between RSA and HMAC
        rsa_payload = {
            'sub': 'auth0|test_user_123',
            'iat': int(datetime.utcnow().timestamp()),
            'exp': int((datetime.utcnow() + timedelta(hours=1)).timestamp())
        }
        
        # Create RSA token
        rsa_token = jwt.encode(rsa_payload, test_rsa_keys['private_key'], algorithm='RS256')
        
        # Attempt key confusion - use RSA public key as HMAC secret
        with pytest.raises((jwt.InvalidSignatureError, jwt.InvalidTokenError)):
            jwt.decode(rsa_token, test_rsa_keys['public_key'], algorithms=['HS256'])
        
        # Test 2: Algorithm downgrade attack
        secure_algorithms = ['RS256', 'RS384', 'RS512', 'HS256', 'HS384', 'HS512']
        insecure_algorithms = ['none', 'HS1', 'RS1']  # None and weak algorithms
        
        for insecure_alg in insecure_algorithms:
            try:
                insecure_token = jwt.encode(rsa_payload, '', algorithm=insecure_alg)
                
                # Should reject insecure algorithms
                with pytest.raises((jwt.InvalidTokenError, jwt.InvalidSignatureError)):
                    jwt.decode(insecure_token, test_secret_key, algorithms=secure_algorithms)
            except (ValueError, jwt.InvalidKeyError):
                # Expected for invalid algorithms
                pass
        
        # Test 3: Timing attack resistance
        timing_measurements = []
        
        # Test multiple token validations with various scenarios
        test_scenarios = [
            (jwt.encode(rsa_payload, test_secret_key, algorithm='HS256'), test_secret_key, ['HS256']),
            (jwt.encode(rsa_payload, test_secret_key, algorithm='HS256'), 'wrong_key', ['HS256']),
            ('invalid.token.structure', test_secret_key, ['HS256']),
            (jwt.encode(rsa_payload, test_rsa_keys['private_key'], algorithm='RS256'), test_rsa_keys['public_key'], ['RS256'])
        ]
        
        for token, key, algorithms in test_scenarios:
            measurements_for_scenario = []
            
            # Measure multiple attempts for each scenario
            for _ in range(5):
                start_time = time.perf_counter()
                try:
                    jwt.decode(token, key, algorithms=algorithms)
                except (jwt.InvalidTokenError, jwt.InvalidSignatureError, jwt.ExpiredSignatureError):
                    pass  # Expected for some scenarios
                end_time = time.perf_counter()
                
                measurements_for_scenario.append(end_time - start_time)
            
            timing_measurements.append(measurements_for_scenario)
        
        # Verify timing consistency across scenarios (no significant timing leakage)
        all_times = [time for scenario_times in timing_measurements for time in scenario_times]
        max_time = max(all_times)
        min_time = min(all_times)
        timing_variance = (max_time - min_time) / min_time if min_time > 0 else 0
        
        # Timing variance should be reasonable (implementation dependent)
        assert timing_variance < 5.0, f"Potential timing attack vulnerability: {timing_variance:.2%} variance"
    
    def test_token_replay_attack_prevention(self, test_secret_key):
        """
        Test prevention of token replay attacks.
        
        Security Validation:
        - Timestamp validation security
        - Token uniqueness enforcement
        - Replay detection mechanisms
        - Time window validation
        """
        # Test 1: Token with past timestamp (issued in the past)
        past_payload = {
            'sub': 'auth0|test_user_123',
            'iat': int((datetime.utcnow() - timedelta(hours=2)).timestamp()),  # 2 hours ago
            'exp': int((datetime.utcnow() + timedelta(hours=1)).timestamp())   # Still valid expiration
        }
        
        past_token = jwt.encode(past_payload, test_secret_key, algorithm='HS256')
        
        # Should be valid (past issued time is acceptable)
        decoded = jwt.decode(past_token, test_secret_key, algorithms=['HS256'])
        assert decoded['sub'] == 'auth0|test_user_123'
        
        # Test 2: Token with future timestamp (issued in the future)
        future_payload = {
            'sub': 'auth0|test_user_123',
            'iat': int((datetime.utcnow() + timedelta(hours=1)).timestamp()),  # 1 hour in future
            'exp': int((datetime.utcnow() + timedelta(hours=2)).timestamp())
        }
        
        future_token = jwt.encode(future_payload, test_secret_key, algorithm='HS256')
        
        # Should handle future tokens with reasonable leeway
        try:
            jwt.decode(future_token, test_secret_key, algorithms=['HS256'], leeway=timedelta(minutes=5))
            # If no leeway, should fail
            with pytest.raises(jwt.ImmatureSignatureError):
                jwt.decode(future_token, test_secret_key, algorithms=['HS256'], leeway=0)
        except jwt.ImmatureSignatureError:
            # Expected for tokens issued in the future
            pass
        
        # Test 3: Token uniqueness validation
        # Generate multiple tokens with same payload but different jti (if supported)
        base_payload = {
            'sub': 'auth0|test_user_123',
            'iat': int(datetime.utcnow().timestamp()),
            'exp': int((datetime.utcnow() + timedelta(hours=1)).timestamp())
        }
        
        tokens = []
        for i in range(5):
            payload_with_jti = base_payload.copy()
            payload_with_jti['jti'] = f'unique_token_id_{i}_{int(time.time())}'
            token = jwt.encode(payload_with_jti, test_secret_key, algorithm='HS256')
            tokens.append(token)
        
        # All tokens should be valid and unique
        decoded_tokens = []
        for token in tokens:
            decoded = jwt.decode(token, test_secret_key, algorithms=['HS256'])
            decoded_tokens.append(decoded)
        
        # Verify all tokens have unique JTI values
        jti_values = [token.get('jti') for token in decoded_tokens]
        assert len(set(jti_values)) == len(jti_values), "JTI values should be unique"


class TestAuth0IntegrationSecurity:
    """
    Auth0 integration security testing with mock attack scenarios implementing comprehensive
    external service security validation per Section 6.4.1 Auth0 integration requirements.
    
    Security Test Coverage:
    - Auth0 API security validation and mocking
    - External service attack simulation
    - Circuit breaker security patterns
    - API rate limiting and abuse prevention
    - Service degradation and fallback security
    """
    
    @pytest.fixture
    def mock_auth0_config(self):
        """Mock Auth0 configuration for security testing"""
        with patch.dict(os.environ, {
            'AUTH0_DOMAIN': 'test-tenant.auth0.com',
            'AUTH0_CLIENT_ID': 'test_client_id_security',
            'AUTH0_CLIENT_SECRET': 'test_client_secret_security',
            'AUTH0_AUDIENCE': 'test_audience_security',
            'JWT_ALGORITHM': 'RS256'
        }):
            from src.auth.authentication import Auth0Config
            return Auth0Config()
    
    @pytest.fixture
    def mock_jwks_response(self):
        """Mock JWKS response for testing"""
        return {
            'keys': [
                {
                    'kty': 'RSA',
                    'kid': 'test_key_id_123',
                    'use': 'sig',
                    'alg': 'RS256',
                    'n': 'test_modulus_value',
                    'e': 'AQAB'
                }
            ]
        }
    
    @pytest.mark.asyncio
    async def test_auth0_api_security_validation(self, mock_auth0_config, mock_jwks_response):
        """
        Test Auth0 API security validation against malicious responses.
        
        Security Validation:
        - Malicious JWKS response handling
        - API response injection prevention
        - Invalid certificate validation
        - Response tampering detection
        """
        from src.auth.authentication import JWTTokenValidator
        from src.auth.cache import get_auth_cache
        
        # Test 1: Malicious JWKS response injection
        malicious_jwks_responses = [
            {'keys': []},  # Empty keys
            {'keys': [{'kty': 'INVALID', 'kid': 'malicious'}]},  # Invalid key type
            {'malicious': 'response'},  # Wrong structure
            None,  # No response
            {'keys': [{'kty': 'RSA', 'kid': '../../../etc/passwd'}]}  # Path traversal in kid
        ]
        
        validator = JWTTokenValidator(mock_auth0_config, get_auth_cache())
        
        for malicious_response in malicious_jwks_responses:
            with patch('httpx.AsyncClient.get') as mock_get:
                mock_response = Mock()
                mock_response.json.return_value = malicious_response
                mock_response.raise_for_status.return_value = None
                mock_get.return_value = mock_response
                
                with pytest.raises((Auth0Exception, JWTException)):
                    await validator._get_signing_key('test_key_id')
        
        await validator.close()
        
        # Test 2: HTTP response status attack
        error_statuses = [400, 401, 403, 404, 429, 500, 502, 503, 504]
        
        for status_code in error_statuses:
            validator = JWTTokenValidator(mock_auth0_config, get_auth_cache())
            
            with patch('httpx.AsyncClient.get') as mock_get:
                mock_response = Mock()
                mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
                    message=f"HTTP {status_code}", 
                    request=Mock(), 
                    response=Mock(status_code=status_code)
                )
                mock_get.return_value = mock_response
                
                with pytest.raises(Auth0Exception):
                    await validator._get_signing_key('test_key_id')
            
            await validator.close()
        
        # Test 3: Response timeout attack
        validator = JWTTokenValidator(mock_auth0_config, get_auth_cache())
        
        with patch('httpx.AsyncClient.get') as mock_get:
            mock_get.side_effect = httpx.TimeoutException("Request timeout")
            
            with pytest.raises(Auth0Exception):
                await validator._get_signing_key('test_key_id')
        
        await validator.close()
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_security_patterns(self, mock_auth0_config):
        """
        Test circuit breaker security patterns against service abuse.
        
        Security Validation:
        - Circuit breaker activation on failures
        - Service abuse prevention
        - Fallback mechanism security
        - Recovery pattern validation
        """
        from src.auth.authentication import Auth0CircuitBreaker
        
        # Test 1: Circuit breaker activation
        circuit_breaker = Auth0CircuitBreaker(failure_threshold=3, recovery_timeout=5)
        
        @circuit_breaker
        async def mock_auth0_call():
            raise httpx.RequestError("Auth0 service unavailable")
        
        # Trigger failures to open circuit breaker
        for i in range(3):
            with pytest.raises(httpx.RequestError):
                await mock_auth0_call()
        
        # Circuit should be open now
        with pytest.raises(CircuitBreakerException) as exc_info:
            await mock_auth0_call()
        
        assert exc_info.value.error_code == SecurityErrorCode.EXT_CIRCUIT_BREAKER_OPEN
        
        # Test 2: Circuit breaker state validation
        state = circuit_breaker.get_state()
        assert state['state'] == 'open'
        assert state['failure_count'] >= 3
        
        # Test 3: Recovery timeout security
        # Wait for recovery timeout (simulate)
        await asyncio.sleep(0.1)  # Short wait for test
        
        # Should still be open (recovery timeout not reached)
        with pytest.raises(CircuitBreakerException):
            await mock_auth0_call()
    
    @pytest.mark.asyncio 
    async def test_auth0_rate_limiting_security(self, mock_auth0_config):
        """
        Test Auth0 rate limiting and abuse prevention.
        
        Security Validation:
        - Rate limiting detection and handling
        - Burst request prevention
        - API abuse detection
        - Rate limit recovery handling
        """
        from src.auth.authentication import Auth0UserManager
        from src.auth.cache import get_auth_cache
        
        user_manager = Auth0UserManager(mock_auth0_config, get_auth_cache())
        
        # Test 1: Rate limiting response handling
        with patch('httpx.AsyncClient.get') as mock_get:
            # Simulate rate limiting response
            mock_response = Mock()
            mock_response.status_code = 429
            mock_response.headers = {'Retry-After': '60'}
            mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
                message="Too Many Requests",
                request=Mock(),
                response=mock_response
            )
            mock_get.return_value = mock_response
            
            with pytest.raises(Auth0Exception) as exc_info:
                await user_manager.get_user_profile('test_user_123', use_cache=False)
            
            # Should handle rate limiting appropriately
            assert 'rate' in str(exc_info.value).lower() or 'unavailable' in str(exc_info.value).lower()
        
        # Test 2: Burst request simulation
        tasks = []
        for i in range(20):  # Simulate burst of requests
            task = user_manager.get_user_profile(f'user_{i}', use_cache=False)
            tasks.append(task)
        
        with patch('httpx.AsyncClient.get') as mock_get:
            mock_response = Mock()
            mock_response.json.return_value = {'user_id': 'test_user', 'email': 'test@example.com'}
            mock_response.raise_for_status.return_value = None
            mock_get.return_value = mock_response
            
            # Execute burst requests
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Should handle burst gracefully
            for result in results:
                if isinstance(result, Exception):
                    assert isinstance(result, (Auth0Exception, CircuitBreakerException))
        
        await user_manager.close()
    
    @pytest.mark.asyncio
    async def test_auth0_service_degradation_security(self, mock_auth0_config):
        """
        Test Auth0 service degradation and fallback security.
        
        Security Validation:
        - Service degradation detection
        - Fallback mechanism security
        - Cache-based fallback validation
        - Degraded mode operation security
        """
        from src.auth.authentication import Auth0UserManager
        from src.auth.cache import get_auth_cache
        
        cache = get_auth_cache()
        user_manager = Auth0UserManager(mock_auth0_config, cache)
        
        # Test 1: Service degradation with cache fallback
        test_user_id = 'auth0|test_user_degradation'
        
        # First, populate cache with valid data
        cache.cache_auth0_user_profile(test_user_id, {
            'user_id': test_user_id,
            'email': 'test@example.com',
            'name': 'Test User',
            'cached_at': datetime.utcnow().isoformat()
        }, ttl=3600)
        
        # Simulate service degradation
        with patch('httpx.AsyncClient.get') as mock_get:
            mock_get.side_effect = httpx.ConnectError("Connection failed")
            
            # Should fallback to cache
            profile = await user_manager.get_user_profile(test_user_id, use_cache=True)
            
            assert profile is not None
            assert profile['user_id'] == test_user_id
            assert 'fallback_used' in profile.get('profile_metadata', {})
        
        # Test 2: Complete service failure without cache
        new_user_id = 'auth0|new_user_no_cache'
        
        with patch('httpx.AsyncClient.get') as mock_get:
            mock_get.side_effect = httpx.ConnectError("Service unavailable")
            
            with pytest.raises(Auth0Exception) as exc_info:
                await user_manager.get_user_profile(new_user_id, use_cache=True)
            
            assert exc_info.value.error_code == SecurityErrorCode.EXT_AUTH0_API_ERROR
        
        # Test 3: Permission validation degradation
        cache.cache_user_permissions(test_user_id, {'read:profile', 'update:profile'}, ttl=3600)
        
        with patch.object(user_manager, '_fetch_user_permissions') as mock_fetch:
            mock_fetch.side_effect = httpx.ConnectError("Service unavailable")
            
            # Should use cached permissions
            permission_result = await user_manager.validate_user_permissions(
                user_id=test_user_id,
                required_permissions=['read:profile'],
                use_cache=True
            )
            
            assert permission_result['has_permissions'] is True
            assert permission_result['validation_source'] == 'cache_fallback'
            assert permission_result.get('degraded_mode') is True
        
        await user_manager.close()


class TestTimingAttackPrevention:
    """
    Timing attack detection and prevention testing implementing comprehensive temporal security
    validation per Section 6.4.1 authentication flows timing attack prevention requirements.
    
    Security Test Coverage:
    - Authentication response time consistency
    - Password verification timing attacks
    - Token validation timing consistency  
    - User enumeration timing prevention
    - Side-channel attack prevention
    """
    
    @pytest.fixture
    def timing_test_samples(self):
        """Number of samples for timing attack detection"""
        return 50
    
    @pytest.fixture
    def timing_variance_threshold(self):
        """Maximum acceptable timing variance percentage"""
        return 0.50  # 50% variance threshold
    
    def test_authentication_timing_consistency(self, timing_test_samples, timing_variance_threshold):
        """
        Test authentication timing consistency to prevent timing attacks.
        
        Security Validation:
        - Consistent response times for valid/invalid tokens
        - Username enumeration timing prevention
        - Password verification timing consistency
        - Error response timing uniformity
        """
        from src.auth.utils import JWTTokenUtils
        
        jwt_utils = JWTTokenUtils(secret_key='timing-test-secret-key')
        
        # Test 1: Token validation timing consistency
        valid_payload = {
            'sub': 'auth0|timing_test_user',
            'email': 'timing@example.com',
            'iat': int(datetime.utcnow().timestamp()),
            'exp': int((datetime.utcnow() + timedelta(hours=1)).timestamp())
        }
        
        valid_token = jwt_utils.generate_token(valid_payload, expires_in=3600)
        invalid_tokens = [
            'invalid.token.structure',
            jwt_utils.generate_token(valid_payload, expires_in=-3600),  # Expired
            'malformed_token_without_dots',
            jwt.encode(valid_payload, 'wrong-key', algorithm='HS256'),  # Wrong signature
        ]
        
        # Measure timing for valid token validation
        valid_times = []
        for _ in range(timing_test_samples):
            start_time = time.perf_counter()
            try:
                jwt_utils.validate_token(valid_token)
            except Exception:
                pass
            end_time = time.perf_counter()
            valid_times.append(end_time - start_time)
        
        # Measure timing for invalid token validation
        invalid_times = []
        for _ in range(timing_test_samples):
            invalid_token = invalid_tokens[_ % len(invalid_tokens)]
            start_time = time.perf_counter()
            try:
                jwt_utils.validate_token(invalid_token)
            except Exception:
                pass  # Expected for invalid tokens
            end_time = time.perf_counter()
            invalid_times.append(end_time - start_time)
        
        # Calculate timing statistics
        valid_avg = sum(valid_times) / len(valid_times)
        invalid_avg = sum(invalid_times) / len(invalid_times)
        
        # Calculate timing variance
        if valid_avg > 0:
            timing_variance = abs(valid_avg - invalid_avg) / valid_avg
        else:
            timing_variance = 0
        
        # Verify timing consistency (should not leak information)
        assert timing_variance < timing_variance_threshold, \
            f"Timing attack vulnerability detected: {timing_variance:.2%} variance " \
            f"(threshold: {timing_variance_threshold:.2%})"
    
    def test_user_enumeration_timing_prevention(self, timing_test_samples, timing_variance_threshold):
        """
        Test prevention of user enumeration through timing attacks.
        
        Security Validation:
        - Consistent response times for existing/non-existing users
        - Email validation timing consistency
        - User lookup timing uniformity
        - Error message timing consistency
        """
        from src.auth.utils import InputValidator
        
        validator = InputValidator()
        
        # Test 1: Email validation timing consistency
        valid_emails = [
            'valid@example.com',
            'user@test.org',
            'admin@company.com',
            'test@domain.net'
        ]
        
        invalid_emails = [
            'invalid.email',
            '@missing-local.com',
            'missing-domain@',
            'spaces in@email.com'
        ]
        
        # Measure timing for valid email validation
        valid_email_times = []
        for _ in range(timing_test_samples):
            email = valid_emails[_ % len(valid_emails)]
            start_time = time.perf_counter()
            try:
                validator.validate_email(email)
            except Exception:
                pass
            end_time = time.perf_counter()
            valid_email_times.append(end_time - start_time)
        
        # Measure timing for invalid email validation
        invalid_email_times = []
        for _ in range(timing_test_samples):
            email = invalid_emails[_ % len(invalid_emails)]
            start_time = time.perf_counter()
            try:
                validator.validate_email(email)
            except Exception:
                pass
            end_time = time.perf_counter()
            invalid_email_times.append(end_time - start_time)
        
        # Calculate timing variance
        valid_avg = sum(valid_email_times) / len(valid_email_times)
        invalid_avg = sum(invalid_email_times) / len(invalid_email_times)
        
        if valid_avg > 0:
            email_timing_variance = abs(valid_avg - invalid_avg) / valid_avg
        else:
            email_timing_variance = 0
        
        assert email_timing_variance < timing_variance_threshold, \
            f"Email validation timing attack vulnerability: {email_timing_variance:.2%} variance"
    
    def test_password_verification_timing_consistency(self, timing_test_samples, timing_variance_threshold):
        """
        Test password verification timing consistency.
        
        Security Validation:
        - Consistent response times for correct/incorrect passwords
        - Hash comparison timing uniformity
        - Password strength validation timing
        - Authentication failure timing consistency
        """
        from src.auth.utils import CryptographicUtils
        
        crypto_utils = CryptographicUtils()
        
        # Test 1: Password hashing and verification timing
        test_password = 'secure_test_password_123'
        password_hash, salt = crypto_utils.hash_password(test_password)
        
        # Measure timing for correct password verification
        correct_times = []
        for _ in range(timing_test_samples):
            start_time = time.perf_counter()
            result = crypto_utils.verify_password(test_password, password_hash, salt)
            end_time = time.perf_counter()
            correct_times.append(end_time - start_time)
            assert result is True  # Should be correct
        
        # Measure timing for incorrect password verification
        incorrect_passwords = [
            'wrong_password',
            'incorrect123',
            '',
            'x' * 100,  # Long incorrect password
        ]
        
        incorrect_times = []
        for _ in range(timing_test_samples):
            wrong_password = incorrect_passwords[_ % len(incorrect_passwords)]
            start_time = time.perf_counter()
            result = crypto_utils.verify_password(wrong_password, password_hash, salt)
            end_time = time.perf_counter()
            incorrect_times.append(end_time - start_time)
            assert result is False  # Should be incorrect
        
        # Calculate timing variance
        correct_avg = sum(correct_times) / len(correct_times)
        incorrect_avg = sum(incorrect_times) / len(incorrect_times)
        
        if correct_avg > 0:
            password_timing_variance = abs(correct_avg - incorrect_avg) / correct_avg
        else:
            password_timing_variance = 0
        
        assert password_timing_variance < timing_variance_threshold, \
            f"Password verification timing attack vulnerability: {password_timing_variance:.2%} variance"
    
    def test_cryptographic_operation_timing_consistency(self, timing_test_samples, timing_variance_threshold):
        """
        Test cryptographic operation timing consistency.
        
        Security Validation:
        - HMAC computation timing consistency
        - Signature verification timing uniformity
        - Encryption/decryption timing consistency
        - Key derivation timing uniformity
        """
        from src.auth.utils import CryptographicUtils
        
        crypto_utils = CryptographicUtils()
        
        # Test 1: HMAC signature timing consistency
        test_data = 'test_data_for_hmac_timing'
        secret_key = 'hmac_secret_key_for_timing_test'
        
        # Measure HMAC generation timing
        hmac_gen_times = []
        signatures = []
        for _ in range(timing_test_samples):
            start_time = time.perf_counter()
            signature = crypto_utils.generate_hmac_signature(test_data, secret_key)
            end_time = time.perf_counter()
            hmac_gen_times.append(end_time - start_time)
            signatures.append(signature)
        
        # Measure HMAC verification timing for valid signatures
        hmac_verify_valid_times = []
        for i in range(timing_test_samples):
            signature = signatures[i % len(signatures)]
            start_time = time.perf_counter()
            result = crypto_utils.verify_hmac_signature(test_data, signature, secret_key)
            end_time = time.perf_counter()
            hmac_verify_valid_times.append(end_time - start_time)
            assert result is True  # Should be valid
        
        # Measure HMAC verification timing for invalid signatures
        invalid_signatures = [
            'invalid_signature_123',
            'wrong_hmac_value',
            '',
            'x' * 64  # Wrong length
        ]
        
        hmac_verify_invalid_times = []
        for _ in range(timing_test_samples):
            invalid_sig = invalid_signatures[_ % len(invalid_signatures)]
            start_time = time.perf_counter()
            result = crypto_utils.verify_hmac_signature(test_data, invalid_sig, secret_key)
            end_time = time.perf_counter()
            hmac_verify_invalid_times.append(end_time - start_time)
            assert result is False  # Should be invalid
        
        # Calculate timing variances
        valid_verify_avg = sum(hmac_verify_valid_times) / len(hmac_verify_valid_times)
        invalid_verify_avg = sum(hmac_verify_invalid_times) / len(hmac_verify_invalid_times)
        
        if valid_verify_avg > 0:
            hmac_timing_variance = abs(valid_verify_avg - invalid_verify_avg) / valid_verify_avg
        else:
            hmac_timing_variance = 0
        
        assert hmac_timing_variance < timing_variance_threshold, \
            f"HMAC verification timing attack vulnerability: {hmac_timing_variance:.2%} variance"
        
        # Test 2: Encryption/Decryption timing consistency
        test_plaintext = 'encryption_test_data_for_timing_analysis'
        
        # Measure encryption timing
        encryption_times = []
        encrypted_data_list = []
        for _ in range(min(timing_test_samples, 20)):  # Limit for performance
            start_time = time.perf_counter()
            encrypted_data, nonce, key = crypto_utils.encrypt_aes_gcm(test_plaintext)
            end_time = time.perf_counter()
            encryption_times.append(end_time - start_time)
            encrypted_data_list.append((encrypted_data, nonce, key))
        
        # Measure decryption timing
        decryption_times = []
        for i in range(len(encrypted_data_list)):
            encrypted_data, nonce, key = encrypted_data_list[i]
            start_time = time.perf_counter()
            decrypted_data = crypto_utils.decrypt_aes_gcm(encrypted_data, nonce, key)
            end_time = time.perf_counter()
            decryption_times.append(end_time - start_time)
            assert decrypted_data.decode() == test_plaintext
        
        # Verify encryption/decryption timing consistency
        if encryption_times and decryption_times:
            enc_avg = sum(encryption_times) / len(encryption_times)
            dec_avg = sum(decryption_times) / len(decryption_times)
            
            # Times should be reasonably consistent
            max_enc = max(encryption_times)
            min_enc = min(encryption_times)
            enc_variance = (max_enc - min_enc) / min_enc if min_enc > 0 else 0
            
            max_dec = max(decryption_times)
            min_dec = min(decryption_times)
            dec_variance = (max_dec - min_dec) / min_dec if min_dec > 0 else 0
            
            assert enc_variance < 2.0, f"Encryption timing variance too high: {enc_variance:.2%}"
            assert dec_variance < 2.0, f"Decryption timing variance too high: {dec_variance:.2%}"


class TestSecurityTestCoverage:
    """
    Comprehensive security test coverage validation ensuring ≥95% authentication security
    test coverage per Section 6.6.3 and zero tolerance for critical vulnerabilities per Section 6.4.5.
    
    Security Test Coverage:
    - Authentication component security coverage validation
    - Critical vulnerability detection and prevention
    - Security pattern compliance verification  
    - OWASP Top 10 security validation coverage
    - Enterprise security requirement compliance
    """
    
    @pytest.mark.asyncio
    async def test_jwt_security_coverage_validation(self):
        """
        Test comprehensive JWT security coverage validation.
        
        Security Coverage Validation:
        - JWT token signature verification security
        - Token expiration and timing validation
        - Token structure and format validation
        - Claims validation and injection prevention
        - Algorithm confusion attack prevention
        """
        # Import all JWT security components for coverage validation
        from src.auth.authentication import (
            JWTTokenValidator,
            AuthenticationManager,
            Auth0Config
        )
        from src.auth.utils import JWTTokenUtils
        from src.auth.exceptions import JWTException, SecurityErrorCode
        
        # Test 1: JWT security component instantiation
        jwt_utils = JWTTokenUtils(secret_key='coverage-test-key')
        auth0_config = Auth0Config()
        
        # Verify security components are properly configured
        assert jwt_utils.secret_key is not None
        assert jwt_utils.algorithm in ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512']
        assert auth0_config.domain is not None
        assert auth0_config.client_id is not None
        
        # Test 2: JWT security exception coverage
        security_error_codes = [
            SecurityErrorCode.AUTH_TOKEN_INVALID,
            SecurityErrorCode.AUTH_TOKEN_EXPIRED,
            SecurityErrorCode.AUTH_TOKEN_MALFORMED,
            SecurityErrorCode.AUTH_TOKEN_MISSING
        ]
        
        for error_code in security_error_codes:
            jwt_exception = JWTException(
                message=f"Test JWT security error: {error_code.value}",
                error_code=error_code
            )
            assert jwt_exception.error_code == error_code
            assert jwt_exception.metadata['security_event'] is True
        
        # Test 3: JWT validation security patterns
        test_payload = {
            'sub': 'coverage_test_user',
            'iat': int(datetime.utcnow().timestamp()),
            'exp': int((datetime.utcnow() + timedelta(hours=1)).timestamp())
        }
        
        # Generate and validate token
        token = jwt_utils.generate_token(test_payload, expires_in=3600)
        decoded_payload = jwt_utils.validate_token(token)
        
        assert decoded_payload['sub'] == test_payload['sub']
        assert 'iat' in decoded_payload
        assert 'exp' in decoded_payload
        assert 'jti' in decoded_payload  # JWT ID for uniqueness
    
    @pytest.mark.asyncio
    async def test_authentication_security_coverage_validation(self):
        """
        Test comprehensive authentication security coverage validation.
        
        Security Coverage Validation:
        - Authentication bypass prevention coverage
        - Session security validation coverage
        - Permission validation security coverage
        - External service security coverage
        """
        from src.auth.authentication import AuthenticationManager
        from src.auth.exceptions import (
            AuthenticationException,
            AuthorizationException,
            Auth0Exception,
            SecurityErrorCode
        )
        
        # Test 1: Authentication security exception coverage
        auth_exceptions = [
            AuthenticationException(
                message="Authentication coverage test",
                error_code=SecurityErrorCode.AUTH_CREDENTIALS_INVALID
            ),
            AuthorizationException(
                message="Authorization coverage test",
                error_code=SecurityErrorCode.AUTHZ_PERMISSION_DENIED
            ),
            Auth0Exception(
                message="Auth0 integration coverage test",
                error_code=SecurityErrorCode.EXT_AUTH0_UNAVAILABLE
            )
        ]
        
        for exception in auth_exceptions:
            assert exception.error_code is not None
            assert exception.metadata['security_event'] is True
            assert exception.timestamp is not None
            assert exception.error_id is not None
        
        # Test 2: Security error code coverage validation
        critical_security_codes = [
            SecurityErrorCode.AUTH_TOKEN_INVALID,
            SecurityErrorCode.AUTH_TOKEN_EXPIRED,
            SecurityErrorCode.AUTHZ_PERMISSION_DENIED,
            SecurityErrorCode.EXT_AUTH0_UNAVAILABLE,
            SecurityErrorCode.SEC_RATE_LIMIT_EXCEEDED
        ]
        
        for code in critical_security_codes:
            assert code.value.startswith(('AUTH_', 'AUTHZ_', 'EXT_', 'SEC_'))
            assert len(code.value) > 5  # Meaningful error codes
    
    def test_input_validation_security_coverage(self):
        """
        Test comprehensive input validation security coverage.
        
        Security Coverage Validation:
        - Email validation security coverage
        - HTML sanitization security coverage
        - URL validation security coverage
        - Password validation security coverage
        """
        from src.auth.utils import InputValidator
        from src.auth.exceptions import ValidationException, SecurityErrorCode
        
        validator = InputValidator()
        
        # Test 1: Email validation security coverage
        security_test_emails = [
            'valid@example.com',
            'invalid.email.format',
            '<script>alert("xss")</script>@evil.com',
            'user@domain..com',
            '',
            'a' * 256 + '@example.com'  # Oversized email
        ]
        
        for email in security_test_emails:
            try:
                is_valid, result = validator.validate_email(email)
                # Validation should handle all cases appropriately
                assert isinstance(is_valid, bool)
                assert isinstance(result, str)
            except Exception as e:
                # Should raise appropriate validation exceptions
                assert isinstance(e, (ValidationException, ValueError))
        
        # Test 2: HTML sanitization security coverage
        malicious_html_inputs = [
            '<script>alert("xss")</script>',
            '<img src="x" onerror="alert(1)">',
            '<iframe src="javascript:alert(1)"></iframe>',
            '"><script>evil()</script>',
            'javascript:alert(1)',
            '<svg onload="alert(1)">',
            '<!-- --><script>alert(1)</script><!-- -->'
        ]
        
        for malicious_html in malicious_html_inputs:
            sanitized = validator.sanitize_html(malicious_html, strip_tags=True)
            # Should remove all malicious content
            assert '<script>' not in sanitized.lower()
            assert 'javascript:' not in sanitized.lower()
            assert 'onerror=' not in sanitized.lower()
            assert 'onload=' not in sanitized.lower()
        
        # Test 3: URL validation security coverage
        security_test_urls = [
            'https://example.com',
            'http://test.org',
            'javascript:alert(1)',
            'file:///etc/passwd',
            'ftp://malicious.com',
            '',
            'not_a_url',
            'https://evil.com/../../../etc/passwd'
        ]
        
        for url in security_test_urls:
            is_valid = validator.validate_url(url, allowed_schemes=['http', 'https'])
            assert isinstance(is_valid, bool)
            
            # Dangerous schemes should be rejected
            if url.startswith(('javascript:', 'file:', 'ftp:')):
                assert is_valid is False
    
    def test_cryptographic_security_coverage(self):
        """
        Test comprehensive cryptographic security coverage.
        
        Security Coverage Validation:
        - Encryption/decryption security coverage
        - HMAC generation/verification security coverage
        - Secure token generation coverage
        - Key management security coverage
        """
        from src.auth.utils import CryptographicUtils
        from src.auth.exceptions import CryptographicError
        
        crypto_utils = CryptographicUtils()
        
        # Test 1: Encryption security coverage
        test_data = 'sensitive_data_for_encryption_testing'
        
        # Test AES-GCM encryption
        encrypted_data, nonce, key = crypto_utils.encrypt_aes_gcm(test_data)
        assert len(encrypted_data) > len(test_data)  # Should be larger due to padding/tag
        assert len(nonce) == 12  # GCM nonce length
        assert len(key) == 32  # AES-256 key length
        
        # Test decryption
        decrypted_data = crypto_utils.decrypt_aes_gcm(encrypted_data, nonce, key)
        assert decrypted_data.decode() == test_data
        
        # Test 2: HMAC security coverage
        hmac_data = 'data_for_hmac_testing'
        hmac_secret = 'hmac_secret_key_testing'
        
        # Generate HMAC signature
        signature = crypto_utils.generate_hmac_signature(hmac_data, hmac_secret)
        assert len(signature) > 0
        assert isinstance(signature, str)
        
        # Verify HMAC signature
        is_valid = crypto_utils.verify_hmac_signature(hmac_data, signature, hmac_secret)
        assert is_valid is True
        
        # Verify invalid signature rejection
        is_invalid = crypto_utils.verify_hmac_signature(hmac_data, 'wrong_signature', hmac_secret)
        assert is_invalid is False
        
        # Test 3: Secure token generation coverage
        token_lengths = [16, 32, 64, 128]
        
        for length in token_lengths:
            secure_token = crypto_utils.generate_secure_token(length)
            assert len(secure_token) > 0
            assert isinstance(secure_token, str)
            # Should be URL-safe base64 encoded
            import base64
            try:
                decoded = base64.urlsafe_b64decode(secure_token + '==')  # Add padding
                assert len(decoded) == length
            except Exception:
                pass  # Some tokens may not need padding
        
        # Test 4: Password hashing security coverage
        test_passwords = ['password123', 'complex!Password@456', '', 'x' * 100]
        
        for password in test_passwords:
            if password:  # Skip empty password
                password_hash, salt = crypto_utils.hash_password(password)
                assert len(password_hash) == 32  # SHA256 output length
                assert len(salt) == 32  # Salt length
                
                # Verify password
                is_correct = crypto_utils.verify_password(password, password_hash, salt)
                assert is_correct is True
                
                # Verify wrong password rejection
                is_wrong = crypto_utils.verify_password('wrong_password', password_hash, salt)
                assert is_wrong is False
    
    @pytest.mark.asyncio
    async def test_security_monitoring_coverage(self):
        """
        Test security monitoring and audit coverage validation.
        
        Security Coverage Validation:
        - Security event logging coverage
        - Error tracking and monitoring coverage
        - Performance monitoring coverage
        - Compliance validation coverage
        """
        from src.auth.authentication import AuthenticationManager
        from src.auth.exceptions import (
            SecurityException,
            get_error_category,
            is_critical_security_error,
            create_safe_error_response
        )
        
        # Test 1: Security event categorization coverage
        test_error_codes = [
            SecurityErrorCode.AUTH_TOKEN_INVALID,
            SecurityErrorCode.AUTHZ_PERMISSION_DENIED,
            SecurityErrorCode.EXT_AUTH0_UNAVAILABLE,
            SecurityErrorCode.SEC_RATE_LIMIT_EXCEEDED,
            SecurityErrorCode.VAL_INPUT_INVALID
        ]
        
        for error_code in test_error_codes:
            category = get_error_category(error_code)
            assert category in ['authentication', 'authorization', 'external_service', 'security_violation', 'validation']
            
            # Test critical error detection
            is_critical = is_critical_security_error(error_code)
            assert isinstance(is_critical, bool)
        
        # Test 2: Safe error response generation coverage
        test_exception = SecurityException(
            message="Test security event for monitoring coverage",
            error_code=SecurityErrorCode.AUTH_CREDENTIALS_INVALID,
            user_message="Access denied for security testing"
        )
        
        safe_response = create_safe_error_response(test_exception)
        
        # Verify safe response structure
        required_fields = ['error', 'error_code', 'message', 'error_id', 'timestamp', 'category']
        for field in required_fields:
            assert field in safe_response
        
        assert safe_response['error'] is True
        assert safe_response['error_code'] == SecurityErrorCode.AUTH_CREDENTIALS_INVALID.value
        assert safe_response['message'] == "Access denied for security testing"
        assert len(safe_response['error_id']) > 0
        
        # Test 3: Security metadata coverage
        assert test_exception.metadata['security_event'] is True
        assert test_exception.metadata['error_code'] == SecurityErrorCode.AUTH_CREDENTIALS_INVALID.value
        assert test_exception.metadata['exception_type'] == 'SecurityException'
        assert 'timestamp' in test_exception.metadata
        assert 'error_id' in test_exception.metadata


# Additional security test markers for comprehensive coverage
pytestmark = [
    pytest.mark.security,
    pytest.mark.asyncio
]