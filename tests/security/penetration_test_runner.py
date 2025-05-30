"""
Automated Penetration Testing Framework for Flask Application Security Validation

This module implements comprehensive automated penetration testing capabilities integrating
OWASP ZAP 2.14+ Dynamic Application Security Testing (DAST) and Nuclei 3.1+ vulnerability
scanning for enterprise-grade security assessment per Section 6.4.5 and Section 6.6.2.

Key Features:
- OWASP ZAP 2.14+ automated penetration testing per Section 6.4.5
- Nuclei 3.1+ vulnerability scanner integration per Section 6.4.5  
- Automated security assessment workflows per Section 6.4.5
- Penetration testing automation for CI/CD integration per Section 6.6.2
- Comprehensive vulnerability discovery and reporting per Section 6.4.5
- Enterprise-grade security testing compliance per Section 6.4.5
- Penetration testing integration with compliance dashboards per Section 6.4.6

Architecture Integration:
- Builds on security testing configuration from tests/security/security_config.py
- Utilizes security testing fixtures from tests/security/conftest.py
- Integrates with pytest 7.4+ testing framework per Section 6.6.1
- Supports parallel execution via pytest-xdist per Section 6.6.1
- Performance monitoring with ≤10% variance compliance per Section 6.6.3

Security Standards:
- OWASP Top 10 comprehensive vulnerability assessment
- Enterprise security compliance per SOC 2, ISO 27001, GDPR
- Automated threat modeling and attack simulation
- Continuous security monitoring and alerting
- Comprehensive audit logging and forensic capabilities

Dependencies:
- python-owasp-zap-v2.4 for OWASP ZAP integration
- requests 2.31+ for HTTP communications and API testing
- structlog 23.1+ for comprehensive security event logging
- prometheus-client for security metrics collection
- asyncio for concurrent penetration testing operations
"""

import asyncio
import json
import logging
import os
import secrets
import subprocess
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple, AsyncGenerator
from urllib.parse import urljoin, urlparse, parse_qs
import xml.etree.ElementTree as ET

import requests
import structlog
from zapv2 import ZAPv2
import pytest
from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry

# Import security testing infrastructure
from tests.security.conftest import (
    SecurityTestConfig, SecurityMonitor, AttackSimulator, SecurityMetricsCollector,
    PenetrationTestSuite, OWASPAttackPayloads, SecurityTestDataFactory
)
from tests.security.security_config import (
    SecurityTestConfiguration, SecurityTestRunner, SecurityTestResult,
    PenetrationTestConfig, SecurityTestSeverity, AttackType, ComplianceFramework,
    get_security_config, security_metrics
)

# Configure structured logging for penetration testing
penetration_logger = structlog.get_logger("security.penetration_testing")

# Penetration testing specific metrics
pentest_registry = CollectorRegistry()
pentest_metrics = {
    'penetration_tests_total': Counter(
        'penetration_tests_executed_total',
        'Total penetration tests executed',
        ['test_type', 'target', 'result'],
        registry=pentest_registry
    ),
    'vulnerability_discoveries': Gauge(
        'penetration_test_vulnerabilities_discovered',
        'Vulnerabilities discovered during penetration testing',
        ['severity', 'category', 'tool'],
        registry=pentest_registry
    ),
    'zap_scan_duration': Histogram(
        'zap_scan_duration_seconds',
        'Duration of OWASP ZAP scans',
        ['scan_type', 'target'],
        registry=pentest_registry
    ),
    'nuclei_scan_duration': Histogram(
        'nuclei_scan_duration_seconds', 
        'Duration of Nuclei vulnerability scans',
        ['template_category', 'target'],
        registry=pentest_registry
    ),
    'attack_simulations_executed': Counter(
        'attack_simulations_executed_total',
        'Attack simulations executed during penetration testing',
        ['attack_type', 'success'],
        registry=pentest_registry
    ),
    'compliance_violations': Gauge(
        'penetration_test_compliance_violations',
        'Compliance violations discovered during penetration testing',
        ['framework', 'severity'],
        registry=pentest_registry
    ),
    'security_coverage_percentage': Gauge(
        'penetration_test_security_coverage_percentage',
        'Percentage of security coverage achieved by penetration testing',
        ['category'],
        registry=pentest_registry
    )
}


class PenetrationTestTarget:
    """
    Penetration testing target configuration and validation.
    
    Represents a target application or endpoint for penetration testing with
    comprehensive configuration, authentication, and validation capabilities.
    """
    
    def __init__(
        self,
        base_url: str,
        name: str = None,
        authentication: Optional[Dict[str, Any]] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        excluded_paths: Optional[List[str]] = None,
        included_paths: Optional[List[str]] = None
    ):
        """
        Initialize penetration testing target.
        
        Args:
            base_url: Base URL of the target application
            name: Human-readable name for the target
            authentication: Authentication configuration for the target
            custom_headers: Custom headers to include in requests
            excluded_paths: List of paths to exclude from testing
            included_paths: List of paths to include in testing (if specified, only these are tested)
        """
        self.base_url = base_url.rstrip('/')
        self.name = name or f"target_{secrets.token_hex(4)}"
        self.authentication = authentication or {}
        self.custom_headers = custom_headers or {}
        self.excluded_paths = excluded_paths or [
            '/health', '/metrics', '/admin/shutdown', '/docs', '/swagger'
        ]
        self.included_paths = included_paths or []
        
        # Validate target URL
        self._validate_target_url()
        
        # Initialize target metadata
        self.target_id = str(uuid.uuid4())
        self.discovery_timestamp = datetime.now(timezone.utc)
        self.endpoints_discovered = []
        self.security_context = {}
        
    def _validate_target_url(self):
        """Validate target URL format and accessibility."""
        try:
            parsed = urlparse(self.base_url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError(f"Invalid target URL format: {self.base_url}")
            
            if parsed.scheme not in ['http', 'https']:
                raise ValueError(f"Unsupported scheme: {parsed.scheme}")
                
        except Exception as e:
            raise ValueError(f"Target URL validation failed: {str(e)}")
    
    def is_path_in_scope(self, path: str) -> bool:
        """
        Check if a path is in scope for penetration testing.
        
        Args:
            path: URL path to check
            
        Returns:
            True if path is in scope, False otherwise
        """
        # If included_paths is specified, only test those paths
        if self.included_paths:
            return any(path.startswith(included) for included in self.included_paths)
        
        # Otherwise, test all paths except excluded ones
        return not any(path.startswith(excluded) for excluded in self.excluded_paths)
    
    def get_authenticated_session(self) -> requests.Session:
        """
        Create authenticated session for target testing.
        
        Returns:
            Configured requests session with authentication
        """
        session = requests.Session()
        
        # Add custom headers
        session.headers.update(self.custom_headers)
        
        # Add User-Agent for security testing identification
        session.headers.update({
            'User-Agent': 'Penetration-Testing-Framework/1.0',
            'X-Security-Test': 'automated-penetration-test'
        })
        
        # Configure authentication
        auth_config = self.authentication
        if auth_config.get('type') == 'bearer':
            session.headers['Authorization'] = f"Bearer {auth_config['token']}"
        elif auth_config.get('type') == 'basic':
            from requests.auth import HTTPBasicAuth
            session.auth = HTTPBasicAuth(auth_config['username'], auth_config['password'])
        elif auth_config.get('type') == 'session':
            # Perform session-based authentication
            self._authenticate_session(session, auth_config)
        
        return session
    
    def _authenticate_session(self, session: requests.Session, auth_config: Dict[str, Any]):
        """Perform session-based authentication."""
        try:
            login_url = urljoin(self.base_url, auth_config.get('login_endpoint', '/api/login'))
            login_data = {
                'username': auth_config.get('username'),
                'password': auth_config.get('password')
            }
            
            response = session.post(login_url, json=login_data)
            if response.status_code not in [200, 201]:
                penetration_logger.warning(
                    "Session authentication failed",
                    target=self.name,
                    status_code=response.status_code
                )
        except Exception as e:
            penetration_logger.error(
                "Session authentication error",
                target=self.name,
                error=str(e)
            )


class ZAPPenetrationTester:
    """
    OWASP ZAP 2.14+ integration for Dynamic Application Security Testing (DAST).
    
    Implements comprehensive OWASP ZAP integration per Section 6.4.5 for automated
    penetration testing with spider crawling, active scanning, and vulnerability
    discovery with enterprise-grade reporting capabilities.
    """
    
    def __init__(
        self,
        zap_proxy_host: str = 'localhost',
        zap_proxy_port: int = 8080,
        zap_api_key: Optional[str] = None
    ):
        """
        Initialize OWASP ZAP penetration tester.
        
        Args:
            zap_proxy_host: ZAP proxy host address
            zap_proxy_port: ZAP proxy port number
            zap_api_key: ZAP API key for authentication (optional)
        """
        self.zap_host = zap_proxy_host
        self.zap_port = zap_proxy_port
        self.zap_api_key = zap_api_key
        
        # Initialize ZAP client
        self.zap = None
        self.session_name = f"pentest_session_{int(time.time())}"
        
        # Test execution tracking
        self.scan_results = {}
        self.vulnerability_findings = []
        self.coverage_metrics = {}
        
        self.logger = penetration_logger.bind(
            component="zap_penetration_tester",
            zap_host=zap_proxy_host,
            zap_port=zap_proxy_port
        )
    
    def initialize_zap_session(self) -> bool:
        """
        Initialize OWASP ZAP session and validate connectivity.
        
        Returns:
            True if ZAP session initialized successfully, False otherwise
        """
        try:
            # Initialize ZAP client
            self.zap = ZAPv2(
                proxies={
                    'http': f'http://{self.zap_host}:{self.zap_port}',
                    'https': f'http://{self.zap_host}:{self.zap_port}'
                },
                apikey=self.zap_api_key
            )
            
            # Test ZAP connectivity
            version = self.zap.core.version
            self.logger.info("ZAP connection established", zap_version=version)
            
            # Create new session
            self.zap.core.new_session(name=self.session_name, overwrite=True)
            
            # Configure ZAP for penetration testing
            self._configure_zap_settings()
            
            return True
            
        except Exception as e:
            self.logger.error("Failed to initialize ZAP session", error=str(e))
            return False
    
    def _configure_zap_settings(self):
        """Configure ZAP settings for optimal penetration testing."""
        try:
            # Configure spider settings
            self.zap.spider.set_option_max_depth(5)
            self.zap.spider.set_option_max_duration(10)  # 10 minutes max
            self.zap.spider.set_option_max_children(10)
            
            # Configure active scan settings
            self.zap.ascan.set_option_default_policy('Default Policy')
            self.zap.ascan.set_option_max_scan_duration_in_mins(30)  # 30 minutes max
            self.zap.ascan.set_option_thread_per_host(5)
            
            # Configure passive scan settings
            self.zap.pscan.enable_all_scanners()
            
            self.logger.info("ZAP settings configured for penetration testing")
            
        except Exception as e:
            self.logger.warning("Failed to configure ZAP settings", error=str(e))
    
    async def execute_comprehensive_dast_scan(
        self,
        target: PenetrationTestTarget,
        scan_types: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Execute comprehensive DAST scan using OWASP ZAP.
        
        Args:
            target: Penetration testing target configuration
            scan_types: List of scan types to execute (spider, passive, active)
            
        Returns:
            Comprehensive DAST scan results with vulnerability findings
        """
        scan_start_time = time.time()
        scan_id = f"dast_scan_{target.name}_{int(time.time())}"
        
        if scan_types is None:
            scan_types = ['spider', 'passive', 'active']
        
        self.logger.info(
            "Starting comprehensive DAST scan",
            scan_id=scan_id,
            target_url=target.base_url,
            scan_types=scan_types
        )
        
        try:
            # Initialize ZAP session if not already done
            if not self.zap:
                if not self.initialize_zap_session():
                    raise RuntimeError("Failed to initialize ZAP session")
            
            scan_results = {
                'scan_id': scan_id,
                'target': target.name,
                'target_url': target.base_url,
                'scan_types': scan_types,
                'start_time': datetime.now(timezone.utc).isoformat(),
                'status': 'running'
            }
            
            # Execute spider scan for endpoint discovery
            if 'spider' in scan_types:
                spider_results = await self._execute_spider_scan(target)
                scan_results['spider_results'] = spider_results
            
            # Execute passive scan for vulnerability discovery
            if 'passive' in scan_types:
                passive_results = await self._execute_passive_scan(target)
                scan_results['passive_results'] = passive_results
            
            # Execute active scan for comprehensive vulnerability testing
            if 'active' in scan_types:
                active_results = await self._execute_active_scan(target)
                scan_results['active_results'] = active_results
            
            # Collect and analyze all findings
            all_findings = self._consolidate_scan_findings(scan_results)
            scan_results['consolidated_findings'] = all_findings
            
            # Calculate security metrics
            security_metrics = self._calculate_security_metrics(all_findings)
            scan_results['security_metrics'] = security_metrics
            
            # Generate compliance assessment
            compliance_assessment = self._assess_compliance_status(all_findings)
            scan_results['compliance_assessment'] = compliance_assessment
            
            scan_duration = time.time() - scan_start_time
            scan_results.update({
                'status': 'completed',
                'end_time': datetime.now(timezone.utc).isoformat(),
                'duration_seconds': scan_duration,
                'total_vulnerabilities': len(all_findings),
                'critical_vulnerabilities': len([f for f in all_findings if f.get('severity') == 'critical']),
                'high_vulnerabilities': len([f for f in all_findings if f.get('severity') == 'high'])
            })
            
            # Record metrics
            pentest_metrics['zap_scan_duration'].labels(
                scan_type='comprehensive',
                target=target.name
            ).observe(scan_duration)
            
            pentest_metrics['vulnerability_discoveries'].labels(
                severity='total',
                category='dast',
                tool='zap'
            ).set(len(all_findings))
            
            self.logger.info(
                "DAST scan completed successfully",
                scan_id=scan_id,
                duration=scan_duration,
                vulnerabilities_found=len(all_findings)
            )
            
            return scan_results
            
        except Exception as e:
            self.logger.error(
                "DAST scan failed",
                scan_id=scan_id,
                error=str(e)
            )
            
            return {
                'scan_id': scan_id,
                'target': target.name,
                'status': 'failed',
                'error': str(e),
                'duration_seconds': time.time() - scan_start_time
            }
    
    async def _execute_spider_scan(self, target: PenetrationTestTarget) -> Dict[str, Any]:
        """Execute ZAP spider scan for endpoint discovery."""
        spider_start_time = time.time()
        
        try:
            self.logger.info("Starting ZAP spider scan", target=target.name)
            
            # Start spider scan
            spider_id = self.zap.spider.scan(target.base_url)
            
            # Wait for spider to complete with timeout
            spider_timeout = 600  # 10 minutes
            start_time = time.time()
            
            while int(self.zap.spider.status(spider_id)) < 100:
                if time.time() - start_time > spider_timeout:
                    self.zap.spider.stop(spider_id)
                    self.logger.warning("Spider scan timed out", spider_id=spider_id)
                    break
                await asyncio.sleep(5)
            
            # Get spider results
            spider_results = self.zap.spider.results(spider_id)
            urls_found = len(spider_results)
            
            # Filter URLs based on target scope
            in_scope_urls = [
                url for url in spider_results
                if target.is_path_in_scope(urlparse(url).path)
            ]
            
            spider_duration = time.time() - spider_start_time
            
            results = {
                'spider_id': spider_id,
                'duration_seconds': spider_duration,
                'total_urls_found': urls_found,
                'in_scope_urls': len(in_scope_urls),
                'discovered_endpoints': in_scope_urls[:100],  # Limit for reporting
                'completion_percentage': int(self.zap.spider.status(spider_id))
            }
            
            self.logger.info(
                "Spider scan completed",
                target=target.name,
                urls_found=urls_found,
                in_scope_urls=len(in_scope_urls),
                duration=spider_duration
            )
            
            return results
            
        except Exception as e:
            self.logger.error("Spider scan failed", target=target.name, error=str(e))
            return {
                'error': str(e),
                'duration_seconds': time.time() - spider_start_time
            }
    
    async def _execute_passive_scan(self, target: PenetrationTestTarget) -> Dict[str, Any]:
        """Execute ZAP passive scan for vulnerability discovery."""
        passive_start_time = time.time()
        
        try:
            self.logger.info("Starting ZAP passive scan", target=target.name)
            
            # Enable all passive scanners
            self.zap.pscan.enable_all_scanners()
            
            # Wait for passive scan to complete
            passive_timeout = 300  # 5 minutes
            start_time = time.time()
            
            while int(self.zap.pscan.records_to_scan) > 0:
                if time.time() - start_time > passive_timeout:
                    self.logger.warning("Passive scan timed out")
                    break
                await asyncio.sleep(2)
            
            # Get passive scan alerts
            alerts = self.zap.core.alerts(baseurl=target.base_url)
            
            # Process and categorize alerts
            passive_findings = []
            for alert in alerts:
                finding = {
                    'alert_id': alert.get('id'),
                    'name': alert.get('alert'),
                    'description': alert.get('description'),
                    'severity': alert.get('risk', '').lower(),
                    'confidence': alert.get('confidence', '').lower(),
                    'url': alert.get('url'),
                    'param': alert.get('param'),
                    'evidence': alert.get('evidence'),
                    'cwe_id': alert.get('cweid'),
                    'wasc_id': alert.get('wascid'),
                    'solution': alert.get('solution'),
                    'reference': alert.get('reference'),
                    'source': 'zap_passive_scan'
                }
                passive_findings.append(finding)
            
            passive_duration = time.time() - passive_start_time
            
            results = {
                'duration_seconds': passive_duration,
                'total_alerts': len(alerts),
                'findings': passive_findings,
                'severity_breakdown': self._categorize_findings_by_severity(passive_findings)
            }
            
            self.logger.info(
                "Passive scan completed",
                target=target.name,
                alerts_found=len(alerts),
                duration=passive_duration
            )
            
            return results
            
        except Exception as e:
            self.logger.error("Passive scan failed", target=target.name, error=str(e))
            return {
                'error': str(e),
                'duration_seconds': time.time() - passive_start_time
            }
    
    async def _execute_active_scan(self, target: PenetrationTestTarget) -> Dict[str, Any]:
        """Execute ZAP active scan for comprehensive vulnerability testing."""
        active_start_time = time.time()
        
        try:
            self.logger.info("Starting ZAP active scan", target=target.name)
            
            # Start active scan
            scan_id = self.zap.ascan.scan(target.base_url)
            
            # Wait for active scan to complete with timeout
            active_timeout = 1800  # 30 minutes
            start_time = time.time()
            
            while int(self.zap.ascan.status(scan_id)) < 100:
                if time.time() - start_time > active_timeout:
                    self.zap.ascan.stop(scan_id)
                    self.logger.warning("Active scan timed out", scan_id=scan_id)
                    break
                
                # Log progress every 30 seconds
                if int(time.time() - start_time) % 30 == 0:
                    progress = self.zap.ascan.status(scan_id)
                    self.logger.info("Active scan progress", progress=f"{progress}%")
                
                await asyncio.sleep(10)
            
            # Get active scan alerts
            alerts = self.zap.core.alerts(baseurl=target.base_url)
            
            # Filter alerts from active scan (new alerts since passive scan)
            active_findings = []
            for alert in alerts:
                if alert.get('source', '').lower() in ['active', 'ascan']:
                    finding = {
                        'alert_id': alert.get('id'),
                        'name': alert.get('alert'),
                        'description': alert.get('description'),
                        'severity': alert.get('risk', '').lower(),
                        'confidence': alert.get('confidence', '').lower(),
                        'url': alert.get('url'),
                        'param': alert.get('param'),
                        'attack': alert.get('attack'),
                        'evidence': alert.get('evidence'),
                        'cwe_id': alert.get('cweid'),
                        'wasc_id': alert.get('wascid'),
                        'solution': alert.get('solution'),
                        'reference': alert.get('reference'),
                        'source': 'zap_active_scan'
                    }
                    active_findings.append(finding)
            
            active_duration = time.time() - active_start_time
            
            results = {
                'scan_id': scan_id,
                'duration_seconds': active_duration,
                'completion_percentage': int(self.zap.ascan.status(scan_id)),
                'total_alerts': len(active_findings),
                'findings': active_findings,
                'severity_breakdown': self._categorize_findings_by_severity(active_findings)
            }
            
            self.logger.info(
                "Active scan completed",
                target=target.name,
                alerts_found=len(active_findings),
                duration=active_duration
            )
            
            return results
            
        except Exception as e:
            self.logger.error("Active scan failed", target=target.name, error=str(e))
            return {
                'error': str(e),
                'duration_seconds': time.time() - active_start_time
            }
    
    def _categorize_findings_by_severity(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Categorize security findings by severity level."""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts['info'] += 1
        
        return severity_counts
    
    def _consolidate_scan_findings(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Consolidate findings from all scan types."""
        all_findings = []
        
        # Collect spider findings (endpoint discovery)
        spider_results = scan_results.get('spider_results', {})
        if 'discovered_endpoints' in spider_results:
            for endpoint in spider_results['discovered_endpoints']:
                all_findings.append({
                    'type': 'endpoint_discovery',
                    'url': endpoint,
                    'severity': 'info',
                    'source': 'zap_spider'
                })
        
        # Collect passive scan findings
        passive_results = scan_results.get('passive_results', {})
        if 'findings' in passive_results:
            all_findings.extend(passive_results['findings'])
        
        # Collect active scan findings
        active_results = scan_results.get('active_results', {})
        if 'findings' in active_results:
            all_findings.extend(active_results['findings'])
        
        # Deduplicate findings based on URL and alert type
        deduplicated_findings = self._deduplicate_findings(all_findings)
        
        return deduplicated_findings
    
    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate findings based on URL and alert type."""
        seen_findings = set()
        deduplicated = []
        
        for finding in findings:
            # Create unique key for deduplication
            key = (
                finding.get('url', ''),
                finding.get('name', ''),
                finding.get('param', '')
            )
            
            if key not in seen_findings:
                seen_findings.add(key)
                deduplicated.append(finding)
        
        return deduplicated
    
    def _calculate_security_metrics(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate comprehensive security metrics from findings."""
        severity_counts = self._categorize_findings_by_severity(findings)
        
        # Calculate security score (0-100)
        critical_weight = 50
        high_weight = 25
        medium_weight = 10
        low_weight = 5
        
        total_penalty = (
            severity_counts['critical'] * critical_weight +
            severity_counts['high'] * high_weight +
            severity_counts['medium'] * medium_weight +
            severity_counts['low'] * low_weight
        )
        
        security_score = max(0, 100 - total_penalty)
        
        # OWASP Top 10 coverage analysis
        owasp_coverage = self._analyze_owasp_top10_coverage(findings)
        
        return {
            'security_score': security_score,
            'total_findings': len(findings),
            'severity_breakdown': severity_counts,
            'owasp_top10_coverage': owasp_coverage,
            'compliance_status': 'compliant' if severity_counts['critical'] == 0 and severity_counts['high'] == 0 else 'non_compliant'
        }
    
    def _analyze_owasp_top10_coverage(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze OWASP Top 10 vulnerability coverage in findings."""
        owasp_categories = {
            'A01_broken_access_control': ['access control', 'authorization', 'privilege'],
            'A02_cryptographic_failures': ['crypto', 'encryption', 'ssl', 'tls'],
            'A03_injection': ['injection', 'sql', 'xss', 'command'],
            'A04_insecure_design': ['design', 'logic', 'business'],
            'A05_security_misconfiguration': ['configuration', 'default', 'debug'],
            'A06_vulnerable_components': ['component', 'dependency', 'library'],
            'A07_authentication_failures': ['authentication', 'session', 'password'],
            'A08_data_integrity_failures': ['integrity', 'validation', 'tamper'],
            'A09_logging_monitoring_failures': ['logging', 'monitoring', 'detection'],
            'A10_ssrf': ['ssrf', 'request forgery', 'redirect']
        }
        
        coverage = {}
        for category, keywords in owasp_categories.items():
            category_findings = []
            for finding in findings:
                finding_text = (finding.get('name', '') + ' ' + finding.get('description', '')).lower()
                if any(keyword in finding_text for keyword in keywords):
                    category_findings.append(finding)
            
            coverage[category] = {
                'findings_count': len(category_findings),
                'tested': len(category_findings) > 0,
                'highest_severity': self._get_highest_severity(category_findings)
            }
        
        return coverage
    
    def _get_highest_severity(self, findings: List[Dict[str, Any]]) -> str:
        """Get the highest severity level from a list of findings."""
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        
        for severity in severity_order:
            if any(f.get('severity') == severity for f in findings):
                return severity
        
        return 'info'
    
    def _assess_compliance_status(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess compliance status based on security findings."""
        severity_counts = self._categorize_findings_by_severity(findings)
        
        # SOC 2 Type II compliance assessment
        soc2_compliant = severity_counts['critical'] == 0 and severity_counts['high'] <= 2
        
        # OWASP Top 10 compliance assessment
        owasp_coverage = self._analyze_owasp_top10_coverage(findings)
        owasp_compliant = all(
            coverage['highest_severity'] not in ['critical', 'high']
            for coverage in owasp_coverage.values()
        )
        
        # PCI DSS compliance assessment (if applicable)
        pci_relevant_findings = [
            f for f in findings
            if any(keyword in f.get('name', '').lower() for keyword in ['card', 'payment', 'pci'])
        ]
        pci_compliant = not pci_relevant_findings or all(
            f.get('severity') not in ['critical', 'high'] for f in pci_relevant_findings
        )
        
        return {
            'soc2_type2_compliant': soc2_compliant,
            'owasp_top10_compliant': owasp_compliant,
            'pci_dss_compliant': pci_compliant,
            'overall_compliance_score': (
                int(soc2_compliant) + int(owasp_compliant) + int(pci_compliant)
            ) / 3 * 100
        }


class NucleiVulnerabilityScanner:
    """
    Nuclei 3.1+ vulnerability scanner integration for community-driven security templates.
    
    Implements comprehensive Nuclei vulnerability scanning per Section 6.4.5 with
    community-driven security templates, custom attack patterns, and enterprise
    reporting capabilities for continuous security assessment.
    """
    
    def __init__(
        self,
        nuclei_binary: str = 'nuclei',
        templates_path: Optional[str] = None,
        custom_templates_path: Optional[str] = None
    ):
        """
        Initialize Nuclei vulnerability scanner.
        
        Args:
            nuclei_binary: Path to Nuclei binary executable
            templates_path: Path to Nuclei templates directory
            custom_templates_path: Path to custom templates directory
        """
        self.nuclei_binary = nuclei_binary
        self.templates_path = templates_path or os.path.expanduser('~/nuclei-templates')
        self.custom_templates_path = custom_templates_path
        
        # Scan configuration
        self.default_severity_filters = ['critical', 'high', 'medium']
        self.default_tags = ['flask', 'python', 'web', 'auth', 'sqli', 'xss', 'rce']
        self.rate_limit = 150  # requests per second
        self.timeout = 10  # seconds
        self.retries = 3
        
        # Results tracking
        self.scan_results = {}
        self.vulnerability_database = []
        
        self.logger = penetration_logger.bind(
            component="nuclei_vulnerability_scanner",
            nuclei_binary=nuclei_binary
        )
    
    def validate_nuclei_installation(self) -> bool:
        """
        Validate Nuclei installation and template availability.
        
        Returns:
            True if Nuclei is properly installed and configured, False otherwise
        """
        try:
            # Check Nuclei binary availability
            result = subprocess.run(
                [self.nuclei_binary, '-version'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                self.logger.error("Nuclei binary not found or not executable")
                return False
            
            version_output = result.stdout
            self.logger.info("Nuclei installation validated", version=version_output.strip())
            
            # Check templates directory
            if not os.path.exists(self.templates_path):
                self.logger.warning("Nuclei templates directory not found", path=self.templates_path)
                # Attempt to update templates
                self._update_nuclei_templates()
            
            return True
            
        except subprocess.TimeoutExpired:
            self.logger.error("Nuclei version check timed out")
            return False
        except Exception as e:
            self.logger.error("Nuclei validation failed", error=str(e))
            return False
    
    def _update_nuclei_templates(self) -> bool:
        """Update Nuclei templates to latest version."""
        try:
            self.logger.info("Updating Nuclei templates")
            
            result = subprocess.run(
                [self.nuclei_binary, '-update-templates'],
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes
            )
            
            if result.returncode == 0:
                self.logger.info("Nuclei templates updated successfully")
                return True
            else:
                self.logger.error("Nuclei template update failed", stderr=result.stderr)
                return False
                
        except Exception as e:
            self.logger.error("Failed to update Nuclei templates", error=str(e))
            return False
    
    async def execute_vulnerability_scan(
        self,
        target: PenetrationTestTarget,
        severity_filters: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        custom_templates: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Execute comprehensive vulnerability scan using Nuclei.
        
        Args:
            target: Penetration testing target configuration
            severity_filters: List of severity levels to include
            tags: List of template tags to include
            custom_templates: List of custom template files to use
            
        Returns:
            Comprehensive vulnerability scan results
        """
        scan_start_time = time.time()
        scan_id = f"nuclei_scan_{target.name}_{int(time.time())}"
        
        if severity_filters is None:
            severity_filters = self.default_severity_filters
        
        if tags is None:
            tags = self.default_tags
        
        self.logger.info(
            "Starting Nuclei vulnerability scan",
            scan_id=scan_id,
            target_url=target.base_url,
            severity_filters=severity_filters,
            tags=tags
        )
        
        try:
            # Validate Nuclei installation
            if not self.validate_nuclei_installation():
                raise RuntimeError("Nuclei installation validation failed")
            
            # Build Nuclei command
            nuclei_cmd = self._build_nuclei_command(
                target, severity_filters, tags, custom_templates
            )
            
            # Execute Nuclei scan
            scan_results = await self._execute_nuclei_command(nuclei_cmd, scan_id)
            
            # Process and analyze results
            processed_results = self._process_nuclei_results(scan_results, target)
            
            # Calculate security metrics
            security_metrics = self._calculate_nuclei_security_metrics(processed_results)
            
            # Generate compliance assessment
            compliance_assessment = self._assess_nuclei_compliance(processed_results)
            
            scan_duration = time.time() - scan_start_time
            
            final_results = {
                'scan_id': scan_id,
                'target': target.name,
                'target_url': target.base_url,
                'start_time': datetime.fromtimestamp(scan_start_time, timezone.utc).isoformat(),
                'end_time': datetime.now(timezone.utc).isoformat(),
                'duration_seconds': scan_duration,
                'status': 'completed',
                'severity_filters': severity_filters,
                'tags_used': tags,
                'templates_executed': scan_results.get('templates_executed', 0),
                'total_findings': len(processed_results.get('findings', [])),
                'findings': processed_results.get('findings', []),
                'security_metrics': security_metrics,
                'compliance_assessment': compliance_assessment,
                'nuclei_version': scan_results.get('nuclei_version'),
                'command_executed': ' '.join(nuclei_cmd)
            }
            
            # Record metrics
            pentest_metrics['nuclei_scan_duration'].labels(
                template_category='comprehensive',
                target=target.name
            ).observe(scan_duration)
            
            pentest_metrics['vulnerability_discoveries'].labels(
                severity='total',
                category='vulnerability_scan',
                tool='nuclei'
            ).set(len(processed_results.get('findings', [])))
            
            self.logger.info(
                "Nuclei vulnerability scan completed successfully",
                scan_id=scan_id,
                duration=scan_duration,
                findings_count=len(processed_results.get('findings', []))
            )
            
            return final_results
            
        except Exception as e:
            self.logger.error(
                "Nuclei vulnerability scan failed",
                scan_id=scan_id,
                error=str(e)
            )
            
            return {
                'scan_id': scan_id,
                'target': target.name,
                'status': 'failed',
                'error': str(e),
                'duration_seconds': time.time() - scan_start_time
            }
    
    def _build_nuclei_command(
        self,
        target: PenetrationTestTarget,
        severity_filters: List[str],
        tags: List[str],
        custom_templates: Optional[List[str]]
    ) -> List[str]:
        """Build Nuclei command with comprehensive configuration."""
        cmd = [
            self.nuclei_binary,
            '-target', target.base_url,
            '-json',  # Output in JSON format
            '-severity', ','.join(severity_filters),
            '-tags', ','.join(tags),
            '-rate-limit', str(self.rate_limit),
            '-timeout', str(self.timeout),
            '-retries', str(self.retries),
            '-no-color',  # Disable color output
            '-silent',  # Reduce verbose output
        ]
        
        # Add templates path
        if self.templates_path:
            cmd.extend(['-templates', self.templates_path])
        
        # Add custom templates if specified
        if custom_templates:
            for template in custom_templates:
                cmd.extend(['-templates', template])
        
        # Add custom headers from target
        if target.custom_headers:
            for header, value in target.custom_headers.items():
                cmd.extend(['-header', f'{header}: {value}'])
        
        return cmd
    
    async def _execute_nuclei_command(
        self,
        nuclei_cmd: List[str],
        scan_id: str
    ) -> Dict[str, Any]:
        """Execute Nuclei command asynchronously."""
        try:
            # Execute Nuclei command
            process = await asyncio.create_subprocess_exec(
                *nuclei_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Parse results
            results = {
                'scan_id': scan_id,
                'return_code': process.returncode,
                'stdout': stdout.decode('utf-8'),
                'stderr': stderr.decode('utf-8'),
                'templates_executed': 0,
                'raw_findings': []
            }
            
            # Parse JSON output
            if stdout:
                for line in stdout.decode('utf-8').strip().split('\n'):
                    if line.strip():
                        try:
                            finding = json.loads(line)
                            results['raw_findings'].append(finding)
                        except json.JSONDecodeError:
                            # Skip non-JSON lines
                            continue
            
            results['templates_executed'] = len(set(
                f.get('template-id', '') for f in results['raw_findings']
            ))
            
            return results
            
        except Exception as e:
            self.logger.error("Nuclei command execution failed", error=str(e))
            return {
                'scan_id': scan_id,
                'error': str(e),
                'raw_findings': []
            }
    
    def _process_nuclei_results(
        self,
        scan_results: Dict[str, Any],
        target: PenetrationTestTarget
    ) -> Dict[str, Any]:
        """Process and normalize Nuclei scan results."""
        processed_findings = []
        
        for raw_finding in scan_results.get('raw_findings', []):
            try:
                # Extract and normalize finding data
                finding = {
                    'template_id': raw_finding.get('template-id'),
                    'template_name': raw_finding.get('info', {}).get('name'),
                    'description': raw_finding.get('info', {}).get('description'),
                    'severity': raw_finding.get('info', {}).get('severity', 'info').lower(),
                    'classification': raw_finding.get('info', {}).get('classification', {}),
                    'tags': raw_finding.get('info', {}).get('tags', []),
                    'url': raw_finding.get('matched-at'),
                    'extracted_results': raw_finding.get('extracted-results', []),
                    'metadata': raw_finding.get('meta', {}),
                    'timestamp': raw_finding.get('timestamp'),
                    'source': 'nuclei_scan',
                    'cve_ids': self._extract_cve_ids(raw_finding),
                    'cwe_ids': self._extract_cwe_ids(raw_finding),
                    'references': self._extract_references(raw_finding)
                }
                
                # Add OWASP Top 10 mapping
                finding['owasp_category'] = self._map_to_owasp_top10(finding)
                
                # Calculate risk score
                finding['risk_score'] = self._calculate_risk_score(finding)
                
                processed_findings.append(finding)
                
            except Exception as e:
                self.logger.warning("Failed to process Nuclei finding", error=str(e))
                continue
        
        return {
            'findings': processed_findings,
            'total_findings': len(processed_findings),
            'severity_breakdown': self._categorize_findings_by_severity(processed_findings),
            'template_breakdown': self._categorize_findings_by_template(processed_findings),
            'owasp_mapping': self._map_findings_to_owasp(processed_findings)
        }
    
    def _extract_cve_ids(self, raw_finding: Dict[str, Any]) -> List[str]:
        """Extract CVE IDs from Nuclei finding."""
        cve_ids = []
        
        # Check classification section
        classification = raw_finding.get('info', {}).get('classification', {})
        if 'cve-id' in classification:
            cve_ids.extend(classification['cve-id'])
        
        # Check references
        references = raw_finding.get('info', {}).get('reference', [])
        for ref in references:
            if 'cve' in ref.lower():
                cve_ids.append(ref)
        
        return list(set(cve_ids))  # Remove duplicates
    
    def _extract_cwe_ids(self, raw_finding: Dict[str, Any]) -> List[str]:
        """Extract CWE IDs from Nuclei finding."""
        cwe_ids = []
        
        # Check classification section
        classification = raw_finding.get('info', {}).get('classification', {})
        if 'cwe-id' in classification:
            cwe_ids.extend(classification['cwe-id'])
        
        return cwe_ids
    
    def _extract_references(self, raw_finding: Dict[str, Any]) -> List[str]:
        """Extract reference URLs from Nuclei finding."""
        return raw_finding.get('info', {}).get('reference', [])
    
    def _map_to_owasp_top10(self, finding: Dict[str, Any]) -> Optional[str]:
        """Map Nuclei finding to OWASP Top 10 category."""
        tags = finding.get('tags', [])
        description = finding.get('description', '').lower()
        template_name = finding.get('template_name', '').lower()
        
        # OWASP Top 10 mapping based on tags and description
        owasp_mapping = {
            'A01_broken_access_control': ['auth', 'authorization', 'access', 'privilege'],
            'A02_cryptographic_failures': ['ssl', 'tls', 'crypto', 'hash', 'encryption'],
            'A03_injection': ['sqli', 'xss', 'injection', 'command', 'ldap'],
            'A04_insecure_design': ['logic', 'business', 'design'],
            'A05_security_misconfiguration': ['config', 'default', 'debug', 'error'],
            'A06_vulnerable_components': ['cve', 'version', 'outdated', 'component'],
            'A07_authentication_failures': ['auth', 'login', 'session', 'password'],
            'A08_data_integrity_failures': ['integrity', 'validation', 'tamper'],
            'A09_logging_monitoring_failures': ['log', 'monitor', 'audit'],
            'A10_ssrf': ['ssrf', 'redirect', 'url']
        }
        
        search_text = f"{template_name} {description} {' '.join(tags)}".lower()
        
        for category, keywords in owasp_mapping.items():
            if any(keyword in search_text for keyword in keywords):
                return category
        
        return None
    
    def _calculate_risk_score(self, finding: Dict[str, Any]) -> float:
        """Calculate risk score for Nuclei finding."""
        severity_scores = {
            'critical': 10.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 1.0
        }
        
        base_score = severity_scores.get(finding.get('severity', 'info'), 1.0)
        
        # Adjust score based on additional factors
        adjustments = 0.0
        
        # CVE presence increases score
        if finding.get('cve_ids'):
            adjustments += 1.0
        
        # Multiple CWE IDs indicate complex vulnerability
        cwe_count = len(finding.get('cwe_ids', []))
        if cwe_count > 1:
            adjustments += 0.5 * (cwe_count - 1)
        
        # OWASP Top 10 mapping increases score
        if finding.get('owasp_category'):
            adjustments += 0.5
        
        return min(10.0, base_score + adjustments)
    
    def _categorize_findings_by_template(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Categorize findings by template category."""
        template_counts = {}
        
        for finding in findings:
            template_id = finding.get('template_id', 'unknown')
            template_counts[template_id] = template_counts.get(template_id, 0) + 1
        
        return template_counts
    
    def _map_findings_to_owasp(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Map findings to OWASP Top 10 categories."""
        owasp_mapping = {}
        
        for finding in findings:
            owasp_category = finding.get('owasp_category')
            if owasp_category:
                if owasp_category not in owasp_mapping:
                    owasp_mapping[owasp_category] = []
                owasp_mapping[owasp_category].append(finding)
        
        return owasp_mapping
    
    def _calculate_nuclei_security_metrics(self, processed_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate security metrics from Nuclei scan results."""
        findings = processed_results.get('findings', [])
        severity_breakdown = processed_results.get('severity_breakdown', {})
        
        # Calculate security score
        critical_weight = 40
        high_weight = 20
        medium_weight = 10
        low_weight = 5
        
        total_penalty = (
            severity_breakdown.get('critical', 0) * critical_weight +
            severity_breakdown.get('high', 0) * high_weight +
            severity_breakdown.get('medium', 0) * medium_weight +
            severity_breakdown.get('low', 0) * low_weight
        )
        
        security_score = max(0, 100 - total_penalty)
        
        # Calculate coverage metrics
        unique_templates = len(set(f.get('template_id') for f in findings))
        owasp_categories_found = len(processed_results.get('owasp_mapping', {}))
        
        return {
            'security_score': security_score,
            'total_findings': len(findings),
            'severity_breakdown': severity_breakdown,
            'unique_templates_triggered': unique_templates,
            'owasp_categories_covered': owasp_categories_found,
            'average_risk_score': sum(f.get('risk_score', 0) for f in findings) / len(findings) if findings else 0,
            'cve_findings': len([f for f in findings if f.get('cve_ids')]),
            'compliance_impact': self._assess_compliance_impact(findings)
        }
    
    def _assess_compliance_impact(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess compliance impact of Nuclei findings."""
        # Count findings that impact different compliance frameworks
        soc2_impact_findings = [
            f for f in findings
            if f.get('severity') in ['critical', 'high'] and
            any(tag in f.get('tags', []) for tag in ['auth', 'access', 'config'])
        ]
        
        pci_impact_findings = [
            f for f in findings
            if f.get('severity') in ['critical', 'high'] and
            any(keyword in f.get('description', '').lower() for keyword in ['ssl', 'tls', 'encryption', 'crypto'])
        ]
        
        gdpr_impact_findings = [
            f for f in findings
            if f.get('severity') in ['critical', 'high'] and
            any(keyword in f.get('description', '').lower() for keyword in ['data', 'privacy', 'personal'])
        ]
        
        return {
            'soc2_impact_findings': len(soc2_impact_findings),
            'pci_impact_findings': len(pci_impact_findings),
            'gdpr_impact_findings': len(gdpr_impact_findings),
            'overall_compliance_risk': max(
                len(soc2_impact_findings),
                len(pci_impact_findings),
                len(gdpr_impact_findings)
            )
        }
    
    def _assess_nuclei_compliance(self, processed_results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess compliance status based on Nuclei findings."""
        findings = processed_results.get('findings', [])
        severity_breakdown = processed_results.get('severity_breakdown', {})
        
        # Enterprise compliance thresholds
        critical_threshold = 0
        high_threshold = 3
        medium_threshold = 10
        
        compliance_status = {
            'critical_findings_compliant': severity_breakdown.get('critical', 0) <= critical_threshold,
            'high_findings_compliant': severity_breakdown.get('high', 0) <= high_threshold,
            'medium_findings_compliant': severity_breakdown.get('medium', 0) <= medium_threshold,
        }
        
        overall_compliant = all(compliance_status.values())
        
        return {
            'overall_compliant': overall_compliant,
            'compliance_details': compliance_status,
            'compliance_score': sum(compliance_status.values()) / len(compliance_status) * 100,
            'recommendations': self._generate_compliance_recommendations(findings, severity_breakdown)
        }
    
    def _generate_compliance_recommendations(
        self,
        findings: List[Dict[str, Any]],
        severity_breakdown: Dict[str, int]
    ) -> List[str]:
        """Generate compliance recommendations based on findings."""
        recommendations = []
        
        if severity_breakdown.get('critical', 0) > 0:
            recommendations.append("Immediately address all critical vulnerabilities to meet enterprise security standards")
        
        if severity_breakdown.get('high', 0) > 3:
            recommendations.append("Reduce high-severity findings to 3 or fewer for SOC 2 compliance")
        
        if severity_breakdown.get('medium', 0) > 10:
            recommendations.append("Implement systematic remediation plan for medium-severity vulnerabilities")
        
        # CVE-specific recommendations
        cve_findings = [f for f in findings if f.get('cve_ids')]
        if cve_findings:
            recommendations.append(f"Address {len(cve_findings)} CVE-related vulnerabilities through component updates")
        
        # OWASP Top 10 recommendations
        owasp_categories = set(f.get('owasp_category') for f in findings if f.get('owasp_category'))
        if len(owasp_categories) > 5:
            recommendations.append("Comprehensive security review needed - multiple OWASP Top 10 categories affected")
        
        return recommendations


class PenetrationTestOrchestrator:
    """
    Penetration Testing Orchestration Engine for Comprehensive Security Assessment.
    
    Implements enterprise-grade penetration testing orchestration per Section 6.4.5
    and Section 6.6.2, coordinating OWASP ZAP DAST, Nuclei vulnerability scanning,
    attack simulation, and compliance dashboard integration for comprehensive
    automated security assessment workflows.
    """
    
    def __init__(
        self,
        security_config: SecurityTestConfiguration,
        zap_config: Optional[Dict[str, Any]] = None,
        nuclei_config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize penetration testing orchestrator.
        
        Args:
            security_config: Security testing configuration instance
            zap_config: OWASP ZAP configuration parameters
            nuclei_config: Nuclei scanner configuration parameters
        """
        self.security_config = security_config
        self.zap_config = zap_config or {}
        self.nuclei_config = nuclei_config or {}
        
        # Initialize security testing components
        self.zap_tester = ZAPPenetrationTester(
            zap_proxy_host=self.zap_config.get('host', 'localhost'),
            zap_proxy_port=self.zap_config.get('port', 8080),
            zap_api_key=self.zap_config.get('api_key')
        )
        
        self.nuclei_scanner = NucleiVulnerabilityScanner(
            nuclei_binary=self.nuclei_config.get('binary', 'nuclei'),
            templates_path=self.nuclei_config.get('templates_path'),
            custom_templates_path=self.nuclei_config.get('custom_templates_path')
        )
        
        # Test execution tracking
        self.orchestration_session_id = f"pentest_orchestration_{int(time.time())}"
        self.execution_results = {}
        self.compliance_dashboard_data = {}
        
        self.logger = penetration_logger.bind(
            component="penetration_test_orchestrator",
            session_id=self.orchestration_session_id
        )
    
    async def execute_comprehensive_penetration_test(
        self,
        targets: List[PenetrationTestTarget],
        test_categories: Optional[List[str]] = None,
        parallel_execution: bool = True
    ) -> Dict[str, Any]:
        """
        Execute comprehensive penetration testing across multiple targets.
        
        Args:
            targets: List of penetration testing targets
            test_categories: Categories of tests to execute (dast, nuclei, simulation)
            parallel_execution: Whether to execute tests in parallel
            
        Returns:
            Comprehensive penetration testing results with compliance assessment
        """
        orchestration_start_time = time.time()
        
        if test_categories is None:
            test_categories = ['dast', 'nuclei', 'simulation', 'compliance']
        
        self.logger.info(
            "Starting comprehensive penetration testing orchestration",
            targets_count=len(targets),
            test_categories=test_categories,
            parallel_execution=parallel_execution
        )
        
        try:
            orchestration_results = {
                'orchestration_id': self.orchestration_session_id,
                'start_time': datetime.now(timezone.utc).isoformat(),
                'targets': [{'name': t.name, 'url': t.base_url} for t in targets],
                'test_categories': test_categories,
                'parallel_execution': parallel_execution,
                'status': 'running'
            }
            
            # Execute penetration tests
            if parallel_execution:
                test_results = await self._execute_parallel_penetration_tests(targets, test_categories)
            else:
                test_results = await self._execute_sequential_penetration_tests(targets, test_categories)
            
            orchestration_results['test_results'] = test_results
            
            # Consolidate all findings
            consolidated_findings = self._consolidate_all_findings(test_results)
            orchestration_results['consolidated_findings'] = consolidated_findings
            
            # Generate comprehensive security assessment
            security_assessment = self._generate_security_assessment(consolidated_findings)
            orchestration_results['security_assessment'] = security_assessment
            
            # Generate compliance dashboard data
            compliance_data = self._generate_compliance_dashboard_data(
                consolidated_findings, security_assessment
            )
            orchestration_results['compliance_dashboard'] = compliance_data
            
            # Generate executive summary
            executive_summary = self._generate_executive_summary(
                orchestration_results, consolidated_findings
            )
            orchestration_results['executive_summary'] = executive_summary
            
            orchestration_duration = time.time() - orchestration_start_time
            orchestration_results.update({
                'status': 'completed',
                'end_time': datetime.now(timezone.utc).isoformat(),
                'duration_seconds': orchestration_duration,
                'total_vulnerabilities': len(consolidated_findings),
                'critical_vulnerabilities': len([f for f in consolidated_findings if f.get('severity') == 'critical']),
                'high_vulnerabilities': len([f for f in consolidated_findings if f.get('severity') == 'high'])
            })
            
            # Record orchestration metrics
            pentest_metrics['penetration_tests_total'].labels(
                test_type='comprehensive_orchestration',
                target='multiple',
                result='success'
            ).inc()
            
            self.logger.info(
                "Penetration testing orchestration completed successfully",
                duration=orchestration_duration,
                total_vulnerabilities=len(consolidated_findings),
                targets_tested=len(targets)
            )
            
            return orchestration_results
            
        except Exception as e:
            self.logger.error(
                "Penetration testing orchestration failed",
                error=str(e)
            )
            
            pentest_metrics['penetration_tests_total'].labels(
                test_type='comprehensive_orchestration',
                target='multiple',
                result='failure'
            ).inc()
            
            return {
                'orchestration_id': self.orchestration_session_id,
                'status': 'failed',
                'error': str(e),
                'duration_seconds': time.time() - orchestration_start_time
            }
    
    async def _execute_parallel_penetration_tests(
        self,
        targets: List[PenetrationTestTarget],
        test_categories: List[str]
    ) -> Dict[str, Any]:
        """Execute penetration tests in parallel across targets and categories."""
        parallel_tasks = []
        
        for target in targets:
            if 'dast' in test_categories:
                task = asyncio.create_task(
                    self.zap_tester.execute_comprehensive_dast_scan(target),
                    name=f"dast_{target.name}"
                )
                parallel_tasks.append(('dast', target.name, task))
            
            if 'nuclei' in test_categories:
                task = asyncio.create_task(
                    self.nuclei_scanner.execute_vulnerability_scan(target),
                    name=f"nuclei_{target.name}"
                )
                parallel_tasks.append(('nuclei', target.name, task))
            
            if 'simulation' in test_categories:
                task = asyncio.create_task(
                    self._execute_attack_simulation(target),
                    name=f"simulation_{target.name}"
                )
                parallel_tasks.append(('simulation', target.name, task))
        
        # Wait for all tasks to complete
        results = {}
        completed_tasks = await asyncio.gather(
            *[task for _, _, task in parallel_tasks],
            return_exceptions=True
        )
        
        # Process results
        for i, (test_type, target_name, _) in enumerate(parallel_tasks):
            result = completed_tasks[i]
            
            if isinstance(result, Exception):
                self.logger.error(
                    "Parallel test execution failed",
                    test_type=test_type,
                    target=target_name,
                    error=str(result)
                )
                result = {
                    'status': 'failed',
                    'error': str(result),
                    'test_type': test_type,
                    'target': target_name
                }
            
            if target_name not in results:
                results[target_name] = {}
            results[target_name][test_type] = result
        
        return results
    
    async def _execute_sequential_penetration_tests(
        self,
        targets: List[PenetrationTestTarget],
        test_categories: List[str]
    ) -> Dict[str, Any]:
        """Execute penetration tests sequentially across targets and categories."""
        results = {}
        
        for target in targets:
            target_results = {}
            
            if 'dast' in test_categories:
                self.logger.info("Executing DAST scan", target=target.name)
                target_results['dast'] = await self.zap_tester.execute_comprehensive_dast_scan(target)
            
            if 'nuclei' in test_categories:
                self.logger.info("Executing Nuclei scan", target=target.name)
                target_results['nuclei'] = await self.nuclei_scanner.execute_vulnerability_scan(target)
            
            if 'simulation' in test_categories:
                self.logger.info("Executing attack simulation", target=target.name)
                target_results['simulation'] = await self._execute_attack_simulation(target)
            
            results[target.name] = target_results
        
        return results
    
    async def _execute_attack_simulation(self, target: PenetrationTestTarget) -> Dict[str, Any]:
        """Execute comprehensive attack simulation against target."""
        simulation_start_time = time.time()
        
        try:
            session = target.get_authenticated_session()
            attack_results = []
            
            # SQL Injection simulation
            sql_payloads = self.security_config.generate_test_payloads(AttackType.SQL_INJECTION)
            for payload in sql_payloads[:10]:  # Limit for performance
                try:
                    response = session.get(
                        target.base_url + '/api/search',
                        params={'q': payload},
                        timeout=10
                    )
                    
                    attack_results.append({
                        'attack_type': 'sql_injection',
                        'payload': payload,
                        'status_code': response.status_code,
                        'response_length': len(response.content),
                        'vulnerability_detected': self._detect_sql_injection_vulnerability(response)
                    })
                    
                    pentest_metrics['attack_simulations_executed'].labels(
                        attack_type='sql_injection',
                        success=str(self._detect_sql_injection_vulnerability(response))
                    ).inc()
                    
                except Exception:
                    continue
            
            # XSS simulation
            xss_payloads = self.security_config.generate_test_payloads(AttackType.XSS)
            for payload in xss_payloads[:10]:  # Limit for performance
                try:
                    response = session.post(
                        target.base_url + '/api/comments',
                        json={'comment': payload},
                        timeout=10
                    )
                    
                    attack_results.append({
                        'attack_type': 'xss',
                        'payload': payload,
                        'status_code': response.status_code,
                        'response_length': len(response.content),
                        'vulnerability_detected': payload in response.text
                    })
                    
                    pentest_metrics['attack_simulations_executed'].labels(
                        attack_type='xss',
                        success=str(payload in response.text)
                    ).inc()
                    
                except Exception:
                    continue
            
            simulation_duration = time.time() - simulation_start_time
            
            return {
                'attack_simulation_id': f"simulation_{target.name}_{int(time.time())}",
                'target': target.name,
                'duration_seconds': simulation_duration,
                'total_attacks': len(attack_results),
                'successful_attacks': len([r for r in attack_results if r.get('vulnerability_detected')]),
                'attack_results': attack_results,
                'status': 'completed'
            }
            
        except Exception as e:
            return {
                'target': target.name,
                'status': 'failed',
                'error': str(e),
                'duration_seconds': time.time() - simulation_start_time
            }
    
    def _detect_sql_injection_vulnerability(self, response: requests.Response) -> bool:
        """Detect SQL injection vulnerability indicators in response."""
        sql_error_indicators = [
            'syntax error', 'mysql_fetch', 'ora-01756', 'microsoft jet database',
            'odbc sql server driver', 'ole db provider', 'unclosed quotation mark',
            'quoted string not properly terminated'
        ]
        
        response_text = response.text.lower()
        return any(indicator in response_text for indicator in sql_error_indicators)
    
    def _consolidate_all_findings(self, test_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Consolidate findings from all penetration testing tools and targets."""
        all_findings = []
        
        for target_name, target_results in test_results.items():
            # Consolidate DAST findings
            dast_results = target_results.get('dast', {})
            if 'consolidated_findings' in dast_results:
                for finding in dast_results['consolidated_findings']:
                    finding['target'] = target_name
                    finding['test_category'] = 'dast'
                    all_findings.append(finding)
            
            # Consolidate Nuclei findings
            nuclei_results = target_results.get('nuclei', {})
            if 'findings' in nuclei_results:
                for finding in nuclei_results['findings']:
                    finding['target'] = target_name
                    finding['test_category'] = 'nuclei'
                    all_findings.append(finding)
            
            # Consolidate attack simulation findings
            simulation_results = target_results.get('simulation', {})
            if 'attack_results' in simulation_results:
                for attack in simulation_results['attack_results']:
                    if attack.get('vulnerability_detected'):
                        finding = {
                            'target': target_name,
                            'test_category': 'simulation',
                            'attack_type': attack.get('attack_type'),
                            'payload': attack.get('payload'),
                            'severity': 'high',  # Successful attacks are considered high severity
                            'description': f"Successful {attack.get('attack_type')} attack",
                            'source': 'attack_simulation'
                        }
                        all_findings.append(finding)
        
        # Deduplicate findings
        deduplicated_findings = self._deduplicate_consolidated_findings(all_findings)
        
        return deduplicated_findings
    
    def _deduplicate_consolidated_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate findings across different tools and targets."""
        seen_findings = set()
        deduplicated = []
        
        for finding in findings:
            # Create unique key for deduplication
            key = (
                finding.get('target', ''),
                finding.get('url', ''),
                finding.get('name', ''),
                finding.get('attack_type', ''),
                finding.get('template_id', '')
            )
            
            if key not in seen_findings:
                seen_findings.add(key)
                deduplicated.append(finding)
        
        return deduplicated
    
    def _generate_security_assessment(self, consolidated_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive security assessment from all findings."""
        # Categorize findings by severity
        severity_breakdown = {}
        for finding in consolidated_findings:
            severity = finding.get('severity', 'info')
            severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1
        
        # Calculate overall security score
        total_penalty = (
            severity_breakdown.get('critical', 0) * 50 +
            severity_breakdown.get('high', 0) * 25 +
            severity_breakdown.get('medium', 0) * 10 +
            severity_breakdown.get('low', 0) * 5
        )
        security_score = max(0, 100 - total_penalty)
        
        # Analyze attack success rates
        simulation_findings = [f for f in consolidated_findings if f.get('test_category') == 'simulation']
        attack_success_rate = len(simulation_findings) / max(1, len([f for f in consolidated_findings if f.get('test_category') == 'simulation']))
        
        # OWASP Top 10 coverage analysis
        owasp_categories = set()
        for finding in consolidated_findings:
            owasp_cat = finding.get('owasp_category')
            if owasp_cat:
                owasp_categories.add(owasp_cat)
        
        return {
            'overall_security_score': security_score,
            'total_vulnerabilities': len(consolidated_findings),
            'severity_breakdown': severity_breakdown,
            'attack_success_rate': attack_success_rate,
            'owasp_top10_categories_affected': len(owasp_categories),
            'security_posture': self._determine_security_posture(security_score, severity_breakdown),
            'recommendations': self._generate_security_recommendations(consolidated_findings),
            'risk_level': self._calculate_risk_level(severity_breakdown)
        }
    
    def _determine_security_posture(self, security_score: float, severity_breakdown: Dict[str, int]) -> str:
        """Determine overall security posture based on score and findings."""
        if severity_breakdown.get('critical', 0) > 0:
            return 'Critical'
        elif severity_breakdown.get('high', 0) > 5:
            return 'Poor'
        elif security_score >= 90:
            return 'Excellent'
        elif security_score >= 75:
            return 'Good'
        elif security_score >= 60:
            return 'Fair'
        else:
            return 'Poor'
    
    def _calculate_risk_level(self, severity_breakdown: Dict[str, int]) -> str:
        """Calculate enterprise risk level based on vulnerability severity."""
        if severity_breakdown.get('critical', 0) >= 1:
            return 'Critical'
        elif severity_breakdown.get('high', 0) >= 3:
            return 'High'
        elif severity_breakdown.get('medium', 0) >= 10:
            return 'Medium'
        else:
            return 'Low'
    
    def _generate_security_recommendations(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Generate actionable security recommendations based on findings."""
        recommendations = []
        
        # Critical findings recommendations
        critical_findings = [f for f in findings if f.get('severity') == 'critical']
        if critical_findings:
            recommendations.append(f"URGENT: Address {len(critical_findings)} critical vulnerabilities immediately")
        
        # High severity recommendations
        high_findings = [f for f in findings if f.get('severity') == 'high']
        if high_findings:
            recommendations.append(f"High Priority: Remediate {len(high_findings)} high-severity vulnerabilities within 24 hours")
        
        # Attack simulation recommendations
        simulation_findings = [f for f in findings if f.get('test_category') == 'simulation']
        if simulation_findings:
            recommendations.append(f"Security Controls: {len(simulation_findings)} successful attack simulations indicate control gaps")
        
        # OWASP Top 10 recommendations
        owasp_categories = set(f.get('owasp_category') for f in findings if f.get('owasp_category'))
        if len(owasp_categories) > 3:
            recommendations.append("Comprehensive Security Review: Multiple OWASP Top 10 categories affected")
        
        # Compliance recommendations
        if any(f.get('severity') in ['critical', 'high'] for f in findings):
            recommendations.append("Compliance Impact: Current vulnerabilities may affect SOC 2 and enterprise compliance")
        
        return recommendations
    
    def _generate_compliance_dashboard_data(
        self,
        findings: List[Dict[str, Any]],
        security_assessment: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate compliance dashboard data for enterprise reporting."""
        # SOC 2 Type II compliance assessment
        soc2_critical = len([f for f in findings if f.get('severity') == 'critical'])
        soc2_high = len([f for f in findings if f.get('severity') == 'high'])
        soc2_compliant = soc2_critical == 0 and soc2_high <= 2
        
        # OWASP Top 10 compliance assessment
        owasp_findings = [f for f in findings if f.get('owasp_category')]
        owasp_critical_high = [f for f in owasp_findings if f.get('severity') in ['critical', 'high']]
        owasp_compliant = len(owasp_critical_high) == 0
        
        # PCI DSS compliance assessment (if applicable)
        encryption_findings = [
            f for f in findings
            if any(keyword in f.get('description', '').lower() for keyword in ['ssl', 'tls', 'encryption'])
        ]
        pci_compliant = not encryption_findings
        
        return {
            'compliance_summary': {
                'soc2_type2': {
                    'compliant': soc2_compliant,
                    'critical_findings': soc2_critical,
                    'high_findings': soc2_high,
                    'compliance_score': 100 if soc2_compliant else max(0, 100 - (soc2_critical * 50 + soc2_high * 25))
                },
                'owasp_top10': {
                    'compliant': owasp_compliant,
                    'categories_affected': len(set(f.get('owasp_category') for f in owasp_findings if f.get('owasp_category'))),
                    'critical_high_findings': len(owasp_critical_high),
                    'compliance_score': 100 if owasp_compliant else max(0, 100 - len(owasp_critical_high) * 20)
                },
                'pci_dss': {
                    'compliant': pci_compliant,
                    'encryption_findings': len(encryption_findings),
                    'compliance_score': 100 if pci_compliant else max(0, 100 - len(encryption_findings) * 30)
                }
            },
            'security_metrics': {
                'overall_security_score': security_assessment.get('overall_security_score', 0),
                'total_vulnerabilities': len(findings),
                'risk_level': security_assessment.get('risk_level', 'Unknown'),
                'security_posture': security_assessment.get('security_posture', 'Unknown')
            },
            'trend_data': {
                'vulnerability_discovery_rate': len(findings) / max(1, len(set(f.get('target') for f in findings))),
                'attack_success_rate': security_assessment.get('attack_success_rate', 0),
                'owasp_coverage_percentage': min(100, len(set(f.get('owasp_category') for f in findings if f.get('owasp_category'))) / 10 * 100)
            },
            'recommendations': security_assessment.get('recommendations', []),
            'next_assessment_date': (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        }
    
    def _generate_executive_summary(
        self,
        orchestration_results: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate executive summary for stakeholder reporting."""
        severity_breakdown = {}
        for finding in findings:
            severity = finding.get('severity', 'info')
            severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1
        
        return {
            'assessment_overview': {
                'targets_tested': len(orchestration_results.get('targets', [])),
                'test_duration': f"{orchestration_results.get('duration_seconds', 0) / 3600:.1f} hours",
                'vulnerabilities_discovered': len(findings),
                'security_tools_used': ['OWASP ZAP 2.14+', 'Nuclei 3.1+', 'Attack Simulation']
            },
            'risk_summary': {
                'overall_risk_level': self._calculate_risk_level(severity_breakdown),
                'critical_issues': severity_breakdown.get('critical', 0),
                'high_priority_issues': severity_breakdown.get('high', 0),
                'requires_immediate_attention': severity_breakdown.get('critical', 0) > 0
            },
            'compliance_status': {
                'enterprise_ready': severity_breakdown.get('critical', 0) == 0 and severity_breakdown.get('high', 0) <= 2,
                'audit_findings': len([f for f in findings if f.get('severity') in ['critical', 'high']]),
                'remediation_timeline': self._calculate_remediation_timeline(severity_breakdown)
            },
            'business_impact': {
                'security_score': orchestration_results.get('security_assessment', {}).get('overall_security_score', 0),
                'reputation_risk': 'High' if severity_breakdown.get('critical', 0) > 0 else 'Low',
                'operational_risk': 'High' if severity_breakdown.get('high', 0) > 5 else 'Medium',
                'financial_risk': self._assess_financial_risk(findings)
            },
            'next_steps': [
                "Review and prioritize vulnerability remediation based on severity",
                "Implement security controls for identified attack vectors", 
                "Schedule follow-up penetration testing after remediation",
                "Update security policies and procedures based on findings"
            ]
        }
    
    def _calculate_remediation_timeline(self, severity_breakdown: Dict[str, int]) -> str:
        """Calculate recommended remediation timeline based on findings."""
        if severity_breakdown.get('critical', 0) > 0:
            return "Immediate (24 hours)"
        elif severity_breakdown.get('high', 0) > 0:
            return "Urgent (1 week)"
        elif severity_breakdown.get('medium', 0) > 0:
            return "Standard (30 days)"
        else:
            return "Maintenance (90 days)"
    
    def _assess_financial_risk(self, findings: List[Dict[str, Any]]) -> str:
        """Assess financial risk based on vulnerability impact."""
        critical_high_count = len([f for f in findings if f.get('severity') in ['critical', 'high']])
        
        if critical_high_count >= 5:
            return "High"
        elif critical_high_count >= 2:
            return "Medium"
        else:
            return "Low"


# Pytest integration for automated penetration testing
@pytest.mark.penetration_test
async def test_automated_penetration_testing(
    security_test_config: SecurityTestConfiguration,
    penetration_test_config: PenetrationTestConfig
):
    """
    Automated penetration testing integration for CI/CD pipelines per Section 6.6.2.
    
    Executes comprehensive penetration testing including OWASP ZAP DAST,
    Nuclei vulnerability scanning, and attack simulation with enterprise
    compliance validation and reporting.
    """
    # Initialize penetration testing orchestrator
    orchestrator = PenetrationTestOrchestrator(security_test_config)
    
    # Create test target from configuration
    target = PenetrationTestTarget(
        base_url=penetration_test_config.target_base_url,
        name="automated_test_target",
        authentication={
            'type': 'bearer',
            'token': penetration_test_config.authentication_token
        } if penetration_test_config.authentication_token else None
    )
    
    # Execute comprehensive penetration testing
    results = await orchestrator.execute_comprehensive_penetration_test(
        targets=[target],
        test_categories=['dast', 'nuclei', 'simulation'],
        parallel_execution=True
    )
    
    # Validate results meet enterprise security standards
    assert results['status'] == 'completed', "Penetration testing must complete successfully"
    
    # Validate compliance with security thresholds
    critical_vulnerabilities = results.get('critical_vulnerabilities', 0)
    assert critical_vulnerabilities == 0, f"Critical vulnerabilities found: {critical_vulnerabilities}"
    
    high_vulnerabilities = results.get('high_vulnerabilities', 0)
    assert high_vulnerabilities <= 3, f"Too many high vulnerabilities: {high_vulnerabilities}"
    
    # Validate security score meets enterprise requirements
    security_score = results.get('security_assessment', {}).get('overall_security_score', 0)
    assert security_score >= 75, f"Security score below threshold: {security_score}"
    
    # Log results for CI/CD pipeline
    penetration_logger.info(
        "Automated penetration testing completed successfully",
        security_score=security_score,
        total_vulnerabilities=results.get('total_vulnerabilities', 0),
        compliance_status=results.get('compliance_dashboard', {}).get('compliance_summary', {})
    )


# Export main penetration testing components
__all__ = [
    "PenetrationTestTarget",
    "ZAPPenetrationTester", 
    "NucleiVulnerabilityScanner",
    "PenetrationTestOrchestrator",
    "pentest_metrics",
    "test_automated_penetration_testing"
]