"""
Automated Penetration Testing Framework

This module provides comprehensive penetration testing capabilities implementing OWASP ZAP 2.14+
integration, vulnerability discovery automation, Nuclei 3.1+ scanner integration, and enterprise-grade
security assessment capabilities for Flask application security validation as specified in Section 6.4.5
and Section 6.4.6 of the technical specification.

Key Features:
- Dynamic Application Security Testing (DAST) with OWASP ZAP 2.14+ per Section 6.4.5
- Automated penetration testing with community-driven security templates per Section 6.4.5
- Nuclei 3.1+ vulnerability scanner integration for comprehensive template-based testing
- Comprehensive security assessment for enterprise compliance per Section 6.4.5
- Penetration testing integration with compliance dashboards per Section 6.4.6
- CI/CD pipeline integration for automated security validation per Section 6.6.2
- Enterprise security reporting with SIEM integration per Section 6.4.6

Architecture Integration:
- Section 6.4.5: Security Controls Matrix with DAST implementation and vulnerability scanning
- Section 6.4.6: Compliance Requirements with penetration testing automation and reporting
- Section 6.6.1: Testing Approach with comprehensive security test automation
- Section 6.6.2: Test Automation with CI/CD security pipeline integration
- Section 6.6.3: Quality Metrics with security scan enforcement and threshold management

Author: Flask Migration Team
Version: 1.0.0
Security Framework: OWASP ZAP 2.14+, Nuclei 3.1+, Bandit 1.7+, Safety 3.0+
Compliance: SOC 2, ISO 27001, OWASP Top 10, SANS Top 25
Dependencies: zapv2 0.0.21+, python-nuclei 3.1+, requests 2.31+, httpx 0.24+
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import subprocess
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, TimeoutError, as_completed
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Generator, Union, Callable
from urllib.parse import urljoin, urlparse

import httpx
import pytest
import requests
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential_jitter,
    retry_if_exception_type,
    before_sleep_log,
    after_log
)

# Security testing framework imports
from zapv2 import ZAPv2
import docker
from docker.models.containers import Container
from docker.errors import DockerException, NotFound, APIError

# Import security configuration and utilities
from .security_config import (
    SecurityTestConfig,
    SecurityTestLevel,
    VulnerabilitySeverity,
    AttackCategory,
    SecurityTestMetrics,
    OWASPZAPScanner,
    PenetrationTestRunner as BasePenetrationTestRunner,
    ComplianceValidator,
    SecurityTestOrchestrator
)
from .conftest import (
    SecurityTestConfig as ConfTestSecurityConfig,
    SecurityPayloads,
    SecurityAuditLogger,
    MockAttackScenarios,
    SecurityValidationTools,
    SecurityPerformanceMonitor,
    comprehensive_security_environment
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PenetrationTestError(Exception):
    """Base exception for penetration testing errors."""
    pass


class NucleiScannerError(PenetrationTestError):
    """Exception for Nuclei scanner specific errors."""
    pass


class ZAPProxyError(PenetrationTestError):
    """Exception for OWASP ZAP proxy errors."""
    pass


class SecurityComplianceError(PenetrationTestError):
    """Exception for security compliance validation errors."""
    pass


class NucleiVulnerabilityScanner:
    """
    Nuclei vulnerability scanner integration for template-based security testing.
    
    Implements comprehensive vulnerability discovery using Nuclei 3.1+ with community-driven
    security templates, custom enterprise templates, and automated CI/CD integration
    per Section 6.4.5 automated penetration testing requirements.
    """
    
    def __init__(self, config: SecurityTestConfig):
        """
        Initialize Nuclei vulnerability scanner with enterprise configuration.
        
        Args:
            config: Security test configuration instance
        """
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.NucleiScanner")
        self.scan_results: Dict[str, Any] = {}
        self.docker_client = None
        self.nuclei_container: Optional[Container] = None
        
        # Nuclei configuration
        self.nuclei_version = "3.1.5"
        self.nuclei_image = f"projectdiscovery/nuclei:v{self.nuclei_version}"
        self.templates_path = "/nuclei-templates"
        self.output_format = "json"
        
        # Initialize Docker client
        self._initialize_docker_client()
    
    def _initialize_docker_client(self) -> None:
        """Initialize Docker client for containerized Nuclei execution."""
        try:
            self.docker_client = docker.from_env()
            self.docker_client.ping()
            self.logger.info("Docker client initialized successfully")
        except DockerException as e:
            self.logger.error(f"Failed to initialize Docker client: {str(e)}")
            raise NucleiScannerError(f"Docker initialization failed: {str(e)}")
    
    @contextmanager
    def _nuclei_container_context(self, target_url: str) -> Generator[Container, None, None]:
        """
        Context manager for Nuclei container lifecycle management.
        
        Args:
            target_url: Target URL for vulnerability scanning
            
        Yields:
            Container: Running Nuclei container instance
        """
        container = None
        try:
            # Prepare container configuration
            container_config = {
                'image': self.nuclei_image,
                'command': self._build_nuclei_command(target_url),
                'detach': True,
                'remove': False,  # Keep container for log retrieval
                'network_mode': 'host',  # Allow access to local services
                'environment': {
                    'NUCLEI_DISABLE_ANALYTICS': 'true',
                    'NUCLEI_NO_COLOR': 'true'
                },
                'mem_limit': '2g',
                'cpu_period': 100000,
                'cpu_quota': 50000  # 50% CPU limit
            }
            
            # Pull latest Nuclei image
            self.logger.info(f"Pulling Nuclei image: {self.nuclei_image}")
            self.docker_client.images.pull(self.nuclei_image)
            
            # Start Nuclei container
            self.logger.info("Starting Nuclei container for vulnerability scanning")
            container = self.docker_client.containers.run(**container_config)
            self.nuclei_container = container
            
            yield container
            
        except DockerException as e:
            self.logger.error(f"Nuclei container error: {str(e)}")
            raise NucleiScannerError(f"Container execution failed: {str(e)}")
        finally:
            if container:
                try:
                    container.stop(timeout=30)
                    self.logger.info("Nuclei container stopped successfully")
                except Exception as e:
                    self.logger.warning(f"Error stopping Nuclei container: {str(e)}")
                finally:
                    try:
                        container.remove()
                        self.logger.info("Nuclei container removed")
                    except Exception as e:
                        self.logger.warning(f"Error removing Nuclei container: {str(e)}")
    
    def _build_nuclei_command(self, target_url: str) -> List[str]:
        """
        Build Nuclei command with enterprise security configuration.
        
        Args:
            target_url: Target URL for scanning
            
        Returns:
            List[str]: Nuclei command arguments
        """
        command = [
            'nuclei',
            '-u', target_url,
            '-json',  # JSON output format
            '-o', '/tmp/nuclei-output.json',
            '-severity', 'critical,high,medium,low,info',
            '-rate-limit', '50',  # Rate limit for responsible scanning
            '-timeout', '30',
            '-retries', '2',
            '-max-redirects', '5',
            '-disable-update-check',
            '-no-color',
            '-no-interactsh',  # Disable interactsh for CI/CD environments
            '-silent'
        ]
        
        # Add template categories based on configuration
        if hasattr(self.config, 'NUCLEI_TEMPLATE_CATEGORIES'):
            categories = self.config.NUCLEI_TEMPLATE_CATEGORIES
            if categories:
                command.extend(['-tags', ','.join(categories)])
        else:
            # Default comprehensive template categories
            default_categories = [
                'cve',
                'oast',
                'xss',
                'sqli',
                'rce',
                'lfi',
                'ssrf',
                'auth-bypass',
                'exposure',
                'misconfiguration',
                'injection',
                'traversal',
                'disclosure'
            ]
            command.extend(['-tags', ','.join(default_categories)])
        
        # Add custom templates if configured
        if hasattr(self.config, 'NUCLEI_CUSTOM_TEMPLATES'):
            custom_templates = self.config.NUCLEI_CUSTOM_TEMPLATES
            if custom_templates and os.path.exists(custom_templates):
                command.extend(['-templates', custom_templates])
        
        # Add exclusions for responsible testing
        exclusions = [
            'dos',  # Exclude denial-of-service tests
            'intrusive'  # Exclude intrusive tests
        ]
        command.extend(['-exclude-tags', ','.join(exclusions)])
        
        self.logger.debug(f"Nuclei command: {' '.join(command)}")
        return command
    
    def run_vulnerability_scan(self, target_url: str, 
                             timeout: int = 1800) -> Dict[str, Any]:
        """
        Execute comprehensive Nuclei vulnerability scan with enterprise configuration.
        
        Args:
            target_url: Target URL for vulnerability scanning
            timeout: Scan timeout in seconds (default: 30 minutes)
            
        Returns:
            Dict containing comprehensive scan results and vulnerability findings
        """
        scan_start_time = datetime.utcnow()
        
        try:
            self.logger.info(f"Starting Nuclei vulnerability scan for: {target_url}")
            
            # Validate target URL
            if not self._validate_target_url(target_url):
                return {
                    'scan_status': 'failed',
                    'error': f'Invalid target URL: {target_url}',
                    'timestamp': scan_start_time.isoformat()
                }
            
            scan_results = {
                'scan_status': 'running',
                'target_url': target_url,
                'start_time': scan_start_time.isoformat(),
                'nuclei_version': self.nuclei_version,
                'template_categories': [],
                'vulnerabilities': [],
                'scan_statistics': {},
                'compliance_assessment': {}
            }
            
            # Execute containerized Nuclei scan
            with self._nuclei_container_context(target_url) as container:
                # Monitor container execution
                scan_completed = self._monitor_scan_execution(container, timeout)
                
                if not scan_completed:
                    scan_results['scan_status'] = 'timeout'
                    scan_results['error'] = f'Scan timed out after {timeout} seconds'
                    return scan_results
                
                # Retrieve scan results
                scan_output = self._extract_scan_results(container)
                
                # Process and categorize vulnerabilities
                vulnerabilities = self._parse_nuclei_output(scan_output)
                scan_results['vulnerabilities'] = vulnerabilities
                
                # Generate scan statistics
                statistics = self._generate_scan_statistics(vulnerabilities)
                scan_results['scan_statistics'] = statistics
                
                # Perform compliance assessment
                compliance = self._assess_compliance(vulnerabilities)
                scan_results['compliance_assessment'] = compliance
                
                # Validate against security thresholds
                threshold_validation = self._validate_security_thresholds(vulnerabilities)
                scan_results['threshold_validation'] = threshold_validation
                
                scan_results['scan_status'] = 'completed'
                scan_results['end_time'] = datetime.utcnow().isoformat()
                scan_results['duration'] = (datetime.utcnow() - scan_start_time).total_seconds()
                
                self.logger.info(
                    f"Nuclei scan completed: {len(vulnerabilities)} vulnerabilities found"
                )
                
                return scan_results
                
        except Exception as e:
            error_msg = f"Nuclei vulnerability scan failed: {str(e)}"
            self.logger.error(error_msg)
            
            return {
                'scan_status': 'failed',
                'error': error_msg,
                'target_url': target_url,
                'start_time': scan_start_time.isoformat(),
                'end_time': datetime.utcnow().isoformat()
            }
    
    def _validate_target_url(self, target_url: str) -> bool:
        """
        Validate target URL for security scanning.
        
        Args:
            target_url: URL to validate
            
        Returns:
            bool: True if URL is valid for scanning
        """
        try:
            parsed = urlparse(target_url)
            
            # Check for valid scheme
            if parsed.scheme not in ['http', 'https']:
                return False
            
            # Check for valid hostname
            if not parsed.netloc:
                return False
            
            # Prevent scanning of localhost in production
            if hasattr(self.config, 'ENVIRONMENT') and self.config.ENVIRONMENT == 'production':
                localhost_indicators = ['localhost', '127.0.0.1', '0.0.0.0', '::1']
                if any(indicator in parsed.netloc for indicator in localhost_indicators):
                    self.logger.warning(f"Localhost scanning blocked in production: {target_url}")
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"URL validation error: {str(e)}")
            return False
    
    def _monitor_scan_execution(self, container: Container, timeout: int) -> bool:
        """
        Monitor Nuclei container execution with timeout handling.
        
        Args:
            container: Running Nuclei container
            timeout: Maximum execution time in seconds
            
        Returns:
            bool: True if scan completed successfully
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                container.reload()
                status = container.status
                
                if status == 'exited':
                    exit_code = container.attrs['State']['ExitCode']
                    if exit_code == 0:
                        self.logger.info("Nuclei scan completed successfully")
                        return True
                    else:
                        self.logger.error(f"Nuclei scan failed with exit code: {exit_code}")
                        return False
                
                elif status in ['dead', 'removing']:
                    self.logger.error(f"Nuclei container failed with status: {status}")
                    return False
                
                # Wait before next status check
                time.sleep(10)
                
            except Exception as e:
                self.logger.error(f"Error monitoring Nuclei container: {str(e)}")
                return False
        
        self.logger.warning(f"Nuclei scan timed out after {timeout} seconds")
        return False
    
    def _extract_scan_results(self, container: Container) -> str:
        """
        Extract scan results from Nuclei container.
        
        Args:
            container: Completed Nuclei container
            
        Returns:
            str: Raw scan output in JSON format
        """
        try:
            # Get container logs
            logs = container.logs(decode=True)
            
            # Try to extract output file
            try:
                output_archive, _ = container.get_archive('/tmp/nuclei-output.json')
                # Process tar archive to extract JSON content
                import tarfile
                import io
                
                tar_data = b''.join(output_archive)
                with tarfile.open(fileobj=io.BytesIO(tar_data)) as tar:
                    output_file = tar.extractfile('nuclei-output.json')
                    if output_file:
                        return output_file.read().decode('utf-8')
            except Exception as e:
                self.logger.debug(f"Could not extract output file: {str(e)}")
            
            # Fallback to parsing logs for JSON output
            json_lines = []
            for line in logs.split('\n'):
                line = line.strip()
                if line.startswith('{') and '"template-id"' in line:
                    json_lines.append(line)
            
            return '\n'.join(json_lines) if json_lines else logs
            
        except Exception as e:
            self.logger.error(f"Error extracting Nuclei results: {str(e)}")
            return ""
    
    def _parse_nuclei_output(self, scan_output: str) -> List[Dict[str, Any]]:
        """
        Parse Nuclei JSON output into structured vulnerability data.
        
        Args:
            scan_output: Raw Nuclei scan output
            
        Returns:
            List[Dict]: Parsed vulnerability findings
        """
        vulnerabilities = []
        
        if not scan_output.strip():
            return vulnerabilities
        
        try:
            # Process each JSON line
            for line in scan_output.strip().split('\n'):
                line = line.strip()
                if not line or not line.startswith('{'):
                    continue
                
                try:
                    result = json.loads(line)
                    
                    # Extract vulnerability information
                    vulnerability = {
                        'id': str(uuid.uuid4()),
                        'template_id': result.get('template-id', 'unknown'),
                        'template_name': result.get('info', {}).get('name', 'Unknown'),
                        'severity': result.get('info', {}).get('severity', 'info').lower(),
                        'description': result.get('info', {}).get('description', ''),
                        'classification': result.get('info', {}).get('classification', {}),
                        'tags': result.get('info', {}).get('tags', []),
                        'reference': result.get('info', {}).get('reference', []),
                        'matched_at': result.get('matched-at', ''),
                        'extracted_results': result.get('extracted-results', []),
                        'curl_command': result.get('curl-command', ''),
                        'timestamp': datetime.utcnow().isoformat(),
                        'source': 'nuclei'
                    }
                    
                    # Add request/response details if available
                    if 'request' in result:
                        vulnerability['request'] = result['request']
                    if 'response' in result:
                        vulnerability['response'] = result['response']
                    
                    # Map Nuclei classification to our schema
                    vulnerability['cwe_id'] = self._extract_cwe_id(vulnerability['classification'])
                    vulnerability['owasp_category'] = self._map_to_owasp_category(vulnerability)
                    
                    vulnerabilities.append(vulnerability)
                    
                except json.JSONDecodeError as e:
                    self.logger.debug(f"Failed to parse JSON line: {line[:100]}... Error: {str(e)}")
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error parsing Nuclei output: {str(e)}")
        
        self.logger.info(f"Parsed {len(vulnerabilities)} vulnerabilities from Nuclei output")
        return vulnerabilities
    
    def _extract_cwe_id(self, classification: Dict[str, Any]) -> Optional[str]:
        """Extract CWE ID from Nuclei classification data."""
        if not classification:
            return None
        
        # Check for direct CWE ID
        cwe_id = classification.get('cwe-id')
        if cwe_id:
            return f"CWE-{cwe_id}" if not str(cwe_id).startswith('CWE-') else str(cwe_id)
        
        # Check in CVE mappings
        cve_list = classification.get('cve-id', [])
        if cve_list:
            # For now, return the first CVE; could be enhanced with CVE-to-CWE mapping
            return f"CVE-{cve_list[0]}" if cve_list else None
        
        return None
    
    def _map_to_owasp_category(self, vulnerability: Dict[str, Any]) -> Optional[str]:
        """
        Map vulnerability to OWASP Top 10 category.
        
        Args:
            vulnerability: Vulnerability data
            
        Returns:
            Optional[str]: OWASP category if mappable
        """
        tags = vulnerability.get('tags', [])
        template_id = vulnerability.get('template_id', '').lower()
        
        # OWASP Top 10 2021 mapping
        owasp_mappings = {
            'A01_2021_Broken_Access_Control': [
                'auth-bypass', 'privilege-escalation', 'idor', 'directory-traversal'
            ],
            'A02_2021_Cryptographic_Failures': [
                'ssl', 'tls', 'weak-crypto', 'encryption'
            ],
            'A03_2021_Injection': [
                'sqli', 'xss', 'rce', 'command-injection', 'ldap-injection'
            ],
            'A04_2021_Insecure_Design': [
                'design-flaw', 'business-logic'
            ],
            'A05_2021_Security_Misconfiguration': [
                'misconfiguration', 'default-login', 'exposed-panel'
            ],
            'A06_2021_Vulnerable_Components': [
                'cve', 'outdated-software'
            ],
            'A07_2021_Identification_Authentication_Failures': [
                'weak-password', 'brute-force', 'session-fixation'
            ],
            'A08_2021_Software_Data_Integrity_Failures': [
                'deserialization', 'integrity'
            ],
            'A09_2021_Security_Logging_Monitoring_Failures': [
                'log-exposure', 'monitoring'
            ],
            'A10_2021_Server_Side_Request_Forgery': [
                'ssrf'
            ]
        }
        
        # Check tags and template ID for OWASP mapping
        for owasp_category, indicators in owasp_mappings.items():
            if any(indicator in tags for indicator in indicators) or \
               any(indicator in template_id for indicator in indicators):
                return owasp_category
        
        return None
    
    def _generate_scan_statistics(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate comprehensive scan statistics.
        
        Args:
            vulnerabilities: List of vulnerability findings
            
        Returns:
            Dict: Scan statistics and metrics
        """
        statistics = {
            'total_vulnerabilities': len(vulnerabilities),
            'severity_distribution': {},
            'category_distribution': {},
            'template_usage': {},
            'owasp_coverage': {},
            'cwe_distribution': {}
        }
        
        # Initialize severity counts
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            statistics['severity_distribution'][severity] = 0
        
        # Process vulnerabilities
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info')
            template_id = vuln.get('template_id', 'unknown')
            owasp_category = vuln.get('owasp_category')
            cwe_id = vuln.get('cwe_id')
            
            # Count severity
            if severity in statistics['severity_distribution']:
                statistics['severity_distribution'][severity] += 1
            
            # Count template usage
            statistics['template_usage'][template_id] = \
                statistics['template_usage'].get(template_id, 0) + 1
            
            # Count OWASP categories
            if owasp_category:
                statistics['owasp_coverage'][owasp_category] = \
                    statistics['owasp_coverage'].get(owasp_category, 0) + 1
            
            # Count CWE distribution
            if cwe_id:
                statistics['cwe_distribution'][cwe_id] = \
                    statistics['cwe_distribution'].get(cwe_id, 0) + 1
        
        # Calculate additional metrics
        statistics['critical_high_count'] = (
            statistics['severity_distribution']['critical'] +
            statistics['severity_distribution']['high']
        )
        
        statistics['risk_score'] = self._calculate_risk_score(statistics['severity_distribution'])
        
        return statistics
    
    def _calculate_risk_score(self, severity_distribution: Dict[str, int]) -> float:
        """
        Calculate overall risk score based on vulnerability severity distribution.
        
        Args:
            severity_distribution: Count of vulnerabilities by severity
            
        Returns:
            float: Risk score from 0-100
        """
        severity_weights = {
            'critical': 10.0,
            'high': 7.0,
            'medium': 4.0,
            'low': 1.0,
            'info': 0.1
        }
        
        total_score = 0.0
        for severity, count in severity_distribution.items():
            weight = severity_weights.get(severity, 0.0)
            total_score += count * weight
        
        # Normalize to 0-100 scale (assuming max 50 critical vulnerabilities as ceiling)
        max_possible_score = 50 * severity_weights['critical']
        normalized_score = min(100.0, (total_score / max_possible_score) * 100)
        
        return round(normalized_score, 2)
    
    def _assess_compliance(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Assess compliance against security frameworks.
        
        Args:
            vulnerabilities: List of vulnerability findings
            
        Returns:
            Dict: Compliance assessment results
        """
        compliance_assessment = {
            'owasp_top_10_compliance': {},
            'sans_top_25_compliance': {},
            'overall_compliance_score': 0.0,
            'compliance_violations': []
        }
        
        # OWASP Top 10 compliance assessment
        owasp_categories = [
            'A01_2021_Broken_Access_Control',
            'A02_2021_Cryptographic_Failures',
            'A03_2021_Injection',
            'A04_2021_Insecure_Design',
            'A05_2021_Security_Misconfiguration',
            'A06_2021_Vulnerable_Components',
            'A07_2021_Identification_Authentication_Failures',
            'A08_2021_Software_Data_Integrity_Failures',
            'A09_2021_Security_Logging_Monitoring_Failures',
            'A10_2021_Server_Side_Request_Forgery'
        ]
        
        for category in owasp_categories:
            category_vulns = [v for v in vulnerabilities if v.get('owasp_category') == category]
            critical_high_count = len([
                v for v in category_vulns 
                if v.get('severity') in ['critical', 'high']
            ])
            
            compliance_assessment['owasp_top_10_compliance'][category] = {
                'total_vulnerabilities': len(category_vulns),
                'critical_high_count': critical_high_count,
                'compliant': critical_high_count == 0
            }
            
            if critical_high_count > 0:
                compliance_assessment['compliance_violations'].append({
                    'framework': 'OWASP Top 10',
                    'category': category,
                    'violation_count': critical_high_count,
                    'severity': 'high' if critical_high_count > 0 else 'medium'
                })
        
        # Calculate overall compliance score
        total_categories = len(owasp_categories)
        compliant_categories = len([
            cat_data for cat_data in compliance_assessment['owasp_top_10_compliance'].values()
            if cat_data['compliant']
        ])
        
        compliance_assessment['overall_compliance_score'] = \
            (compliant_categories / total_categories) * 100 if total_categories > 0 else 100.0
        
        return compliance_assessment
    
    def _validate_security_thresholds(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate vulnerability findings against configured security thresholds.
        
        Args:
            vulnerabilities: List of vulnerability findings
            
        Returns:
            Dict: Threshold validation results
        """
        threshold_validation = {
            'passed': True,
            'violations': [],
            'severity_counts': {},
            'threshold_limits': {}
        }
        
        # Count vulnerabilities by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        threshold_validation['severity_counts'] = severity_counts
        
        # Define security thresholds (configurable via config)
        default_thresholds = {
            'critical': 0,    # Zero tolerance for critical
            'high': 0,        # Zero tolerance for high
            'medium': 5,      # Maximum 5 medium severity
            'low': 20,        # Maximum 20 low severity
            'info': 100       # Maximum 100 informational
        }
        
        # Use configured thresholds or defaults
        if hasattr(self.config, 'NUCLEI_SEVERITY_THRESHOLDS'):
            thresholds = self.config.NUCLEI_SEVERITY_THRESHOLDS
        else:
            thresholds = default_thresholds
        
        threshold_validation['threshold_limits'] = thresholds
        
        # Check each severity against thresholds
        for severity, count in severity_counts.items():
            threshold = thresholds.get(severity, 0)
            
            if count > threshold:
                threshold_validation['passed'] = False
                threshold_validation['violations'].append({
                    'severity': severity,
                    'count': count,
                    'threshold': threshold,
                    'excess': count - threshold,
                    'message': f"Found {count} {severity} vulnerabilities, threshold is {threshold}"
                })
        
        return threshold_validation


class EnhancedOWASPZAPScanner(OWASPZAPScanner):
    """
    Enhanced OWASP ZAP scanner with enterprise features and comprehensive reporting.
    
    Extends the base OWASPZAPScanner with advanced enterprise features including
    compliance reporting, vulnerability correlation, and CI/CD integration
    per Section 6.4.5 and Section 6.4.6 requirements.
    """
    
    def __init__(self, config: SecurityTestConfig):
        """
        Initialize enhanced OWASP ZAP scanner.
        
        Args:
            config: Security test configuration instance
        """
        super().__init__(config)
        self.compliance_validator = ComplianceValidator(config)
        self.vulnerability_correlator = VulnerabilityCorrelator()
        
    def run_comprehensive_scan(self, target_url: str, 
                             scan_policies: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Execute comprehensive DAST scan with enterprise reporting.
        
        Args:
            target_url: Target URL for scanning
            scan_policies: Optional list of custom scan policies
            
        Returns:
            Dict containing comprehensive scan results with enterprise metrics
        """
        try:
            self.logger.info(f"Starting comprehensive OWASP ZAP scan for: {target_url}")
            
            # Run base ZAP scan
            base_results = self.run_security_scan(target_url)
            
            if base_results.get('scan_status') != 'completed':
                return base_results
            
            # Enhance results with enterprise features
            enhanced_results = self._enhance_scan_results(base_results, target_url)
            
            # Add compliance assessment
            compliance_results = self._assess_zap_compliance(enhanced_results)
            enhanced_results['compliance_assessment'] = compliance_results
            
            # Generate executive summary
            executive_summary = self._generate_executive_summary(enhanced_results)
            enhanced_results['executive_summary'] = executive_summary
            
            self.logger.info("Comprehensive OWASP ZAP scan completed successfully")
            return enhanced_results
            
        except Exception as e:
            error_msg = f"Comprehensive ZAP scan failed: {str(e)}"
            self.logger.error(error_msg)
            return {
                'scan_status': 'failed',
                'error': error_msg,
                'target_url': target_url,
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _enhance_scan_results(self, base_results: Dict[str, Any], 
                            target_url: str) -> Dict[str, Any]:
        """
        Enhance base ZAP results with additional enterprise metrics.
        
        Args:
            base_results: Base scan results from ZAP
            target_url: Target URL that was scanned
            
        Returns:
            Dict: Enhanced results with additional metrics
        """
        enhanced_results = base_results.copy()
        
        # Add scan metadata
        enhanced_results['scan_metadata'] = {
            'scanner': 'OWASP ZAP Enhanced',
            'version': '2.14+',
            'target_url': target_url,
            'scan_type': 'DAST',
            'enhancement_level': 'enterprise'
        }
        
        # Process alerts for enhanced categorization
        alerts = enhanced_results.get('alerts', {}).get('alerts', [])
        
        # Categorize alerts by OWASP Top 10
        owasp_categorization = self._categorize_by_owasp(alerts)
        enhanced_results['owasp_categorization'] = owasp_categorization
        
        # Add risk assessment
        risk_assessment = self._calculate_risk_assessment(alerts)
        enhanced_results['risk_assessment'] = risk_assessment
        
        # Add remediation priorities
        remediation_priorities = self._prioritize_remediation(alerts)
        enhanced_results['remediation_priorities'] = remediation_priorities
        
        return enhanced_results
    
    def _categorize_by_owasp(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Categorize ZAP alerts by OWASP Top 10 categories.
        
        Args:
            alerts: List of ZAP alert findings
            
        Returns:
            Dict: OWASP categorization results
        """
        owasp_mapping = {
            'A01_2021_Broken_Access_Control': [
                'Path Traversal', 'Directory Browsing', 'Access Control'
            ],
            'A02_2021_Cryptographic_Failures': [
                'Weak Encryption', 'SSL/TLS', 'Cryptography'
            ],
            'A03_2021_Injection': [
                'SQL Injection', 'XSS', 'Command Injection', 'LDAP Injection'
            ],
            'A05_2021_Security_Misconfiguration': [
                'Server Misconfiguration', 'Default Configuration'
            ],
            'A06_2021_Vulnerable_Components': [
                'Outdated Software', 'Known Vulnerabilities'
            ],
            'A07_2021_Identification_Authentication_Failures': [
                'Authentication', 'Session Management', 'Weak Password'
            ]
        }
        
        categorization = {}
        for category in owasp_mapping.keys():
            categorization[category] = {
                'alerts': [],
                'count': 0,
                'risk_levels': {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
            }
        
        # Categorize each alert
        for alert in alerts:
            alert_name = alert.get('name', '')
            risk_level = alert.get('risk', 'Informational')
            
            categorized = False
            for category, keywords in owasp_mapping.items():
                if any(keyword.lower() in alert_name.lower() for keyword in keywords):
                    categorization[category]['alerts'].append(alert)
                    categorization[category]['count'] += 1
                    categorization[category]['risk_levels'][risk_level] += 1
                    categorized = True
                    break
            
            # Add to miscellaneous if not categorized
            if not categorized:
                if 'Miscellaneous' not in categorization:
                    categorization['Miscellaneous'] = {
                        'alerts': [],
                        'count': 0,
                        'risk_levels': {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
                    }
                categorization['Miscellaneous']['alerts'].append(alert)
                categorization['Miscellaneous']['count'] += 1
                categorization['Miscellaneous']['risk_levels'][risk_level] += 1
        
        return categorization
    
    def _calculate_risk_assessment(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate comprehensive risk assessment from ZAP alerts.
        
        Args:
            alerts: List of ZAP alert findings
            
        Returns:
            Dict: Risk assessment metrics
        """
        risk_weights = {'High': 8, 'Medium': 4, 'Low': 2, 'Informational': 1}
        risk_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
        
        total_risk_score = 0
        for alert in alerts:
            risk_level = alert.get('risk', 'Informational')
            if risk_level in risk_counts:
                risk_counts[risk_level] += 1
                total_risk_score += risk_weights[risk_level]
        
        # Calculate risk rating
        if total_risk_score >= 50:
            risk_rating = 'Critical'
        elif total_risk_score >= 30:
            risk_rating = 'High'
        elif total_risk_score >= 15:
            risk_rating = 'Medium'
        elif total_risk_score > 0:
            risk_rating = 'Low'
        else:
            risk_rating = 'Minimal'
        
        return {
            'total_risk_score': total_risk_score,
            'risk_rating': risk_rating,
            'risk_distribution': risk_counts,
            'critical_issues': risk_counts['High'],
            'needs_immediate_attention': risk_counts['High'] > 0 or risk_counts['Medium'] > 5
        }
    
    def _prioritize_remediation(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Prioritize remediation activities based on risk and impact.
        
        Args:
            alerts: List of ZAP alert findings
            
        Returns:
            List: Prioritized remediation recommendations
        """
        priorities = []
        
        # Group alerts by type and risk level
        alert_groups = {}
        for alert in alerts:
            alert_type = alert.get('name', 'Unknown')
            risk_level = alert.get('risk', 'Informational')
            
            if alert_type not in alert_groups:
                alert_groups[alert_type] = {
                    'instances': [],
                    'max_risk': 'Informational',
                    'count': 0
                }
            
            alert_groups[alert_type]['instances'].append(alert)
            alert_groups[alert_type]['count'] += 1
            
            # Update max risk level
            risk_hierarchy = ['High', 'Medium', 'Low', 'Informational']
            if (risk_hierarchy.index(risk_level) < 
                risk_hierarchy.index(alert_groups[alert_type]['max_risk'])):
                alert_groups[alert_type]['max_risk'] = risk_level
        
        # Create prioritized recommendations
        risk_order = ['High', 'Medium', 'Low', 'Informational']
        for risk_level in risk_order:
            for alert_type, group_data in alert_groups.items():
                if group_data['max_risk'] == risk_level:
                    priority = {
                        'alert_type': alert_type,
                        'risk_level': risk_level,
                        'instance_count': group_data['count'],
                        'priority_score': self._calculate_priority_score(group_data),
                        'remediation_effort': self._estimate_remediation_effort(alert_type),
                        'business_impact': self._assess_business_impact(alert_type, risk_level)
                    }
                    priorities.append(priority)
        
        # Sort by priority score
        priorities.sort(key=lambda x: x['priority_score'], reverse=True)
        
        return priorities
    
    def _calculate_priority_score(self, group_data: Dict[str, Any]) -> int:
        """Calculate priority score for remediation grouping."""
        risk_scores = {'High': 100, 'Medium': 50, 'Low': 25, 'Informational': 10}
        base_score = risk_scores.get(group_data['max_risk'], 10)
        
        # Multiply by instance count (more instances = higher priority)
        count_multiplier = min(group_data['count'] * 0.1, 2.0)  # Cap at 2x
        
        return int(base_score * (1 + count_multiplier))
    
    def _estimate_remediation_effort(self, alert_type: str) -> str:
        """Estimate remediation effort level."""
        high_effort_types = ['SQL Injection', 'XSS', 'Authentication Bypass']
        medium_effort_types = ['Session Management', 'Configuration']
        
        if any(he_type.lower() in alert_type.lower() for he_type in high_effort_types):
            return 'High'
        elif any(me_type.lower() in alert_type.lower() for me_type in medium_effort_types):
            return 'Medium'
        else:
            return 'Low'
    
    def _assess_business_impact(self, alert_type: str, risk_level: str) -> str:
        """Assess potential business impact."""
        high_impact_types = ['SQL Injection', 'Authentication', 'Authorization']
        
        if risk_level == 'High' and any(hi_type.lower() in alert_type.lower() 
                                       for hi_type in high_impact_types):
            return 'Critical'
        elif risk_level in ['High', 'Medium']:
            return 'High'
        elif risk_level == 'Low':
            return 'Medium'
        else:
            return 'Low'
    
    def _assess_zap_compliance(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess compliance based on ZAP scan results.
        
        Args:
            scan_results: Enhanced scan results
            
        Returns:
            Dict: Compliance assessment
        """
        # Use the base compliance validator
        return self.compliance_validator.validate_compliance({
            'zap_enhanced': scan_results
        })
    
    def _generate_executive_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate executive summary for business stakeholders.
        
        Args:
            scan_results: Enhanced scan results
            
        Returns:
            Dict: Executive summary
        """
        risk_assessment = scan_results.get('risk_assessment', {})
        alerts = scan_results.get('alerts', {})
        compliance = scan_results.get('compliance_assessment', {})
        
        return {
            'overall_security_posture': risk_assessment.get('risk_rating', 'Unknown'),
            'critical_findings': risk_assessment.get('critical_issues', 0),
            'total_vulnerabilities': alerts.get('total_alerts', 0),
            'compliance_score': compliance.get('overall_compliance_score', 0),
            'immediate_action_required': risk_assessment.get('needs_immediate_attention', False),
            'key_recommendations': self._generate_key_recommendations(scan_results),
            'next_steps': self._generate_next_steps(risk_assessment)
        }
    
    def _generate_key_recommendations(self, scan_results: Dict[str, Any]) -> List[str]:
        """Generate key security recommendations."""
        recommendations = []
        
        remediation_priorities = scan_results.get('remediation_priorities', [])
        if remediation_priorities:
            top_priority = remediation_priorities[0]
            recommendations.append(
                f"Address {top_priority['alert_type']} vulnerabilities "
                f"({top_priority['instance_count']} instances)"
            )
        
        risk_assessment = scan_results.get('risk_assessment', {})
        if risk_assessment.get('critical_issues', 0) > 0:
            recommendations.append("Immediate remediation required for high-risk vulnerabilities")
        
        compliance = scan_results.get('compliance_assessment', {})
        if compliance.get('overall_compliance_score', 100) < 80:
            recommendations.append("Improve security compliance through systematic vulnerability remediation")
        
        if not recommendations:
            recommendations.append("Continue regular security assessments to maintain security posture")
        
        return recommendations
    
    def _generate_next_steps(self, risk_assessment: Dict[str, Any]) -> List[str]:
        """Generate actionable next steps."""
        next_steps = []
        
        if risk_assessment.get('needs_immediate_attention', False):
            next_steps.append("Schedule emergency security review within 24 hours")
            next_steps.append("Implement temporary mitigations for critical vulnerabilities")
        
        next_steps.extend([
            "Review detailed vulnerability report with development team",
            "Create remediation timeline with priority assignments",
            "Schedule follow-up security assessment after remediation"
        ])
        
        return next_steps


class VulnerabilityCorrelator:
    """
    Advanced vulnerability correlation engine for cross-tool analysis.
    
    Correlates findings from multiple security tools (ZAP, Nuclei, Bandit, Safety)
    to provide comprehensive vulnerability analysis and reduce false positives.
    """
    
    def __init__(self):
        """Initialize vulnerability correlator."""
        self.logger = logging.getLogger(f"{__name__}.VulnerabilityCorrelator")
    
    def correlate_findings(self, scan_results: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """
        Correlate findings from multiple security scanning tools.
        
        Args:
            scan_results: Dictionary mapping tool names to their vulnerability findings
            
        Returns:
            Dict: Correlated vulnerability analysis
        """
        correlation_results = {
            'correlated_vulnerabilities': [],
            'unique_findings': {},
            'correlation_statistics': {},
            'confidence_scores': {},
            'recommended_actions': []
        }
        
        try:
            # Extract vulnerabilities from each tool
            all_findings = {}
            for tool_name, findings in scan_results.items():
                all_findings[tool_name] = self._normalize_findings(findings, tool_name)
            
            # Perform correlation analysis
            correlated_vulns = self._perform_correlation(all_findings)
            correlation_results['correlated_vulnerabilities'] = correlated_vulns
            
            # Identify unique findings
            unique_findings = self._identify_unique_findings(all_findings, correlated_vulns)
            correlation_results['unique_findings'] = unique_findings
            
            # Calculate correlation statistics
            statistics = self._calculate_correlation_statistics(all_findings, correlated_vulns)
            correlation_results['correlation_statistics'] = statistics
            
            # Generate confidence scores
            confidence_scores = self._calculate_confidence_scores(correlated_vulns)
            correlation_results['confidence_scores'] = confidence_scores
            
            # Generate recommendations
            recommendations = self._generate_recommendations(correlated_vulns, unique_findings)
            correlation_results['recommended_actions'] = recommendations
            
            self.logger.info("Vulnerability correlation completed successfully")
            return correlation_results
            
        except Exception as e:
            self.logger.error(f"Vulnerability correlation failed: {str(e)}")
            return correlation_results
    
    def _normalize_findings(self, findings: List[Dict[str, Any]], 
                          tool_name: str) -> List[Dict[str, Any]]:
        """
        Normalize findings from different tools to common format.
        
        Args:
            findings: Raw findings from security tool
            tool_name: Name of the security tool
            
        Returns:
            List: Normalized vulnerability findings
        """
        normalized = []
        
        for finding in findings:
            normalized_finding = {
                'id': finding.get('id', str(uuid.uuid4())),
                'source_tool': tool_name,
                'title': self._extract_title(finding, tool_name),
                'description': self._extract_description(finding, tool_name),
                'severity': self._normalize_severity(finding, tool_name),
                'category': self._extract_category(finding, tool_name),
                'location': self._extract_location(finding, tool_name),
                'cwe_id': self._extract_cwe(finding, tool_name),
                'owasp_category': self._extract_owasp_category(finding, tool_name),
                'confidence': self._extract_confidence(finding, tool_name),
                'raw_finding': finding
            }
            normalized.append(normalized_finding)
        
        return normalized
    
    def _extract_title(self, finding: Dict[str, Any], tool_name: str) -> str:
        """Extract vulnerability title from tool-specific finding."""
        if tool_name == 'nuclei':
            return finding.get('template_name', 'Unknown Nuclei Finding')
        elif tool_name == 'zap':
            return finding.get('name', 'Unknown ZAP Finding')
        elif tool_name == 'bandit':
            return finding.get('test_name', 'Unknown Bandit Finding')
        else:
            return finding.get('title', finding.get('name', 'Unknown Finding'))
    
    def _extract_description(self, finding: Dict[str, Any], tool_name: str) -> str:
        """Extract vulnerability description from tool-specific finding."""
        return finding.get('description', finding.get('desc', ''))
    
    def _normalize_severity(self, finding: Dict[str, Any], tool_name: str) -> str:
        """Normalize severity levels across tools."""
        severity_map = {
            'zap': {
                'High': 'high',
                'Medium': 'medium', 
                'Low': 'low',
                'Informational': 'info'
            },
            'nuclei': {
                'critical': 'critical',
                'high': 'high',
                'medium': 'medium',
                'low': 'low',
                'info': 'info'
            },
            'bandit': {
                'HIGH': 'high',
                'MEDIUM': 'medium',
                'LOW': 'low'
            }
        }
        
        raw_severity = finding.get('severity', finding.get('risk', 'info'))
        tool_map = severity_map.get(tool_name, {})
        return tool_map.get(raw_severity, str(raw_severity).lower())
    
    def _extract_category(self, finding: Dict[str, Any], tool_name: str) -> str:
        """Extract vulnerability category from tool-specific finding."""
        if tool_name == 'nuclei':
            tags = finding.get('tags', [])
            return tags[0] if tags else 'miscellaneous'
        elif tool_name == 'zap':
            return finding.get('pluginId', 'unknown')
        else:
            return finding.get('category', 'unknown')
    
    def _extract_location(self, finding: Dict[str, Any], tool_name: str) -> str:
        """Extract vulnerability location from tool-specific finding."""
        if tool_name == 'nuclei':
            return finding.get('matched_at', '')
        elif tool_name == 'zap':
            return finding.get('url', '')
        elif tool_name == 'bandit':
            return f"{finding.get('filename', '')}:{finding.get('line_number', '')}"
        else:
            return finding.get('location', '')
    
    def _extract_cwe(self, finding: Dict[str, Any], tool_name: str) -> Optional[str]:
        """Extract CWE ID from tool-specific finding."""
        return finding.get('cwe_id', finding.get('cwe'))
    
    def _extract_owasp_category(self, finding: Dict[str, Any], tool_name: str) -> Optional[str]:
        """Extract OWASP category from tool-specific finding."""
        return finding.get('owasp_category')
    
    def _extract_confidence(self, finding: Dict[str, Any], tool_name: str) -> str:
        """Extract confidence level from tool-specific finding."""
        confidence_map = {
            'zap': {
                'High': 'high',
                'Medium': 'medium',
                'Low': 'low'
            },
            'bandit': {
                'HIGH': 'high',
                'MEDIUM': 'medium', 
                'LOW': 'low'
            }
        }
        
        raw_confidence = finding.get('confidence', 'medium')
        tool_map = confidence_map.get(tool_name, {})
        return tool_map.get(raw_confidence, 'medium')
    
    def _perform_correlation(self, all_findings: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """
        Perform correlation analysis across findings from different tools.
        
        Args:
            all_findings: Normalized findings from all tools
            
        Returns:
            List: Correlated vulnerability groups
        """
        correlated_vulns = []
        processed_findings = set()
        
        # Compare findings across tools
        tools = list(all_findings.keys())
        for i, tool1 in enumerate(tools):
            for j, tool2 in enumerate(tools[i+1:], i+1):
                correlations = self._correlate_tool_findings(
                    all_findings[tool1], 
                    all_findings[tool2],
                    tool1,
                    tool2
                )
                
                for correlation in correlations:
                    # Mark findings as processed
                    for finding in correlation['findings']:
                        processed_findings.add(finding['id'])
                    
                    correlated_vulns.append(correlation)
        
        return correlated_vulns
    
    def _correlate_tool_findings(self, findings1: List[Dict[str, Any]], 
                                findings2: List[Dict[str, Any]],
                                tool1: str, tool2: str) -> List[Dict[str, Any]]:
        """
        Correlate findings between two specific tools.
        
        Args:
            findings1: Findings from first tool
            findings2: Findings from second tool
            tool1: Name of first tool
            tool2: Name of second tool
            
        Returns:
            List: Correlated findings between the two tools
        """
        correlations = []
        
        for finding1 in findings1:
            for finding2 in findings2:
                correlation_score = self._calculate_correlation_score(finding1, finding2)
                
                if correlation_score >= 0.7:  # Threshold for correlation
                    correlation = {
                        'correlation_id': str(uuid.uuid4()),
                        'correlation_score': correlation_score,
                        'tools': [tool1, tool2],
                        'findings': [finding1, finding2],
                        'combined_severity': self._combine_severity(
                            finding1['severity'], 
                            finding2['severity']
                        ),
                        'correlation_factors': self._identify_correlation_factors(
                            finding1, 
                            finding2
                        )
                    }
                    correlations.append(correlation)
        
        return correlations
    
    def _calculate_correlation_score(self, finding1: Dict[str, Any], 
                                   finding2: Dict[str, Any]) -> float:
        """
        Calculate correlation score between two findings.
        
        Args:
            finding1: First vulnerability finding
            finding2: Second vulnerability finding
            
        Returns:
            float: Correlation score from 0.0 to 1.0
        """
        score = 0.0
        
        # Location similarity (30% weight)
        location_similarity = self._calculate_location_similarity(
            finding1.get('location', ''),
            finding2.get('location', '')
        )
        score += location_similarity * 0.3
        
        # Category similarity (25% weight)
        category_similarity = self._calculate_category_similarity(
            finding1.get('category', ''),
            finding2.get('category', '')
        )
        score += category_similarity * 0.25
        
        # CWE similarity (20% weight)
        cwe_similarity = self._calculate_cwe_similarity(
            finding1.get('cwe_id'),
            finding2.get('cwe_id')
        )
        score += cwe_similarity * 0.2
        
        # Title similarity (15% weight)
        title_similarity = self._calculate_text_similarity(
            finding1.get('title', ''),
            finding2.get('title', '')
        )
        score += title_similarity * 0.15
        
        # OWASP category similarity (10% weight)
        owasp_similarity = self._calculate_owasp_similarity(
            finding1.get('owasp_category'),
            finding2.get('owasp_category')
        )
        score += owasp_similarity * 0.1
        
        return min(1.0, score)
    
    def _calculate_location_similarity(self, location1: str, location2: str) -> float:
        """Calculate similarity between vulnerability locations."""
        if not location1 or not location2:
            return 0.0
        
        # Exact match
        if location1 == location2:
            return 1.0
        
        # URL path similarity for web vulnerabilities
        if location1.startswith('http') and location2.startswith('http'):
            return self._calculate_url_similarity(location1, location2)
        
        # File path similarity for code vulnerabilities
        if '/' in location1 and '/' in location2:
            return self._calculate_path_similarity(location1, location2)
        
        # Text similarity fallback
        return self._calculate_text_similarity(location1, location2)
    
    def _calculate_url_similarity(self, url1: str, url2: str) -> float:
        """Calculate similarity between URLs."""
        try:
            from urllib.parse import urlparse
            parsed1 = urlparse(url1)
            parsed2 = urlparse(url2)
            
            # Same host and path
            if parsed1.netloc == parsed2.netloc and parsed1.path == parsed2.path:
                return 0.9
            
            # Same host, different path
            if parsed1.netloc == parsed2.netloc:
                return 0.5
            
            return 0.0
        except:
            return 0.0
    
    def _calculate_path_similarity(self, path1: str, path2: str) -> float:
        """Calculate similarity between file paths."""
        path1_parts = path1.split('/')
        path2_parts = path2.split('/')
        
        # Same file
        if path1_parts[-1] == path2_parts[-1]:
            return 0.8
        
        # Same directory
        if len(path1_parts) > 1 and len(path2_parts) > 1:
            if path1_parts[-2] == path2_parts[-2]:
                return 0.4
        
        return 0.0
    
    def _calculate_category_similarity(self, category1: str, category2: str) -> float:
        """Calculate similarity between vulnerability categories."""
        if not category1 or not category2:
            return 0.0
        
        if category1.lower() == category2.lower():
            return 1.0
        
        # Check for related categories
        related_categories = {
            'injection': ['sql-injection', 'command-injection', 'xss'],
            'auth': ['authentication', 'authorization', 'session'],
            'crypto': ['ssl', 'tls', 'encryption']
        }
        
        for group, categories in related_categories.items():
            if (any(cat in category1.lower() for cat in categories) and
                any(cat in category2.lower() for cat in categories)):
                return 0.6
        
        return 0.0
    
    def _calculate_cwe_similarity(self, cwe1: Optional[str], cwe2: Optional[str]) -> float:
        """Calculate similarity between CWE IDs."""
        if not cwe1 or not cwe2:
            return 0.0
        
        if cwe1 == cwe2:
            return 1.0
        
        return 0.0
    
    def _calculate_text_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity between text strings."""
        if not text1 or not text2:
            return 0.0
        
        # Simple Jaccard similarity for demonstration
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())
        
        intersection = words1.intersection(words2)
        union = words1.union(words2)
        
        if not union:
            return 0.0
        
        return len(intersection) / len(union)
    
    def _calculate_owasp_similarity(self, owasp1: Optional[str], owasp2: Optional[str]) -> float:
        """Calculate similarity between OWASP categories."""
        if not owasp1 or not owasp2:
            return 0.0
        
        if owasp1 == owasp2:
            return 1.0
        
        return 0.0
    
    def _combine_severity(self, severity1: str, severity2: str) -> str:
        """Combine severity levels from two findings."""
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        
        try:
            index1 = severity_order.index(severity1.lower())
            index2 = severity_order.index(severity2.lower())
            # Return the higher severity (lower index)
            return severity_order[min(index1, index2)]
        except ValueError:
            return 'medium'  # Default if unable to determine
    
    def _identify_correlation_factors(self, finding1: Dict[str, Any], 
                                    finding2: Dict[str, Any]) -> List[str]:
        """Identify factors that contributed to correlation."""
        factors = []
        
        if finding1.get('location') == finding2.get('location'):
            factors.append('identical_location')
        
        if finding1.get('category') == finding2.get('category'):
            factors.append('same_category')
        
        if finding1.get('cwe_id') == finding2.get('cwe_id'):
            factors.append('same_cwe')
        
        if finding1.get('owasp_category') == finding2.get('owasp_category'):
            factors.append('same_owasp_category')
        
        return factors
    
    def _identify_unique_findings(self, all_findings: Dict[str, List[Dict[str, Any]]],
                                correlated_vulns: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Identify findings that were not correlated with others."""
        # Get IDs of all correlated findings
        correlated_ids = set()
        for correlation in correlated_vulns:
            for finding in correlation['findings']:
                correlated_ids.add(finding['id'])
        
        # Find unique findings for each tool
        unique_findings = {}
        for tool_name, findings in all_findings.items():
            unique_findings[tool_name] = [
                finding for finding in findings 
                if finding['id'] not in correlated_ids
            ]
        
        return unique_findings
    
    def _calculate_correlation_statistics(self, all_findings: Dict[str, List[Dict[str, Any]]],
                                        correlated_vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate correlation statistics."""
        total_findings = sum(len(findings) for findings in all_findings.values())
        correlated_count = sum(len(correlation['findings']) for correlation in correlated_vulns)
        
        return {
            'total_findings': total_findings,
            'correlated_findings': correlated_count,
            'unique_findings': total_findings - correlated_count,
            'correlation_rate': (correlated_count / total_findings * 100) if total_findings > 0 else 0,
            'correlation_groups': len(correlated_vulns)
        }
    
    def _calculate_confidence_scores(self, correlated_vulns: List[Dict[str, Any]]) -> Dict[str, float]:
        """Calculate confidence scores for correlated vulnerabilities."""
        confidence_scores = {}
        
        for correlation in correlated_vulns:
            correlation_id = correlation['correlation_id']
            
            # Base confidence from correlation score
            base_confidence = correlation['correlation_score']
            
            # Boost confidence based on number of tools agreeing
            tool_count_boost = len(correlation['tools']) * 0.1
            
            # Boost confidence based on correlation factors
            factor_boost = len(correlation['correlation_factors']) * 0.05
            
            total_confidence = min(1.0, base_confidence + tool_count_boost + factor_boost)
            confidence_scores[correlation_id] = total_confidence
        
        return confidence_scores
    
    def _generate_recommendations(self, correlated_vulns: List[Dict[str, Any]],
                                unique_findings: Dict[str, List[Dict[str, Any]]]) -> List[str]:
        """Generate actionable recommendations based on correlation analysis."""
        recommendations = []
        
        # Recommendations for correlated vulnerabilities
        high_confidence_correlations = [
            corr for corr in correlated_vulns 
            if corr['correlation_score'] >= 0.8
        ]
        
        if high_confidence_correlations:
            recommendations.append(
                f"Prioritize {len(high_confidence_correlations)} high-confidence "
                "correlated vulnerabilities confirmed by multiple tools"
            )
        
        # Recommendations for unique findings
        total_unique = sum(len(findings) for findings in unique_findings.values())
        if total_unique > 0:
            recommendations.append(
                f"Review {total_unique} unique findings that require individual assessment"
            )
        
        # Tool-specific recommendations
        if 'zap' in unique_findings and len(unique_findings['zap']) > 0:
            recommendations.append(
                "ZAP identified unique web application vulnerabilities requiring manual verification"
            )
        
        if 'nuclei' in unique_findings and len(unique_findings['nuclei']) > 0:
            recommendations.append(
                "Nuclei discovered template-based vulnerabilities not found by other tools"
            )
        
        return recommendations


class ComprehensivePenetrationTestRunner:
    """
    Comprehensive penetration testing framework integrating multiple security tools.
    
    This class orchestrates OWASP ZAP 2.14+, Nuclei 3.1+, and other security tools
    to provide enterprise-grade penetration testing capabilities with comprehensive
    reporting and compliance validation per Section 6.4.5 and Section 6.4.6.
    """
    
    def __init__(self, config: Optional[SecurityTestConfig] = None):
        """
        Initialize comprehensive penetration testing framework.
        
        Args:
            config: Security test configuration instance
        """
        self.config = config or SecurityTestConfig()
        self.logger = logging.getLogger(f"{__name__}.ComprehensivePenetrationTestRunner")
        
        # Initialize security scanners
        self.zap_scanner = EnhancedOWASPZAPScanner(self.config)
        self.nuclei_scanner = NucleiVulnerabilityScanner(self.config)
        self.correlator = VulnerabilityCorrelator()
        self.compliance_validator = ComplianceValidator(self.config)
        
        # Initialize metrics tracking
        self.test_metrics = SecurityTestMetrics()
        
        # Test execution results
        self.execution_results: Dict[str, Any] = {}
    
    def run_comprehensive_penetration_test(self, target_url: str,
                                         test_level: Optional[SecurityTestLevel] = None,
                                         custom_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute comprehensive penetration testing with multiple security tools.
        
        Args:
            target_url: Target URL for penetration testing
            test_level: Security test execution level
            custom_config: Optional custom configuration overrides
            
        Returns:
            Dict containing comprehensive penetration test results and analysis
        """
        test_start_time = datetime.utcnow()
        self.test_metrics.start_time = test_start_time
        
        try:
            self.logger.info(f"Starting comprehensive penetration test for: {target_url}")
            
            # Validate target and configuration
            if not self._validate_test_configuration(target_url, custom_config):
                return {
                    'test_status': 'failed',
                    'error': 'Invalid test configuration or target',
                    'timestamp': test_start_time.isoformat()
                }
            
            # Initialize test results structure
            test_results = {
                'test_execution': {
                    'status': 'running',
                    'test_level': (test_level or self.config.get_security_test_level()).value,
                    'target_url': target_url,
                    'start_time': test_start_time.isoformat(),
                    'scanners_used': []
                },
                'scanner_results': {},
                'vulnerability_analysis': {},
                'compliance_assessment': {},
                'risk_assessment': {},
                'recommendations': [],
                'executive_summary': {}
            }
            
            # Execute security scans based on test level
            scan_results = self._execute_security_scans(target_url, test_level, test_results)
            test_results['scanner_results'] = scan_results
            
            # Perform vulnerability correlation analysis
            if len(scan_results) > 1:
                correlation_results = self._perform_vulnerability_correlation(scan_results)
                test_results['vulnerability_analysis'] = correlation_results
            
            # Execute compliance validation
            compliance_results = self._execute_compliance_validation(scan_results)
            test_results['compliance_assessment'] = compliance_results
            
            # Perform comprehensive risk assessment
            risk_assessment = self._perform_risk_assessment(scan_results, correlation_results)
            test_results['risk_assessment'] = risk_assessment
            
            # Generate actionable recommendations
            recommendations = self._generate_comprehensive_recommendations(
                scan_results, correlation_results, compliance_results, risk_assessment
            )
            test_results['recommendations'] = recommendations
            
            # Generate executive summary
            executive_summary = self._generate_executive_summary(test_results)
            test_results['executive_summary'] = executive_summary
            
            # Finalize test execution
            test_results['test_execution']['status'] = 'completed'
            test_results['test_execution']['end_time'] = datetime.utcnow().isoformat()
            test_results['test_execution']['duration'] = str(
                datetime.utcnow() - test_start_time
            )
            
            # Update metrics
            self._update_test_metrics(test_results)
            test_results['test_metrics'] = self._get_metrics_summary()
            
            self.execution_results = test_results
            
            self.logger.info("Comprehensive penetration test completed successfully")
            return test_results
            
        except Exception as e:
            error_msg = f"Comprehensive penetration test failed: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            
            return {
                'test_execution': {
                    'status': 'failed',
                    'error': error_msg,
                    'target_url': target_url,
                    'start_time': test_start_time.isoformat(),
                    'end_time': datetime.utcnow().isoformat()
                }
            }
    
    def _validate_test_configuration(self, target_url: str, 
                                   custom_config: Optional[Dict[str, Any]]) -> bool:
        """
        Validate penetration test configuration and target.
        
        Args:
            target_url: Target URL for testing
            custom_config: Custom configuration parameters
            
        Returns:
            bool: True if configuration is valid
        """
        try:
            # Validate target URL
            parsed_url = urlparse(target_url)
            if not parsed_url.scheme or not parsed_url.netloc:
                self.logger.error(f"Invalid target URL: {target_url}")
                return False
            
            # Validate custom configuration if provided
            if custom_config:
                required_fields = ['scan_timeout', 'rate_limit']
                for field in required_fields:
                    if field in custom_config:
                        if not isinstance(custom_config[field], (int, float)):
                            self.logger.error(f"Invalid {field} in custom config")
                            return False
            
            # Check if target is accessible
            try:
                response = requests.head(target_url, timeout=30, verify=False)
                if response.status_code >= 400:
                    self.logger.warning(f"Target returned status {response.status_code}")
            except requests.RequestException as e:
                self.logger.warning(f"Target accessibility check failed: {str(e)}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Configuration validation failed: {str(e)}")
            return False
    
    def _execute_security_scans(self, target_url: str, 
                              test_level: Optional[SecurityTestLevel],
                              test_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute security scans based on configured test level.
        
        Args:
            target_url: Target URL for scanning
            test_level: Security test execution level
            test_results: Test results dictionary to update
            
        Returns:
            Dict: Results from all executed security scanners
        """
        scan_results = {}
        level = test_level or self.config.get_security_test_level()
        
        # Determine which scanners to run based on test level
        scanners_to_run = self._determine_scanners(level)
        test_results['test_execution']['scanners_used'] = scanners_to_run
        
        # Execute scans in parallel for efficiency
        with ThreadPoolExecutor(max_workers=3) as executor:
            scan_futures = {}
            
            # Submit scan jobs
            if 'nuclei' in scanners_to_run:
                future = executor.submit(
                    self.nuclei_scanner.run_vulnerability_scan, 
                    target_url
                )
                scan_futures['nuclei'] = future
            
            if 'zap' in scanners_to_run:
                future = executor.submit(
                    self.zap_scanner.run_comprehensive_scan, 
                    target_url
                )
                scan_futures['zap'] = future
            
            # Collect results with timeout handling
            for scanner_name, future in scan_futures.items():
                try:
                    self.logger.info(f"Waiting for {scanner_name} scan to complete...")
                    result = future.result(timeout=self.config.SECURITY_TEST_TIMEOUT)
                    scan_results[scanner_name] = result
                    
                    self.logger.info(f"{scanner_name} scan completed successfully")
                    
                except TimeoutError:
                    self.logger.error(f"{scanner_name} scan timed out")
                    scan_results[scanner_name] = {
                        'scan_status': 'timeout',
                        'error': f'Scan timed out after {self.config.SECURITY_TEST_TIMEOUT} seconds'
                    }
                    
                except Exception as e:
                    self.logger.error(f"{scanner_name} scan failed: {str(e)}")
                    scan_results[scanner_name] = {
                        'scan_status': 'failed',
                        'error': str(e)
                    }
        
        return scan_results
    
    def _determine_scanners(self, test_level: SecurityTestLevel) -> List[str]:
        """
        Determine which scanners to run based on test level.
        
        Args:
            test_level: Security test execution level
            
        Returns:
            List[str]: Scanner names to execute
        """
        scanners = []
        
        if test_level in [SecurityTestLevel.BASIC, SecurityTestLevel.STANDARD, 
                         SecurityTestLevel.COMPREHENSIVE, SecurityTestLevel.PENETRATION]:
            scanners.append('nuclei')
        
        if test_level in [SecurityTestLevel.STANDARD, SecurityTestLevel.COMPREHENSIVE, 
                         SecurityTestLevel.PENETRATION]:
            scanners.append('zap')
        
        # Additional scanners for comprehensive testing
        if test_level in [SecurityTestLevel.COMPREHENSIVE, SecurityTestLevel.PENETRATION]:
            # Could add more scanners here (Nikto, Nmap, etc.)
            pass
        
        return scanners
    
    def _perform_vulnerability_correlation(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform vulnerability correlation analysis across scanner results.
        
        Args:
            scan_results: Results from multiple security scanners
            
        Returns:
            Dict: Vulnerability correlation analysis results
        """
        try:
            self.logger.info("Starting vulnerability correlation analysis...")
            
            # Extract vulnerability findings from scan results
            vulnerability_findings = {}
            
            for scanner_name, results in scan_results.items():
                if results.get('scan_status') == 'completed':
                    vulnerabilities = self._extract_vulnerabilities(scanner_name, results)
                    if vulnerabilities:
                        vulnerability_findings[scanner_name] = vulnerabilities
            
            if len(vulnerability_findings) < 2:
                self.logger.info("Insufficient scanners for correlation analysis")
                return {
                    'correlation_status': 'skipped',
                    'reason': 'Requires at least 2 successful scans for correlation'
                }
            
            # Perform correlation
            correlation_results = self.correlator.correlate_findings(vulnerability_findings)
            correlation_results['correlation_status'] = 'completed'
            
            self.logger.info("Vulnerability correlation analysis completed")
            return correlation_results
            
        except Exception as e:
            self.logger.error(f"Vulnerability correlation failed: {str(e)}")
            return {
                'correlation_status': 'failed',
                'error': str(e)
            }
    
    def _extract_vulnerabilities(self, scanner_name: str, 
                               scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract vulnerability findings from scanner-specific results.
        
        Args:
            scanner_name: Name of the security scanner
            scan_results: Scanner-specific results
            
        Returns:
            List: Extracted vulnerability findings
        """
        vulnerabilities = []
        
        try:
            if scanner_name == 'nuclei':
                vulnerabilities = scan_results.get('vulnerabilities', [])
            elif scanner_name == 'zap':
                alerts = scan_results.get('alerts', {}).get('alerts', [])
                vulnerabilities = alerts
            
            self.logger.debug(f"Extracted {len(vulnerabilities)} vulnerabilities from {scanner_name}")
            
        except Exception as e:
            self.logger.error(f"Failed to extract vulnerabilities from {scanner_name}: {str(e)}")
        
        return vulnerabilities
    
    def _execute_compliance_validation(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute compliance validation against security frameworks.
        
        Args:
            scan_results: Results from security scanners
            
        Returns:
            Dict: Compliance validation results
        """
        try:
            self.logger.info("Starting compliance validation...")
            
            # Prepare compliance input data
            compliance_input = {}
            
            for scanner_name, results in scan_results.items():
                if results.get('scan_status') == 'completed':
                    compliance_input[scanner_name] = results
            
            # Run compliance validation
            compliance_results = self.compliance_validator.validate_compliance(compliance_input)
            
            self.logger.info("Compliance validation completed")
            return compliance_results
            
        except Exception as e:
            self.logger.error(f"Compliance validation failed: {str(e)}")
            return {
                'validation_status': 'failed',
                'error': str(e)
            }
    
    def _perform_risk_assessment(self, scan_results: Dict[str, Any],
                               correlation_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform comprehensive risk assessment based on all findings.
        
        Args:
            scan_results: Results from security scanners
            correlation_results: Vulnerability correlation results
            
        Returns:
            Dict: Comprehensive risk assessment
        """
        try:
            self.logger.info("Starting comprehensive risk assessment...")
            
            risk_assessment = {
                'overall_risk_level': 'low',
                'risk_score': 0.0,
                'critical_vulnerabilities': 0,
                'high_vulnerabilities': 0,
                'medium_vulnerabilities': 0,
                'low_vulnerabilities': 0,
                'total_vulnerabilities': 0,
                'risk_factors': [],
                'immediate_threats': [],
                'long_term_risks': []
            }
            
            # Aggregate vulnerability counts across all scanners
            total_vulns = 0
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            
            for scanner_name, results in scan_results.items():
                if results.get('scan_status') == 'completed':
                    scanner_vulns = self._count_scanner_vulnerabilities(scanner_name, results)
                    total_vulns += scanner_vulns['total']
                    
                    for severity, count in scanner_vulns['by_severity'].items():
                        if severity in severity_counts:
                            severity_counts[severity] += count
            
            # Update risk assessment with vulnerability counts
            risk_assessment['total_vulnerabilities'] = total_vulns
            risk_assessment['critical_vulnerabilities'] = severity_counts['critical']
            risk_assessment['high_vulnerabilities'] = severity_counts['high']
            risk_assessment['medium_vulnerabilities'] = severity_counts['medium']
            risk_assessment['low_vulnerabilities'] = severity_counts['low']
            
            # Calculate overall risk score
            risk_score = self._calculate_overall_risk_score(severity_counts)
            risk_assessment['risk_score'] = risk_score
            
            # Determine overall risk level
            risk_assessment['overall_risk_level'] = self._determine_risk_level(risk_score)
            
            # Identify risk factors
            risk_factors = self._identify_risk_factors(scan_results, correlation_results)
            risk_assessment['risk_factors'] = risk_factors
            
            # Categorize threats
            immediate_threats, long_term_risks = self._categorize_threats(scan_results)
            risk_assessment['immediate_threats'] = immediate_threats
            risk_assessment['long_term_risks'] = long_term_risks
            
            self.logger.info(f"Risk assessment completed - Overall risk: {risk_assessment['overall_risk_level']}")
            return risk_assessment
            
        except Exception as e:
            self.logger.error(f"Risk assessment failed: {str(e)}")
            return {
                'overall_risk_level': 'unknown',
                'error': str(e)
            }
    
    def _count_scanner_vulnerabilities(self, scanner_name: str, 
                                     results: Dict[str, Any]) -> Dict[str, Any]:
        """Count vulnerabilities from specific scanner results."""
        counts = {'total': 0, 'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}}
        
        try:
            if scanner_name == 'nuclei':
                vulnerabilities = results.get('vulnerabilities', [])
                counts['total'] = len(vulnerabilities)
                
                for vuln in vulnerabilities:
                    severity = vuln.get('severity', 'info').lower()
                    if severity in counts['by_severity']:
                        counts['by_severity'][severity] += 1
                        
            elif scanner_name == 'zap':
                alerts = results.get('alerts', {})
                risk_counts = alerts.get('risk_counts', {})
                
                # Map ZAP risk levels to our severity levels
                zap_mapping = {
                    'high': 'high',
                    'medium': 'medium',
                    'low': 'low',
                    'informational': 'info'
                }
                
                for zap_risk, count in risk_counts.items():
                    severity = zap_mapping.get(zap_risk.lower(), 'info')
                    counts['by_severity'][severity] += count
                    counts['total'] += count
                    
        except Exception as e:
            self.logger.error(f"Error counting vulnerabilities for {scanner_name}: {str(e)}")
        
        return counts
    
    def _calculate_overall_risk_score(self, severity_counts: Dict[str, int]) -> float:
        """Calculate overall risk score based on vulnerability severity distribution."""
        severity_weights = {
            'critical': 10.0,
            'high': 7.0,
            'medium': 4.0,
            'low': 2.0,
            'info': 0.5
        }
        
        total_score = 0.0
        for severity, count in severity_counts.items():
            weight = severity_weights.get(severity, 0.0)
            total_score += count * weight
        
        # Normalize to 0-100 scale
        max_possible_score = 100.0  # Assuming max 10 critical vulnerabilities as ceiling
        normalized_score = min(100.0, total_score)
        
        return round(normalized_score, 2)
    
    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level based on calculated risk score."""
        if risk_score >= 70:
            return 'critical'
        elif risk_score >= 50:
            return 'high'
        elif risk_score >= 30:
            return 'medium'
        elif risk_score > 0:
            return 'low'
        else:
            return 'minimal'
    
    def _identify_risk_factors(self, scan_results: Dict[str, Any],
                             correlation_results: Dict[str, Any]) -> List[str]:
        """Identify key risk factors from scan results."""
        risk_factors = []
        
        # Check for critical vulnerabilities
        for scanner_name, results in scan_results.items():
            if results.get('scan_status') == 'completed':
                critical_count = self._count_critical_vulnerabilities(scanner_name, results)
                if critical_count > 0:
                    risk_factors.append(f"{critical_count} critical vulnerabilities found by {scanner_name}")
        
        # Check for correlation findings
        if correlation_results.get('correlation_status') == 'completed':
            correlated_vulns = correlation_results.get('correlated_vulnerabilities', [])
            high_confidence_correlations = [
                corr for corr in correlated_vulns 
                if corr.get('correlation_score', 0) >= 0.8
            ]
            if high_confidence_correlations:
                risk_factors.append(
                    f"{len(high_confidence_correlations)} vulnerabilities confirmed by multiple tools"
                )
        
        # Check for compliance violations
        for scanner_name, results in scan_results.items():
            if 'compliance_assessment' in results:
                compliance = results['compliance_assessment']
                if compliance.get('overall_compliance_score', 100) < 70:
                    risk_factors.append(f"Low compliance score from {scanner_name}")
        
        return risk_factors
    
    def _count_critical_vulnerabilities(self, scanner_name: str, results: Dict[str, Any]) -> int:
        """Count critical vulnerabilities from scanner results."""
        critical_count = 0
        
        try:
            if scanner_name == 'nuclei':
                vulnerabilities = results.get('vulnerabilities', [])
                critical_count = len([v for v in vulnerabilities if v.get('severity') == 'critical'])
            elif scanner_name == 'zap':
                risk_counts = results.get('alerts', {}).get('risk_counts', {})
                critical_count = risk_counts.get('high', 0)  # ZAP's "High" maps to our "Critical"
        except Exception as e:
            self.logger.error(f"Error counting critical vulnerabilities for {scanner_name}: {str(e)}")
        
        return critical_count
    
    def _categorize_threats(self, scan_results: Dict[str, Any]) -> Tuple[List[str], List[str]]:
        """Categorize threats into immediate and long-term risks."""
        immediate_threats = []
        long_term_risks = []
        
        # Define threat categories
        immediate_threat_patterns = [
            'sql injection', 'command injection', 'authentication bypass',
            'remote code execution', 'privilege escalation'
        ]
        
        long_term_risk_patterns = [
            'information disclosure', 'weak encryption', 'misconfiguration',
            'outdated software', 'weak password policy'
        ]
        
        try:
            for scanner_name, results in scan_results.items():
                if results.get('scan_status') == 'completed':
                    vulnerabilities = self._extract_vulnerabilities(scanner_name, results)
                    
                    for vuln in vulnerabilities:
                        vuln_description = str(vuln.get('description', '')).lower()
                        vuln_title = str(vuln.get('title', vuln.get('name', ''))).lower()
                        vuln_text = f"{vuln_description} {vuln_title}"
                        
                        # Check for immediate threats
                        for pattern in immediate_threat_patterns:
                            if pattern in vuln_text and pattern not in immediate_threats:
                                immediate_threats.append(pattern.title())
                                break
                        
                        # Check for long-term risks
                        for pattern in long_term_risk_patterns:
                            if pattern in vuln_text and pattern not in long_term_risks:
                                long_term_risks.append(pattern.title())
                                break
                                
        except Exception as e:
            self.logger.error(f"Error categorizing threats: {str(e)}")
        
        return immediate_threats, long_term_risks
    
    def _generate_comprehensive_recommendations(self, scan_results: Dict[str, Any],
                                              correlation_results: Dict[str, Any],
                                              compliance_results: Dict[str, Any],
                                              risk_assessment: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate comprehensive security recommendations."""
        recommendations = []
        
        try:
            # Priority 1: Critical and High severity vulnerabilities
            if risk_assessment.get('critical_vulnerabilities', 0) > 0:
                recommendations.append({
                    'priority': 'critical',
                    'category': 'vulnerability_remediation',
                    'title': 'Immediate Critical Vulnerability Remediation',
                    'description': f"Address {risk_assessment['critical_vulnerabilities']} critical vulnerabilities immediately",
                    'impact': 'high',
                    'effort': 'high',
                    'timeline': '24-48 hours'
                })
            
            if risk_assessment.get('high_vulnerabilities', 0) > 0:
                recommendations.append({
                    'priority': 'high',
                    'category': 'vulnerability_remediation',
                    'title': 'High Severity Vulnerability Remediation',
                    'description': f"Remediate {risk_assessment['high_vulnerabilities']} high severity vulnerabilities",
                    'impact': 'high',
                    'effort': 'medium',
                    'timeline': '1-2 weeks'
                })
            
            # Priority 2: Correlated vulnerabilities
            if correlation_results.get('correlation_status') == 'completed':
                correlated_vulns = correlation_results.get('correlated_vulnerabilities', [])
                if correlated_vulns:
                    recommendations.append({
                        'priority': 'high',
                        'category': 'vulnerability_correlation',
                        'title': 'Address Multi-Tool Confirmed Vulnerabilities',
                        'description': f"Prioritize {len(correlated_vulns)} vulnerabilities confirmed by multiple scanners",
                        'impact': 'high',
                        'effort': 'medium',
                        'timeline': '2-3 weeks'
                    })
            
            # Priority 3: Compliance improvements
            overall_compliance = compliance_results.get('overall_compliance_score', 100)
            if overall_compliance < 80:
                recommendations.append({
                    'priority': 'medium',
                    'category': 'compliance',
                    'title': 'Improve Security Compliance',
                    'description': f"Current compliance score is {overall_compliance:.1f}%, target is >90%",
                    'impact': 'medium',
                    'effort': 'medium',
                    'timeline': '1-2 months'
                })
            
            # Priority 4: Risk mitigation
            for threat in risk_assessment.get('immediate_threats', []):
                recommendations.append({
                    'priority': 'high',
                    'category': 'threat_mitigation',
                    'title': f'Mitigate {threat} Threats',
                    'description': f'Implement controls to prevent {threat.lower()} attacks',
                    'impact': 'high',
                    'effort': 'medium',
                    'timeline': '2-4 weeks'
                })
            
            # Priority 5: Long-term security improvements
            recommendations.append({
                'priority': 'medium',
                'category': 'security_improvement',
                'title': 'Implement Regular Security Scanning',
                'description': 'Establish automated security scanning in CI/CD pipeline',
                'impact': 'medium',
                'effort': 'high',
                'timeline': '1-3 months'
            })
            
            recommendations.append({
                'priority': 'low',
                'category': 'security_improvement',
                'title': 'Security Awareness Training',
                'description': 'Provide security training to development team',
                'impact': 'medium',
                'effort': 'low',
                'timeline': '1 month'
            })
            
        except Exception as e:
            self.logger.error(f"Error generating recommendations: {str(e)}")
        
        return recommendations
    
    def _generate_executive_summary(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary for business stakeholders."""
        try:
            risk_assessment = test_results.get('risk_assessment', {})
            compliance_assessment = test_results.get('compliance_assessment', {})
            recommendations = test_results.get('recommendations', [])
            
            # Count vulnerabilities by priority
            critical_recommendations = len([r for r in recommendations if r.get('priority') == 'critical'])
            high_recommendations = len([r for r in recommendations if r.get('priority') == 'high'])
            
            summary = {
                'overall_security_posture': risk_assessment.get('overall_risk_level', 'unknown'),
                'security_score': round(100 - risk_assessment.get('risk_score', 0), 1),
                'total_vulnerabilities': risk_assessment.get('total_vulnerabilities', 0),
                'critical_issues': risk_assessment.get('critical_vulnerabilities', 0),
                'high_priority_issues': risk_assessment.get('high_vulnerabilities', 0),
                'compliance_score': compliance_assessment.get('overall_compliance_score', 0),
                'immediate_action_required': critical_recommendations > 0,
                'recommended_actions': critical_recommendations + high_recommendations,
                'key_findings': self._extract_key_findings(test_results),
                'business_impact': self._assess_business_impact(risk_assessment),
                'next_steps': self._generate_executive_next_steps(recommendations)
            }
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error generating executive summary: {str(e)}")
            return {
                'error': 'Failed to generate executive summary',
                'overall_security_posture': 'unknown'
            }
    
    def _extract_key_findings(self, test_results: Dict[str, Any]) -> List[str]:
        """Extract key security findings for executive summary."""
        findings = []
        
        try:
            # Check scanner results for key findings
            scanner_results = test_results.get('scanner_results', {})
            
            # Nuclei findings
            if 'nuclei' in scanner_results:
                nuclei_results = scanner_results['nuclei']
                if nuclei_results.get('scan_status') == 'completed':
                    vuln_count = len(nuclei_results.get('vulnerabilities', []))
                    if vuln_count > 0:
                        findings.append(f"Nuclei scanner identified {vuln_count} potential vulnerabilities")
            
            # ZAP findings  
            if 'zap' in scanner_results:
                zap_results = scanner_results['zap']
                if zap_results.get('scan_status') == 'completed':
                    alerts = zap_results.get('alerts', {})
                    total_alerts = alerts.get('total_alerts', 0)
                    if total_alerts > 0:
                        findings.append(f"OWASP ZAP identified {total_alerts} security alerts")
            
            # Correlation findings
            correlation = test_results.get('vulnerability_analysis', {})
            if correlation.get('correlation_status') == 'completed':
                correlated_count = len(correlation.get('correlated_vulnerabilities', []))
                if correlated_count > 0:
                    findings.append(f"{correlated_count} vulnerabilities confirmed by multiple tools")
            
            # Risk assessment findings
            risk_assessment = test_results.get('risk_assessment', {})
            immediate_threats = risk_assessment.get('immediate_threats', [])
            if immediate_threats:
                findings.append(f"Immediate security threats identified: {', '.join(immediate_threats)}")
            
        except Exception as e:
            self.logger.error(f"Error extracting key findings: {str(e)}")
        
        return findings[:5]  # Limit to top 5 findings
    
    def _assess_business_impact(self, risk_assessment: Dict[str, Any]) -> str:
        """Assess business impact based on risk assessment."""
        overall_risk = risk_assessment.get('overall_risk_level', 'low')
        critical_vulns = risk_assessment.get('critical_vulnerabilities', 0)
        
        if overall_risk == 'critical' or critical_vulns > 0:
            return 'Critical - Immediate business risk requiring urgent attention'
        elif overall_risk == 'high':
            return 'High - Significant business risk requiring prompt remediation'
        elif overall_risk == 'medium':
            return 'Medium - Moderate business risk requiring planned remediation'
        elif overall_risk == 'low':
            return 'Low - Minimal business risk with recommended improvements'
        else:
            return 'Minimal - Strong security posture with minor improvements needed'
    
    def _generate_executive_next_steps(self, recommendations: List[Dict[str, Any]]) -> List[str]:
        """Generate executive-level next steps."""
        next_steps = []
        
        critical_recs = [r for r in recommendations if r.get('priority') == 'critical']
        high_recs = [r for r in recommendations if r.get('priority') == 'high']
        
        if critical_recs:
            next_steps.append("Schedule immediate security review meeting with technical leadership")
            next_steps.append("Implement emergency response plan for critical vulnerabilities")
        
        if high_recs:
            next_steps.append("Prioritize high-risk security remediation in upcoming sprint planning")
        
        next_steps.extend([
            "Review detailed technical report with security and development teams",
            "Establish regular security scanning schedule",
            "Consider security training and awareness programs"
        ])
        
        return next_steps[:5]
    
    def _update_test_metrics(self, test_results: Dict[str, Any]) -> None:
        """Update test execution metrics."""
        try:
            self.test_metrics.end_time = datetime.utcnow()
            
            # Count successful and failed scans
            scanner_results = test_results.get('scanner_results', {})
            for scanner_name, results in scanner_results.items():
                self.test_metrics.total_tests += 1
                
                if results.get('scan_status') == 'completed':
                    self.test_metrics.passed_tests += 1
                else:
                    self.test_metrics.failed_tests += 1
            
            # Update vulnerability counts
            risk_assessment = test_results.get('risk_assessment', {})
            severity_mapping = {
                'critical': 'critical_vulnerabilities',
                'high': 'high_vulnerabilities', 
                'medium': 'medium_vulnerabilities',
                'low': 'low_vulnerabilities'
            }
            
            for severity, key in severity_mapping.items():
                count = risk_assessment.get(key, 0)
                self.test_metrics.vulnerabilities_found[severity] = count
            
            # Update compliance score
            compliance_assessment = test_results.get('compliance_assessment', {})
            self.test_metrics.compliance_score = compliance_assessment.get('overall_compliance_score', 0.0)
            
        except Exception as e:
            self.logger.error(f"Error updating test metrics: {str(e)}")
    
    def _get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of test execution metrics."""
        return {
            'execution_duration': str(self.test_metrics.duration),
            'total_tests': self.test_metrics.total_tests,
            'passed_tests': self.test_metrics.passed_tests,
            'failed_tests': self.test_metrics.failed_tests,
            'success_rate': self.test_metrics.success_rate,
            'vulnerabilities_found': dict(self.test_metrics.vulnerabilities_found),
            'compliance_score': self.test_metrics.compliance_score
        }
    
    def generate_compliance_report(self, output_format: str = 'json') -> Union[str, Dict[str, Any]]:
        """
        Generate comprehensive compliance report for enterprise stakeholders.
        
        Args:
            output_format: Report format ('json', 'html', 'pdf')
            
        Returns:
            Union[str, Dict]: Formatted compliance report
        """
        if not self.execution_results:
            raise PenetrationTestError("No test results available for report generation")
        
        try:
            compliance_report = {
                'report_metadata': {
                    'generated_at': datetime.utcnow().isoformat(),
                    'report_type': 'penetration_testing_compliance',
                    'format': output_format,
                    'version': '1.0.0'
                },
                'executive_summary': self.execution_results.get('executive_summary', {}),
                'compliance_assessment': self.execution_results.get('compliance_assessment', {}),
                'risk_assessment': self.execution_results.get('risk_assessment', {}),
                'vulnerability_summary': self._generate_vulnerability_summary(),
                'recommendations': self.execution_results.get('recommendations', []),
                'technical_details': {
                    'scanners_used': self.execution_results.get('test_execution', {}).get('scanners_used', []),
                    'scan_duration': self.execution_results.get('test_execution', {}).get('duration', ''),
                    'target_url': self.execution_results.get('test_execution', {}).get('target_url', '')
                }
            }
            
            if output_format == 'json':
                return compliance_report
            elif output_format == 'html':
                return self._generate_html_report(compliance_report)
            else:
                return json.dumps(compliance_report, indent=2)
                
        except Exception as e:
            self.logger.error(f"Error generating compliance report: {str(e)}")
            raise PenetrationTestError(f"Report generation failed: {str(e)}")
    
    def _generate_vulnerability_summary(self) -> Dict[str, Any]:
        """Generate vulnerability summary for compliance report."""
        try:
            risk_assessment = self.execution_results.get('risk_assessment', {})
            
            return {
                'total_vulnerabilities': risk_assessment.get('total_vulnerabilities', 0),
                'by_severity': {
                    'critical': risk_assessment.get('critical_vulnerabilities', 0),
                    'high': risk_assessment.get('high_vulnerabilities', 0),
                    'medium': risk_assessment.get('medium_vulnerabilities', 0),
                    'low': risk_assessment.get('low_vulnerabilities', 0)
                },
                'risk_score': risk_assessment.get('risk_score', 0.0),
                'risk_level': risk_assessment.get('overall_risk_level', 'unknown')
            }
            
        except Exception as e:
            self.logger.error(f"Error generating vulnerability summary: {str(e)}")
            return {}
    
    def _generate_html_report(self, report_data: Dict[str, Any]) -> str:
        """Generate HTML format compliance report."""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Penetration Testing Compliance Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background-color: #f8f9fa; padding: 20px; border-radius: 5px; }
                .section { margin: 20px 0; }
                .critical { color: #dc3545; }
                .high { color: #fd7e14; }
                .medium { color: #ffc107; }
                .low { color: #28a745; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Penetration Testing Compliance Report</h1>
                <p>Generated: {generated_at}</p>
                <p>Target: {target_url}</p>
            </div>
            
            <div class="section">
                <h2>Executive Summary</h2>
                <p><strong>Overall Security Posture:</strong> {security_posture}</p>
                <p><strong>Security Score:</strong> {security_score}/100</p>
                <p><strong>Total Vulnerabilities:</strong> {total_vulns}</p>
                <p><strong>Compliance Score:</strong> {compliance_score}%</p>
            </div>
            
            <div class="section">
                <h2>Vulnerability Summary</h2>
                <table>
                    <tr><th>Severity</th><th>Count</th></tr>
                    <tr><td class="critical">Critical</td><td>{critical_vulns}</td></tr>
                    <tr><td class="high">High</td><td>{high_vulns}</td></tr>
                    <tr><td class="medium">Medium</td><td>{medium_vulns}</td></tr>
                    <tr><td class="low">Low</td><td>{low_vulns}</td></tr>
                </table>
            </div>
            
            <div class="section">
                <h2>Recommendations</h2>
                <ul>
                {recommendations_list}
                </ul>
            </div>
        </body>
        </html>
        """
        
        try:
            executive_summary = report_data.get('executive_summary', {})
            vulnerability_summary = report_data.get('vulnerability_summary', {})
            recommendations = report_data.get('recommendations', [])
            
            recommendations_html = '\n'.join([
                f"<li><strong>{rec.get('title', '')}:</strong> {rec.get('description', '')}</li>"
                for rec in recommendations[:10]  # Limit to first 10
            ])
            
            return html_template.format(
                generated_at=report_data.get('report_metadata', {}).get('generated_at', ''),
                target_url=report_data.get('technical_details', {}).get('target_url', ''),
                security_posture=executive_summary.get('overall_security_posture', 'unknown'),
                security_score=executive_summary.get('security_score', 0),
                total_vulns=vulnerability_summary.get('total_vulnerabilities', 0),
                compliance_score=executive_summary.get('compliance_score', 0),
                critical_vulns=vulnerability_summary.get('by_severity', {}).get('critical', 0),
                high_vulns=vulnerability_summary.get('by_severity', {}).get('high', 0),
                medium_vulns=vulnerability_summary.get('by_severity', {}).get('medium', 0),
                low_vulns=vulnerability_summary.get('by_severity', {}).get('low', 0),
                recommendations_list=recommendations_html
            )
            
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {str(e)}")
            return f"<html><body><h1>Error generating report: {str(e)}</h1></body></html>"


# Pytest integration and test fixtures
@pytest.fixture(scope="session")
def penetration_test_runner():
    """
    Session-scoped fixture providing penetration test runner instance.
    
    Returns:
        ComprehensivePenetrationTestRunner: Configured penetration testing framework
    """
    config = SecurityTestConfig()
    runner = ComprehensivePenetrationTestRunner(config)
    
    logger.info("Penetration test runner fixture initialized")
    return runner


@pytest.fixture(scope="function")
def mock_target_application(flask_app):
    """
    Function-scoped fixture providing mock target application for testing.
    
    Args:
        flask_app: Flask application fixture from conftest.py
        
    Returns:
        str: Target URL for penetration testing
    """
    # Use the Flask test server as target
    target_url = "http://localhost:5000"
    
    logger.info(f"Mock target application available at: {target_url}")
    return target_url


# Export main classes and functions
__all__ = [
    # Main classes
    'ComprehensivePenetrationTestRunner',
    'NucleiVulnerabilityScanner',
    'EnhancedOWASPZAPScanner',
    'VulnerabilityCorrelator',
    
    # Exception classes
    'PenetrationTestError',
    'NucleiScannerError',
    'ZAPProxyError',
    'SecurityComplianceError',
    
    # Pytest fixtures
    'penetration_test_runner',
    'mock_target_application'
]