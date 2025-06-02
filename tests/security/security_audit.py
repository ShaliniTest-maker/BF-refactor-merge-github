"""
Comprehensive Security Audit Automation Module

This module implements enterprise-grade security audit automation for Flask application 
security validation, providing comprehensive compliance validation, security posture 
assessment, and regulatory compliance testing with automated audit trail generation 
as specified in Section 6.4.6 of the technical specification.

Key Features:
- Comprehensive security audit automation for enterprise compliance per Section 6.4.6
- Regulatory compliance validation (SOC 2, ISO 27001, PCI DSS) per Section 6.4.6
- Automated audit trail generation for compliance verification per Section 6.4.6
- Security posture monitoring and assessment per Section 6.4.6
- Real-time security monitoring with Prometheus metrics integration
- Enterprise compliance dashboard integration per Section 6.4.6
- Automated penetration testing with OWASP compliance validation
- Comprehensive security reporting with executive dashboard integration

Architecture Integration:
- Section 6.4.6: Comprehensive enterprise compliance requirements and audit frameworks
- Section 6.4.5: Security Controls Matrix with automated vulnerability scanning
- Section 6.6.1: Security testing approach with pytest framework integration
- Section 6.6.3: Quality metrics with security coverage enforcement
- Section 3.6: Monitoring & Observability with Prometheus metrics collection
- Integration with tests/security/conftest.py for security testing fixtures
- Integration with tests/security/security_config.py for security configurations
- Integration with src/auth/audit.py for enterprise audit logging

Security Testing Coverage:
- Authentication security (JWT validation, Auth0 integration, session management)
- Authorization security (RBAC, permissions, resource access control)
- Input validation security (XSS prevention, injection attacks, data sanitization)
- Session security (Flask-Session with Redis, encryption, secure cookies)
- Transport security (HTTPS/TLS enforcement, security headers, CORS)
- Infrastructure security (container scanning, dependency validation)
- API security (rate limiting, versioning, swagger security)
- Data protection (encryption, PII handling, GDPR compliance)

Compliance Frameworks:
- SOC 2 Type II: Comprehensive audit trail and security control validation
- ISO 27001: Information security management system compliance
- PCI DSS: Payment card industry security standards validation
- GDPR: Data protection and privacy compliance verification
- OWASP Top 10: Web application security vulnerability assessment
- NIST Cybersecurity Framework: Risk management and security control alignment

Performance Requirements:
- Security audit execution: ≤30 minutes for comprehensive audit
- Compliance validation: ≤10 minutes for framework validation
- Report generation: ≤5 minutes for executive dashboard updates
- Real-time monitoring: ≤1 second latency for security event correlation

Author: Flask Migration Team
Version: 1.0.0
Dependencies: pytest 7.4+, pytest-mock, bandit 1.7+, safety 3.0+, owasp-zap-api 0.0.21+
"""

import asyncio
import csv
import json
import logging
import os
import subprocess
import tempfile
import time
import uuid
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from threading import Lock, Thread
from typing import Any, Dict, List, Optional, Tuple, Union, Callable, Generator
from urllib.parse import urlparse

import pytest
import requests
from flask import Flask
from flask.testing import FlaskClient
from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge, Enum as PrometheusEnum

# Import security testing framework dependencies
from tests.security.conftest import (
    SecurityTestConfig,
    SecurityPayloads, 
    SecurityAuditLogger as TestAuditLogger,
    MockAuth0SecurityService,
    SecurityValidationTools,
    MockAttackScenarios,
    SecurityPerformanceMonitor,
    comprehensive_security_environment
)

from tests.security.security_config import (
    SecurityTestOrchestrator,
    BanditSecurityScanner,
    SafetyDependencyScanner,
    OWASPZAPScanner,
    PenetrationTestRunner,
    ComplianceValidator,
    SecurityTestLevel,
    VulnerabilitySeverity,
    AttackCategory
)

# Import enterprise audit logging
from src.auth.audit import (
    SecurityAuditLogger,
    SecurityAuditConfig,
    SecurityAuditMetrics,
    SecurityEventType,
    PIISanitizer,
    init_security_audit
)

# Configure module logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ComplianceFramework(Enum):
    """Enterprise compliance framework definitions for audit automation."""
    
    SOC2_TYPE2 = "soc2_type2"
    ISO_27001 = "iso_27001"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    OWASP_TOP_10 = "owasp_top_10"
    NIST_CSF = "nist_csf"
    HIPAA = "hipaa"
    SOX = "sox"


class AuditSeverity(Enum):
    """Security audit finding severity levels for risk assessment."""
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AuditStatus(Enum):
    """Security audit execution status tracking."""
    
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class SecurityFinding:
    """
    Comprehensive security finding data structure for audit trail and compliance reporting.
    
    This class provides standardized security finding representation with enterprise-grade
    metadata and compliance tracking capabilities for comprehensive audit documentation.
    """
    
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    severity: AuditSeverity = AuditSeverity.INFO
    category: str = ""
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    compliance_frameworks: List[ComplianceFramework] = field(default_factory=list)
    affected_components: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    remediation_effort: str = "medium"  # low, medium, high
    business_impact: str = ""
    technical_impact: str = ""
    likelihood: str = "medium"  # low, medium, high
    cvss_score: Optional[float] = None
    discovered_date: datetime = field(default_factory=datetime.utcnow)
    last_seen_date: datetime = field(default_factory=datetime.utcnow)
    status: str = "open"  # open, remediated, accepted, false_positive
    assigned_to: Optional[str] = None
    source_scanner: str = ""
    source_test: str = ""
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for JSON serialization."""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['compliance_frameworks'] = [f.value for f in self.compliance_frameworks]
        data['discovered_date'] = self.discovered_date.isoformat()
        data['last_seen_date'] = self.last_seen_date.isoformat()
        return data
    
    def calculate_risk_score(self) -> float:
        """
        Calculate comprehensive risk score based on CVSS, likelihood, and business impact.
        
        Returns:
            Risk score from 0.0 to 10.0
        """
        # Base score from CVSS if available
        base_score = self.cvss_score or self._severity_to_score()
        
        # Likelihood multiplier
        likelihood_multiplier = {
            'low': 0.3,
            'medium': 0.6,
            'high': 1.0
        }.get(self.likelihood.lower(), 0.6)
        
        # Business impact multiplier
        business_multiplier = 1.0
        if 'critical' in self.business_impact.lower():
            business_multiplier = 1.3
        elif 'high' in self.business_impact.lower():
            business_multiplier = 1.1
        elif 'low' in self.business_impact.lower():
            business_multiplier = 0.8
        
        risk_score = base_score * likelihood_multiplier * business_multiplier
        return min(10.0, max(0.0, risk_score))
    
    def _severity_to_score(self) -> float:
        """Convert severity to numerical score."""
        severity_scores = {
            AuditSeverity.CRITICAL: 9.0,
            AuditSeverity.HIGH: 7.5,
            AuditSeverity.MEDIUM: 5.0,
            AuditSeverity.LOW: 2.5,
            AuditSeverity.INFO: 0.5
        }
        return severity_scores.get(self.severity, 5.0)


@dataclass
class ComplianceResult:
    """
    Comprehensive compliance validation result for regulatory framework assessment.
    
    This class provides detailed compliance status tracking with control mapping,
    gap analysis, and remediation planning for enterprise compliance management.
    """
    
    framework: ComplianceFramework
    overall_score: float = 0.0
    max_possible_score: float = 100.0
    compliance_percentage: float = 0.0
    status: str = "non_compliant"  # compliant, partially_compliant, non_compliant
    control_results: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    gaps_identified: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    findings_count: Dict[str, int] = field(default_factory=dict)
    assessment_date: datetime = field(default_factory=datetime.utcnow)
    next_assessment_due: datetime = field(default_factory=lambda: datetime.utcnow() + timedelta(days=365))
    assessor: str = "automated_audit_system"
    evidence_links: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Calculate compliance percentage and status after initialization."""
        if self.max_possible_score > 0:
            self.compliance_percentage = (self.overall_score / self.max_possible_score) * 100
        
        # Determine compliance status based on percentage
        if self.compliance_percentage >= 95:
            self.status = "compliant"
        elif self.compliance_percentage >= 70:
            self.status = "partially_compliant"
        else:
            self.status = "non_compliant"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert compliance result to dictionary for JSON serialization."""
        data = asdict(self)
        data['framework'] = self.framework.value
        data['assessment_date'] = self.assessment_date.isoformat()
        data['next_assessment_due'] = self.next_assessment_due.isoformat()
        return data


@dataclass
class SecurityAuditReport:
    """
    Comprehensive security audit report with executive summary and detailed findings.
    
    This class provides enterprise-grade audit reporting with compliance dashboards,
    executive summaries, and detailed technical findings for stakeholder communication.
    """
    
    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    audit_name: str = "Comprehensive Security Audit"
    audit_scope: str = "Full Application Security Assessment"
    execution_date: datetime = field(default_factory=datetime.utcnow)
    completion_date: Optional[datetime] = None
    duration_minutes: float = 0.0
    auditor: str = "Automated Security Audit System"
    
    # Executive Summary
    overall_security_score: float = 0.0
    risk_level: str = "medium"  # low, medium, high, critical
    compliance_status: str = "partially_compliant"
    
    # Findings Summary
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    info_findings: int = 0
    
    # Detailed Results
    findings: List[SecurityFinding] = field(default_factory=list)
    compliance_results: Dict[str, ComplianceResult] = field(default_factory=dict)
    security_metrics: Dict[str, Any] = field(default_factory=dict)
    performance_metrics: Dict[str, Any] = field(default_factory=dict)
    
    # Remediation Planning
    immediate_actions: List[str] = field(default_factory=list)
    short_term_actions: List[str] = field(default_factory=list)
    long_term_actions: List[str] = field(default_factory=list)
    estimated_remediation_effort: str = "medium"
    
    # Quality Assurance
    test_coverage: float = 0.0
    automated_tests_passed: int = 0
    automated_tests_failed: int = 0
    manual_verification_required: List[str] = field(default_factory=list)
    
    # Metadata
    audit_configuration: Dict[str, Any] = field(default_factory=dict)
    environment_details: Dict[str, Any] = field(default_factory=dict)
    tool_versions: Dict[str, str] = field(default_factory=dict)
    
    def __post_init__(self):
        """Calculate derived metrics after initialization."""
        self._calculate_findings_summary()
        self._calculate_risk_level()
        self._calculate_security_score()
    
    def _calculate_findings_summary(self):
        """Calculate findings summary statistics."""
        self.total_findings = len(self.findings)
        
        severity_counts = defaultdict(int)
        for finding in self.findings:
            severity_counts[finding.severity] += 1
        
        self.critical_findings = severity_counts[AuditSeverity.CRITICAL]
        self.high_findings = severity_counts[AuditSeverity.HIGH]
        self.medium_findings = severity_counts[AuditSeverity.MEDIUM]
        self.low_findings = severity_counts[AuditSeverity.LOW]
        self.info_findings = severity_counts[AuditSeverity.INFO]
    
    def _calculate_risk_level(self):
        """Calculate overall risk level based on findings severity."""
        if self.critical_findings > 0:
            self.risk_level = "critical"
        elif self.high_findings > 0:
            self.risk_level = "high"
        elif self.medium_findings > 3:  # Multiple medium findings = high risk
            self.risk_level = "high"
        elif self.medium_findings > 0 or self.low_findings > 5:
            self.risk_level = "medium"
        else:
            self.risk_level = "low"
    
    def _calculate_security_score(self):
        """Calculate overall security score (0-100)."""
        base_score = 100.0
        
        # Deduct points based on findings severity
        penalties = {
            AuditSeverity.CRITICAL: 25.0,
            AuditSeverity.HIGH: 15.0,
            AuditSeverity.MEDIUM: 8.0,
            AuditSeverity.LOW: 3.0,
            AuditSeverity.INFO: 1.0
        }
        
        total_penalty = 0.0
        for finding in self.findings:
            total_penalty += penalties.get(finding.severity, 0.0)
        
        # Factor in compliance scores
        if self.compliance_results:
            avg_compliance = sum(
                result.compliance_percentage 
                for result in self.compliance_results.values()
            ) / len(self.compliance_results)
            base_score = (base_score * 0.7) + (avg_compliance * 0.3)
        
        self.overall_security_score = max(0.0, min(100.0, base_score - total_penalty))
    
    def get_executive_summary(self) -> Dict[str, Any]:
        """Generate executive summary for stakeholder communication."""
        return {
            'audit_overview': {
                'report_id': self.report_id,
                'audit_name': self.audit_name,
                'execution_date': self.execution_date.strftime('%Y-%m-%d'),
                'duration_hours': round(self.duration_minutes / 60, 2),
                'scope': self.audit_scope
            },
            'security_posture': {
                'overall_score': round(self.overall_security_score, 1),
                'risk_level': self.risk_level,
                'compliance_status': self.compliance_status,
                'improvement_trend': 'stable'  # Would track over time
            },
            'key_findings': {
                'total_findings': self.total_findings,
                'critical_issues': self.critical_findings,
                'high_priority_issues': self.high_findings,
                'requires_immediate_attention': self.critical_findings + self.high_findings
            },
            'compliance_overview': {
                'frameworks_assessed': len(self.compliance_results),
                'fully_compliant': sum(
                    1 for result in self.compliance_results.values() 
                    if result.status == 'compliant'
                ),
                'compliance_gaps': sum(
                    len(result.gaps_identified) 
                    for result in self.compliance_results.values()
                )
            },
            'recommended_actions': {
                'immediate': len(self.immediate_actions),
                'short_term': len(self.short_term_actions),
                'long_term': len(self.long_term_actions),
                'estimated_effort': self.estimated_remediation_effort
            }
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit report to dictionary for JSON serialization."""
        data = asdict(self)
        data['execution_date'] = self.execution_date.isoformat()
        if self.completion_date:
            data['completion_date'] = self.completion_date.isoformat()
        data['findings'] = [finding.to_dict() for finding in self.findings]
        data['compliance_results'] = {
            name: result.to_dict() 
            for name, result in self.compliance_results.items()
        }
        return data


class SecurityAuditMetrics:
    """
    Comprehensive Prometheus metrics for security audit monitoring and observability.
    
    This class provides enterprise-grade metrics collection for security audit execution,
    compliance validation, and security posture monitoring with dashboard integration.
    """
    
    def __init__(self, registry: Optional[CollectorRegistry] = None):
        """Initialize security audit metrics with optional custom registry."""
        self.registry = registry or CollectorRegistry()
        
        # Audit Execution Metrics
        self.audit_executions_total = Counter(
            'security_audit_executions_total',
            'Total number of security audit executions',
            ['audit_type', 'status', 'trigger'],
            registry=self.registry
        )
        
        self.audit_duration_seconds = Histogram(
            'security_audit_duration_seconds',
            'Security audit execution duration',
            ['audit_type', 'scope'],
            buckets=[60, 300, 600, 1200, 1800, 3600, 7200],
            registry=self.registry
        )
        
        # Security Findings Metrics
        self.security_findings_total = Counter(
            'security_findings_total',
            'Total security findings by severity and category',
            ['severity', 'category', 'scanner', 'compliance_framework'],
            registry=self.registry
        )
        
        self.security_score_gauge = Gauge(
            'security_score',
            'Overall security score (0-100)',
            ['application', 'environment'],
            registry=self.registry
        )
        
        self.risk_level_enum = PrometheusEnum(
            'security_risk_level',
            'Current security risk level',
            ['application'],
            states=['low', 'medium', 'high', 'critical'],
            registry=self.registry
        )
        
        # Compliance Metrics
        self.compliance_score_gauge = Gauge(
            'compliance_framework_score',
            'Compliance framework score percentage',
            ['framework', 'environment'],
            registry=self.registry
        )
        
        self.compliance_status_enum = PrometheusEnum(
            'compliance_framework_status',
            'Compliance framework status',
            ['framework'],
            states=['compliant', 'partially_compliant', 'non_compliant'],
            registry=self.registry
        )
        
        self.compliance_gaps_total = Counter(
            'compliance_gaps_total',
            'Total compliance gaps identified',
            ['framework', 'control_category', 'severity'],
            registry=self.registry
        )
        
        # Vulnerability Metrics
        self.vulnerabilities_by_severity = Gauge(
            'vulnerabilities_by_severity',
            'Current vulnerabilities by severity level',
            ['severity', 'category'],
            registry=self.registry
        )
        
        self.vulnerability_age_histogram = Histogram(
            'vulnerability_age_days',
            'Age of vulnerabilities in days',
            ['severity'],
            buckets=[1, 7, 14, 30, 60, 90, 180, 365],
            registry=self.registry
        )
        
        # Security Test Coverage Metrics
        self.test_coverage_percentage = Gauge(
            'security_test_coverage_percentage',
            'Security test coverage percentage',
            ['test_category', 'environment'],
            registry=self.registry
        )
        
        self.automated_tests_total = Counter(
            'security_automated_tests_total',
            'Total automated security tests executed',
            ['test_type', 'result'],
            registry=self.registry
        )
        
        # Performance Metrics
        self.scanner_performance_seconds = Histogram(
            'security_scanner_performance_seconds',
            'Security scanner execution time',
            ['scanner', 'scan_type'],
            buckets=[10, 30, 60, 300, 600, 1200, 1800],
            registry=self.registry
        )
        
        self.audit_memory_usage_bytes = Gauge(
            'security_audit_memory_usage_bytes',
            'Memory usage during security audit',
            registry=self.registry
        )
        
        # Remediation Metrics
        self.remediation_efforts_histogram = Histogram(
            'security_remediation_effort_hours',
            'Estimated remediation effort in hours',
            ['finding_severity', 'category'],
            buckets=[1, 4, 8, 16, 40, 80, 160],
            registry=self.registry
        )
        
        self.findings_remediated_total = Counter(
            'security_findings_remediated_total',
            'Total security findings remediated',
            ['severity', 'category', 'remediation_type'],
            registry=self.registry
        )
    
    def record_audit_execution(
        self, 
        audit_type: str, 
        status: str, 
        duration: float,
        trigger: str = "scheduled"
    ):
        """Record security audit execution metrics."""
        self.audit_executions_total.labels(
            audit_type=audit_type,
            status=status,
            trigger=trigger
        ).inc()
        
        self.audit_duration_seconds.labels(
            audit_type=audit_type,
            scope="comprehensive"
        ).observe(duration)
    
    def record_security_finding(
        self,
        severity: str,
        category: str,
        scanner: str,
        compliance_framework: str = "general"
    ):
        """Record security finding discovery."""
        self.security_findings_total.labels(
            severity=severity,
            category=category,
            scanner=scanner,
            compliance_framework=compliance_framework
        ).inc()
    
    def update_security_score(self, score: float, application: str = "flask_app"):
        """Update overall security score gauge."""
        self.security_score_gauge.labels(
            application=application,
            environment="production"
        ).set(score)
    
    def update_risk_level(self, risk_level: str, application: str = "flask_app"):
        """Update security risk level enum."""
        self.risk_level_enum.labels(application=application).state(risk_level)
    
    def update_compliance_metrics(self, framework: str, score: float, status: str):
        """Update compliance framework metrics."""
        self.compliance_score_gauge.labels(
            framework=framework,
            environment="production"
        ).set(score)
        
        self.compliance_status_enum.labels(framework=framework).state(status)
    
    def record_vulnerability_metrics(self, findings: List[SecurityFinding]):
        """Record comprehensive vulnerability metrics."""
        # Clear existing vulnerability gauges
        self.vulnerabilities_by_severity.clear()
        
        # Count vulnerabilities by severity and category
        severity_counts = defaultdict(lambda: defaultdict(int))
        
        for finding in findings:
            severity = finding.severity.value
            category = finding.category
            severity_counts[severity][category] += 1
            
            # Record vulnerability age
            age_days = (datetime.utcnow() - finding.discovered_date).days
            self.vulnerability_age_histogram.labels(severity=severity).observe(age_days)
        
        # Update vulnerability gauges
        for severity, categories in severity_counts.items():
            for category, count in categories.items():
                self.vulnerabilities_by_severity.labels(
                    severity=severity,
                    category=category
                ).set(count)


class ComprehensiveSecurityAuditor:
    """
    Enterprise-grade comprehensive security auditor implementing automated compliance 
    validation, security posture assessment, and regulatory compliance testing.
    
    This class provides the core security audit automation functionality including:
    - Comprehensive security testing orchestration across multiple scanners and frameworks
    - Enterprise compliance validation for SOC 2, ISO 27001, PCI DSS, and GDPR
    - Automated audit trail generation with comprehensive documentation
    - Security posture monitoring with real-time metrics and alerting
    - Executive dashboard integration with stakeholder-focused reporting
    - Continuous compliance monitoring with gap analysis and remediation planning
    
    The auditor integrates with existing security testing infrastructure and provides
    enterprise-grade audit capabilities with minimal performance impact.
    """
    
    def __init__(
        self,
        app: Optional[Flask] = None,
        config: Optional[Dict[str, Any]] = None,
        audit_logger: Optional[SecurityAuditLogger] = None
    ):
        """
        Initialize comprehensive security auditor with enterprise configuration.
        
        Args:
            app: Flask application instance for integration testing
            config: Security audit configuration dictionary
            audit_logger: Enterprise audit logger for compliance tracking
        """
        self.app = app
        self.config = config or {}
        self.audit_logger = audit_logger
        
        # Initialize audit metrics
        self.metrics = SecurityAuditMetrics()
        
        # Initialize security testing framework
        self.security_config = SecurityTestConfig()
        self.test_orchestrator = SecurityTestOrchestrator(self.security_config)
        
        # Initialize compliance validators
        self.compliance_validators = {
            ComplianceFramework.SOC2_TYPE2: self._create_soc2_validator(),
            ComplianceFramework.ISO_27001: self._create_iso27001_validator(),
            ComplianceFramework.PCI_DSS: self._create_pci_dss_validator(),
            ComplianceFramework.GDPR: self._create_gdpr_validator(),
            ComplianceFramework.OWASP_TOP_10: self._create_owasp_validator(),
            ComplianceFramework.NIST_CSF: self._create_nist_validator()
        }
        
        # Initialize audit execution tracking
        self.current_audit: Optional[SecurityAuditReport] = None
        self.audit_history: List[SecurityAuditReport] = []
        self.audit_lock = Lock()
        
        # Initialize performance monitoring
        self.performance_monitor = SecurityPerformanceMonitor(None)
        
        # Configure audit scheduling
        self.scheduled_audits = {}
        self.audit_scheduler_thread: Optional[Thread] = None
        
        logger.info("Comprehensive Security Auditor initialized successfully")
    
    def execute_comprehensive_audit(
        self,
        scope: List[str] = None,
        compliance_frameworks: List[ComplianceFramework] = None,
        include_penetration_testing: bool = True,
        generate_executive_report: bool = True
    ) -> SecurityAuditReport:
        """
        Execute comprehensive security audit with full enterprise compliance validation.
        
        This method orchestrates a complete security assessment including static analysis,
        dynamic testing, penetration testing, compliance validation, and executive reporting.
        
        Args:
            scope: List of security domains to audit (defaults to all)
            compliance_frameworks: Compliance frameworks to validate against
            include_penetration_testing: Whether to include penetration testing
            generate_executive_report: Whether to generate executive summary
            
        Returns:
            SecurityAuditReport with comprehensive findings and compliance results
            
        Example:
            auditor = ComprehensiveSecurityAuditor(app=flask_app)
            
            report = auditor.execute_comprehensive_audit(
                scope=['authentication', 'authorization', 'data_protection'],
                compliance_frameworks=[ComplianceFramework.SOC2_TYPE2, ComplianceFramework.GDPR],
                include_penetration_testing=True
            )
            
            print(f"Security Score: {report.overall_security_score}")
            print(f"Critical Findings: {report.critical_findings}")
        """
        audit_start_time = datetime.utcnow()
        
        # Initialize audit report
        with self.audit_lock:
            self.current_audit = SecurityAuditReport(
                audit_name="Comprehensive Security Audit",
                audit_scope=", ".join(scope) if scope else "Full Application Security Assessment",
                execution_date=audit_start_time,
                auditor="Comprehensive Security Auditor v1.0"
            )
        
        try:
            logger.info("Starting comprehensive security audit execution")
            
            # Log audit initiation
            if self.audit_logger:
                self.audit_logger.log_security_event(
                    event_type=SecurityEventType.ADMIN_SECURITY_POLICY_UPDATE,
                    message="Comprehensive security audit initiated",
                    severity="info",
                    metadata={
                        'audit_id': self.current_audit.report_id,
                        'scope': scope or ['full_application'],
                        'compliance_frameworks': [f.value for f in (compliance_frameworks or [])],
                        'penetration_testing_enabled': include_penetration_testing
                    }
                )
            
            # Phase 1: Static Security Analysis
            logger.info("Phase 1: Executing static security analysis")
            static_findings = self._execute_static_analysis()
            self.current_audit.findings.extend(static_findings)
            
            # Phase 2: Dynamic Security Testing
            logger.info("Phase 2: Executing dynamic security testing")
            dynamic_findings = self._execute_dynamic_testing()
            self.current_audit.findings.extend(dynamic_findings)
            
            # Phase 3: Penetration Testing (if enabled)
            if include_penetration_testing:
                logger.info("Phase 3: Executing penetration testing scenarios")
                pentest_findings = self._execute_penetration_testing()
                self.current_audit.findings.extend(pentest_findings)
            
            # Phase 4: Compliance Validation
            logger.info("Phase 4: Executing compliance framework validation")
            compliance_results = self._execute_compliance_validation(
                compliance_frameworks or [
                    ComplianceFramework.SOC2_TYPE2,
                    ComplianceFramework.OWASP_TOP_10,
                    ComplianceFramework.GDPR
                ]
            )
            self.current_audit.compliance_results = compliance_results
            
            # Phase 5: Security Posture Assessment
            logger.info("Phase 5: Executing security posture assessment")
            posture_findings = self._execute_security_posture_assessment()
            self.current_audit.findings.extend(posture_findings)
            
            # Phase 6: Risk Analysis and Prioritization
            logger.info("Phase 6: Executing risk analysis and prioritization")
            self._execute_risk_analysis()
            
            # Phase 7: Remediation Planning
            logger.info("Phase 7: Generating remediation recommendations")
            self._generate_remediation_plan()
            
            # Finalize audit report
            self.current_audit.completion_date = datetime.utcnow()
            self.current_audit.duration_minutes = (
                self.current_audit.completion_date - audit_start_time
            ).total_seconds() / 60
            
            # Update metrics
            self._update_audit_metrics()
            
            # Generate executive report if requested
            if generate_executive_report:
                self._generate_executive_dashboard()
            
            # Add to audit history
            self.audit_history.append(self.current_audit)
            
            # Log audit completion
            if self.audit_logger:
                self.audit_logger.log_security_event(
                    event_type=SecurityEventType.ADMIN_SECURITY_POLICY_UPDATE,
                    message="Comprehensive security audit completed",
                    severity="info",
                    metadata={
                        'audit_id': self.current_audit.report_id,
                        'duration_minutes': self.current_audit.duration_minutes,
                        'total_findings': self.current_audit.total_findings,
                        'security_score': self.current_audit.overall_security_score,
                        'risk_level': self.current_audit.risk_level
                    }
                )
            
            logger.info(f"Comprehensive security audit completed successfully. "
                       f"Security Score: {self.current_audit.overall_security_score:.1f}, "
                       f"Findings: {self.current_audit.total_findings}")
            
            return self.current_audit
            
        except Exception as e:
            logger.error(f"Comprehensive security audit failed: {str(e)}")
            
            if self.current_audit:
                self.current_audit.completion_date = datetime.utcnow()
                self.current_audit.duration_minutes = (
                    self.current_audit.completion_date - audit_start_time
                ).total_seconds() / 60
            
            # Log audit failure
            if self.audit_logger:
                self.audit_logger.log_security_event(
                    event_type=SecurityEventType.ADMIN_SECURITY_POLICY_UPDATE,
                    message="Comprehensive security audit failed",
                    severity="high",
                    metadata={
                        'audit_id': self.current_audit.report_id if self.current_audit else 'unknown',
                        'error': str(e),
                        'phase': 'comprehensive_audit'
                    }
                )
            
            raise
    
    def _execute_static_analysis(self) -> List[SecurityFinding]:
        """Execute comprehensive static security analysis using multiple scanners."""
        findings = []
        
        try:
            # Bandit Static Analysis
            logger.info("Running Bandit static analysis security scan")
            bandit_scanner = BanditSecurityScanner(self.security_config)
            bandit_results = bandit_scanner.run_security_scan()
            
            if bandit_results.get('scan_status') == 'completed':
                for issue in bandit_results.get('issues', []):
                    finding = SecurityFinding(
                        title=f"Static Analysis: {issue.get('test_name', 'Security Issue')}",
                        description=issue.get('issue_text', 'Static analysis security finding'),
                        severity=self._map_bandit_severity(issue.get('issue_severity', 'LOW')),
                        category="static_analysis",
                        cwe_id=issue.get('test_id'),
                        affected_components=[issue.get('filename', 'unknown')],
                        evidence={
                            'line_number': issue.get('line_number'),
                            'code': issue.get('code'),
                            'confidence': issue.get('issue_confidence'),
                            'more_info': issue.get('more_info')
                        },
                        remediation=self._generate_bandit_remediation(issue),
                        source_scanner="bandit",
                        source_test=issue.get('test_name', 'bandit_scan'),
                        compliance_frameworks=[ComplianceFramework.OWASP_TOP_10, ComplianceFramework.SOC2_TYPE2]
                    )
                    findings.append(finding)
            
            # Safety Dependency Analysis
            logger.info("Running Safety dependency vulnerability scan")
            safety_scanner = SafetyDependencyScanner(self.security_config)
            safety_results = safety_scanner.run_dependency_scan()
            
            if safety_results.get('scan_status') == 'completed':
                for vuln in safety_results.get('vulnerabilities', []):
                    finding = SecurityFinding(
                        title=f"Dependency Vulnerability: {vuln.get('package_name', 'Unknown Package')}",
                        description=vuln.get('advisory', 'Vulnerable dependency detected'),
                        severity=self._map_safety_severity(vuln),
                        category="dependency_vulnerability",
                        cwe_id=vuln.get('cve', vuln.get('id')),
                        affected_components=[vuln.get('package_name', 'unknown')],
                        evidence={
                            'vulnerable_spec': vuln.get('vulnerable_spec'),
                            'installed_version': vuln.get('installed_version'),
                            'advisory_url': vuln.get('more_info_url')
                        },
                        remediation=f"Update {vuln.get('package_name')} to version {vuln.get('safe_version', 'latest')}",
                        source_scanner="safety",
                        source_test="dependency_scan",
                        compliance_frameworks=[ComplianceFramework.OWASP_TOP_10, ComplianceFramework.SOC2_TYPE2]
                    )
                    findings.append(finding)
            
            logger.info(f"Static analysis completed: {len(findings)} findings discovered")
            
        except Exception as e:
            logger.error(f"Static analysis execution failed: {str(e)}")
            # Create error finding
            error_finding = SecurityFinding(
                title="Static Analysis Execution Error",
                description=f"Static security analysis failed: {str(e)}",
                severity=AuditSeverity.HIGH,
                category="audit_failure",
                remediation="Review static analysis configuration and dependencies",
                source_scanner="static_analysis",
                source_test="execution_error"
            )
            findings.append(error_finding)
        
        return findings
    
    def _execute_dynamic_testing(self) -> List[SecurityFinding]:
        """Execute comprehensive dynamic security testing using OWASP ZAP."""
        findings = []
        
        try:
            if not self.security_config.ZAP_ENABLED:
                logger.info("OWASP ZAP dynamic testing disabled, skipping")
                return findings
            
            logger.info("Running OWASP ZAP dynamic security testing")
            zap_scanner = OWASPZAPScanner(self.security_config)
            zap_results = zap_scanner.run_security_scan()
            
            if zap_results.get('scan_status') == 'completed':
                alerts = zap_results.get('alerts', {}).get('alerts', [])
                
                for alert in alerts:
                    finding = SecurityFinding(
                        title=f"Dynamic Analysis: {alert.get('alert', 'Security Alert')}",
                        description=alert.get('desc', 'Dynamic analysis security finding'),
                        severity=self._map_zap_risk_to_severity(alert.get('risk', 'Low')),
                        category="dynamic_analysis",
                        cwe_id=alert.get('cweid'),
                        owasp_category=alert.get('wasc_id'),
                        affected_components=[alert.get('url', 'unknown')],
                        evidence={
                            'url': alert.get('url'),
                            'method': alert.get('method'),
                            'evidence': alert.get('evidence'),
                            'attack': alert.get('attack'),
                            'param': alert.get('param'),
                            'confidence': alert.get('confidence'),
                            'reference': alert.get('reference')
                        },
                        remediation=alert.get('solution', 'Review and remediate the identified vulnerability'),
                        source_scanner="owasp_zap",
                        source_test="dynamic_scan",
                        compliance_frameworks=[ComplianceFramework.OWASP_TOP_10, ComplianceFramework.PCI_DSS]
                    )
                    findings.append(finding)
            
            logger.info(f"Dynamic testing completed: {len(findings)} findings discovered")
            
        except Exception as e:
            logger.error(f"Dynamic testing execution failed: {str(e)}")
            # Create error finding
            error_finding = SecurityFinding(
                title="Dynamic Testing Execution Error",
                description=f"Dynamic security testing failed: {str(e)}",
                severity=AuditSeverity.HIGH,
                category="audit_failure",
                remediation="Review OWASP ZAP configuration and target application availability",
                source_scanner="owasp_zap",
                source_test="execution_error"
            )
            findings.append(error_finding)
        
        return findings
    
    def _execute_penetration_testing(self) -> List[SecurityFinding]:
        """Execute comprehensive penetration testing scenarios."""
        findings = []
        
        try:
            logger.info("Running comprehensive penetration testing scenarios")
            penetration_tester = PenetrationTestRunner(self.security_config)
            pentest_results = penetration_tester.run_penetration_tests()
            
            if pentest_results.get('test_status') == 'completed':
                scenarios = pentest_results.get('scenarios', {})
                
                for scenario_name, scenario_result in scenarios.items():
                    if scenario_result.get('status') == 'completed':
                        vulnerabilities = scenario_result.get('vulnerabilities_found', [])
                        
                        for vuln in vulnerabilities:
                            finding = SecurityFinding(
                                title=f"Penetration Test: {vuln.get('type', 'Security Vulnerability')}",
                                description=vuln.get('description', 'Penetration testing vulnerability'),
                                severity=self._map_pentest_severity(vuln.get('severity', 'medium')),
                                category="penetration_testing",
                                affected_components=[vuln.get('endpoint', scenario_name)],
                                evidence={
                                    'attack_vector': vuln.get('payload'),
                                    'endpoint': vuln.get('endpoint'),
                                    'method': vuln.get('method'),
                                    'response_code': vuln.get('response_code'),
                                    'scenario': scenario_name
                                },
                                remediation=vuln.get('remediation', 'Implement security controls to prevent exploitation'),
                                likelihood="high",  # Penetration test findings are exploitable
                                technical_impact="High - Vulnerability confirmed through exploitation",
                                source_scanner="penetration_testing",
                                source_test=scenario_name,
                                compliance_frameworks=[ComplianceFramework.OWASP_TOP_10, ComplianceFramework.SOC2_TYPE2]
                            )
                            findings.append(finding)
            
            logger.info(f"Penetration testing completed: {len(findings)} findings discovered")
            
        except Exception as e:
            logger.error(f"Penetration testing execution failed: {str(e)}")
            # Create error finding
            error_finding = SecurityFinding(
                title="Penetration Testing Execution Error",
                description=f"Penetration testing failed: {str(e)}",
                severity=AuditSeverity.MEDIUM,
                category="audit_failure",
                remediation="Review penetration testing configuration and target application",
                source_scanner="penetration_testing",
                source_test="execution_error"
            )
            findings.append(error_finding)
        
        return findings
    
    def _execute_compliance_validation(
        self, 
        frameworks: List[ComplianceFramework]
    ) -> Dict[str, ComplianceResult]:
        """Execute comprehensive compliance validation for specified frameworks."""
        compliance_results = {}
        
        for framework in frameworks:
            try:
                logger.info(f"Validating compliance for {framework.value}")
                
                validator = self.compliance_validators.get(framework)
                if validator:
                    result = validator(self.current_audit.findings if self.current_audit else [])
                    compliance_results[framework.value] = result
                    
                    # Update compliance metrics
                    self.metrics.update_compliance_metrics(
                        framework=framework.value,
                        score=result.compliance_percentage,
                        status=result.status
                    )
                    
                else:
                    logger.warning(f"No validator available for framework: {framework.value}")
                    
            except Exception as e:
                logger.error(f"Compliance validation failed for {framework.value}: {str(e)}")
                
                # Create error result
                error_result = ComplianceResult(
                    framework=framework,
                    overall_score=0.0,
                    status="validation_error",
                    gaps_identified=[f"Validation error: {str(e)}"],
                    recommendations=["Review compliance validation configuration"]
                )
                compliance_results[framework.value] = error_result
        
        logger.info(f"Compliance validation completed for {len(compliance_results)} frameworks")
        return compliance_results
    
    def _execute_security_posture_assessment(self) -> List[SecurityFinding]:
        """Execute comprehensive security posture assessment."""
        findings = []
        
        try:
            logger.info("Executing security posture assessment")
            
            # Security Configuration Assessment
            config_findings = self._assess_security_configuration()
            findings.extend(config_findings)
            
            # Authentication Security Assessment
            auth_findings = self._assess_authentication_security()
            findings.extend(auth_findings)
            
            # Authorization Security Assessment
            authz_findings = self._assess_authorization_security()
            findings.extend(authz_findings)
            
            # Data Protection Assessment
            data_findings = self._assess_data_protection()
            findings.extend(data_findings)
            
            # Infrastructure Security Assessment
            infra_findings = self._assess_infrastructure_security()
            findings.extend(infra_findings)
            
            logger.info(f"Security posture assessment completed: {len(findings)} findings")
            
        except Exception as e:
            logger.error(f"Security posture assessment failed: {str(e)}")
            
            error_finding = SecurityFinding(
                title="Security Posture Assessment Error",
                description=f"Security posture assessment failed: {str(e)}",
                severity=AuditSeverity.MEDIUM,
                category="audit_failure",
                remediation="Review security posture assessment configuration",
                source_scanner="posture_assessment",
                source_test="execution_error"
            )
            findings.append(error_finding)
        
        return findings
    
    def _assess_security_configuration(self) -> List[SecurityFinding]:
        """Assess security configuration and hardening."""
        findings = []
        
        # Check Flask security configuration
        if self.app:
            # Check secret key configuration
            if not self.app.config.get('SECRET_KEY') or self.app.config.get('SECRET_KEY') == 'dev':
                findings.append(SecurityFinding(
                    title="Weak or Default Secret Key",
                    description="Flask application using weak or default secret key",
                    severity=AuditSeverity.HIGH,
                    category="configuration",
                    cwe_id="CWE-798",
                    remediation="Configure strong, randomly generated SECRET_KEY",
                    compliance_frameworks=[ComplianceFramework.SOC2_TYPE2, ComplianceFramework.OWASP_TOP_10]
                ))
            
            # Check debug mode
            if self.app.config.get('DEBUG'):
                findings.append(SecurityFinding(
                    title="Debug Mode Enabled in Production",
                    description="Flask debug mode enabled, exposing sensitive information",
                    severity=AuditSeverity.CRITICAL,
                    category="configuration",
                    cwe_id="CWE-489",
                    remediation="Disable debug mode in production environment",
                    compliance_frameworks=[ComplianceFramework.OWASP_TOP_10, ComplianceFramework.PCI_DSS]
                ))
            
            # Check session configuration
            if not self.app.config.get('SESSION_COOKIE_SECURE'):
                findings.append(SecurityFinding(
                    title="Insecure Session Cookies",
                    description="Session cookies not configured with Secure flag",
                    severity=AuditSeverity.MEDIUM,
                    category="session_management",
                    cwe_id="CWE-614",
                    remediation="Enable SESSION_COOKIE_SECURE for HTTPS-only cookies",
                    compliance_frameworks=[ComplianceFramework.OWASP_TOP_10, ComplianceFramework.PCI_DSS]
                ))
        
        return findings
    
    def _assess_authentication_security(self) -> List[SecurityFinding]:
        """Assess authentication security implementation."""
        findings = []
        
        # JWT Configuration Assessment
        findings.append(SecurityFinding(
            title="JWT Security Configuration Review",
            description="Verify JWT implementation follows security best practices",
            severity=AuditSeverity.INFO,
            category="authentication",
            remediation="Review JWT configuration for proper algorithm, expiration, and validation",
            compliance_frameworks=[ComplianceFramework.SOC2_TYPE2, ComplianceFramework.OWASP_TOP_10]
        ))
        
        # Session Management Assessment
        findings.append(SecurityFinding(
            title="Session Management Security Review",
            description="Verify session management implementation security",
            severity=AuditSeverity.INFO,
            category="session_management",
            remediation="Review session timeout, encryption, and regeneration policies",
            compliance_frameworks=[ComplianceFramework.SOC2_TYPE2, ComplianceFramework.PCI_DSS]
        ))
        
        return findings
    
    def _assess_authorization_security(self) -> List[SecurityFinding]:
        """Assess authorization and access control security."""
        findings = []
        
        # RBAC Implementation Assessment
        findings.append(SecurityFinding(
            title="Role-Based Access Control Review",
            description="Verify RBAC implementation and permission granularity",
            severity=AuditSeverity.INFO,
            category="authorization",
            remediation="Review role definitions, permission assignments, and access control enforcement",
            compliance_frameworks=[ComplianceFramework.SOC2_TYPE2, ComplianceFramework.OWASP_TOP_10]
        ))
        
        return findings
    
    def _assess_data_protection(self) -> List[SecurityFinding]:
        """Assess data protection and privacy controls."""
        findings = []
        
        # Encryption Assessment
        findings.append(SecurityFinding(
            title="Data Encryption Implementation Review",
            description="Verify data encryption for data at rest and in transit",
            severity=AuditSeverity.INFO,
            category="data_protection",
            remediation="Review encryption implementation for sensitive data handling",
            compliance_frameworks=[ComplianceFramework.GDPR, ComplianceFramework.PCI_DSS]
        ))
        
        # PII Handling Assessment
        findings.append(SecurityFinding(
            title="PII Handling and Privacy Controls",
            description="Assess personally identifiable information handling procedures",
            severity=AuditSeverity.INFO,
            category="privacy",
            remediation="Review PII collection, processing, and retention policies",
            compliance_frameworks=[ComplianceFramework.GDPR, ComplianceFramework.SOC2_TYPE2]
        ))
        
        return findings
    
    def _assess_infrastructure_security(self) -> List[SecurityFinding]:
        """Assess infrastructure and deployment security."""
        findings = []
        
        # Container Security Assessment
        findings.append(SecurityFinding(
            title="Container Security Configuration",
            description="Assess container security configuration and image scanning",
            severity=AuditSeverity.INFO,
            category="infrastructure",
            remediation="Review container security policies and image vulnerability scanning",
            compliance_frameworks=[ComplianceFramework.SOC2_TYPE2, ComplianceFramework.NIST_CSF]
        ))
        
        return findings
    
    def _execute_risk_analysis(self) -> None:
        """Execute comprehensive risk analysis and prioritization."""
        if not self.current_audit:
            return
        
        logger.info("Executing risk analysis and prioritization")
        
        # Calculate risk scores for all findings
        for finding in self.current_audit.findings:
            # Set business impact based on severity and category
            if finding.severity in [AuditSeverity.CRITICAL, AuditSeverity.HIGH]:
                finding.business_impact = "High - Could impact business operations or data security"
            elif finding.severity == AuditSeverity.MEDIUM:
                finding.business_impact = "Medium - May impact security posture"
            else:
                finding.business_impact = "Low - Minimal business impact"
            
            # Set technical impact
            if finding.category in ["injection", "authentication", "authorization"]:
                finding.technical_impact = "High - Could lead to system compromise"
            elif finding.category in ["session_management", "data_protection"]:
                finding.technical_impact = "Medium - Could expose sensitive data"
            else:
                finding.technical_impact = "Low - Limited technical impact"
            
            # Set likelihood based on category and exploitability
            if finding.source_scanner == "penetration_testing":
                finding.likelihood = "high"  # Confirmed exploitable
            elif finding.category in ["injection", "xss", "authentication"]:
                finding.likelihood = "medium"
            else:
                finding.likelihood = "low"
        
        # Sort findings by risk score
        self.current_audit.findings.sort(
            key=lambda f: f.calculate_risk_score(), 
            reverse=True
        )
        
        logger.info("Risk analysis completed")
    
    def _generate_remediation_plan(self) -> None:
        """Generate comprehensive remediation plan with prioritized actions."""
        if not self.current_audit:
            return
        
        logger.info("Generating remediation plan")
        
        immediate_actions = []
        short_term_actions = []
        long_term_actions = []
        
        for finding in self.current_audit.findings:
            risk_score = finding.calculate_risk_score()
            
            if risk_score >= 8.0 or finding.severity == AuditSeverity.CRITICAL:
                immediate_actions.append(
                    f"Critical: {finding.title} - {finding.remediation}"
                )
            elif risk_score >= 5.0 or finding.severity == AuditSeverity.HIGH:
                short_term_actions.append(
                    f"High Priority: {finding.title} - {finding.remediation}"
                )
            else:
                long_term_actions.append(
                    f"Standard Priority: {finding.title} - {finding.remediation}"
                )
        
        self.current_audit.immediate_actions = immediate_actions[:10]  # Top 10 critical
        self.current_audit.short_term_actions = short_term_actions[:20]  # Top 20 high
        self.current_audit.long_term_actions = long_term_actions[:30]  # Top 30 standard
        
        # Estimate overall remediation effort
        effort_scores = []
        for finding in self.current_audit.findings:
            if finding.severity == AuditSeverity.CRITICAL:
                effort_scores.append(3)
            elif finding.severity == AuditSeverity.HIGH:
                effort_scores.append(2)
            else:
                effort_scores.append(1)
        
        avg_effort = sum(effort_scores) / len(effort_scores) if effort_scores else 1
        if avg_effort >= 2.5:
            self.current_audit.estimated_remediation_effort = "high"
        elif avg_effort >= 1.5:
            self.current_audit.estimated_remediation_effort = "medium"
        else:
            self.current_audit.estimated_remediation_effort = "low"
        
        logger.info(f"Remediation plan generated: {len(immediate_actions)} immediate, "
                   f"{len(short_term_actions)} short-term, {len(long_term_actions)} long-term actions")
    
    def _update_audit_metrics(self) -> None:
        """Update Prometheus metrics with audit results."""
        if not self.current_audit:
            return
        
        # Record audit execution
        self.metrics.record_audit_execution(
            audit_type="comprehensive",
            status="completed",
            duration=self.current_audit.duration_minutes * 60
        )
        
        # Update security score and risk level
        self.metrics.update_security_score(self.current_audit.overall_security_score)
        self.metrics.update_risk_level(self.current_audit.risk_level)
        
        # Record findings metrics
        for finding in self.current_audit.findings:
            self.metrics.record_security_finding(
                severity=finding.severity.value,
                category=finding.category,
                scanner=finding.source_scanner
            )
        
        # Update vulnerability metrics
        self.metrics.record_vulnerability_metrics(self.current_audit.findings)
        
        # Update compliance metrics
        for framework_name, result in self.current_audit.compliance_results.items():
            self.metrics.update_compliance_metrics(
                framework=framework_name,
                score=result.compliance_percentage,
                status=result.status
            )
    
    def _generate_executive_dashboard(self) -> None:
        """Generate executive dashboard data for stakeholder communication."""
        if not self.current_audit:
            return
        
        logger.info("Generating executive dashboard")
        
        # Create executive summary
        executive_summary = self.current_audit.get_executive_summary()
        
        # Store dashboard data
        dashboard_data = {
            'executive_summary': executive_summary,
            'security_trends': self._calculate_security_trends(),
            'compliance_dashboard': self._generate_compliance_dashboard(),
            'risk_heatmap': self._generate_risk_heatmap(),
            'remediation_roadmap': self._generate_remediation_roadmap()
        }
        
        # Save dashboard data
        self.current_audit.metadata['executive_dashboard'] = dashboard_data
        
        logger.info("Executive dashboard generated successfully")
    
    def _calculate_security_trends(self) -> Dict[str, Any]:
        """Calculate security trends from historical audit data."""
        if len(self.audit_history) < 2:
            return {'trend': 'stable', 'message': 'Insufficient historical data'}
        
        # Compare with previous audit
        previous_audit = self.audit_history[-2]
        current_score = self.current_audit.overall_security_score
        previous_score = previous_audit.overall_security_score
        
        score_change = current_score - previous_score
        
        if score_change > 5:
            trend = 'improving'
        elif score_change < -5:
            trend = 'declining'
        else:
            trend = 'stable'
        
        return {
            'trend': trend,
            'score_change': score_change,
            'current_score': current_score,
            'previous_score': previous_score,
            'message': f"Security score {trend} by {abs(score_change):.1f} points"
        }
    
    def _generate_compliance_dashboard(self) -> Dict[str, Any]:
        """Generate compliance dashboard visualization data."""
        if not self.current_audit or not self.current_audit.compliance_results:
            return {}
        
        compliance_summary = {}
        for framework_name, result in self.current_audit.compliance_results.items():
            compliance_summary[framework_name] = {
                'score': result.compliance_percentage,
                'status': result.status,
                'gaps': len(result.gaps_identified),
                'next_assessment': result.next_assessment_due.strftime('%Y-%m-%d')
            }
        
        return compliance_summary
    
    def _generate_risk_heatmap(self) -> Dict[str, Any]:
        """Generate risk heatmap for visualization."""
        if not self.current_audit:
            return {}
        
        # Categorize findings by category and severity
        risk_matrix = defaultdict(lambda: defaultdict(int))
        
        for finding in self.current_audit.findings:
            category = finding.category
            severity = finding.severity.value
            risk_matrix[category][severity] += 1
        
        return dict(risk_matrix)
    
    def _generate_remediation_roadmap(self) -> Dict[str, Any]:
        """Generate remediation roadmap with timelines."""
        if not self.current_audit:
            return {}
        
        return {
            'immediate': {
                'count': len(self.current_audit.immediate_actions),
                'timeline': '0-30 days',
                'priority': 'critical'
            },
            'short_term': {
                'count': len(self.current_audit.short_term_actions),
                'timeline': '1-3 months',
                'priority': 'high'
            },
            'long_term': {
                'count': len(self.current_audit.long_term_actions),
                'timeline': '3-12 months',
                'priority': 'medium'
            }
        }
    
    # Compliance Framework Validators
    
    def _create_soc2_validator(self) -> Callable:
        """Create SOC 2 Type II compliance validator."""
        def validate_soc2_compliance(findings: List[SecurityFinding]) -> ComplianceResult:
            result = ComplianceResult(
                framework=ComplianceFramework.SOC2_TYPE2,
                assessor="SOC 2 Automated Validator"
            )
            
            # SOC 2 Trust Criteria Assessment
            trust_criteria = {
                'security': {'weight': 30, 'score': 100},
                'availability': {'weight': 20, 'score': 100},
                'processing_integrity': {'weight': 20, 'score': 100},
                'confidentiality': {'weight': 15, 'score': 100},
                'privacy': {'weight': 15, 'score': 100}
            }
            
            # Deduct points based on findings
            for finding in findings:
                penalty = self._calculate_soc2_penalty(finding)
                
                # Apply penalties to relevant criteria
                if finding.category in ['authentication', 'authorization', 'session_management']:
                    trust_criteria['security']['score'] -= penalty
                elif finding.category in ['infrastructure', 'availability']:
                    trust_criteria['availability']['score'] -= penalty
                elif finding.category in ['data_validation', 'integrity']:
                    trust_criteria['processing_integrity']['score'] -= penalty
                elif finding.category in ['encryption', 'data_protection']:
                    trust_criteria['confidentiality']['score'] -= penalty
                elif finding.category in ['privacy', 'pii_handling']:
                    trust_criteria['privacy']['score'] -= penalty
            
            # Calculate weighted score
            total_score = 0
            for criteria, data in trust_criteria.items():
                criteria_score = max(0, min(100, data['score']))
                weighted_score = criteria_score * (data['weight'] / 100)
                total_score += weighted_score
                result.control_results[criteria] = {
                    'score': criteria_score,
                    'weight': data['weight'],
                    'status': 'compliant' if criteria_score >= 80 else 'non_compliant'
                }
            
            result.overall_score = total_score
            
            # Identify gaps
            for criteria, data in result.control_results.items():
                if data['status'] == 'non_compliant':
                    result.gaps_identified.append(f"SOC 2 {criteria.title()} criteria not meeting requirements")
            
            # Generate recommendations
            if result.overall_score < 80:
                result.recommendations.append("Implement comprehensive security controls")
                result.recommendations.append("Establish formal security policies and procedures")
                result.recommendations.append("Conduct regular security training")
            
            return result
        
        return validate_soc2_compliance
    
    def _create_iso27001_validator(self) -> Callable:
        """Create ISO 27001 compliance validator."""
        def validate_iso27001_compliance(findings: List[SecurityFinding]) -> ComplianceResult:
            result = ComplianceResult(
                framework=ComplianceFramework.ISO_27001,
                assessor="ISO 27001 Automated Validator"
            )
            
            # ISO 27001 Control Categories
            control_categories = {
                'access_control': {'weight': 20, 'score': 100},
                'cryptography': {'weight': 15, 'score': 100},
                'operations_security': {'weight': 15, 'score': 100},
                'communications_security': {'weight': 10, 'score': 100},
                'system_acquisition': {'weight': 10, 'score': 100},
                'supplier_relationships': {'weight': 5, 'score': 100},
                'incident_management': {'weight': 10, 'score': 100},
                'business_continuity': {'weight': 5, 'score': 100},
                'compliance': {'weight': 10, 'score': 100}
            }
            
            # Apply penalties based on findings
            for finding in findings:
                penalty = self._calculate_iso27001_penalty(finding)
                
                if finding.category in ['authentication', 'authorization']:
                    control_categories['access_control']['score'] -= penalty
                elif finding.category in ['encryption', 'data_protection']:
                    control_categories['cryptography']['score'] -= penalty
                elif finding.category in ['configuration', 'infrastructure']:
                    control_categories['operations_security']['score'] -= penalty
                elif finding.category in ['transport_security', 'network']:
                    control_categories['communications_security']['score'] -= penalty
            
            # Calculate weighted score
            total_score = 0
            for category, data in control_categories.items():
                category_score = max(0, min(100, data['score']))
                weighted_score = category_score * (data['weight'] / 100)
                total_score += weighted_score
                result.control_results[category] = {
                    'score': category_score,
                    'weight': data['weight'],
                    'status': 'compliant' if category_score >= 85 else 'non_compliant'
                }
            
            result.overall_score = total_score
            
            # Identify gaps
            for category, data in result.control_results.items():
                if data['status'] == 'non_compliant':
                    result.gaps_identified.append(f"ISO 27001 {category.replace('_', ' ').title()} controls inadequate")
            
            return result
        
        return validate_iso27001_compliance
    
    def _create_pci_dss_validator(self) -> Callable:
        """Create PCI DSS compliance validator."""
        def validate_pci_dss_compliance(findings: List[SecurityFinding]) -> ComplianceResult:
            result = ComplianceResult(
                framework=ComplianceFramework.PCI_DSS,
                assessor="PCI DSS Automated Validator"
            )
            
            # PCI DSS Requirements
            pci_requirements = {
                'network_security': {'weight': 15, 'score': 100},
                'cardholder_data_protection': {'weight': 20, 'score': 100},
                'encryption_in_transit': {'weight': 15, 'score': 100},
                'vulnerability_management': {'weight': 15, 'score': 100},
                'access_control': {'weight': 15, 'score': 100},
                'network_monitoring': {'weight': 10, 'score': 100},
                'security_testing': {'weight': 10, 'score': 100}
            }
            
            # Apply penalties
            for finding in findings:
                penalty = self._calculate_pci_penalty(finding)
                
                if finding.category in ['network', 'infrastructure']:
                    pci_requirements['network_security']['score'] -= penalty
                elif finding.category in ['data_protection', 'privacy']:
                    pci_requirements['cardholder_data_protection']['score'] -= penalty
                elif finding.category in ['encryption', 'transport_security']:
                    pci_requirements['encryption_in_transit']['score'] -= penalty
                elif finding.category in ['dependency_vulnerability', 'static_analysis']:
                    pci_requirements['vulnerability_management']['score'] -= penalty
                elif finding.category in ['authentication', 'authorization']:
                    pci_requirements['access_control']['score'] -= penalty
            
            # Calculate score
            total_score = sum(
                max(0, min(100, data['score'])) * (data['weight'] / 100)
                for data in pci_requirements.values()
            )
            result.overall_score = total_score
            
            return result
        
        return validate_pci_dss_compliance
    
    def _create_gdpr_validator(self) -> Callable:
        """Create GDPR compliance validator."""
        def validate_gdpr_compliance(findings: List[SecurityFinding]) -> ComplianceResult:
            result = ComplianceResult(
                framework=ComplianceFramework.GDPR,
                assessor="GDPR Automated Validator"
            )
            
            # GDPR Principles
            gdpr_principles = {
                'lawfulness_fairness_transparency': {'weight': 15, 'score': 100},
                'purpose_limitation': {'weight': 10, 'score': 100},
                'data_minimisation': {'weight': 15, 'score': 100},
                'accuracy': {'weight': 10, 'score': 100},
                'storage_limitation': {'weight': 15, 'score': 100},
                'integrity_confidentiality': {'weight': 20, 'score': 100},
                'accountability': {'weight': 15, 'score': 100}
            }
            
            # Apply penalties for privacy and data protection findings
            for finding in findings:
                if finding.category in ['privacy', 'data_protection', 'encryption']:
                    penalty = self._calculate_gdpr_penalty(finding)
                    gdpr_principles['integrity_confidentiality']['score'] -= penalty
                    gdpr_principles['accountability']['score'] -= penalty / 2
            
            # Calculate score
            total_score = sum(
                max(0, min(100, data['score'])) * (data['weight'] / 100)
                for data in gdpr_principles.values()
            )
            result.overall_score = total_score
            
            return result
        
        return validate_gdpr_compliance
    
    def _create_owasp_validator(self) -> Callable:
        """Create OWASP Top 10 compliance validator."""
        def validate_owasp_compliance(findings: List[SecurityFinding]) -> ComplianceResult:
            result = ComplianceResult(
                framework=ComplianceFramework.OWASP_TOP_10,
                assessor="OWASP Top 10 Automated Validator"
            )
            
            # OWASP Top 10 Categories
            owasp_categories = {
                'broken_access_control': {'weight': 12, 'score': 100},
                'cryptographic_failures': {'weight': 12, 'score': 100},
                'injection': {'weight': 12, 'score': 100},
                'insecure_design': {'weight': 10, 'score': 100},
                'security_misconfiguration': {'weight': 12, 'score': 100},
                'vulnerable_components': {'weight': 12, 'score': 100},
                'authentication_failures': {'weight': 10, 'score': 100},
                'integrity_failures': {'weight': 8, 'score': 100},
                'logging_monitoring_failures': {'weight': 6, 'score': 100},
                'ssrf': {'weight': 6, 'score': 100}
            }
            
            # Map findings to OWASP categories and apply penalties
            for finding in findings:
                penalty = self._calculate_owasp_penalty(finding)
                
                if finding.category in ['authorization', 'access_control']:
                    owasp_categories['broken_access_control']['score'] -= penalty
                elif finding.category in ['encryption', 'cryptography']:
                    owasp_categories['cryptographic_failures']['score'] -= penalty
                elif finding.category in ['injection', 'xss', 'sql_injection']:
                    owasp_categories['injection']['score'] -= penalty
                elif finding.category in ['configuration', 'security_headers']:
                    owasp_categories['security_misconfiguration']['score'] -= penalty
                elif finding.category in ['dependency_vulnerability']:
                    owasp_categories['vulnerable_components']['score'] -= penalty
                elif finding.category in ['authentication', 'session_management']:
                    owasp_categories['authentication_failures']['score'] -= penalty
            
            # Calculate score
            total_score = sum(
                max(0, min(100, data['score'])) * (data['weight'] / 100)
                for data in owasp_categories.values()
            )
            result.overall_score = total_score
            
            return result
        
        return validate_owasp_compliance
    
    def _create_nist_validator(self) -> Callable:
        """Create NIST Cybersecurity Framework validator."""
        def validate_nist_compliance(findings: List[SecurityFinding]) -> ComplianceResult:
            result = ComplianceResult(
                framework=ComplianceFramework.NIST_CSF,
                assessor="NIST CSF Automated Validator"
            )
            
            # NIST Framework Functions
            nist_functions = {
                'identify': {'weight': 20, 'score': 100},
                'protect': {'weight': 25, 'score': 100},
                'detect': {'weight': 20, 'score': 100},
                'respond': {'weight': 15, 'score': 100},
                'recover': {'weight': 20, 'score': 100}
            }
            
            # Apply penalties based on findings
            for finding in findings:
                penalty = self._calculate_nist_penalty(finding)
                
                # Most security findings impact the "Protect" function
                nist_functions['protect']['score'] -= penalty
                
                # Configuration and vulnerability findings impact "Identify"
                if finding.category in ['configuration', 'vulnerability_management']:
                    nist_functions['identify']['score'] -= penalty / 2
            
            # Calculate score
            total_score = sum(
                max(0, min(100, data['score'])) * (data['weight'] / 100)
                for data in nist_functions.values()
            )
            result.overall_score = total_score
            
            return result
        
        return validate_nist_compliance
    
    # Penalty Calculation Methods
    
    def _calculate_soc2_penalty(self, finding: SecurityFinding) -> float:
        """Calculate SOC 2 compliance penalty for a finding."""
        base_penalties = {
            AuditSeverity.CRITICAL: 25.0,
            AuditSeverity.HIGH: 15.0,
            AuditSeverity.MEDIUM: 8.0,
            AuditSeverity.LOW: 3.0,
            AuditSeverity.INFO: 1.0
        }
        return base_penalties.get(finding.severity, 5.0)
    
    def _calculate_iso27001_penalty(self, finding: SecurityFinding) -> float:
        """Calculate ISO 27001 compliance penalty for a finding."""
        base_penalties = {
            AuditSeverity.CRITICAL: 30.0,
            AuditSeverity.HIGH: 20.0,
            AuditSeverity.MEDIUM: 10.0,
            AuditSeverity.LOW: 4.0,
            AuditSeverity.INFO: 1.0
        }
        return base_penalties.get(finding.severity, 5.0)
    
    def _calculate_pci_penalty(self, finding: SecurityFinding) -> float:
        """Calculate PCI DSS compliance penalty for a finding."""
        base_penalties = {
            AuditSeverity.CRITICAL: 35.0,
            AuditSeverity.HIGH: 25.0,
            AuditSeverity.MEDIUM: 12.0,
            AuditSeverity.LOW: 5.0,
            AuditSeverity.INFO: 1.0
        }
        return base_penalties.get(finding.severity, 7.0)
    
    def _calculate_gdpr_penalty(self, finding: SecurityFinding) -> float:
        """Calculate GDPR compliance penalty for a finding."""
        base_penalties = {
            AuditSeverity.CRITICAL: 40.0,
            AuditSeverity.HIGH: 25.0,
            AuditSeverity.MEDIUM: 12.0,
            AuditSeverity.LOW: 5.0,
            AuditSeverity.INFO: 2.0
        }
        return base_penalties.get(finding.severity, 8.0)
    
    def _calculate_owasp_penalty(self, finding: SecurityFinding) -> float:
        """Calculate OWASP Top 10 compliance penalty for a finding."""
        base_penalties = {
            AuditSeverity.CRITICAL: 30.0,
            AuditSeverity.HIGH: 20.0,
            AuditSeverity.MEDIUM: 10.0,
            AuditSeverity.LOW: 4.0,
            AuditSeverity.INFO: 1.0
        }
        return base_penalties.get(finding.severity, 6.0)
    
    def _calculate_nist_penalty(self, finding: SecurityFinding) -> float:
        """Calculate NIST CSF compliance penalty for a finding."""
        base_penalties = {
            AuditSeverity.CRITICAL: 25.0,
            AuditSeverity.HIGH: 15.0,
            AuditSeverity.MEDIUM: 8.0,
            AuditSeverity.LOW: 3.0,
            AuditSeverity.INFO: 1.0
        }
        return base_penalties.get(finding.severity, 5.0)
    
    # Severity Mapping Methods
    
    def _map_bandit_severity(self, bandit_severity: str) -> AuditSeverity:
        """Map Bandit severity to audit severity."""
        mapping = {
            'HIGH': AuditSeverity.HIGH,
            'MEDIUM': AuditSeverity.MEDIUM,
            'LOW': AuditSeverity.LOW
        }
        return mapping.get(bandit_severity.upper(), AuditSeverity.INFO)
    
    def _map_safety_severity(self, vulnerability: Dict[str, Any]) -> AuditSeverity:
        """Map Safety vulnerability to audit severity."""
        # Safety doesn't provide direct severity, use heuristics
        advisory = vulnerability.get('advisory', '').lower()
        
        if any(term in advisory for term in ['critical', 'remote code execution', 'rce']):
            return AuditSeverity.CRITICAL
        elif any(term in advisory for term in ['high', 'privilege escalation', 'sql injection']):
            return AuditSeverity.HIGH
        elif any(term in advisory for term in ['medium', 'xss', 'csrf']):
            return AuditSeverity.MEDIUM
        else:
            return AuditSeverity.LOW
    
    def _map_zap_risk_to_severity(self, zap_risk: str) -> AuditSeverity:
        """Map ZAP risk level to audit severity."""
        mapping = {
            'High': AuditSeverity.HIGH,
            'Medium': AuditSeverity.MEDIUM,
            'Low': AuditSeverity.LOW,
            'Informational': AuditSeverity.INFO
        }
        return mapping.get(zap_risk, AuditSeverity.INFO)
    
    def _map_pentest_severity(self, pentest_severity: str) -> AuditSeverity:
        """Map penetration test severity to audit severity."""
        mapping = {
            'critical': AuditSeverity.CRITICAL,
            'high': AuditSeverity.HIGH,
            'medium': AuditSeverity.MEDIUM,
            'low': AuditSeverity.LOW,
            'info': AuditSeverity.INFO
        }
        return mapping.get(pentest_severity.lower(), AuditSeverity.MEDIUM)
    
    def _generate_bandit_remediation(self, issue: Dict[str, Any]) -> str:
        """Generate specific remediation advice for Bandit findings."""
        test_id = issue.get('test_id', '')
        
        remediation_map = {
            'B101': 'Remove or properly handle assert statements in production code',
            'B102': 'Use safe functions instead of exec()',
            'B103': 'Avoid setting file permissions to 0777',
            'B104': 'Use secure methods for network binding',
            'B105': 'Use secure password hashing algorithms',
            'B106': 'Avoid hardcoded passwords in source code',
            'B107': 'Use secure random number generators',
            'B108': 'Use secure temporary file creation methods',
            'B110': 'Avoid try/except with bare except clauses',
            'B201': 'Use parameterized queries to prevent SQL injection',
            'B301': 'Use safe pickle alternatives or validate input',
            'B302': 'Use secure methods for object serialization',
            'B303': 'Use secure hash algorithms instead of MD5',
            'B304': 'Use secure hash algorithms instead of MD4',
            'B305': 'Use secure hash algorithms instead of SHA1',
            'B306': 'Use tempfile module for temporary file creation',
            'B307': 'Use safe eval alternatives or input validation',
            'B308': 'Use secure random number generators',
            'B309': 'Use secure HTTP methods and headers',
            'B310': 'Use secure URL validation',
            'B311': 'Use secure random number generators',
            'B312': 'Use secure random number generators',
            'B313': 'Use secure XML parsing to prevent XXE attacks',
            'B314': 'Use secure XML processing to prevent XXE attacks',
            'B315': 'Use secure XML processing to prevent XXE attacks',
            'B316': 'Use secure XML processing to prevent XXE attacks',
            'B317': 'Use secure XML processing to prevent XXE attacks',
            'B318': 'Use secure XML processing to prevent XXE attacks',
            'B319': 'Use secure XML processing to prevent XXE attacks',
            'B320': 'Use secure XML processing to prevent XXE attacks',
            'B321': 'Use secure FTP methods with proper authentication',
            'B322': 'Use secure input validation for user data',
            'B323': 'Use secure URL parsing and validation',
            'B324': 'Use strong hash algorithms for security purposes',
            'B325': 'Use secure temporary directory creation',
            'B401': 'Use secure import mechanisms',
            'B402': 'Use secure import mechanisms',
            'B403': 'Use secure import mechanisms',
            'B404': 'Use secure subprocess calls',
            'B405': 'Use secure import mechanisms',
            'B406': 'Use secure import mechanisms',
            'B407': 'Use secure XML processing',
            'B408': 'Use secure XML processing',
            'B409': 'Use secure XML processing',
            'B410': 'Use secure XML processing',
            'B411': 'Use secure XML processing',
            'B412': 'Use secure XML processing',
            'B501': 'Use certificate verification for requests',
            'B502': 'Use secure SSL/TLS configurations',
            'B503': 'Use secure SSL/TLS configurations',
            'B504': 'Use secure SSL/TLS configurations',
            'B505': 'Use secure SSH configurations',
            'B506': 'Use secure YAML loading methods',
            'B507': 'Use secure SSH key configurations',
            'B601': 'Avoid shell injection vulnerabilities',
            'B602': 'Use subprocess with shell=False',
            'B603': 'Use subprocess with shell=False',
            'B604': 'Use secure subprocess calls',
            'B605': 'Use secure subprocess calls',
            'B606': 'Use secure subprocess calls',
            'B607': 'Use secure subprocess calls',
            'B608': 'Use secure SQL query construction',
            'B609': 'Use secure subprocess calls',
            'B610': 'Use secure subprocess calls',
            'B611': 'Use secure subprocess calls',
            'B701': 'Use secure Jinja2 configurations',
            'B702': 'Use secure test configurations',
            'B703': 'Use secure test configurations'
        }
        
        return remediation_map.get(test_id, 'Review the security issue and implement appropriate mitigations')
    
    # Public API Methods
    
    def get_latest_audit_report(self) -> Optional[SecurityAuditReport]:
        """
        Get the latest completed security audit report.
        
        Returns:
            Latest SecurityAuditReport or None if no audits completed
        """
        return self.current_audit if self.current_audit else None
    
    def get_audit_history(self, limit: int = 10) -> List[SecurityAuditReport]:
        """
        Get historical audit reports.
        
        Args:
            limit: Maximum number of reports to return
            
        Returns:
            List of historical SecurityAuditReport instances
        """
        return self.audit_history[-limit:] if self.audit_history else []
    
    def export_audit_report(
        self, 
        report: Optional[SecurityAuditReport] = None,
        format_type: str = 'json',
        include_executive_summary: bool = True
    ) -> str:
        """
        Export audit report in specified format.
        
        Args:
            report: SecurityAuditReport to export (defaults to latest)
            format_type: Export format ('json', 'csv', 'html')
            include_executive_summary: Whether to include executive summary
            
        Returns:
            Exported report as string
        """
        target_report = report or self.current_audit
        if not target_report:
            raise ValueError("No audit report available for export")
        
        if format_type == 'json':
            return self._export_json_report(target_report, include_executive_summary)
        elif format_type == 'csv':
            return self._export_csv_report(target_report)
        elif format_type == 'html':
            return self._export_html_report(target_report, include_executive_summary)
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
    
    def _export_json_report(self, report: SecurityAuditReport, include_summary: bool) -> str:
        """Export audit report as JSON."""
        data = report.to_dict()
        
        if include_summary:
            data['executive_summary'] = report.get_executive_summary()
        
        return json.dumps(data, indent=2, default=str)
    
    def _export_csv_report(self, report: SecurityAuditReport) -> str:
        """Export audit report findings as CSV."""
        output = []
        
        # CSV Header
        headers = [
            'Finding ID', 'Title', 'Severity', 'Category', 'CWE ID', 
            'OWASP Category', 'Risk Score', 'Remediation', 'Source Scanner',
            'Discovered Date', 'Status'
        ]
        output.append(','.join(headers))
        
        # CSV Data
        for finding in report.findings:
            row = [
                finding.finding_id,
                f'"{finding.title}"',
                finding.severity.value,
                finding.category,
                finding.cwe_id or '',
                finding.owasp_category or '',
                str(finding.calculate_risk_score()),
                f'"{finding.remediation}"',
                finding.source_scanner,
                finding.discovered_date.strftime('%Y-%m-%d'),
                finding.status
            ]
            output.append(','.join(row))
        
        return '\n'.join(output)
    
    def _export_html_report(self, report: SecurityAuditReport, include_summary: bool) -> str:
        """Export audit report as HTML."""
        html_parts = [
            '<!DOCTYPE html>',
            '<html>',
            '<head>',
            '<title>Security Audit Report</title>',
            '<style>',
            'body { font-family: Arial, sans-serif; margin: 40px; }',
            'h1, h2, h3 { color: #333; }',
            '.summary { background: #f5f5f5; padding: 20px; border-radius: 5px; }',
            '.finding { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }',
            '.critical { border-left: 5px solid #d32f2f; }',
            '.high { border-left: 5px solid #f57c00; }',
            '.medium { border-left: 5px solid #fbc02d; }',
            '.low { border-left: 5px solid #388e3c; }',
            '.info { border-left: 5px solid #1976d2; }',
            '</style>',
            '</head>',
            '<body>',
            f'<h1>Security Audit Report</h1>',
            f'<p><strong>Report ID:</strong> {report.report_id}</p>',
            f'<p><strong>Execution Date:</strong> {report.execution_date.strftime("%Y-%m-%d %H:%M:%S")}</p>',
            f'<p><strong>Duration:</strong> {report.duration_minutes:.1f} minutes</p>'
        ]
        
        if include_summary:
            summary = report.get_executive_summary()
            html_parts.extend([
                '<div class="summary">',
                '<h2>Executive Summary</h2>',
                f'<p><strong>Security Score:</strong> {summary["security_posture"]["overall_score"]}/100</p>',
                f'<p><strong>Risk Level:</strong> {summary["security_posture"]["risk_level"].title()}</p>',
                f'<p><strong>Total Findings:</strong> {summary["key_findings"]["total_findings"]}</p>',
                f'<p><strong>Critical Issues:</strong> {summary["key_findings"]["critical_issues"]}</p>',
                '</div>'
            ])
        
        html_parts.append('<h2>Security Findings</h2>')
        
        for finding in report.findings:
            severity_class = finding.severity.value
            html_parts.extend([
                f'<div class="finding {severity_class}">',
                f'<h3>{finding.title}</h3>',
                f'<p><strong>Severity:</strong> {finding.severity.value.title()}</p>',
                f'<p><strong>Category:</strong> {finding.category}</p>',
                f'<p><strong>Description:</strong> {finding.description}</p>',
                f'<p><strong>Remediation:</strong> {finding.remediation}</p>',
                f'<p><strong>Risk Score:</strong> {finding.calculate_risk_score():.1f}/10</p>',
                '</div>'
            ])
        
        html_parts.extend(['</body>', '</html>'])
        
        return '\n'.join(html_parts)
    
    def get_compliance_dashboard(self) -> Dict[str, Any]:
        """
        Get comprehensive compliance dashboard data for enterprise reporting.
        
        Returns:
            Dictionary containing compliance dashboard metrics and visualizations
        """
        if not self.current_audit:
            return {'error': 'No audit data available'}
        
        dashboard = {
            'overview': {
                'last_audit_date': self.current_audit.execution_date.strftime('%Y-%m-%d'),
                'overall_security_score': self.current_audit.overall_security_score,
                'risk_level': self.current_audit.risk_level,
                'total_findings': self.current_audit.total_findings,
                'compliance_frameworks_assessed': len(self.current_audit.compliance_results)
            },
            'compliance_status': {},
            'findings_by_severity': {
                'critical': self.current_audit.critical_findings,
                'high': self.current_audit.high_findings,
                'medium': self.current_audit.medium_findings,
                'low': self.current_audit.low_findings,
                'info': self.current_audit.info_findings
            },
            'remediation_plan': {
                'immediate_actions': len(self.current_audit.immediate_actions),
                'short_term_actions': len(self.current_audit.short_term_actions),
                'long_term_actions': len(self.current_audit.long_term_actions)
            },
            'trends': self._calculate_security_trends(),
            'next_audit_due': (
                self.current_audit.execution_date + timedelta(days=90)
            ).strftime('%Y-%m-%d')
        }
        
        # Add compliance framework details
        for framework_name, result in self.current_audit.compliance_results.items():
            dashboard['compliance_status'][framework_name] = {
                'score': result.compliance_percentage,
                'status': result.status,
                'gaps': len(result.gaps_identified),
                'next_assessment': result.next_assessment_due.strftime('%Y-%m-%d')
            }
        
        return dashboard


# Pytest Integration and Test Automation
class SecurityAuditTestSuite:
    """
    Pytest-integrated security audit test suite for automated testing and CI/CD integration.
    
    This class provides pytest-compatible test methods for automated security testing
    with comprehensive coverage and enterprise-grade reporting capabilities.
    """
    
    def __init__(self, auditor: ComprehensiveSecurityAuditor):
        """Initialize security audit test suite with auditor instance."""
        self.auditor = auditor
        self.test_results = []
    
    def test_comprehensive_security_audit(self):
        """Test comprehensive security audit execution."""
        # Execute comprehensive audit
        report = self.auditor.execute_comprehensive_audit(
            compliance_frameworks=[
                ComplianceFramework.SOC2_TYPE2,
                ComplianceFramework.OWASP_TOP_10,
                ComplianceFramework.GDPR
            ]
        )
        
        # Assertions for test validation
        assert report is not None, "Security audit report should be generated"
        assert report.overall_security_score >= 0, "Security score should be non-negative"
        assert report.overall_security_score <= 100, "Security score should not exceed 100"
        assert len(report.compliance_results) > 0, "Compliance results should be available"
        
        # Check critical findings threshold
        assert report.critical_findings <= 5, f"Too many critical findings: {report.critical_findings}"
        
        # Log test results
        logger.info(f"Security audit test completed: Score={report.overall_security_score}, "
                   f"Findings={report.total_findings}, Risk={report.risk_level}")
        
        return report
    
    def test_compliance_validation(self):
        """Test individual compliance framework validation."""
        frameworks_to_test = [
            ComplianceFramework.SOC2_TYPE2,
            ComplianceFramework.OWASP_TOP_10,
            ComplianceFramework.GDPR
        ]
        
        for framework in frameworks_to_test:
            result = self.auditor._execute_compliance_validation([framework])
            
            assert framework.value in result, f"Compliance result missing for {framework.value}"
            
            compliance_result = result[framework.value]
            assert compliance_result.compliance_percentage >= 0, "Compliance percentage should be non-negative"
            assert compliance_result.compliance_percentage <= 100, "Compliance percentage should not exceed 100"
            
            logger.info(f"Compliance test passed for {framework.value}: "
                       f"{compliance_result.compliance_percentage:.1f}%")
    
    def test_security_metrics_collection(self):
        """Test security metrics collection and reporting."""
        # Verify metrics are being collected
        assert self.auditor.metrics is not None, "Security metrics should be initialized"
        
        # Test metric recording
        self.auditor.metrics.record_audit_execution(
            audit_type="test",
            status="completed",
            duration=60.0
        )
        
        self.auditor.metrics.update_security_score(85.0)
        self.auditor.metrics.update_risk_level("medium")
        
        logger.info("Security metrics collection test completed")
    
    def test_audit_report_export(self):
        """Test audit report export functionality."""
        if not self.auditor.current_audit:
            # Create a minimal audit report for testing
            self.auditor.current_audit = SecurityAuditReport(
                audit_name="Test Audit",
                overall_security_score=85.0
            )
        
        # Test JSON export
        json_report = self.auditor.export_audit_report(format_type='json')
        assert len(json_report) > 0, "JSON report should not be empty"
        
        # Validate JSON structure
        import json
        report_data = json.loads(json_report)
        assert 'report_id' in report_data, "Report should have ID"
        assert 'overall_security_score' in report_data, "Report should have security score"
        
        # Test CSV export
        csv_report = self.auditor.export_audit_report(format_type='csv')
        assert len(csv_report) > 0, "CSV report should not be empty"
        
        # Test HTML export
        html_report = self.auditor.export_audit_report(format_type='html')
        assert '<html>' in html_report, "HTML report should contain HTML tags"
        
        logger.info("Audit report export test completed")


# Factory function for creating security auditor instances
def create_security_auditor(
    app: Optional[Flask] = None,
    config: Optional[Dict[str, Any]] = None,
    enable_audit_logging: bool = True
) -> ComprehensiveSecurityAuditor:
    """
    Factory function for creating comprehensive security auditor instances.
    
    Args:
        app: Flask application instance for integration testing
        config: Security audit configuration dictionary
        enable_audit_logging: Whether to enable enterprise audit logging
        
    Returns:
        ComprehensiveSecurityAuditor instance ready for use
        
    Example:
        # Create auditor for Flask application
        app = Flask(__name__)
        auditor = create_security_auditor(app=app)
        
        # Execute comprehensive audit
        report = auditor.execute_comprehensive_audit()
        print(f"Security Score: {report.overall_security_score}")
    """
    # Initialize audit logger if enabled
    audit_logger = None
    if enable_audit_logging and app:
        audit_logger = init_security_audit(app)
    
    # Create and return auditor instance
    auditor = ComprehensiveSecurityAuditor(
        app=app,
        config=config,
        audit_logger=audit_logger
    )
    
    logger.info("Comprehensive Security Auditor created successfully")
    return auditor


# Export public API
__all__ = [
    # Main Classes
    'ComprehensiveSecurityAuditor',
    'SecurityAuditReport',
    'SecurityFinding',
    'ComplianceResult',
    'SecurityAuditMetrics',
    'SecurityAuditTestSuite',
    
    # Enums
    'ComplianceFramework',
    'AuditSeverity', 
    'AuditStatus',
    
    # Factory Functions
    'create_security_auditor',
]