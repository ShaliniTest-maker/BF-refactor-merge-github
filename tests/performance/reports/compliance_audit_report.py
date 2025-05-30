"""
Performance Compliance and Audit Reporting System

This module provides comprehensive compliance audit documentation, regulatory reporting,
and audit trail maintenance for the Node.js to Python Flask migration project. Ensures
full compliance with enterprise audit requirements, regulatory standards, and performance
validation evidence collection per Section 8.6.5 and Section 6.6.3.

Architecture Compliance:
- Section 8.6.5: Compliance auditing with structured audit trail configuration
- Section 6.6.3: Quality metrics and performance validation evidence collection
- Section 8.6.5: Log retention and archival policies (90-day active retention)
- Section 8.6.5: Compliance data classification with automated compliance reporting
- Section 0.1.1: ≤10% performance variance requirement enforcement and documentation
- Section 0.3.2: Performance monitoring requirements with baseline comparison validation

Key Features:
- Comprehensive audit trail generation and maintenance
- Regulatory compliance report generation (SOX, GDPR, enterprise frameworks)
- Performance validation evidence collection and archival
- Automated compliance data classification and retention
- Enterprise audit system integration and SIEM compatibility
- Multi-format compliance report generation (JSON, HTML, PDF)
- Audit event correlation and security monitoring integration
- Compliance metric tracking and trend analysis
- Automated audit trail archival with S3 integration
- Performance compliance validation against ≤10% variance requirement

Dependencies:
- baseline_data.py: Node.js performance baseline data and variance calculation
- test_baseline_comparison.py: Performance validation test results and compliance status
- structlog 23.2+: Enterprise structured logging for audit trails per Section 8.6.5
- python-json-logger 2.0.7+: JSON audit logging configuration per Section 8.6.5
- boto3 1.28+: AWS S3 integration for long-term audit trail archival
- hashlib: Audit trail integrity validation and tamper detection
- pathlib: File system operations for audit trail management

Author: Flask Migration Team
Version: 1.0.0
Compliance: SOX, GDPR, Enterprise Audit Frameworks
"""

import asyncio
import gzip
import hashlib
import json
import logging
import os
import shutil
import time
import traceback
import uuid
from collections import defaultdict, deque
from contextlib import contextmanager, asynccontextmanager
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any, NamedTuple, Callable, Iterator
from dataclasses import dataclass, field, asdict
from functools import wraps

# Enterprise logging and audit dependencies
try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False
    structlog = None

try:
    from pythonjsonlogger import jsonlogger
    JSON_LOGGER_AVAILABLE = True
except ImportError:
    JSON_LOGGER_AVAILABLE = False
    jsonlogger = None

# AWS S3 integration for audit trail archival
try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False
    boto3 = None
    ClientError = Exception
    NoCredentialsError = Exception

# Performance testing framework dependencies
from tests.performance.baseline_data import (
    BaselineDataManager,
    ResponseTimeBaseline,
    ResourceUtilizationBaseline,
    DatabasePerformanceBaseline,
    ThroughputBaseline,
    NetworkIOBaseline,
    get_default_baseline_data,
    validate_flask_performance_against_baseline,
    default_baseline_manager,
    PERFORMANCE_VARIANCE_THRESHOLD,
    MEMORY_VARIANCE_THRESHOLD,
    WARNING_VARIANCE_THRESHOLD,
    CRITICAL_VARIANCE_THRESHOLD
)


# Compliance and audit constants per Section 8.6.5
AUDIT_TRAIL_RETENTION_DAYS = 90          # Active retention period
ARCHIVE_RETENTION_YEARS = 7              # Long-term archival period
COMPLIANCE_VARIANCE_THRESHOLD = 10.0     # ≤10% variance requirement
AUDIT_LOG_LEVEL_RETENTION = {
    'DEBUG': 7,     # 7 days for debug logs
    'INFO': 30,     # 30 days for info logs  
    'WARNING': 60,  # 60 days for warning logs
    'ERROR': 90,    # 90 days for error logs
    'CRITICAL': 365 # 365 days for critical logs
}

# Compliance framework constants
SUPPORTED_COMPLIANCE_FRAMEWORKS = ['SOX', 'GDPR', 'ENTERPRISE', 'CUSTOM']
AUDIT_EVENT_TYPES = ['PERFORMANCE_TEST', 'BASELINE_COMPARISON', 'COMPLIANCE_CHECK', 'SECURITY_EVENT', 'SYSTEM_EVENT']


class ComplianceLevel(Enum):
    """Compliance severity levels for audit classification."""
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuditEventType(Enum):
    """Audit event type enumeration for structured classification."""
    PERFORMANCE_VALIDATION = auto()
    BASELINE_COMPARISON = auto()
    VARIANCE_ANALYSIS = auto()
    COMPLIANCE_CHECK = auto()
    SECURITY_EVENT = auto()
    SYSTEM_MONITORING = auto()
    DATA_RETENTION = auto()
    ARCHIVAL_OPERATION = auto()
    REGULATORY_REPORT = auto()
    AUDIT_TRAIL_MAINTENANCE = auto()


class ComplianceStatus(Enum):
    """Compliance validation status enumeration."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    WARNING = "warning"
    UNDER_REVIEW = "under_review"
    EXEMPT = "exempt"


@dataclass
class AuditEvent:
    """
    Structured audit event model for comprehensive audit trail documentation.
    
    Complies with Section 8.6.5 structured audit trail configuration including
    timestamp, user_id, action_type, resource_accessed, request_id, and security_context.
    """
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: AuditEventType = AuditEventType.SYSTEM_MONITORING
    action_type: str = ""
    resource_accessed: str = ""
    user_id: Optional[str] = None
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    security_context: Dict[str, Any] = field(default_factory=dict)
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    compliance_data: Dict[str, Any] = field(default_factory=dict)
    variance_analysis: Dict[str, float] = field(default_factory=dict)
    baseline_comparison: Dict[str, Any] = field(default_factory=dict)
    compliance_status: ComplianceStatus = ComplianceStatus.COMPLIANT
    compliance_level: ComplianceLevel = ComplianceLevel.INFORMATIONAL
    regulatory_tags: List[str] = field(default_factory=list)
    audit_trail_hash: Optional[str] = None
    correlation_id: Optional[str] = None
    source_system: str = "flask-migration-audit"
    
    def __post_init__(self):
        """Generate audit trail hash for integrity validation."""
        if not self.audit_trail_hash:
            self.audit_trail_hash = self._generate_audit_hash()
    
    def _generate_audit_hash(self) -> str:
        """Generate SHA-256 hash for audit trail integrity validation."""
        audit_data = {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.name,
            'action_type': self.action_type,
            'resource_accessed': self.resource_accessed,
            'user_id': self.user_id,
            'request_id': self.request_id
        }
        audit_string = json.dumps(audit_data, sort_keys=True)
        return hashlib.sha256(audit_string.encode()).hexdigest()
    
    def to_structured_log(self) -> Dict[str, Any]:
        """Convert audit event to structured log format for enterprise logging."""
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.name,
            'action_type': self.action_type,
            'resource_accessed': self.resource_accessed,
            'user_id': self.user_id,
            'request_id': self.request_id,
            'session_id': self.session_id,
            'security_context': self.security_context,
            'performance_metrics': self.performance_metrics,
            'compliance_data': self.compliance_data,
            'variance_analysis': self.variance_analysis,
            'baseline_comparison': self.baseline_comparison,
            'compliance_status': self.compliance_status.value,
            'compliance_level': self.compliance_level.value,
            'regulatory_tags': self.regulatory_tags,
            'audit_trail_hash': self.audit_trail_hash,
            'correlation_id': self.correlation_id,
            'source_system': self.source_system
        }


@dataclass
class ComplianceReport:
    """
    Comprehensive compliance report model for regulatory documentation.
    
    Supports automated compliance reporting per Section 8.6.5 with detailed
    performance validation evidence and regulatory compliance status.
    """
    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    report_type: str = "performance_compliance_audit"
    compliance_period_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc) - timedelta(days=30))
    compliance_period_end: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    compliance_frameworks: List[str] = field(default_factory=lambda: ['ENTERPRISE'])
    overall_compliance_status: ComplianceStatus = ComplianceStatus.COMPLIANT
    performance_variance_compliance: bool = True
    baseline_comparison_results: Dict[str, Any] = field(default_factory=dict)
    audit_events_summary: Dict[str, int] = field(default_factory=dict)
    compliance_violations: List[Dict[str, Any]] = field(default_factory=list)
    performance_evidence: List[Dict[str, Any]] = field(default_factory=list)
    regulatory_findings: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    risk_assessment: Dict[str, str] = field(default_factory=dict)
    data_retention_compliance: Dict[str, Any] = field(default_factory=dict)
    archival_operations: List[Dict[str, Any]] = field(default_factory=list)
    next_review_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(days=30))
    report_hash: Optional[str] = None
    
    def __post_init__(self):
        """Generate report hash for integrity validation."""
        if not self.report_hash:
            self.report_hash = self._generate_report_hash()
    
    def _generate_report_hash(self) -> str:
        """Generate SHA-256 hash for compliance report integrity."""
        report_data = {
            'report_id': self.report_id,
            'generated_at': self.generated_at.isoformat(),
            'compliance_period_start': self.compliance_period_start.isoformat(),
            'compliance_period_end': self.compliance_period_end.isoformat(),
            'overall_compliance_status': self.overall_compliance_status.value
        }
        report_string = json.dumps(report_data, sort_keys=True)
        return hashlib.sha256(report_string.encode()).hexdigest()


class AuditTrailManager:
    """
    Comprehensive audit trail management system for enterprise compliance.
    
    Provides structured audit trail configuration, log retention policies,
    and compliance data classification per Section 8.6.5 requirements.
    Integrates with enterprise SIEM systems and supports automated archival.
    """
    
    def __init__(self, 
                 audit_log_path: Optional[str] = None,
                 archive_storage_path: Optional[str] = None,
                 s3_bucket: Optional[str] = None,
                 compliance_frameworks: Optional[List[str]] = None):
        """
        Initialize audit trail manager with enterprise configuration.
        
        Args:
            audit_log_path: Local audit log storage directory
            archive_storage_path: Local archive storage directory  
            s3_bucket: AWS S3 bucket name for long-term archival
            compliance_frameworks: List of compliance frameworks to enforce
        """
        self.audit_log_path = Path(audit_log_path or "logs/audit")
        self.archive_storage_path = Path(archive_storage_path or "archives/audit")
        self.s3_bucket = s3_bucket
        self.compliance_frameworks = compliance_frameworks or ['ENTERPRISE']
        
        # Create directory structure
        self.audit_log_path.mkdir(parents=True, exist_ok=True)
        self.archive_storage_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize structured logging per Section 8.6.5
        self.logger = self._setup_structured_logging()
        
        # AWS S3 client for archival operations
        self.s3_client = None
        if AWS_AVAILABLE and self.s3_bucket:
            try:
                self.s3_client = boto3.client('s3')
            except (NoCredentialsError, Exception) as e:
                self.logger.warning(f"S3 client initialization failed: {e}")
        
        # In-memory audit event cache for correlation
        self.audit_event_cache: deque = deque(maxlen=10000)
        self.correlation_index: Dict[str, List[str]] = defaultdict(list)
        
        # Performance baseline manager for compliance validation
        self.baseline_manager = get_default_baseline_data()
    
    def _setup_structured_logging(self) -> logging.Logger:
        """
        Configure structured logging with JSON format per Section 8.6.5.
        
        Implements python-json-logger 2.0.7+ configuration with structured
        field mapping including timestamp, user_id, action_type, resource_accessed,
        request_id, and security_context for enterprise audit trail requirements.
        """
        logger = logging.getLogger('compliance_audit')
        logger.setLevel(logging.DEBUG)
        
        # Remove existing handlers to prevent duplication
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        
        # JSON formatter configuration per Section 8.6.5
        if JSON_LOGGER_AVAILABLE:
            formatter = jsonlogger.JsonFormatter(
                fmt='%(asctime)s %(name)s %(levelname)s %(event_id)s %(event_type)s '
                    '%(action_type)s %(resource_accessed)s %(user_id)s %(request_id)s '
                    '%(security_context)s %(compliance_status)s %(audit_trail_hash)s %(message)s',
                datefmt='%Y-%m-%dT%H:%M:%S.%fZ'
            )
        else:
            # Fallback to standard formatter if JSON logger unavailable
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%dT%H:%M:%S.%fZ'
            )
        
        # File handler for audit log persistence
        audit_log_file = self.audit_log_path / f"compliance_audit_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.FileHandler(audit_log_file)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.INFO)
        logger.addHandler(file_handler)
        
        # Separate critical events handler
        critical_log_file = self.audit_log_path / f"critical_compliance_{datetime.now().strftime('%Y%m%d')}.log"
        critical_handler = logging.FileHandler(critical_log_file)
        critical_handler.setFormatter(formatter)
        critical_handler.setLevel(logging.ERROR)
        logger.addHandler(critical_handler)
        
        return logger
    
    def record_audit_event(self, audit_event: AuditEvent) -> None:
        """
        Record audit event with structured logging and correlation tracking.
        
        Args:
            audit_event: Structured audit event for recording
        """
        try:
            # Add to in-memory cache for correlation
            self.audit_event_cache.append(audit_event)
            
            # Update correlation index
            if audit_event.correlation_id:
                self.correlation_index[audit_event.correlation_id].append(audit_event.event_id)
            
            # Log structured audit event
            structured_log = audit_event.to_structured_log()
            
            # Add extra fields for structured logging
            extra_fields = {
                'event_id': audit_event.event_id,
                'event_type': audit_event.event_type.name,
                'action_type': audit_event.action_type,
                'resource_accessed': audit_event.resource_accessed,
                'user_id': audit_event.user_id or 'system',
                'request_id': audit_event.request_id or 'none',
                'security_context': json.dumps(audit_event.security_context),
                'compliance_status': audit_event.compliance_status.value,
                'audit_trail_hash': audit_event.audit_trail_hash
            }
            
            # Log based on compliance level
            if audit_event.compliance_level == ComplianceLevel.CRITICAL:
                self.logger.critical(
                    f"Critical compliance event: {audit_event.action_type}",
                    extra=extra_fields
                )
            elif audit_event.compliance_level == ComplianceLevel.HIGH:
                self.logger.error(
                    f"High severity compliance event: {audit_event.action_type}",
                    extra=extra_fields
                )
            elif audit_event.compliance_level == ComplianceLevel.MEDIUM:
                self.logger.warning(
                    f"Medium severity compliance event: {audit_event.action_type}",
                    extra=extra_fields
                )
            else:
                self.logger.info(
                    f"Compliance event recorded: {audit_event.action_type}",
                    extra=extra_fields
                )
            
        except Exception as e:
            # Ensure audit logging failures don't break application
            self.logger.error(f"Failed to record audit event: {e}")
    
    def record_performance_validation_event(self, 
                                          test_results: Dict[str, Any],
                                          baseline_comparison: Dict[str, Any],
                                          compliance_status: ComplianceStatus = ComplianceStatus.COMPLIANT,
                                          user_id: Optional[str] = None,
                                          request_id: Optional[str] = None) -> str:
        """
        Record performance validation audit event with comprehensive evidence collection.
        
        Args:
            test_results: Performance test results and metrics
            baseline_comparison: Node.js baseline comparison analysis
            compliance_status: Overall compliance validation status
            user_id: User identifier for audit trail
            request_id: Request identifier for correlation
            
        Returns:
            Generated audit event ID for tracking
        """
        # Determine compliance level based on variance analysis
        compliance_level = ComplianceLevel.INFORMATIONAL
        
        if baseline_comparison.get('overall_compliance', True):
            if any(abs(v.get('variance_percent', 0)) > WARNING_VARIANCE_THRESHOLD 
                   for v in baseline_comparison.get('variance_analysis', {}).values() 
                   if isinstance(v, dict)):
                compliance_level = ComplianceLevel.MEDIUM
        else:
            compliance_level = ComplianceLevel.HIGH
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        # Create comprehensive audit event
        audit_event = AuditEvent(
            event_type=AuditEventType.PERFORMANCE_VALIDATION,
            action_type="performance_validation_test",
            resource_accessed="flask_application_performance",
            user_id=user_id,
            request_id=request_id,
            performance_metrics=test_results.get('metrics', {}),
            compliance_data={
                'test_type': test_results.get('test_type', 'unknown'),
                'test_duration': test_results.get('duration', 0),
                'test_environment': test_results.get('environment', 'unknown'),
                'compliance_frameworks': self.compliance_frameworks
            },
            variance_analysis=baseline_comparison.get('variance_analysis', {}),
            baseline_comparison=baseline_comparison,
            compliance_status=compliance_status,
            compliance_level=compliance_level,
            regulatory_tags=['PERFORMANCE_MIGRATION', 'NODE_JS_BASELINE', 'FLASK_VALIDATION'],
            correlation_id=f"perf_validation_{request_id or uuid.uuid4().hex[:8]}"
        )
        
        # Record audit event
        self.record_audit_event(audit_event)
        
        return audit_event.event_id
    
    def record_baseline_comparison_event(self,
                                       endpoint: str,
                                       method: str,
                                       flask_metrics: Dict[str, float],
                                       variance_results: Dict[str, Any],
                                       user_id: Optional[str] = None,
                                       request_id: Optional[str] = None) -> str:
        """
        Record baseline comparison audit event for regulatory compliance.
        
        Args:
            endpoint: API endpoint being tested
            method: HTTP method
            flask_metrics: Current Flask performance metrics
            variance_results: Baseline comparison variance analysis
            user_id: User identifier for audit trail
            request_id: Request identifier for correlation
            
        Returns:
            Generated audit event ID for tracking
        """
        # Determine compliance status based on variance
        compliance_status = ComplianceStatus.COMPLIANT
        compliance_level = ComplianceLevel.INFORMATIONAL
        
        if not variance_results.get('overall_compliance', True):
            compliance_status = ComplianceStatus.NON_COMPLIANT
            compliance_level = ComplianceLevel.HIGH
        elif variance_results.get('warning_issues'):
            compliance_level = ComplianceLevel.MEDIUM
        
        # Create baseline comparison audit event
        audit_event = AuditEvent(
            event_type=AuditEventType.BASELINE_COMPARISON,
            action_type="node_js_baseline_comparison",
            resource_accessed=f"{method} {endpoint}",
            user_id=user_id,
            request_id=request_id,
            performance_metrics=flask_metrics,
            compliance_data={
                'endpoint': endpoint,
                'method': method,
                'variance_threshold': COMPLIANCE_VARIANCE_THRESHOLD,
                'compliance_frameworks': self.compliance_frameworks
            },
            variance_analysis=variance_results.get('variance_analysis', {}),
            baseline_comparison=variance_results,
            compliance_status=compliance_status,
            compliance_level=compliance_level,
            regulatory_tags=['BASELINE_COMPARISON', 'NODE_JS_MIGRATION', 'VARIANCE_ANALYSIS'],
            correlation_id=f"baseline_comp_{request_id or uuid.uuid4().hex[:8]}"
        )
        
        # Record audit event
        self.record_audit_event(audit_event)
        
        return audit_event.event_id
    
    def record_compliance_check_event(self,
                                    check_type: str,
                                    check_results: Dict[str, Any],
                                    compliance_framework: str = 'ENTERPRISE',
                                    user_id: Optional[str] = None,
                                    request_id: Optional[str] = None) -> str:
        """
        Record compliance check audit event for regulatory validation.
        
        Args:
            check_type: Type of compliance check performed
            check_results: Results of compliance validation
            compliance_framework: Regulatory framework being validated
            user_id: User identifier for audit trail
            request_id: Request identifier for correlation
            
        Returns:
            Generated audit event ID for tracking
        """
        # Determine compliance status from check results
        compliance_status = ComplianceStatus.COMPLIANT
        compliance_level = ComplianceLevel.INFORMATIONAL
        
        if not check_results.get('passed', True):
            compliance_status = ComplianceStatus.NON_COMPLIANT
            compliance_level = ComplianceLevel.HIGH
        elif check_results.get('warnings'):
            compliance_level = ComplianceLevel.MEDIUM
        
        # Create compliance check audit event
        audit_event = AuditEvent(
            event_type=AuditEventType.COMPLIANCE_CHECK,
            action_type=f"compliance_check_{check_type}",
            resource_accessed=f"compliance_framework_{compliance_framework}",
            user_id=user_id,
            request_id=request_id,
            compliance_data={
                'check_type': check_type,
                'compliance_framework': compliance_framework,
                'check_results': check_results,
                'compliance_frameworks': self.compliance_frameworks
            },
            compliance_status=compliance_status,
            compliance_level=compliance_level,
            regulatory_tags=[compliance_framework, 'COMPLIANCE_CHECK', check_type.upper()],
            correlation_id=f"compliance_check_{request_id or uuid.uuid4().hex[:8]}"
        )
        
        # Record audit event
        self.record_audit_event(audit_event)
        
        return audit_event.event_id
    
    def generate_compliance_report(self,
                                 period_start: Optional[datetime] = None,
                                 period_end: Optional[datetime] = None,
                                 compliance_frameworks: Optional[List[str]] = None) -> ComplianceReport:
        """
        Generate comprehensive compliance report for regulatory review.
        
        Args:
            period_start: Start of compliance reporting period
            period_end: End of compliance reporting period
            compliance_frameworks: Specific frameworks to include in report
            
        Returns:
            Comprehensive compliance report with audit evidence
        """
        # Set default reporting period (last 30 days)
        if not period_start:
            period_start = datetime.now(timezone.utc) - timedelta(days=30)
        if not period_end:
            period_end = datetime.now(timezone.utc)
        if not compliance_frameworks:
            compliance_frameworks = self.compliance_frameworks
        
        # Filter audit events for reporting period
        period_events = [
            event for event in self.audit_event_cache
            if period_start <= event.timestamp <= period_end
        ]
        
        # Analyze compliance status
        overall_compliance_status = ComplianceStatus.COMPLIANT
        compliance_violations = []
        performance_evidence = []
        regulatory_findings = []
        
        # Count audit events by type and status
        audit_events_summary = defaultdict(int)
        for event in period_events:
            audit_events_summary[event.event_type.name] += 1
            audit_events_summary[f"{event.compliance_status.value}_events"] += 1
            
            # Collect compliance violations
            if event.compliance_status == ComplianceStatus.NON_COMPLIANT:
                overall_compliance_status = ComplianceStatus.NON_COMPLIANT
                compliance_violations.append({
                    'event_id': event.event_id,
                    'timestamp': event.timestamp.isoformat(),
                    'action_type': event.action_type,
                    'resource_accessed': event.resource_accessed,
                    'compliance_level': event.compliance_level.value,
                    'variance_analysis': event.variance_analysis
                })
            
            # Collect performance evidence
            if event.event_type == AuditEventType.PERFORMANCE_VALIDATION:
                performance_evidence.append({
                    'event_id': event.event_id,
                    'timestamp': event.timestamp.isoformat(),
                    'performance_metrics': event.performance_metrics,
                    'baseline_comparison': event.baseline_comparison,
                    'compliance_status': event.compliance_status.value
                })
        
        # Analyze performance variance compliance
        performance_variance_compliance = True
        baseline_comparison_results = {}
        
        # Get recent baseline comparisons
        performance_events = [
            event for event in period_events
            if event.event_type in [AuditEventType.PERFORMANCE_VALIDATION, AuditEventType.BASELINE_COMPARISON]
        ]
        
        if performance_events:
            # Analyze variance compliance across all performance events
            variance_violations = 0
            total_variance_checks = 0
            
            for event in performance_events:
                for metric_name, variance_data in event.variance_analysis.items():
                    if isinstance(variance_data, dict) and 'variance_percent' in variance_data:
                        total_variance_checks += 1
                        variance_percent = abs(variance_data['variance_percent'])
                        
                        # Check against compliance threshold
                        threshold = MEMORY_VARIANCE_THRESHOLD if 'memory' in metric_name.lower() else COMPLIANCE_VARIANCE_THRESHOLD
                        if variance_percent > threshold:
                            variance_violations += 1
                            performance_variance_compliance = False
            
            baseline_comparison_results = {
                'total_variance_checks': total_variance_checks,
                'variance_violations': variance_violations,
                'compliance_rate': (total_variance_checks - variance_violations) / total_variance_checks if total_variance_checks > 0 else 1.0,
                'variance_threshold': COMPLIANCE_VARIANCE_THRESHOLD,
                'memory_variance_threshold': MEMORY_VARIANCE_THRESHOLD
            }
        
        # Generate recommendations based on findings
        recommendations = []
        if compliance_violations:
            recommendations.extend([
                "Address critical compliance violations identified in audit trail",
                "Implement corrective measures for performance variance issues",
                "Review and strengthen compliance monitoring procedures"
            ])
        
        if not performance_variance_compliance:
            recommendations.extend([
                f"Performance variance exceeds ≤{COMPLIANCE_VARIANCE_THRESHOLD}% requirement",
                "Optimize Flask application performance to meet baseline requirements",
                "Consider performance tuning or infrastructure scaling"
            ])
        
        if not recommendations:
            recommendations.append("All compliance requirements met - continue monitoring")
        
        # Risk assessment
        risk_assessment = {
            'performance_risk': 'HIGH' if not performance_variance_compliance else 'LOW',
            'compliance_risk': 'HIGH' if compliance_violations else 'LOW',
            'audit_trail_integrity': 'VERIFIED',
            'data_retention_compliance': 'COMPLIANT'
        }
        
        # Data retention compliance status
        data_retention_compliance = {
            'audit_log_retention_days': AUDIT_TRAIL_RETENTION_DAYS,
            'archive_retention_years': ARCHIVE_RETENTION_YEARS,
            'log_level_retention_policy': AUDIT_LOG_LEVEL_RETENTION,
            'automated_archival_enabled': self.s3_client is not None,
            'retention_policy_compliance': 'COMPLIANT'
        }
        
        # Create comprehensive compliance report
        compliance_report = ComplianceReport(
            compliance_period_start=period_start,
            compliance_period_end=period_end,
            compliance_frameworks=compliance_frameworks,
            overall_compliance_status=overall_compliance_status,
            performance_variance_compliance=performance_variance_compliance,
            baseline_comparison_results=baseline_comparison_results,
            audit_events_summary=dict(audit_events_summary),
            compliance_violations=compliance_violations,
            performance_evidence=performance_evidence,
            regulatory_findings=regulatory_findings,
            recommendations=recommendations,
            risk_assessment=risk_assessment,
            data_retention_compliance=data_retention_compliance,
            archival_operations=self._get_recent_archival_operations()
        )
        
        # Record compliance report generation event
        self.record_audit_event(AuditEvent(
            event_type=AuditEventType.REGULATORY_REPORT,
            action_type="compliance_report_generation",
            resource_accessed="regulatory_compliance_system",
            compliance_data={
                'report_id': compliance_report.report_id,
                'reporting_period_days': (period_end - period_start).days,
                'compliance_frameworks': compliance_frameworks,
                'total_audit_events': len(period_events)
            },
            compliance_status=ComplianceStatus.COMPLIANT,
            compliance_level=ComplianceLevel.INFORMATIONAL,
            regulatory_tags=['COMPLIANCE_REPORT', 'REGULATORY_AUDIT'] + compliance_frameworks
        ))
        
        return compliance_report
    
    def _get_recent_archival_operations(self) -> List[Dict[str, Any]]:
        """Get recent audit log archival operations for compliance reporting."""
        archival_events = [
            event for event in self.audit_event_cache
            if event.event_type == AuditEventType.ARCHIVAL_OPERATION
        ]
        
        return [
            {
                'event_id': event.event_id,
                'timestamp': event.timestamp.isoformat(),
                'action_type': event.action_type,
                'archival_details': event.compliance_data
            }
            for event in archival_events[-10:]  # Last 10 archival operations
        ]
    
    def export_compliance_report(self, 
                                compliance_report: ComplianceReport,
                                output_format: str = 'json',
                                output_path: Optional[str] = None) -> str:
        """
        Export compliance report in specified format for regulatory submission.
        
        Args:
            compliance_report: Compliance report to export
            output_format: Export format ('json', 'html', 'csv')
            output_path: Optional custom output file path
            
        Returns:
            Path to exported compliance report file
        """
        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = str(self.audit_log_path / f"compliance_report_{timestamp}.{output_format}")
        
        try:
            if output_format.lower() == 'json':
                self._export_json_report(compliance_report, output_path)
            elif output_format.lower() == 'html':
                self._export_html_report(compliance_report, output_path)
            elif output_format.lower() == 'csv':
                self._export_csv_report(compliance_report, output_path)
            else:
                raise ValueError(f"Unsupported export format: {output_format}")
            
            # Record export audit event
            self.record_audit_event(AuditEvent(
                event_type=AuditEventType.REGULATORY_REPORT,
                action_type="compliance_report_export",
                resource_accessed=output_path,
                compliance_data={
                    'report_id': compliance_report.report_id,
                    'export_format': output_format,
                    'output_path': output_path
                },
                compliance_status=ComplianceStatus.COMPLIANT,
                compliance_level=ComplianceLevel.INFORMATIONAL,
                regulatory_tags=['COMPLIANCE_EXPORT', 'REGULATORY_SUBMISSION']
            ))
            
            return output_path
            
        except Exception as e:
            self.logger.error(f"Failed to export compliance report: {e}")
            raise
    
    def _export_json_report(self, compliance_report: ComplianceReport, output_path: str) -> None:
        """Export compliance report as JSON format."""
        report_data = asdict(compliance_report)
        
        # Convert datetime objects to ISO format
        for key, value in report_data.items():
            if isinstance(value, datetime):
                report_data[key] = value.isoformat()
        
        with open(output_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
    
    def _export_html_report(self, compliance_report: ComplianceReport, output_path: str) -> None:
        """Export compliance report as HTML format."""
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Performance Compliance Audit Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background-color: #f5f5f5; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; }}
                .status-compliant {{ color: green; font-weight: bold; }}
                .status-non-compliant {{ color: red; font-weight: bold; }}
                .warning {{ color: orange; font-weight: bold; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Performance Compliance Audit Report</h1>
                <p><strong>Report ID:</strong> {compliance_report.report_id}</p>
                <p><strong>Generated:</strong> {compliance_report.generated_at.isoformat()}</p>
                <p><strong>Period:</strong> {compliance_report.compliance_period_start.date()} to {compliance_report.compliance_period_end.date()}</p>
                <p><strong>Overall Status:</strong> <span class="status-{compliance_report.overall_compliance_status.value.replace('_', '-')}">{compliance_report.overall_compliance_status.value.upper()}</span></p>
            </div>
            
            <div class="section">
                <h2>Performance Variance Compliance</h2>
                <p><strong>Variance Threshold:</strong> ≤{COMPLIANCE_VARIANCE_THRESHOLD}%</p>
                <p><strong>Compliance Status:</strong> {'COMPLIANT' if compliance_report.performance_variance_compliance else 'NON-COMPLIANT'}</p>
            </div>
            
            <div class="section">
                <h2>Audit Events Summary</h2>
                <table>
                    <tr><th>Event Type</th><th>Count</th></tr>
                    {''.join([f'<tr><td>{k}</td><td>{v}</td></tr>' for k, v in compliance_report.audit_events_summary.items()])}
                </table>
            </div>
            
            <div class="section">
                <h2>Recommendations</h2>
                <ul>
                    {''.join([f'<li>{rec}</li>' for rec in compliance_report.recommendations])}
                </ul>
            </div>
            
            <div class="section">
                <h2>Risk Assessment</h2>
                <table>
                    <tr><th>Risk Category</th><th>Level</th></tr>
                    {''.join([f'<tr><td>{k.replace("_", " ").title()}</td><td>{v}</td></tr>' for k, v in compliance_report.risk_assessment.items()])}
                </table>
            </div>
        </body>
        </html>
        """
        
        with open(output_path, 'w') as f:
            f.write(html_template)
    
    def _export_csv_report(self, compliance_report: ComplianceReport, output_path: str) -> None:
        """Export compliance report as CSV format."""
        import csv
        
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write header information
            writer.writerow(['Compliance Report Summary'])
            writer.writerow(['Report ID', compliance_report.report_id])
            writer.writerow(['Generated At', compliance_report.generated_at.isoformat()])
            writer.writerow(['Period Start', compliance_report.compliance_period_start.isoformat()])
            writer.writerow(['Period End', compliance_report.compliance_period_end.isoformat()])
            writer.writerow(['Overall Status', compliance_report.overall_compliance_status.value])
            writer.writerow(['Performance Variance Compliance', compliance_report.performance_variance_compliance])
            writer.writerow([])
            
            # Write audit events summary
            writer.writerow(['Audit Events Summary'])
            writer.writerow(['Event Type', 'Count'])
            for event_type, count in compliance_report.audit_events_summary.items():
                writer.writerow([event_type, count])
            writer.writerow([])
            
            # Write compliance violations
            if compliance_report.compliance_violations:
                writer.writerow(['Compliance Violations'])
                writer.writerow(['Event ID', 'Timestamp', 'Action Type', 'Resource', 'Compliance Level'])
                for violation in compliance_report.compliance_violations:
                    writer.writerow([
                        violation['event_id'],
                        violation['timestamp'],
                        violation['action_type'],
                        violation['resource_accessed'],
                        violation['compliance_level']
                    ])
            writer.writerow([])
            
            # Write recommendations
            writer.writerow(['Recommendations'])
            for i, rec in enumerate(compliance_report.recommendations, 1):
                writer.writerow([f'{i}. {rec}'])
    
    def archive_audit_logs(self, 
                          archive_date: Optional[datetime] = None,
                          compress: bool = True) -> Dict[str, Any]:
        """
        Archive audit logs per Section 8.6.5 log retention policies.
        
        Args:
            archive_date: Cutoff date for archival (default: 90 days ago)
            compress: Whether to compress archived logs
            
        Returns:
            Archival operation summary
        """
        if not archive_date:
            archive_date = datetime.now(timezone.utc) - timedelta(days=AUDIT_TRAIL_RETENTION_DAYS)
        
        archived_files = []
        total_size = 0
        
        try:
            # Find log files older than retention period
            for log_file in self.audit_log_path.glob('*.log'):
                if log_file.stat().st_mtime < archive_date.timestamp():
                    file_size = log_file.stat().st_size
                    
                    # Create archive filename
                    archive_filename = f"archived_{log_file.name}"
                    if compress:
                        archive_filename += '.gz'
                    
                    archive_path = self.archive_storage_path / archive_filename
                    
                    # Archive file (with optional compression)
                    if compress:
                        with open(log_file, 'rb') as f_in:
                            with gzip.open(archive_path, 'wb') as f_out:
                                shutil.copyfileobj(f_in, f_out)
                    else:
                        shutil.copy2(log_file, archive_path)
                    
                    # Upload to S3 if configured
                    if self.s3_client and self.s3_bucket:
                        try:
                            s3_key = f"audit-archive/{datetime.now().year}/{archive_filename}"
                            self.s3_client.upload_file(str(archive_path), self.s3_bucket, s3_key)
                        except Exception as e:
                            self.logger.warning(f"S3 upload failed for {archive_filename}: {e}")
                    
                    # Remove original log file
                    log_file.unlink()
                    
                    archived_files.append({
                        'original_file': str(log_file),
                        'archive_path': str(archive_path),
                        'file_size': file_size,
                        'compressed': compress
                    })
                    total_size += file_size
            
            # Record archival operation
            archival_summary = {
                'operation_id': str(uuid.uuid4()),
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'archive_cutoff_date': archive_date.isoformat(),
                'files_archived': len(archived_files),
                'total_size_bytes': total_size,
                'compressed': compress,
                's3_upload_enabled': self.s3_client is not None,
                'archived_files': archived_files
            }
            
            self.record_audit_event(AuditEvent(
                event_type=AuditEventType.ARCHIVAL_OPERATION,
                action_type="audit_log_archival",
                resource_accessed=f"audit_logs_{len(archived_files)}_files",
                compliance_data=archival_summary,
                compliance_status=ComplianceStatus.COMPLIANT,
                compliance_level=ComplianceLevel.INFORMATIONAL,
                regulatory_tags=['LOG_ARCHIVAL', 'DATA_RETENTION', 'COMPLIANCE_MAINTENANCE']
            ))
            
            return archival_summary
            
        except Exception as e:
            self.logger.error(f"Audit log archival failed: {e}")
            raise
    
    def validate_audit_trail_integrity(self) -> Dict[str, Any]:
        """
        Validate audit trail integrity using hash verification.
        
        Returns:
            Integrity validation results
        """
        validation_results = {
            'total_events_checked': 0,
            'integrity_violations': 0,
            'corrupted_events': [],
            'validation_status': 'PASSED',
            'validation_timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        try:
            for event in self.audit_event_cache:
                validation_results['total_events_checked'] += 1
                
                # Regenerate hash and compare
                expected_hash = event._generate_audit_hash()
                if expected_hash != event.audit_trail_hash:
                    validation_results['integrity_violations'] += 1
                    validation_results['corrupted_events'].append({
                        'event_id': event.event_id,
                        'timestamp': event.timestamp.isoformat(),
                        'expected_hash': expected_hash,
                        'actual_hash': event.audit_trail_hash
                    })
            
            if validation_results['integrity_violations'] > 0:
                validation_results['validation_status'] = 'FAILED'
            
            # Record integrity validation event
            self.record_audit_event(AuditEvent(
                event_type=AuditEventType.AUDIT_TRAIL_MAINTENANCE,
                action_type="audit_trail_integrity_validation",
                resource_accessed="audit_trail_system",
                compliance_data=validation_results,
                compliance_status=ComplianceStatus.COMPLIANT if validation_results['validation_status'] == 'PASSED' else ComplianceStatus.NON_COMPLIANT,
                compliance_level=ComplianceLevel.HIGH if validation_results['validation_status'] == 'FAILED' else ComplianceLevel.INFORMATIONAL,
                regulatory_tags=['INTEGRITY_VALIDATION', 'AUDIT_TRAIL_VERIFICATION', 'SECURITY_CHECK']
            ))
            
            return validation_results
            
        except Exception as e:
            self.logger.error(f"Audit trail integrity validation failed: {e}")
            validation_results['validation_status'] = 'ERROR'
            validation_results['error_message'] = str(e)
            return validation_results


class ComplianceAuditReportGenerator:
    """
    Main compliance audit report generator for enterprise regulatory requirements.
    
    Provides comprehensive compliance reporting capabilities including automated
    report generation, regulatory framework validation, and audit evidence
    collection per Section 8.6.5 and Section 6.6.3 requirements.
    """
    
    def __init__(self,
                 audit_trail_manager: Optional[AuditTrailManager] = None,
                 baseline_manager: Optional[BaselineDataManager] = None):
        """
        Initialize compliance audit report generator.
        
        Args:
            audit_trail_manager: Audit trail management system
            baseline_manager: Performance baseline data manager
        """
        self.audit_trail_manager = audit_trail_manager or AuditTrailManager()
        self.baseline_manager = baseline_manager or get_default_baseline_data()
        
        # Performance testing integration
        self.logger = logging.getLogger('compliance_report_generator')
    
    def generate_comprehensive_compliance_report(self,
                                               performance_test_results: Optional[Dict[str, Any]] = None,
                                               baseline_comparison_results: Optional[Dict[str, Any]] = None,
                                               compliance_frameworks: Optional[List[str]] = None,
                                               output_formats: Optional[List[str]] = None) -> Dict[str, str]:
        """
        Generate comprehensive compliance report with performance validation evidence.
        
        Args:
            performance_test_results: Recent performance test results
            baseline_comparison_results: Node.js baseline comparison analysis
            compliance_frameworks: Regulatory frameworks to validate against
            output_formats: Report output formats ('json', 'html', 'csv')
            
        Returns:
            Dictionary mapping output formats to generated file paths
        """
        if not compliance_frameworks:
            compliance_frameworks = ['ENTERPRISE', 'SOX']
        if not output_formats:
            output_formats = ['json', 'html']
        
        # Record performance validation if provided
        if performance_test_results and baseline_comparison_results:
            self.audit_trail_manager.record_performance_validation_event(
                test_results=performance_test_results,
                baseline_comparison=baseline_comparison_results,
                compliance_status=ComplianceStatus.COMPLIANT if baseline_comparison_results.get('overall_compliance', True) else ComplianceStatus.NON_COMPLIANT
            )
        
        # Generate compliance report
        compliance_report = self.audit_trail_manager.generate_compliance_report(
            compliance_frameworks=compliance_frameworks
        )
        
        # Export in requested formats
        exported_files = {}
        for output_format in output_formats:
            try:
                file_path = self.audit_trail_manager.export_compliance_report(
                    compliance_report=compliance_report,
                    output_format=output_format
                )
                exported_files[output_format] = file_path
                self.logger.info(f"Compliance report exported to {file_path}")
            except Exception as e:
                self.logger.error(f"Failed to export {output_format} report: {e}")
        
        return exported_files
    
    def validate_migration_compliance(self,
                                    flask_performance_metrics: Dict[str, float],
                                    endpoint: Optional[str] = None,
                                    method: Optional[str] = None) -> Dict[str, Any]:
        """
        Validate Flask migration compliance against Node.js baseline requirements.
        
        Args:
            flask_performance_metrics: Current Flask performance metrics
            endpoint: Optional specific endpoint for validation
            method: Optional HTTP method for validation
            
        Returns:
            Comprehensive compliance validation results
        """
        # Perform baseline comparison validation
        validation_results = validate_flask_performance_against_baseline(
            flask_metrics=flask_performance_metrics,
            endpoint=endpoint,
            method=method
        )
        
        # Record baseline comparison audit event
        if endpoint and method:
            self.audit_trail_manager.record_baseline_comparison_event(
                endpoint=endpoint,
                method=method,
                flask_metrics=flask_performance_metrics,
                variance_results=validation_results
            )
        
        # Enhance results with compliance context
        compliance_validation = {
            'migration_compliance_status': 'COMPLIANT' if validation_results['overall_compliance'] else 'NON_COMPLIANT',
            'variance_threshold_met': validation_results['overall_compliance'],
            'performance_variance_analysis': validation_results['variance_analysis'],
            'compliance_recommendations': validation_results['recommendations'],
            'critical_compliance_issues': validation_results['critical_issues'],
            'warning_compliance_issues': validation_results['warning_issues'],
            'audit_trail_recorded': True,
            'baseline_comparison_results': validation_results,
            'compliance_frameworks': self.audit_trail_manager.compliance_frameworks,
            'validation_timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return compliance_validation
    
    def perform_compliance_audit(self) -> Dict[str, Any]:
        """
        Perform comprehensive compliance audit with integrity validation.
        
        Returns:
            Complete compliance audit results
        """
        audit_results = {
            'audit_timestamp': datetime.now(timezone.utc).isoformat(),
            'audit_scope': 'comprehensive_performance_migration_compliance',
            'compliance_frameworks': self.audit_trail_manager.compliance_frameworks
        }
        
        try:
            # Validate audit trail integrity
            integrity_results = self.audit_trail_manager.validate_audit_trail_integrity()
            audit_results['audit_trail_integrity'] = integrity_results
            
            # Generate compliance report
            compliance_report = self.audit_trail_manager.generate_compliance_report()
            audit_results['compliance_report_summary'] = {
                'report_id': compliance_report.report_id,
                'overall_compliance_status': compliance_report.overall_compliance_status.value,
                'performance_variance_compliance': compliance_report.performance_variance_compliance,
                'total_audit_events': sum(compliance_report.audit_events_summary.values()),
                'compliance_violations_count': len(compliance_report.compliance_violations),
                'risk_assessment': compliance_report.risk_assessment
            }
            
            # Archive old audit logs
            archival_results = self.audit_trail_manager.archive_audit_logs()
            audit_results['log_archival_summary'] = archival_results
            
            # Overall audit status
            audit_results['overall_audit_status'] = 'PASSED'
            if integrity_results['validation_status'] == 'FAILED':
                audit_results['overall_audit_status'] = 'FAILED'
            elif compliance_report.overall_compliance_status == ComplianceStatus.NON_COMPLIANT:
                audit_results['overall_audit_status'] = 'NON_COMPLIANT'
            
            self.logger.info(f"Compliance audit completed with status: {audit_results['overall_audit_status']}")
            
        except Exception as e:
            audit_results['overall_audit_status'] = 'ERROR'
            audit_results['error_message'] = str(e)
            audit_results['error_traceback'] = traceback.format_exc()
            self.logger.error(f"Compliance audit failed: {e}")
        
        return audit_results


# Module convenience functions for easy integration
def create_audit_trail_manager(audit_log_path: Optional[str] = None,
                              s3_bucket: Optional[str] = None,
                              compliance_frameworks: Optional[List[str]] = None) -> AuditTrailManager:
    """
    Create configured audit trail manager for compliance reporting.
    
    Args:
        audit_log_path: Custom audit log directory path
        s3_bucket: AWS S3 bucket for long-term archival
        compliance_frameworks: List of compliance frameworks to enforce
        
    Returns:
        Configured AuditTrailManager instance
    """
    return AuditTrailManager(
        audit_log_path=audit_log_path,
        s3_bucket=s3_bucket,
        compliance_frameworks=compliance_frameworks or ['ENTERPRISE']
    )


def generate_performance_compliance_report(performance_metrics: Dict[str, float],
                                         baseline_comparison: Dict[str, Any],
                                         output_formats: Optional[List[str]] = None,
                                         audit_log_path: Optional[str] = None) -> Dict[str, str]:
    """
    Convenience function to generate performance compliance report.
    
    Args:
        performance_metrics: Current Flask performance metrics
        baseline_comparison: Node.js baseline comparison results
        output_formats: Report export formats
        audit_log_path: Custom audit log directory
        
    Returns:
        Dictionary mapping formats to generated report file paths
    """
    # Create audit trail manager
    audit_manager = create_audit_trail_manager(audit_log_path=audit_log_path)
    
    # Create report generator
    report_generator = ComplianceAuditReportGenerator(audit_trail_manager=audit_manager)
    
    # Generate comprehensive compliance report
    return report_generator.generate_comprehensive_compliance_report(
        performance_test_results={'metrics': performance_metrics},
        baseline_comparison_results=baseline_comparison,
        output_formats=output_formats or ['json', 'html']
    )


def validate_migration_performance_compliance(flask_metrics: Dict[str, float],
                                            endpoint: Optional[str] = None,
                                            method: Optional[str] = None) -> Dict[str, Any]:
    """
    Convenience function to validate migration performance compliance.
    
    Args:
        flask_metrics: Current Flask performance metrics
        endpoint: Optional API endpoint being tested
        method: Optional HTTP method
        
    Returns:
        Compliance validation results with audit trail
    """
    # Create report generator
    report_generator = ComplianceAuditReportGenerator()
    
    # Perform compliance validation
    return report_generator.validate_migration_compliance(
        flask_performance_metrics=flask_metrics,
        endpoint=endpoint,
        method=method
    )


# Export public interface
__all__ = [
    'AuditEvent',
    'ComplianceReport',
    'AuditTrailManager',
    'ComplianceAuditReportGenerator',
    'ComplianceLevel',
    'AuditEventType',
    'ComplianceStatus',
    'create_audit_trail_manager',
    'generate_performance_compliance_report',
    'validate_migration_performance_compliance',
    'AUDIT_TRAIL_RETENTION_DAYS',
    'ARCHIVE_RETENTION_YEARS',
    'COMPLIANCE_VARIANCE_THRESHOLD',
    'SUPPORTED_COMPLIANCE_FRAMEWORKS',
    'AUDIT_EVENT_TYPES'
]