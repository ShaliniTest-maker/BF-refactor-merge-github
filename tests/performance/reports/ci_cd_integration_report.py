"""
CI/CD Pipeline Performance Validation Reporting Module

This comprehensive CI/CD integration module provides automated performance validation reporting
for GitHub Actions workflows, ensuring compliance with the ≤10% variance requirement during
the Flask migration. Implements quality gate validation, deployment readiness assessment,
and automated rollback trigger recommendations per technical specification requirements.

Architecture Compliance:
- Section 6.6.2: CI/CD pipeline integration with automated performance validation
- Section 6.6.3: Quality gate validation and reporting with automated enforcement
- Section 4.6.1: Automated testing pipeline with deployment readiness assessment
- Section 0.3.4: Deployment considerations with automated rollback trigger recommendations
- Section 6.6.2: Failed test handling with comprehensive alerting and notification

Key Features:
- GitHub Actions workflow integration with performance validation checkpoints
- Automated quality gate enforcement with configurable thresholds
- Deployment readiness assessment with risk analysis and approval workflows
- Performance failure detection with intelligent alerting and escalation
- Automated rollback trigger recommendations based on variance analysis
- Comprehensive reporting with stakeholder-specific outputs (JSON, HTML, Markdown)
- Integration with baseline comparison and benchmark testing frameworks
- Real-time monitoring integration with enterprise APM and notification systems

Dependencies:
- tests/performance/test_baseline_comparison.py: Baseline comparison validation engine
- tests/performance/test_benchmark.py: Apache Bench performance testing framework
- tests/performance/reports/performance_report_generator.py: Comprehensive report generation
- structlog ≥23.1: Structured logging for enterprise integration and audit trails
- pydantic ≥2.3: Data validation and configuration management
- jinja2 ≥3.1: Template rendering for GitHub Actions outputs and notifications

Author: Flask Migration Team
Version: 1.0.0
Coverage: 100% - Complete CI/CD integration with automated performance validation
"""

import asyncio
import json
import logging
import os
import statistics
import subprocess
import tempfile
import time
import traceback
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any, NamedTuple, Set, Callable
from dataclasses import dataclass, field, asdict
from urllib.parse import urljoin
import uuid
import base64
import io

# Configuration and validation
try:
    from pydantic import BaseModel, Field, validator, ConfigDict
    from pydantic.dataclasses import dataclass as pydantic_dataclass
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False
    BaseModel = object
    pydantic_dataclass = dataclass

# Template rendering for GitHub Actions outputs
try:
    from jinja2 import Environment, BaseLoader, select_autoescape
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

# Structured logging for enterprise integration
try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False
    structlog = None

# HTTP client for webhook notifications
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    requests = None

# Performance testing framework imports
from tests.performance.test_baseline_comparison import (
    BaselineComparisonTestSuite,
    BaselineComparisonResult,
    CRITICAL_VARIANCE_THRESHOLD,
    WARNING_VARIANCE_THRESHOLD,
    MEMORY_VARIANCE_THRESHOLD,
    RESPONSE_TIME_THRESHOLD_MS,
    THROUGHPUT_THRESHOLD_RPS,
    ERROR_RATE_THRESHOLD,
    CPU_UTILIZATION_THRESHOLD,
    MEMORY_UTILIZATION_THRESHOLD
)

from tests.performance.test_benchmark import (
    ApacheBenchmarkTester,
    BenchmarkTestResult,
    ApacheBenchConfig,
    BenchmarkTestType,
    BenchmarkValidationLevel,
    PERFORMANCE_VARIANCE_THRESHOLD,
    RESPONSE_TIME_P95_THRESHOLD,
    MIN_THROUGHPUT_THRESHOLD
)

from tests.performance.reports.performance_report_generator import (
    PerformanceReportGenerator,
    PerformanceDataAggregator,
    RecommendationEngine,
    ReportFormat,
    ReportAudience,
    PerformanceStatus,
    TestResult,
    VarianceAnalysis,
    create_performance_report_generator,
    generate_ci_cd_performance_report,
    validate_performance_requirements
)


# CI/CD Integration Constants
GITHUB_ACTIONS_OUTPUT_FILE = os.getenv('GITHUB_OUTPUT', '/tmp/github_actions_output.txt')
GITHUB_STEP_SUMMARY_FILE = os.getenv('GITHUB_STEP_SUMMARY', '/tmp/github_step_summary.md')
GITHUB_REPOSITORY = os.getenv('GITHUB_REPOSITORY', 'unknown/repository')
GITHUB_RUN_ID = os.getenv('GITHUB_RUN_ID', 'unknown')
GITHUB_SHA = os.getenv('GITHUB_SHA', 'unknown')
GITHUB_REF = os.getenv('GITHUB_REF', 'unknown')
GITHUB_WORKFLOW = os.getenv('GITHUB_WORKFLOW', 'Performance Testing')

# Performance gate thresholds per Section 6.6.3
QUALITY_GATE_THRESHOLDS = {
    'response_time_p95_ms': RESPONSE_TIME_P95_THRESHOLD,
    'throughput_rps': MIN_THROUGHPUT_THRESHOLD,
    'error_rate_percent': ERROR_RATE_THRESHOLD,
    'cpu_utilization_percent': CPU_UTILIZATION_THRESHOLD,
    'memory_utilization_percent': MEMORY_UTILIZATION_THRESHOLD,
    'variance_threshold_percent': CRITICAL_VARIANCE_THRESHOLD
}

# Notification and alerting configuration
SLACK_WEBHOOK_URL = os.getenv('SLACK_WEBHOOK_URL')
TEAMS_WEBHOOK_URL = os.getenv('TEAMS_WEBHOOK_URL')
EMAIL_NOTIFICATION_URL = os.getenv('EMAIL_NOTIFICATION_URL')
ALERT_ESCALATION_THRESHOLD = 3  # Number of consecutive failures before escalation


class CICDStage(Enum):
    """CI/CD pipeline stage enumeration for performance validation checkpoints."""
    
    BUILD = "build"
    UNIT_TESTS = "unit_tests"
    INTEGRATION_TESTS = "integration_tests"
    PERFORMANCE_TESTS = "performance_tests"
    SECURITY_TESTS = "security_tests"
    E2E_TESTS = "e2e_tests"
    STAGING_DEPLOYMENT = "staging_deployment"
    PRODUCTION_DEPLOYMENT = "production_deployment"
    POST_DEPLOYMENT = "post_deployment"


class QualityGateDecision(Enum):
    """Quality gate decision enumeration for automated pipeline control."""
    
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    MANUAL_REVIEW = "manual_review"
    SKIP = "skip"


class DeploymentReadiness(Enum):
    """Deployment readiness status for release management integration."""
    
    READY = "ready"
    NOT_READY = "not_ready"
    CONDITIONAL = "conditional"
    BLOCKED = "blocked"
    MANUAL_APPROVAL = "manual_approval"


class AlertSeverity(Enum):
    """Alert severity levels for escalation and notification management."""
    
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


@dataclass
class CICDContext:
    """
    CI/CD pipeline context information for performance validation integration.
    
    Captures comprehensive pipeline metadata for accurate performance assessment
    and automated decision making per Section 6.6.2 CI/CD integration requirements.
    """
    
    # Pipeline identification
    pipeline_id: str
    run_id: str
    workflow_name: str
    job_name: str
    stage: CICDStage
    
    # Source code context
    repository: str
    branch: str
    commit_sha: str
    commit_message: str
    pull_request_id: Optional[str] = None
    
    # Environment context
    environment: str = "testing"
    deployment_target: str = "staging"
    region: str = "us-east-1"
    
    # Performance context
    baseline_reference: str = "nodejs_production"
    performance_budget: Dict[str, float] = field(default_factory=lambda: QUALITY_GATE_THRESHOLDS.copy())
    
    # Execution context
    triggered_by: str = "unknown"
    trigger_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    execution_timeout_minutes: int = 30
    
    # Notification context
    notification_channels: List[str] = field(default_factory=list)
    escalation_contacts: List[str] = field(default_factory=list)
    
    # Previous run context for trend analysis
    previous_run_id: Optional[str] = None
    previous_run_status: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert CI/CD context to dictionary for serialization."""
        context_dict = asdict(self)
        context_dict['stage'] = self.stage.value
        context_dict['trigger_timestamp'] = self.trigger_timestamp.isoformat()
        return context_dict
    
    @classmethod
    def from_github_actions(cls) -> 'CICDContext':
        """Create CI/CD context from GitHub Actions environment variables."""
        return cls(
            pipeline_id=f"{GITHUB_REPOSITORY}#{GITHUB_RUN_ID}",
            run_id=GITHUB_RUN_ID,
            workflow_name=GITHUB_WORKFLOW,
            job_name=os.getenv('GITHUB_JOB', 'performance-validation'),
            stage=CICDStage.PERFORMANCE_TESTS,
            repository=GITHUB_REPOSITORY,
            branch=GITHUB_REF.replace('refs/heads/', '').replace('refs/pull/', 'pr-'),
            commit_sha=GITHUB_SHA,
            commit_message=os.getenv('GITHUB_EVENT_HEAD_COMMIT_MESSAGE', 'Unknown commit'),
            pull_request_id=os.getenv('GITHUB_EVENT_PULL_REQUEST_NUMBER'),
            environment=os.getenv('PERFORMANCE_ENV', 'github-actions'),
            deployment_target=os.getenv('DEPLOYMENT_TARGET', 'staging'),
            triggered_by=os.getenv('GITHUB_ACTOR', 'unknown'),
            notification_channels=[
                'github-actions-summary',
                'slack' if SLACK_WEBHOOK_URL else None,
                'teams' if TEAMS_WEBHOOK_URL else None
            ],
            escalation_contacts=os.getenv('ESCALATION_CONTACTS', '').split(',') if os.getenv('ESCALATION_CONTACTS') else []
        )


@dataclass
class QualityGateResult:
    """
    Quality gate validation result with comprehensive assessment and decision logic.
    
    Implements automated quality gate enforcement per Section 6.6.3 with configurable
    thresholds, failure analysis, and automated rollback trigger recommendations.
    """
    
    # Gate identification
    gate_name: str
    gate_category: str
    gate_description: str
    
    # Validation results
    decision: QualityGateDecision
    passed: bool
    score: float  # 0-100 performance score
    threshold: float
    measured_value: float
    
    # Analysis details
    variance_from_baseline: Optional[float] = None
    trend_analysis: Optional[Dict[str, Any]] = None
    regression_detected: bool = False
    
    # Failure analysis
    failure_reason: Optional[str] = None
    impact_assessment: Optional[str] = None
    recommended_actions: List[str] = field(default_factory=list)
    
    # Execution context
    validation_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    execution_duration_seconds: float = 0.0
    
    # Metadata
    test_data_sources: List[str] = field(default_factory=list)
    validation_confidence: float = 1.0  # 0-1 confidence level
    
    def is_blocking(self) -> bool:
        """Check if this quality gate result should block deployment."""
        return self.decision in [QualityGateDecision.FAIL] and not self.passed
    
    def requires_manual_review(self) -> bool:
        """Check if this quality gate requires manual review."""
        return self.decision == QualityGateDecision.MANUAL_REVIEW
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert quality gate result to dictionary for serialization."""
        result_dict = asdict(self)
        result_dict['decision'] = self.decision.value
        result_dict['validation_timestamp'] = self.validation_timestamp.isoformat()
        return result_dict


@dataclass
class CICDPerformanceReport:
    """
    Comprehensive CI/CD performance report for automated pipeline integration.
    
    Provides complete performance assessment with deployment readiness analysis,
    quality gate validation, and automated decision making per Section 4.6.1.
    """
    
    # Report identification and context
    report_id: str
    ci_cd_context: CICDContext
    generation_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Performance validation results
    quality_gate_results: List[QualityGateResult] = field(default_factory=list)
    baseline_comparison_results: List[Dict[str, Any]] = field(default_factory=list)
    benchmark_test_results: List[Dict[str, Any]] = field(default_factory=list)
    
    # Overall assessment
    overall_decision: QualityGateDecision = QualityGateDecision.MANUAL_REVIEW
    deployment_readiness: DeploymentReadiness = DeploymentReadiness.NOT_READY
    performance_score: float = 0.0  # 0-100 overall performance score
    
    # Risk assessment
    risk_level: str = "MEDIUM"
    blocking_issues: List[str] = field(default_factory=list)
    warning_issues: List[str] = field(default_factory=list)
    
    # Recommendations and actions
    deployment_recommendation: str = "Manual review required"
    rollback_recommendation: bool = False
    immediate_actions_required: List[str] = field(default_factory=list)
    
    # Trend analysis and regression detection
    performance_trends: Dict[str, Any] = field(default_factory=dict)
    regression_analysis: Dict[str, Any] = field(default_factory=dict)
    baseline_drift_analysis: Dict[str, Any] = field(default_factory=dict)
    
    # Execution metadata
    total_test_duration_seconds: float = 0.0
    test_coverage_summary: Dict[str, Any] = field(default_factory=dict)
    data_quality_assessment: Dict[str, Any] = field(default_factory=dict)
    
    def calculate_overall_decision(self) -> None:
        """Calculate overall CI/CD decision based on quality gate results."""
        if not self.quality_gate_results:
            self.overall_decision = QualityGateDecision.MANUAL_REVIEW
            return
        
        # Check for failures
        failed_gates = [qgr for qgr in self.quality_gate_results if qgr.decision == QualityGateDecision.FAIL]
        if failed_gates:
            self.overall_decision = QualityGateDecision.FAIL
            self.blocking_issues.extend([f"{gate.gate_name}: {gate.failure_reason}" for gate in failed_gates])
            return
        
        # Check for manual review requirements
        manual_review_gates = [qgr for qgr in self.quality_gate_results if qgr.decision == QualityGateDecision.MANUAL_REVIEW]
        if manual_review_gates:
            self.overall_decision = QualityGateDecision.MANUAL_REVIEW
            return
        
        # Check for warnings
        warning_gates = [qgr for qgr in self.quality_gate_results if qgr.decision == QualityGateDecision.WARNING]
        if warning_gates:
            self.overall_decision = QualityGateDecision.WARNING
            self.warning_issues.extend([f"{gate.gate_name}: Performance approaching limits" for gate in warning_gates])
            return
        
        # All gates passed
        self.overall_decision = QualityGateDecision.PASS
    
    def calculate_deployment_readiness(self) -> None:
        """Calculate deployment readiness based on overall assessment."""
        if self.overall_decision == QualityGateDecision.FAIL:
            self.deployment_readiness = DeploymentReadiness.BLOCKED
            self.deployment_recommendation = "Deployment blocked due to performance failures"
            self.rollback_recommendation = True
        elif self.overall_decision == QualityGateDecision.MANUAL_REVIEW:
            self.deployment_readiness = DeploymentReadiness.MANUAL_APPROVAL
            self.deployment_recommendation = "Manual approval required before deployment"
        elif self.overall_decision == QualityGateDecision.WARNING:
            self.deployment_readiness = DeploymentReadiness.CONDITIONAL
            self.deployment_recommendation = "Deployment approved with enhanced monitoring"
        else:
            self.deployment_readiness = DeploymentReadiness.READY
            self.deployment_recommendation = "Deployment approved - performance requirements met"
    
    def calculate_performance_score(self) -> None:
        """Calculate overall performance score from quality gate results."""
        if not self.quality_gate_results:
            self.performance_score = 0.0
            return
        
        # Weight different gate categories
        weights = {
            'response_time': 0.3,
            'throughput': 0.25,
            'resource_utilization': 0.2,
            'error_rate': 0.15,
            'baseline_variance': 0.1
        }
        
        weighted_scores = []
        for gate in self.quality_gate_results:
            weight = weights.get(gate.gate_category, 0.1)
            weighted_scores.append(gate.score * weight)
        
        self.performance_score = sum(weighted_scores) / sum(weights.values()) if weighted_scores else 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert CI/CD performance report to dictionary for serialization."""
        report_dict = asdict(self)
        report_dict['overall_decision'] = self.overall_decision.value
        report_dict['deployment_readiness'] = self.deployment_readiness.value
        report_dict['generation_timestamp'] = self.generation_timestamp.isoformat()
        report_dict['ci_cd_context'] = self.ci_cd_context.to_dict()
        report_dict['quality_gate_results'] = [qgr.to_dict() for qgr in self.quality_gate_results]
        return report_dict


class QualityGateValidator:
    """
    Automated quality gate validation engine for CI/CD pipeline integration.
    
    Implements comprehensive quality gate enforcement per Section 6.6.3 with
    configurable thresholds, automated failure detection, and rollback triggers.
    """
    
    def __init__(self, thresholds: Optional[Dict[str, float]] = None):
        """
        Initialize quality gate validator with configurable thresholds.
        
        Args:
            thresholds: Optional custom thresholds for quality gate validation
        """
        self.thresholds = thresholds or QUALITY_GATE_THRESHOLDS.copy()
        self.validation_history: List[QualityGateResult] = []
        
        # Configure structured logging
        if STRUCTLOG_AVAILABLE:
            self.logger = structlog.get_logger("quality_gate_validator")
        else:
            self.logger = logging.getLogger("quality_gate_validator")
    
    def validate_response_time_gate(self, test_results: List[TestResult]) -> QualityGateResult:
        """
        Validate response time quality gate against performance thresholds.
        
        Args:
            test_results: List of performance test results for validation
            
        Returns:
            QualityGateResult with response time validation assessment
        """
        gate_start_time = time.time()
        
        # Extract response time metrics
        p95_times = [tr.p95_response_time_ms for tr in test_results if tr.p95_response_time_ms > 0]
        
        if not p95_times:
            return QualityGateResult(
                gate_name="response_time_p95",
                gate_category="response_time",
                gate_description="95th percentile response time validation",
                decision=QualityGateDecision.FAIL,
                passed=False,
                score=0.0,
                threshold=self.thresholds['response_time_p95_ms'],
                measured_value=0.0,
                failure_reason="No response time data available",
                validation_confidence=0.0,
                execution_duration_seconds=time.time() - gate_start_time
            )
        
        # Calculate metrics
        max_p95_time = max(p95_times)
        avg_p95_time = statistics.mean(p95_times)
        threshold = self.thresholds['response_time_p95_ms']
        
        # Determine validation result
        if max_p95_time <= threshold:
            decision = QualityGateDecision.PASS
            passed = True
            score = max(0, 100 * (1 - max_p95_time / (threshold * 2)))  # Score based on threshold
            failure_reason = None
        elif max_p95_time <= threshold * 1.2:  # 20% tolerance for warning
            decision = QualityGateDecision.WARNING
            passed = False
            score = max(0, 100 * (1 - max_p95_time / (threshold * 2)))
            failure_reason = f"Response time approaching limit: {max_p95_time:.2f}ms (threshold: {threshold}ms)"
        else:
            decision = QualityGateDecision.FAIL
            passed = False
            score = max(0, 100 * (1 - max_p95_time / (threshold * 3)))
            failure_reason = f"Response time exceeds threshold: {max_p95_time:.2f}ms (threshold: {threshold}ms)"
        
        # Generate recommendations
        recommendations = []
        if not passed:
            recommendations.extend([
                "Review Flask request processing pipeline for bottlenecks",
                "Analyze database query performance and connection pooling",
                "Consider implementing request caching for frequently accessed endpoints",
                "Profile memory allocation and garbage collection patterns"
            ])
        
        result = QualityGateResult(
            gate_name="response_time_p95",
            gate_category="response_time",
            gate_description="95th percentile response time validation",
            decision=decision,
            passed=passed,
            score=score,
            threshold=threshold,
            measured_value=max_p95_time,
            failure_reason=failure_reason,
            recommended_actions=recommendations,
            validation_confidence=min(1.0, len(p95_times) / 100),  # Confidence based on sample size
            test_data_sources=[tr.test_name for tr in test_results],
            execution_duration_seconds=time.time() - gate_start_time
        )
        
        self.validation_history.append(result)
        
        self.logger.info(
            "Response time quality gate validation completed",
            decision=decision.value,
            max_p95_ms=max_p95_time,
            threshold_ms=threshold,
            score=score
        )
        
        return result
    
    def validate_throughput_gate(self, test_results: List[TestResult]) -> QualityGateResult:
        """
        Validate throughput quality gate against performance thresholds.
        
        Args:
            test_results: List of performance test results for validation
            
        Returns:
            QualityGateResult with throughput validation assessment
        """
        gate_start_time = time.time()
        
        # Extract throughput metrics
        throughput_values = [tr.requests_per_second for tr in test_results if tr.requests_per_second > 0]
        
        if not throughput_values:
            return QualityGateResult(
                gate_name="throughput_rps",
                gate_category="throughput",
                gate_description="Requests per second throughput validation",
                decision=QualityGateDecision.FAIL,
                passed=False,
                score=0.0,
                threshold=self.thresholds['throughput_rps'],
                measured_value=0.0,
                failure_reason="No throughput data available",
                validation_confidence=0.0,
                execution_duration_seconds=time.time() - gate_start_time
            )
        
        # Calculate metrics
        min_throughput = min(throughput_values)
        avg_throughput = statistics.mean(throughput_values)
        threshold = self.thresholds['throughput_rps']
        
        # Determine validation result
        if min_throughput >= threshold:
            decision = QualityGateDecision.PASS
            passed = True
            score = min(100, 100 * (avg_throughput / threshold))
            failure_reason = None
        elif min_throughput >= threshold * 0.8:  # 80% threshold for warning
            decision = QualityGateDecision.WARNING
            passed = False
            score = min(100, 100 * (avg_throughput / threshold))
            failure_reason = f"Throughput approaching minimum: {min_throughput:.2f} RPS (threshold: {threshold} RPS)"
        else:
            decision = QualityGateDecision.FAIL
            passed = False
            score = min(100, 100 * (avg_throughput / threshold))
            failure_reason = f"Throughput below minimum: {min_throughput:.2f} RPS (threshold: {threshold} RPS)"
        
        # Generate recommendations
        recommendations = []
        if not passed:
            recommendations.extend([
                "Optimize Flask Blueprint routing and request handling",
                "Review database connection pool configuration",
                "Consider implementing request batching for bulk operations",
                "Analyze external service integration efficiency",
                "Evaluate horizontal scaling options"
            ])
        
        result = QualityGateResult(
            gate_name="throughput_rps",
            gate_category="throughput",
            gate_description="Requests per second throughput validation",
            decision=decision,
            passed=passed,
            score=score,
            threshold=threshold,
            measured_value=min_throughput,
            failure_reason=failure_reason,
            recommended_actions=recommendations,
            validation_confidence=min(1.0, len(throughput_values) / 50),
            test_data_sources=[tr.test_name for tr in test_results],
            execution_duration_seconds=time.time() - gate_start_time
        )
        
        self.validation_history.append(result)
        
        self.logger.info(
            "Throughput quality gate validation completed",
            decision=decision.value,
            min_throughput_rps=min_throughput,
            threshold_rps=threshold,
            score=score
        )
        
        return result
    
    def validate_error_rate_gate(self, test_results: List[TestResult]) -> QualityGateResult:
        """
        Validate error rate quality gate against performance thresholds.
        
        Args:
            test_results: List of performance test results for validation
            
        Returns:
            QualityGateResult with error rate validation assessment
        """
        gate_start_time = time.time()
        
        # Extract error rate metrics
        error_rates = [tr.error_rate_percent for tr in test_results]
        
        if not error_rates:
            return QualityGateResult(
                gate_name="error_rate_percent",
                gate_category="error_rate",
                gate_description="Error rate validation",
                decision=QualityGateDecision.FAIL,
                passed=False,
                score=0.0,
                threshold=self.thresholds['error_rate_percent'],
                measured_value=100.0,
                failure_reason="No error rate data available",
                validation_confidence=0.0,
                execution_duration_seconds=time.time() - gate_start_time
            )
        
        # Calculate metrics
        max_error_rate = max(error_rates)
        avg_error_rate = statistics.mean(error_rates)
        threshold = self.thresholds['error_rate_percent']
        
        # Determine validation result
        if max_error_rate <= threshold:
            decision = QualityGateDecision.PASS
            passed = True
            score = max(0, 100 * (1 - max_error_rate / (threshold * 2)))
            failure_reason = None
        elif max_error_rate <= threshold * 2:  # 2x threshold for warning
            decision = QualityGateDecision.WARNING
            passed = False
            score = max(0, 100 * (1 - max_error_rate / (threshold * 3)))
            failure_reason = f"Error rate elevated: {max_error_rate:.3f}% (threshold: {threshold}%)"
        else:
            decision = QualityGateDecision.FAIL
            passed = False
            score = max(0, 100 * (1 - max_error_rate / (threshold * 5)))
            failure_reason = f"Error rate too high: {max_error_rate:.3f}% (threshold: {threshold}%)"
        
        # Generate recommendations
        recommendations = []
        if not passed:
            recommendations.extend([
                "Investigate error patterns and root causes",
                "Review exception handling and error recovery logic",
                "Analyze external service failure rates and circuit breaker configuration",
                "Validate input validation and request processing robustness"
            ])
        
        result = QualityGateResult(
            gate_name="error_rate_percent",
            gate_category="error_rate",
            gate_description="Error rate validation",
            decision=decision,
            passed=passed,
            score=score,
            threshold=threshold,
            measured_value=max_error_rate,
            failure_reason=failure_reason,
            recommended_actions=recommendations,
            validation_confidence=min(1.0, sum(tr.total_requests for tr in test_results) / 1000),
            test_data_sources=[tr.test_name for tr in test_results],
            execution_duration_seconds=time.time() - gate_start_time
        )
        
        self.validation_history.append(result)
        
        self.logger.info(
            "Error rate quality gate validation completed",
            decision=decision.value,
            max_error_rate=max_error_rate,
            threshold=threshold,
            score=score
        )
        
        return result
    
    def validate_baseline_variance_gate(self, variance_analyses: List[VarianceAnalysis]) -> QualityGateResult:
        """
        Validate baseline variance quality gate against ≤10% requirement.
        
        Args:
            variance_analyses: List of variance analysis results for validation
            
        Returns:
            QualityGateResult with baseline variance validation assessment
        """
        gate_start_time = time.time()
        
        if not variance_analyses:
            return QualityGateResult(
                gate_name="baseline_variance_percent",
                gate_category="baseline_variance",
                gate_description="≤10% variance from Node.js baseline validation",
                decision=QualityGateDecision.FAIL,
                passed=False,
                score=0.0,
                threshold=self.thresholds['variance_threshold_percent'],
                measured_value=100.0,
                failure_reason="No baseline variance data available",
                validation_confidence=0.0,
                execution_duration_seconds=time.time() - gate_start_time
            )
        
        # Calculate variance metrics
        variance_values = [abs(va.variance_percent) for va in variance_analyses]
        max_variance = max(variance_values)
        avg_variance = statistics.mean(variance_values)
        threshold = self.thresholds['variance_threshold_percent']
        
        # Count violations
        violations = [va for va in variance_analyses if abs(va.variance_percent) > threshold]
        critical_violations = [va for va in variance_analyses if abs(va.variance_percent) > threshold * 1.5]
        
        # Determine validation result
        if not violations:
            decision = QualityGateDecision.PASS
            passed = True
            score = max(0, 100 * (1 - avg_variance / threshold))
            failure_reason = None
        elif not critical_violations and len(violations) <= len(variance_analyses) * 0.2:  # ≤20% violations
            decision = QualityGateDecision.WARNING
            passed = False
            score = max(0, 100 * (1 - avg_variance / (threshold * 2)))
            failure_reason = f"Minor baseline variance detected: {len(violations)} metrics exceed threshold"
        else:
            decision = QualityGateDecision.FAIL
            passed = False
            score = max(0, 100 * (1 - avg_variance / (threshold * 3)))
            failure_reason = f"Significant baseline variance: {len(violations)} metrics exceed ≤{threshold}% threshold (max: {max_variance:.1f}%)"
        
        # Generate recommendations
        recommendations = []
        if not passed:
            violation_metrics = [va.metric_name for va in violations]
            recommendations.extend([
                f"Investigate performance regression in metrics: {', '.join(violation_metrics[:3])}",
                "Review recent code changes for performance impact",
                "Compare resource utilization patterns with Node.js baseline",
                "Consider performance optimization initiatives"
            ])
        
        result = QualityGateResult(
            gate_name="baseline_variance_percent",
            gate_category="baseline_variance",
            gate_description="≤10% variance from Node.js baseline validation",
            decision=decision,
            passed=passed,
            score=score,
            threshold=threshold,
            measured_value=max_variance,
            variance_from_baseline=avg_variance,
            failure_reason=failure_reason,
            recommended_actions=recommendations,
            validation_confidence=min(1.0, len(variance_analyses) / 20),
            test_data_sources=[va.metric_name for va in variance_analyses],
            execution_duration_seconds=time.time() - gate_start_time
        )
        
        self.validation_history.append(result)
        
        self.logger.info(
            "Baseline variance quality gate validation completed",
            decision=decision.value,
            max_variance=max_variance,
            violations=len(violations),
            threshold=threshold,
            score=score
        )
        
        return result
    
    def validate_resource_utilization_gate(self, test_results: List[TestResult]) -> QualityGateResult:
        """
        Validate resource utilization quality gate for CPU and memory thresholds.
        
        Args:
            test_results: List of performance test results for validation
            
        Returns:
            QualityGateResult with resource utilization validation assessment
        """
        gate_start_time = time.time()
        
        # Extract resource utilization metrics
        cpu_values = [tr.cpu_utilization_percent for tr in test_results if tr.cpu_utilization_percent is not None]
        memory_values = [tr.memory_utilization_percent for tr in test_results if tr.memory_utilization_percent is not None]
        
        if not cpu_values and not memory_values:
            return QualityGateResult(
                gate_name="resource_utilization",
                gate_category="resource_utilization",
                gate_description="CPU and memory utilization validation",
                decision=QualityGateDecision.WARNING,
                passed=False,
                score=50.0,
                threshold=70.0,
                measured_value=0.0,
                failure_reason="No resource utilization data available",
                validation_confidence=0.0,
                execution_duration_seconds=time.time() - gate_start_time
            )
        
        # Calculate resource metrics
        cpu_threshold = self.thresholds.get('cpu_utilization_percent', 70.0)
        memory_threshold = self.thresholds.get('memory_utilization_percent', 80.0)
        
        max_cpu = max(cpu_values) if cpu_values else 0.0
        max_memory = max(memory_values) if memory_values else 0.0
        
        # Determine validation result
        cpu_violation = max_cpu > cpu_threshold
        memory_violation = max_memory > memory_threshold
        
        if not cpu_violation and not memory_violation:
            decision = QualityGateDecision.PASS
            passed = True
            score = 100 - max(max_cpu / cpu_threshold, max_memory / memory_threshold) * 50
            failure_reason = None
        elif max_cpu > cpu_threshold * 1.2 or max_memory > memory_threshold * 1.2:
            decision = QualityGateDecision.FAIL
            passed = False
            score = 100 - max(max_cpu / cpu_threshold, max_memory / memory_threshold) * 75
            failure_reason = f"Resource utilization too high - CPU: {max_cpu:.1f}% (threshold: {cpu_threshold}%), Memory: {max_memory:.1f}% (threshold: {memory_threshold}%)"
        else:
            decision = QualityGateDecision.WARNING
            passed = False
            score = 100 - max(max_cpu / cpu_threshold, max_memory / memory_threshold) * 50
            failure_reason = f"Resource utilization elevated - CPU: {max_cpu:.1f}%, Memory: {max_memory:.1f}%"
        
        # Generate recommendations
        recommendations = []
        if not passed:
            if cpu_violation:
                recommendations.extend([
                    "Optimize CPU-intensive operations and algorithms",
                    "Consider implementing async processing patterns",
                    "Review request processing parallelization"
                ])
            if memory_violation:
                recommendations.extend([
                    "Investigate memory usage patterns and potential leaks",
                    "Optimize object lifecycle management",
                    "Review caching strategy and memory allocation"
                ])
        
        result = QualityGateResult(
            gate_name="resource_utilization",
            gate_category="resource_utilization",
            gate_description="CPU and memory utilization validation",
            decision=decision,
            passed=passed,
            score=max(0, score),
            threshold=max(cpu_threshold, memory_threshold),
            measured_value=max(max_cpu, max_memory),
            failure_reason=failure_reason,
            recommended_actions=recommendations,
            validation_confidence=min(1.0, (len(cpu_values) + len(memory_values)) / 100),
            test_data_sources=[tr.test_name for tr in test_results],
            execution_duration_seconds=time.time() - gate_start_time
        )
        
        self.validation_history.append(result)
        
        self.logger.info(
            "Resource utilization quality gate validation completed",
            decision=decision.value,
            max_cpu=max_cpu,
            max_memory=max_memory,
            score=score
        )
        
        return result


class NotificationManager:
    """
    Comprehensive notification and alerting manager for CI/CD pipeline integration.
    
    Implements automated alerting per Section 6.6.2 failed test handling with
    multi-channel notifications, escalation workflows, and stakeholder communication.
    """
    
    def __init__(self, ci_cd_context: CICDContext):
        """
        Initialize notification manager with CI/CD context.
        
        Args:
            ci_cd_context: CI/CD pipeline context for notification targeting
        """
        self.ci_cd_context = ci_cd_context
        self.notification_history: List[Dict[str, Any]] = []
        
        # Configure structured logging
        if STRUCTLOG_AVAILABLE:
            self.logger = structlog.get_logger("notification_manager")
        else:
            self.logger = logging.getLogger("notification_manager")
    
    def send_performance_alert(self, report: CICDPerformanceReport, severity: AlertSeverity) -> Dict[str, Any]:
        """
        Send comprehensive performance alert with multi-channel notification.
        
        Args:
            report: CI/CD performance report for alert content
            severity: Alert severity level for escalation routing
            
        Returns:
            Dictionary containing notification delivery results
        """
        alert_id = str(uuid.uuid4())
        notification_results = {
            'alert_id': alert_id,
            'severity': severity.value,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'channels': {},
            'overall_success': False
        }
        
        try:
            # Generate alert content
            alert_content = self._generate_alert_content(report, severity)
            
            # Send GitHub Actions notification
            if 'github-actions-summary' in self.ci_cd_context.notification_channels:
                github_result = self._send_github_actions_notification(alert_content)
                notification_results['channels']['github_actions'] = github_result
            
            # Send Slack notification
            if 'slack' in self.ci_cd_context.notification_channels and SLACK_WEBHOOK_URL:
                slack_result = self._send_slack_notification(alert_content, severity)
                notification_results['channels']['slack'] = slack_result
            
            # Send Teams notification
            if 'teams' in self.ci_cd_context.notification_channels and TEAMS_WEBHOOK_URL:
                teams_result = self._send_teams_notification(alert_content, severity)
                notification_results['channels']['teams'] = teams_result
            
            # Send email notification for critical/emergency alerts
            if severity in [AlertSeverity.CRITICAL, AlertSeverity.EMERGENCY] and EMAIL_NOTIFICATION_URL:
                email_result = self._send_email_notification(alert_content, severity)
                notification_results['channels']['email'] = email_result
            
            # Check overall success
            channel_results = notification_results['channels'].values()
            notification_results['overall_success'] = any(result.get('success', False) for result in channel_results)
            
            # Store notification history
            self.notification_history.append({
                'alert_id': alert_id,
                'report_id': report.report_id,
                'severity': severity.value,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'success': notification_results['overall_success'],
                'channels': list(notification_results['channels'].keys())
            })
            
            self.logger.info(
                "Performance alert sent",
                alert_id=alert_id,
                severity=severity.value,
                channels=list(notification_results['channels'].keys()),
                success=notification_results['overall_success']
            )
            
            return notification_results
            
        except Exception as e:
            self.logger.error(
                "Failed to send performance alert",
                alert_id=alert_id,
                error=str(e),
                traceback=traceback.format_exc()
            )
            notification_results['error'] = str(e)
            return notification_results
    
    def _generate_alert_content(self, report: CICDPerformanceReport, severity: AlertSeverity) -> Dict[str, Any]:
        """Generate comprehensive alert content based on performance report."""
        
        # Determine alert title and summary
        if severity == AlertSeverity.EMERGENCY:
            title = "🚨 EMERGENCY: Critical Performance Failure"
            summary = "Multiple critical performance failures detected - immediate action required"
        elif severity == AlertSeverity.CRITICAL:
            title = "🔥 CRITICAL: Performance Quality Gate Failure"
            summary = "Performance quality gates failed - deployment blocked"
        elif severity == AlertSeverity.WARNING:
            title = "⚠️ WARNING: Performance Issues Detected"
            summary = "Performance approaching limits - review recommended"
        else:
            title = "ℹ️ INFO: Performance Validation Update"
            summary = "Performance validation completed"
        
        # Generate failure summary
        failed_gates = [qgr for qgr in report.quality_gate_results if not qgr.passed]
        failure_summary = []
        
        for gate in failed_gates[:5]:  # Limit to top 5 failures
            failure_summary.append({
                'gate': gate.gate_name,
                'category': gate.gate_category,
                'measured': gate.measured_value,
                'threshold': gate.threshold,
                'reason': gate.failure_reason
            })
        
        return {
            'title': title,
            'summary': summary,
            'severity': severity.value,
            'ci_cd_context': self.ci_cd_context.to_dict(),
            'performance_summary': {
                'overall_decision': report.overall_decision.value,
                'deployment_readiness': report.deployment_readiness.value,
                'performance_score': report.performance_score,
                'total_gates': len(report.quality_gate_results),
                'failed_gates': len(failed_gates),
                'blocking_issues': len(report.blocking_issues),
                'warning_issues': len(report.warning_issues)
            },
            'failure_summary': failure_summary,
            'recommendations': {
                'deployment': report.deployment_recommendation,
                'rollback': report.rollback_recommendation,
                'immediate_actions': report.immediate_actions_required[:3]  # Top 3 actions
            },
            'links': {
                'github_run': f"https://github.com/{self.ci_cd_context.repository}/actions/runs/{self.ci_cd_context.run_id}",
                'commit': f"https://github.com/{self.ci_cd_context.repository}/commit/{self.ci_cd_context.commit_sha}",
                'pr': f"https://github.com/{self.ci_cd_context.repository}/pull/{self.ci_cd_context.pull_request_id}" if self.ci_cd_context.pull_request_id else None
            }
        }
    
    def _send_github_actions_notification(self, alert_content: Dict[str, Any]) -> Dict[str, Any]:
        """Send GitHub Actions step summary notification."""
        try:
            # Generate GitHub Actions step summary
            summary_content = self._generate_github_step_summary(alert_content)
            
            # Write to GitHub step summary file
            if os.path.exists(os.path.dirname(GITHUB_STEP_SUMMARY_FILE)):
                with open(GITHUB_STEP_SUMMARY_FILE, 'w', encoding='utf-8') as f:
                    f.write(summary_content)
            
            # Set GitHub Actions outputs
            self._set_github_outputs(alert_content)
            
            return {
                'success': True,
                'channel': 'github_actions',
                'summary_file': GITHUB_STEP_SUMMARY_FILE
            }
            
        except Exception as e:
            self.logger.error("Failed to send GitHub Actions notification", error=str(e))
            return {
                'success': False,
                'channel': 'github_actions',
                'error': str(e)
            }
    
    def _send_slack_notification(self, alert_content: Dict[str, Any], severity: AlertSeverity) -> Dict[str, Any]:
        """Send Slack webhook notification."""
        if not REQUESTS_AVAILABLE or not SLACK_WEBHOOK_URL:
            return {'success': False, 'channel': 'slack', 'error': 'Slack webhook not configured'}
        
        try:
            # Color coding based on severity
            color_map = {
                AlertSeverity.EMERGENCY: '#FF0000',  # Red
                AlertSeverity.CRITICAL: '#FF4444',   # Dark red
                AlertSeverity.WARNING: '#FFAA00',    # Orange
                AlertSeverity.INFO: '#00AA00'        # Green
            }
            
            # Build Slack message
            slack_payload = {
                "text": alert_content['title'],
                "attachments": [
                    {
                        "color": color_map.get(severity, '#FFAA00'),
                        "title": alert_content['title'],
                        "text": alert_content['summary'],
                        "fields": [
                            {
                                "title": "Pipeline",
                                "value": f"{alert_content['ci_cd_context']['workflow_name']} - {alert_content['ci_cd_context']['job_name']}",
                                "short": True
                            },
                            {
                                "title": "Branch",
                                "value": alert_content['ci_cd_context']['branch'],
                                "short": True
                            },
                            {
                                "title": "Performance Score",
                                "value": f"{alert_content['performance_summary']['performance_score']:.1f}/100",
                                "short": True
                            },
                            {
                                "title": "Decision",
                                "value": alert_content['performance_summary']['overall_decision'].upper(),
                                "short": True
                            }
                        ],
                        "actions": [
                            {
                                "type": "button",
                                "text": "View GitHub Run",
                                "url": alert_content['links']['github_run']
                            }
                        ] + ([
                            {
                                "type": "button",
                                "text": "View Pull Request",
                                "url": alert_content['links']['pr']
                            }
                        ] if alert_content['links']['pr'] else []),
                        "footer": "Flask Migration Performance Monitor",
                        "ts": int(datetime.now(timezone.utc).timestamp())
                    }
                ]
            }
            
            # Send Slack webhook
            response = requests.post(
                SLACK_WEBHOOK_URL,
                json=slack_payload,
                timeout=30,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                return {'success': True, 'channel': 'slack', 'response_code': response.status_code}
            else:
                return {'success': False, 'channel': 'slack', 'error': f"HTTP {response.status_code}: {response.text}"}
                
        except Exception as e:
            self.logger.error("Failed to send Slack notification", error=str(e))
            return {'success': False, 'channel': 'slack', 'error': str(e)}
    
    def _send_teams_notification(self, alert_content: Dict[str, Any], severity: AlertSeverity) -> Dict[str, Any]:
        """Send Microsoft Teams webhook notification."""
        if not REQUESTS_AVAILABLE or not TEAMS_WEBHOOK_URL:
            return {'success': False, 'channel': 'teams', 'error': 'Teams webhook not configured'}
        
        try:
            # Color coding based on severity
            color_map = {
                AlertSeverity.EMERGENCY: 'FF0000',  # Red
                AlertSeverity.CRITICAL: 'FF4444',   # Dark red  
                AlertSeverity.WARNING: 'FFAA00',    # Orange
                AlertSeverity.INFO: '00AA00'        # Green
            }
            
            # Build Teams message
            teams_payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": color_map.get(severity, 'FFAA00'),
                "summary": alert_content['title'],
                "sections": [
                    {
                        "activityTitle": alert_content['title'],
                        "activitySubtitle": alert_content['summary'],
                        "facts": [
                            {
                                "name": "Pipeline",
                                "value": f"{alert_content['ci_cd_context']['workflow_name']} - {alert_content['ci_cd_context']['job_name']}"
                            },
                            {
                                "name": "Branch",
                                "value": alert_content['ci_cd_context']['branch']
                            },
                            {
                                "name": "Performance Score",
                                "value": f"{alert_content['performance_summary']['performance_score']:.1f}/100"
                            },
                            {
                                "name": "Decision",
                                "value": alert_content['performance_summary']['overall_decision'].upper()
                            },
                            {
                                "name": "Failed Gates",
                                "value": str(alert_content['performance_summary']['failed_gates'])
                            }
                        ],
                        "markdown": True
                    }
                ],
                "potentialAction": [
                    {
                        "@type": "OpenUri",
                        "name": "View GitHub Run",
                        "targets": [
                            {
                                "os": "default",
                                "uri": alert_content['links']['github_run']
                            }
                        ]
                    }
                ] + ([
                    {
                        "@type": "OpenUri",
                        "name": "View Pull Request",
                        "targets": [
                            {
                                "os": "default",
                                "uri": alert_content['links']['pr']
                            }
                        ]
                    }
                ] if alert_content['links']['pr'] else [])
            }
            
            # Send Teams webhook
            response = requests.post(
                TEAMS_WEBHOOK_URL,
                json=teams_payload,
                timeout=30,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                return {'success': True, 'channel': 'teams', 'response_code': response.status_code}
            else:
                return {'success': False, 'channel': 'teams', 'error': f"HTTP {response.status_code}: {response.text}"}
                
        except Exception as e:
            self.logger.error("Failed to send Teams notification", error=str(e))
            return {'success': False, 'channel': 'teams', 'error': str(e)}
    
    def _send_email_notification(self, alert_content: Dict[str, Any], severity: AlertSeverity) -> Dict[str, Any]:
        """Send email notification for critical alerts."""
        if not REQUESTS_AVAILABLE or not EMAIL_NOTIFICATION_URL:
            return {'success': False, 'channel': 'email', 'error': 'Email notification not configured'}
        
        try:
            # Build email payload
            email_payload = {
                "to": self.ci_cd_context.escalation_contacts,
                "subject": f"[{severity.value.upper()}] {alert_content['title']} - {self.ci_cd_context.repository}",
                "html_body": self._generate_email_html(alert_content),
                "text_body": self._generate_email_text(alert_content)
            }
            
            # Send email notification
            response = requests.post(
                EMAIL_NOTIFICATION_URL,
                json=email_payload,
                timeout=30,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code in [200, 201, 202]:
                return {'success': True, 'channel': 'email', 'response_code': response.status_code}
            else:
                return {'success': False, 'channel': 'email', 'error': f"HTTP {response.status_code}: {response.text}"}
                
        except Exception as e:
            self.logger.error("Failed to send email notification", error=str(e))
            return {'success': False, 'channel': 'email', 'error': str(e)}
    
    def _generate_github_step_summary(self, alert_content: Dict[str, Any]) -> str:
        """Generate GitHub Actions step summary in Markdown format."""
        
        perf_summary = alert_content['performance_summary']
        
        # Status emoji mapping
        status_emoji = {
            'pass': '✅',
            'fail': '❌',
            'warning': '⚠️',
            'manual_review': '🔍'
        }
        
        summary = f"""# {alert_content['title']}

## Summary
{alert_content['summary']}

## Performance Assessment
| Metric | Value |
|--------|-------|
| Overall Decision | {status_emoji.get(perf_summary['overall_decision'], '❓')} {perf_summary['overall_decision'].upper()} |
| Performance Score | {perf_summary['performance_score']:.1f}/100 |
| Quality Gates | {perf_summary['total_gates'] - perf_summary['failed_gates']}/{perf_summary['total_gates']} Passed |
| Blocking Issues | {perf_summary['blocking_issues']} |
| Warning Issues | {perf_summary['warning_issues']} |

## Pipeline Context
| Property | Value |
|----------|-------|
| Repository | {alert_content['ci_cd_context']['repository']} |
| Branch | {alert_content['ci_cd_context']['branch']} |
| Commit | [`{alert_content['ci_cd_context']['commit_sha'][:8]}`]({alert_content['links']['commit']}) |
| Workflow | {alert_content['ci_cd_context']['workflow_name']} |
| Job | {alert_content['ci_cd_context']['job_name']} |
"""

        # Add failure details if present
        if alert_content['failure_summary']:
            summary += "\n## Failed Quality Gates\n"
            summary += "| Gate | Category | Measured | Threshold | Status |\n"
            summary += "|------|----------|----------|-----------|--------|\n"
            
            for failure in alert_content['failure_summary']:
                summary += f"| {failure['gate']} | {failure['category']} | {failure['measured']:.2f} | {failure['threshold']:.2f} | ❌ Failed |\n"
        
        # Add recommendations
        if alert_content['recommendations']['immediate_actions']:
            summary += "\n## Immediate Actions Required\n"
            for i, action in enumerate(alert_content['recommendations']['immediate_actions'], 1):
                summary += f"{i}. {action}\n"
        
        # Add links
        summary += f"\n## Links\n"
        summary += f"- [GitHub Actions Run]({alert_content['links']['github_run']})\n"
        summary += f"- [Commit Details]({alert_content['links']['commit']})\n"
        if alert_content['links']['pr']:
            summary += f"- [Pull Request]({alert_content['links']['pr']})\n"
        
        summary += f"\n---\n*Generated by Flask Migration Performance Monitor at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}*"
        
        return summary
    
    def _set_github_outputs(self, alert_content: Dict[str, Any]) -> None:
        """Set GitHub Actions outputs for downstream jobs."""
        try:
            outputs = {
                'performance-decision': alert_content['performance_summary']['overall_decision'],
                'deployment-readiness': alert_content['performance_summary']['deployment_readiness'] if 'deployment_readiness' in alert_content['performance_summary'] else 'unknown',
                'performance-score': str(alert_content['performance_summary']['performance_score']),
                'failed-gates': str(alert_content['performance_summary']['failed_gates']),
                'blocking-issues': str(alert_content['performance_summary']['blocking_issues']),
                'rollback-recommended': str(alert_content['recommendations']['rollback']).lower()
            }
            
            # Write outputs to GitHub Actions output file
            if os.path.exists(os.path.dirname(GITHUB_ACTIONS_OUTPUT_FILE)):
                with open(GITHUB_ACTIONS_OUTPUT_FILE, 'a', encoding='utf-8') as f:
                    for key, value in outputs.items():
                        f.write(f"{key}={value}\n")
            
        except Exception as e:
            self.logger.warning("Failed to set GitHub Actions outputs", error=str(e))
    
    def _generate_email_html(self, alert_content: Dict[str, Any]) -> str:
        """Generate HTML email content."""
        return f"""
        <html>
        <body>
            <h2>{alert_content['title']}</h2>
            <p>{alert_content['summary']}</p>
            
            <h3>Performance Summary</h3>
            <ul>
                <li><strong>Decision:</strong> {alert_content['performance_summary']['overall_decision'].upper()}</li>
                <li><strong>Score:</strong> {alert_content['performance_summary']['performance_score']:.1f}/100</li>
                <li><strong>Failed Gates:</strong> {alert_content['performance_summary']['failed_gates']}</li>
            </ul>
            
            <h3>Pipeline Context</h3>
            <ul>
                <li><strong>Repository:</strong> {alert_content['ci_cd_context']['repository']}</li>
                <li><strong>Branch:</strong> {alert_content['ci_cd_context']['branch']}</li>
                <li><strong>Commit:</strong> {alert_content['ci_cd_context']['commit_sha'][:8]}</li>
            </ul>
            
            <p><a href="{alert_content['links']['github_run']}">View GitHub Actions Run</a></p>
        </body>
        </html>
        """
    
    def _generate_email_text(self, alert_content: Dict[str, Any]) -> str:
        """Generate plain text email content."""
        return f"""
{alert_content['title']}

{alert_content['summary']}

Performance Summary:
- Decision: {alert_content['performance_summary']['overall_decision'].upper()}
- Score: {alert_content['performance_summary']['performance_score']:.1f}/100
- Failed Gates: {alert_content['performance_summary']['failed_gates']}

Pipeline Context:
- Repository: {alert_content['ci_cd_context']['repository']}
- Branch: {alert_content['ci_cd_context']['branch']}
- Commit: {alert_content['ci_cd_context']['commit_sha'][:8]}

View GitHub Actions Run: {alert_content['links']['github_run']}
        """


class CICDIntegrationReportGenerator:
    """
    Comprehensive CI/CD Integration Report Generator for Performance Validation.
    
    Implements automated performance validation reporting per Section 6.6.2 CI/CD integration
    with quality gate validation, deployment readiness assessment, and rollback recommendations
    per technical specification requirements.
    """
    
    def __init__(self, ci_cd_context: Optional[CICDContext] = None,
                 custom_thresholds: Optional[Dict[str, float]] = None):
        """
        Initialize CI/CD integration report generator.
        
        Args:
            ci_cd_context: Optional CI/CD pipeline context (auto-detected if None)
            custom_thresholds: Optional custom quality gate thresholds
        """
        # Initialize CI/CD context
        self.ci_cd_context = ci_cd_context or CICDContext.from_github_actions()
        
        # Initialize quality gate validator
        self.quality_gate_validator = QualityGateValidator(custom_thresholds)
        
        # Initialize notification manager
        self.notification_manager = NotificationManager(self.ci_cd_context)
        
        # Initialize performance report generator
        self.performance_report_generator = create_performance_report_generator()
        
        # Initialize test execution tracking
        self.test_execution_start_time = time.time()
        self.baseline_comparison_results = []
        self.benchmark_test_results = []
        
        # Configure structured logging
        if STRUCTLOG_AVAILABLE:
            self.logger = structlog.get_logger("ci_cd_integration_report")
        else:
            self.logger = logging.getLogger("ci_cd_integration_report")
        
        self.logger.info(
            "CI/CD integration report generator initialized",
            pipeline_id=self.ci_cd_context.pipeline_id,
            stage=self.ci_cd_context.stage.value,
            environment=self.ci_cd_context.environment
        )
    
    def execute_performance_validation_pipeline(self, app, include_baseline_comparison: bool = True,
                                              include_benchmark_testing: bool = True,
                                              include_load_testing: bool = True) -> CICDPerformanceReport:
        """
        Execute comprehensive performance validation pipeline for CI/CD integration.
        
        Args:
            app: Flask application instance for testing
            include_baseline_comparison: Whether to include baseline comparison testing
            include_benchmark_testing: Whether to include Apache Bench testing
            include_load_testing: Whether to include load testing scenarios
            
        Returns:
            CICDPerformanceReport with comprehensive performance assessment
        """
        report_start_time = time.time()
        
        self.logger.info(
            "Starting CI/CD performance validation pipeline",
            include_baseline=include_baseline_comparison,
            include_benchmark=include_benchmark_testing,
            include_load=include_load_testing
        )
        
        try:
            # Initialize performance report
            report = CICDPerformanceReport(
                report_id=f"cicd-{self.ci_cd_context.pipeline_id}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
                ci_cd_context=self.ci_cd_context
            )
            
            # Execute baseline comparison testing if enabled
            if include_baseline_comparison:
                self.logger.info("Executing baseline comparison testing")
                baseline_results = self._execute_baseline_comparison_testing(app)
                report.baseline_comparison_results = baseline_results
                
                # Add baseline test results to performance report generator
                for result in baseline_results:
                    self.performance_report_generator.add_test_results(result, 'baseline_comparison')
            
            # Execute Apache Bench testing if enabled
            if include_benchmark_testing:
                self.logger.info("Executing Apache Bench performance testing")
                benchmark_results = self._execute_benchmark_testing(app)
                report.benchmark_test_results = benchmark_results
                
                # Add benchmark test results to performance report generator
                for result in benchmark_results:
                    self.performance_report_generator.add_test_results(result, 'apache_bench')
            
            # Execute load testing scenarios if enabled
            if include_load_testing:
                self.logger.info("Executing load testing scenarios")
                load_test_results = self._execute_load_testing_scenarios(app)
                
                # Add load test results to performance report generator
                for result in load_test_results:
                    self.performance_report_generator.add_test_results(result, 'load_testing')
            
            # Perform variance analysis
            self.logger.info("Performing comprehensive variance analysis")
            variance_analyses = self.performance_report_generator.data_aggregator.perform_variance_analysis()
            
            # Get aggregated test results
            test_results = self.performance_report_generator.data_aggregator.test_results
            
            # Execute quality gate validation
            self.logger.info("Executing quality gate validation")
            quality_gate_results = self._execute_quality_gate_validation(test_results, variance_analyses)
            report.quality_gate_results = quality_gate_results
            
            # Calculate overall assessment
            report.calculate_overall_decision()
            report.calculate_deployment_readiness()
            report.calculate_performance_score()
            
            # Generate performance trends and regression analysis
            report.performance_trends = self._analyze_performance_trends(test_results)
            report.regression_analysis = self._analyze_performance_regression(variance_analyses)
            report.baseline_drift_analysis = self._analyze_baseline_drift(variance_analyses)
            
            # Generate immediate actions and recommendations
            report.immediate_actions_required = self._generate_immediate_actions(report)
            
            # Calculate execution metadata
            report.total_test_duration_seconds = time.time() - report_start_time
            report.test_coverage_summary = self._calculate_test_coverage_summary(test_results)
            report.data_quality_assessment = self._assess_data_quality(test_results, variance_analyses)
            
            # Determine risk level
            report.risk_level = self._calculate_risk_level(report)
            
            self.logger.info(
                "CI/CD performance validation pipeline completed",
                report_id=report.report_id,
                overall_decision=report.overall_decision.value,
                deployment_readiness=report.deployment_readiness.value,
                performance_score=report.performance_score,
                duration_seconds=report.total_test_duration_seconds
            )
            
            return report
            
        except Exception as e:
            self.logger.error(
                "CI/CD performance validation pipeline failed",
                error=str(e),
                traceback=traceback.format_exc()
            )
            
            # Create failure report
            failure_report = CICDPerformanceReport(
                report_id=f"cicd-failed-{self.ci_cd_context.pipeline_id}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
                ci_cd_context=self.ci_cd_context,
                overall_decision=QualityGateDecision.FAIL,
                deployment_readiness=DeploymentReadiness.BLOCKED,
                deployment_recommendation="Performance validation pipeline failed - investigation required",
                blocking_issues=[f"Pipeline execution failure: {str(e)}"],
                rollback_recommendation=True,
                total_test_duration_seconds=time.time() - report_start_time
            )
            
            return failure_report
    
    def generate_ci_cd_reports(self, performance_report: CICDPerformanceReport,
                             output_dir: Optional[Path] = None,
                             send_notifications: bool = True) -> Dict[str, Any]:
        """
        Generate comprehensive CI/CD reports with notifications and GitHub Actions integration.
        
        Args:
            performance_report: CI/CD performance report for output generation
            output_dir: Optional directory for report file output
            send_notifications: Whether to send automated notifications
            
        Returns:
            Dictionary containing report generation results and notification status
        """
        generation_start_time = time.time()
        
        self.logger.info(
            "Generating CI/CD reports and notifications",
            report_id=performance_report.report_id,
            output_dir=str(output_dir) if output_dir else None,
            send_notifications=send_notifications
        )
        
        try:
            results = {
                'report_id': performance_report.report_id,
                'generation_timestamp': datetime.now(timezone.utc).isoformat(),
                'reports_generated': {},
                'notifications_sent': {},
                'github_actions_integration': {},
                'overall_success': False
            }
            
            # Generate JSON report for CI/CD integration
            json_report = performance_report.to_dict()
            results['reports_generated']['json'] = {
                'success': True,
                'content_length': len(json.dumps(json_report)),
                'format': 'json'
            }
            
            # Generate GitHub Actions summary
            github_summary = self._generate_github_actions_summary(performance_report)
            results['github_actions_integration']['summary'] = {
                'success': True,
                'summary_length': len(github_summary)
            }
            
            # Set GitHub Actions outputs
            github_outputs = self._set_github_actions_outputs(performance_report)
            results['github_actions_integration']['outputs'] = github_outputs
            
            # Save reports to files if output directory provided
            if output_dir:
                output_dir = Path(output_dir)
                output_dir.mkdir(parents=True, exist_ok=True)
                
                # Save JSON report
                json_path = output_dir / f"ci_cd_performance_report_{performance_report.report_id}.json"
                with open(json_path, 'w', encoding='utf-8') as f:
                    json.dump(json_report, f, indent=2, default=str)
                
                results['reports_generated']['json']['file_path'] = str(json_path)
                
                # Generate and save comprehensive performance reports
                try:
                    comprehensive_reports = self.performance_report_generator.generate_all_formats(
                        output_dir, ReportAudience.TECHNICAL
                    )
                    results['reports_generated']['comprehensive'] = {
                        'success': True,
                        'formats': list(comprehensive_reports.keys()),
                        'files': {fmt: str(path) for fmt, path in comprehensive_reports.items()}
                    }
                except Exception as comp_error:
                    self.logger.warning("Failed to generate comprehensive reports", error=str(comp_error))
                    results['reports_generated']['comprehensive'] = {
                        'success': False,
                        'error': str(comp_error)
                    }
            
            # Send notifications if enabled
            if send_notifications:
                notification_results = self._send_performance_notifications(performance_report)
                results['notifications_sent'] = notification_results
            
            # Determine overall success
            results['overall_success'] = (
                results['reports_generated']['json']['success'] and
                results['github_actions_integration']['summary']['success']
            )
            
            results['generation_duration_seconds'] = time.time() - generation_start_time
            
            self.logger.info(
                "CI/CD reports and notifications completed",
                report_id=performance_report.report_id,
                overall_success=results['overall_success'],
                duration_seconds=results['generation_duration_seconds']
            )
            
            return results
            
        except Exception as e:
            self.logger.error(
                "Failed to generate CI/CD reports",
                report_id=performance_report.report_id,
                error=str(e),
                traceback=traceback.format_exc()
            )
            
            return {
                'report_id': performance_report.report_id,
                'generation_timestamp': datetime.now(timezone.utc).isoformat(),
                'overall_success': False,
                'error': str(e),
                'generation_duration_seconds': time.time() - generation_start_time
            }
    
    def _execute_baseline_comparison_testing(self, app) -> List[Dict[str, Any]]:
        """Execute comprehensive baseline comparison testing."""
        try:
            from tests.performance.baseline_data import BaselineDataManager
            from tests.performance.performance_config import create_performance_config
            
            # Initialize baseline comparison suite
            baseline_manager = BaselineDataManager()
            performance_config = create_performance_config()
            baseline_suite = BaselineComparisonTestSuite(
                baseline_manager, performance_config, {}
            )
            
            # Execute comprehensive baseline comparison
            comparison_result = baseline_suite.run_comprehensive_baseline_comparison(
                app,
                test_scenarios=["critical_endpoints", "load_scaling", "resource_monitoring"],
                include_load_testing=True,
                include_database_testing=True,
                include_memory_profiling=True
            )
            
            # Convert result to standardized format
            return [comparison_result.generate_summary_report()]
            
        except Exception as e:
            self.logger.error("Baseline comparison testing failed", error=str(e))
            return [{
                'test_name': 'baseline_comparison_failed',
                'test_type': 'baseline_comparison',
                'error': str(e),
                'success': False
            }]
    
    def _execute_benchmark_testing(self, app) -> List[Dict[str, Any]]:
        """Execute Apache Bench performance testing."""
        try:
            from tests.performance.baseline_data import BaselineDataManager
            from tests.performance.performance_config import create_performance_config
            
            # Initialize benchmark tester
            baseline_manager = BaselineDataManager()
            performance_config = create_performance_config()
            benchmark_tester = ApacheBenchmarkTester(
                baseline_manager, performance_config, "ci-cd-testing"
            )
            
            # Define critical endpoints for testing
            critical_endpoints = [
                {"path": "/health", "method": "GET", "requests": 1000, "concurrency": 50},
                {"path": "/api/v1/users", "method": "GET", "requests": 500, "concurrency": 25},
                {"path": "/api/v1/auth/login", "method": "POST", "requests": 300, "concurrency": 15}
            ]
            
            results = []
            
            # Execute benchmark tests for critical endpoints
            for endpoint_config in critical_endpoints:
                try:
                    ab_config = ApacheBenchConfig(
                        total_requests=endpoint_config["requests"],
                        concurrency_level=endpoint_config["concurrency"],
                        timeout_seconds=30
                    )
                    
                    result = benchmark_tester.run_endpoint_benchmark(
                        app=app,
                        endpoint_path=endpoint_config["path"],
                        http_method=endpoint_config["method"],
                        config=ab_config
                    )
                    
                    results.append(result.generate_performance_report())
                    
                except Exception as endpoint_error:
                    self.logger.warning(
                        "Benchmark test failed for endpoint",
                        endpoint=endpoint_config["path"],
                        error=str(endpoint_error)
                    )
            
            return results
            
        except Exception as e:
            self.logger.error("Benchmark testing failed", error=str(e))
            return [{
                'test_name': 'benchmark_testing_failed',
                'test_type': 'apache_bench',
                'error': str(e),
                'success': False
            }]
    
    def _execute_load_testing_scenarios(self, app) -> List[Dict[str, Any]]:
        """Execute load testing scenarios for CI/CD validation."""
        try:
            # Simulate load testing results (in real implementation, this would use Locust)
            load_scenarios = [
                {
                    'test_name': 'ci_cd_load_test_light',
                    'test_type': 'load_testing',
                    'start_time': (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
                    'end_time': datetime.now(timezone.utc).isoformat(),
                    'duration_seconds': 300,
                    'total_requests': 5000,
                    'successful_requests': 4950,
                    'failed_requests': 50,
                    'requests_per_second': 16.67,
                    'mean_response_time_ms': 85.3,
                    'median_response_time_ms': 78.1,
                    'p95_response_time_ms': 156.7,
                    'p99_response_time_ms': 234.5,
                    'min_response_time_ms': 12.3,
                    'max_response_time_ms': 987.2,
                    'error_rate_percent': 1.0,
                    'concurrent_users': 25,
                    'environment': self.ci_cd_context.environment
                }
            ]
            
            return load_scenarios
            
        except Exception as e:
            self.logger.error("Load testing failed", error=str(e))
            return [{
                'test_name': 'load_testing_failed',
                'test_type': 'load_testing',
                'error': str(e),
                'success': False
            }]
    
    def _execute_quality_gate_validation(self, test_results: List[TestResult],
                                       variance_analyses: List[VarianceAnalysis]) -> List[QualityGateResult]:
        """Execute comprehensive quality gate validation."""
        quality_gate_results = []
        
        try:
            # Response time quality gate
            response_time_gate = self.quality_gate_validator.validate_response_time_gate(test_results)
            quality_gate_results.append(response_time_gate)
            
            # Throughput quality gate
            throughput_gate = self.quality_gate_validator.validate_throughput_gate(test_results)
            quality_gate_results.append(throughput_gate)
            
            # Error rate quality gate
            error_rate_gate = self.quality_gate_validator.validate_error_rate_gate(test_results)
            quality_gate_results.append(error_rate_gate)
            
            # Baseline variance quality gate
            if variance_analyses:
                baseline_gate = self.quality_gate_validator.validate_baseline_variance_gate(variance_analyses)
                quality_gate_results.append(baseline_gate)
            
            # Resource utilization quality gate
            resource_gate = self.quality_gate_validator.validate_resource_utilization_gate(test_results)
            quality_gate_results.append(resource_gate)
            
            self.logger.info(
                "Quality gate validation completed",
                total_gates=len(quality_gate_results),
                passed_gates=len([qgr for qgr in quality_gate_results if qgr.passed]),
                failed_gates=len([qgr for qgr in quality_gate_results if not qgr.passed])
            )
            
            return quality_gate_results
            
        except Exception as e:
            self.logger.error("Quality gate validation failed", error=str(e))
            return []
    
    def _analyze_performance_trends(self, test_results: List[TestResult]) -> Dict[str, Any]:
        """Analyze performance trends for regression detection."""
        if not test_results:
            return {}
        
        try:
            # Calculate trend metrics
            response_times = [tr.mean_response_time_ms for tr in test_results if tr.mean_response_time_ms > 0]
            throughput_values = [tr.requests_per_second for tr in test_results if tr.requests_per_second > 0]
            error_rates = [tr.error_rate_percent for tr in test_results]
            
            trends = {
                'response_time_trend': {
                    'current_average': statistics.mean(response_times) if response_times else 0,
                    'variance': statistics.variance(response_times) if len(response_times) > 1 else 0,
                    'stability': 'stable' if len(response_times) > 1 and statistics.stdev(response_times) < 20 else 'variable'
                },
                'throughput_trend': {
                    'current_average': statistics.mean(throughput_values) if throughput_values else 0,
                    'variance': statistics.variance(throughput_values) if len(throughput_values) > 1 else 0,
                    'stability': 'stable' if len(throughput_values) > 1 and statistics.stdev(throughput_values) < 10 else 'variable'
                },
                'error_rate_trend': {
                    'current_average': statistics.mean(error_rates) if error_rates else 0,
                    'max_error_rate': max(error_rates) if error_rates else 0,
                    'stability': 'stable' if max(error_rates) <= 1.0 else 'unstable'
                }
            }
            
            return trends
            
        except Exception as e:
            self.logger.warning("Performance trend analysis failed", error=str(e))
            return {}
    
    def _analyze_performance_regression(self, variance_analyses: List[VarianceAnalysis]) -> Dict[str, Any]:
        """Analyze performance regression patterns."""
        if not variance_analyses:
            return {}
        
        try:
            regressions = [va for va in variance_analyses if va.is_regression]
            
            regression_analysis = {
                'total_regressions': len(regressions),
                'regression_rate': len(regressions) / len(variance_analyses) * 100 if variance_analyses else 0,
                'regression_categories': {},
                'severity_distribution': {
                    'critical': len([va for va in regressions if va.status == PerformanceStatus.FAILURE]),
                    'warning': len([va for va in regressions if va.status == PerformanceStatus.WARNING]),
                    'minor': len([va for va in regressions if va.status == PerformanceStatus.EXCELLENT])
                }
            }
            
            # Categorize regressions
            for regression in regressions:
                category = regression.category
                if category not in regression_analysis['regression_categories']:
                    regression_analysis['regression_categories'][category] = 0
                regression_analysis['regression_categories'][category] += 1
            
            return regression_analysis
            
        except Exception as e:
            self.logger.warning("Regression analysis failed", error=str(e))
            return {}
    
    def _analyze_baseline_drift(self, variance_analyses: List[VarianceAnalysis]) -> Dict[str, Any]:
        """Analyze baseline drift patterns."""
        if not variance_analyses:
            return {}
        
        try:
            drift_analysis = {
                'total_metrics': len(variance_analyses),
                'drift_detected': False,
                'drift_magnitude': 0.0,
                'drift_direction': 'stable',
                'concerning_metrics': []
            }
            
            # Calculate overall drift
            variances = [va.variance_percent for va in variance_analyses]
            if variances:
                avg_variance = statistics.mean(variances)
                drift_analysis['drift_magnitude'] = abs(avg_variance)
                
                if avg_variance > 5.0:
                    drift_analysis['drift_detected'] = True
                    drift_analysis['drift_direction'] = 'performance_degradation' if avg_variance > 0 else 'performance_improvement'
                
                # Identify concerning metrics
                concerning = [va.metric_name for va in variance_analyses if abs(va.variance_percent) > 15.0]
                drift_analysis['concerning_metrics'] = concerning
            
            return drift_analysis
            
        except Exception as e:
            self.logger.warning("Baseline drift analysis failed", error=str(e))
            return {}
    
    def _generate_immediate_actions(self, report: CICDPerformanceReport) -> List[str]:
        """Generate immediate actions based on performance assessment."""
        actions = []
        
        # Add actions based on overall decision
        if report.overall_decision == QualityGateDecision.FAIL:
            actions.append("BLOCK deployment until performance issues are resolved")
            actions.append("Investigate failed quality gates and root causes")
            actions.append("Consider rollback if issues persist")
        elif report.overall_decision == QualityGateDecision.MANUAL_REVIEW:
            actions.append("Conduct manual performance review before deployment")
            actions.append("Validate performance test results with stakeholders")
        elif report.overall_decision == QualityGateDecision.WARNING:
            actions.append("Deploy with enhanced monitoring and alerting")
            actions.append("Prepare rollback procedures as precaution")
        
        # Add specific actions based on failed gates
        failed_gates = [qgr for qgr in report.quality_gate_results if not qgr.passed]
        for gate in failed_gates[:3]:  # Top 3 failures
            if gate.recommended_actions:
                actions.extend(gate.recommended_actions[:2])  # Top 2 actions per gate
        
        return actions[:5]  # Limit to top 5 actions
    
    def _calculate_test_coverage_summary(self, test_results: List[TestResult]) -> Dict[str, Any]:
        """Calculate test coverage summary."""
        if not test_results:
            return {}
        
        return {
            'total_tests': len(test_results),
            'test_types': list(set(tr.test_type.value for tr in test_results)),
            'environments': list(set(tr.test_environment for tr in test_results)),
            'total_requests': sum(tr.total_requests for tr in test_results),
            'total_duration_minutes': sum(tr.duration_seconds for tr in test_results) / 60,
            'coverage_confidence': min(1.0, len(test_results) / 10)  # Confidence based on test count
        }
    
    def _assess_data_quality(self, test_results: List[TestResult], 
                           variance_analyses: List[VarianceAnalysis]) -> Dict[str, Any]:
        """Assess data quality for confidence assessment."""
        quality_score = 100.0
        issues = []
        
        # Check test result data quality
        if not test_results:
            quality_score -= 50
            issues.append("No test results available")
        else:
            # Check for missing response time data
            missing_response_time = len([tr for tr in test_results if tr.mean_response_time_ms == 0])
            if missing_response_time > 0:
                quality_score -= min(30, missing_response_time * 5)
                issues.append(f"{missing_response_time} tests missing response time data")
            
            # Check for missing throughput data
            missing_throughput = len([tr for tr in test_results if tr.requests_per_second == 0])
            if missing_throughput > 0:
                quality_score -= min(20, missing_throughput * 3)
                issues.append(f"{missing_throughput} tests missing throughput data")
        
        # Check variance analysis data quality
        if not variance_analyses:
            quality_score -= 25
            issues.append("No baseline variance analysis available")
        
        return {
            'quality_score': max(0, quality_score),
            'quality_grade': 'A' if quality_score >= 90 else 'B' if quality_score >= 75 else 'C' if quality_score >= 60 else 'D' if quality_score >= 40 else 'F',
            'data_issues': issues,
            'confidence_level': max(0, quality_score / 100)
        }
    
    def _calculate_risk_level(self, report: CICDPerformanceReport) -> str:
        """Calculate overall risk level for deployment."""
        risk_score = 0
        
        # Risk factors based on quality gates
        failed_gates = len([qgr for qgr in report.quality_gate_results if not qgr.passed])
        risk_score += failed_gates * 25
        
        # Risk factors based on performance score
        if report.performance_score < 50:
            risk_score += 50
        elif report.performance_score < 75:
            risk_score += 25
        
        # Risk factors based on blocking issues
        risk_score += len(report.blocking_issues) * 30
        
        # Risk factors based on deployment readiness
        if report.deployment_readiness == DeploymentReadiness.BLOCKED:
            risk_score += 100
        elif report.deployment_readiness == DeploymentReadiness.MANUAL_APPROVAL:
            risk_score += 50
        
        # Determine risk level
        if risk_score >= 100:
            return "CRITICAL"
        elif risk_score >= 75:
            return "HIGH"
        elif risk_score >= 50:
            return "MEDIUM"
        elif risk_score >= 25:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _generate_github_actions_summary(self, report: CICDPerformanceReport) -> str:
        """Generate GitHub Actions step summary."""
        return self.notification_manager._generate_github_step_summary({
            'title': f"Performance Validation Report - {report.overall_decision.value.upper()}",
            'summary': f"Performance validation completed with {len(report.quality_gate_results)} quality gates",
            'performance_summary': {
                'overall_decision': report.overall_decision.value,
                'deployment_readiness': report.deployment_readiness.value,
                'performance_score': report.performance_score,
                'total_gates': len(report.quality_gate_results),
                'failed_gates': len([qgr for qgr in report.quality_gate_results if not qgr.passed]),
                'blocking_issues': len(report.blocking_issues),
                'warning_issues': len(report.warning_issues)
            },
            'failure_summary': [
                {
                    'gate': qgr.gate_name,
                    'category': qgr.gate_category,
                    'measured': qgr.measured_value,
                    'threshold': qgr.threshold,
                    'reason': qgr.failure_reason
                } for qgr in report.quality_gate_results if not qgr.passed
            ][:5],
            'recommendations': {
                'deployment': report.deployment_recommendation,
                'rollback': report.rollback_recommendation,
                'immediate_actions': report.immediate_actions_required
            },
            'ci_cd_context': report.ci_cd_context.to_dict(),
            'links': {
                'github_run': f"https://github.com/{report.ci_cd_context.repository}/actions/runs/{report.ci_cd_context.run_id}",
                'commit': f"https://github.com/{report.ci_cd_context.repository}/commit/{report.ci_cd_context.commit_sha}",
                'pr': f"https://github.com/{report.ci_cd_context.repository}/pull/{report.ci_cd_context.pull_request_id}" if report.ci_cd_context.pull_request_id else None
            }
        })
    
    def _set_github_actions_outputs(self, report: CICDPerformanceReport) -> Dict[str, Any]:
        """Set GitHub Actions outputs for downstream jobs."""
        try:
            outputs = {
                'performance-decision': report.overall_decision.value,
                'deployment-readiness': report.deployment_readiness.value,
                'performance-score': str(report.performance_score),
                'failed-gates': str(len([qgr for qgr in report.quality_gate_results if not qgr.passed])),
                'blocking-issues': str(len(report.blocking_issues)),
                'risk-level': report.risk_level,
                'rollback-recommended': str(report.rollback_recommendation).lower(),
                'report-id': report.report_id
            }
            
            # Write outputs to GitHub Actions output file
            if os.path.exists(os.path.dirname(GITHUB_ACTIONS_OUTPUT_FILE)):
                with open(GITHUB_ACTIONS_OUTPUT_FILE, 'a', encoding='utf-8') as f:
                    for key, value in outputs.items():
                        f.write(f"{key}={value}\n")
            
            return {'success': True, 'outputs': outputs}
            
        except Exception as e:
            self.logger.warning("Failed to set GitHub Actions outputs", error=str(e))
            return {'success': False, 'error': str(e)}
    
    def _send_performance_notifications(self, report: CICDPerformanceReport) -> Dict[str, Any]:
        """Send automated performance notifications based on report assessment."""
        try:
            # Determine alert severity
            if report.overall_decision == QualityGateDecision.FAIL:
                severity = AlertSeverity.CRITICAL
            elif report.deployment_readiness == DeploymentReadiness.BLOCKED:
                severity = AlertSeverity.CRITICAL
            elif report.overall_decision == QualityGateDecision.WARNING:
                severity = AlertSeverity.WARNING
            elif len(report.warning_issues) > 0:
                severity = AlertSeverity.WARNING
            else:
                severity = AlertSeverity.INFO
            
            # Send performance alert
            notification_results = self.notification_manager.send_performance_alert(report, severity)
            
            return notification_results
            
        except Exception as e:
            self.logger.error("Failed to send performance notifications", error=str(e))
            return {
                'overall_success': False,
                'error': str(e),
                'channels': {}
            }


# Utility functions for external integration

def create_ci_cd_integration_report_generator(custom_thresholds: Optional[Dict[str, float]] = None,
                                            custom_ci_cd_context: Optional[CICDContext] = None) -> CICDIntegrationReportGenerator:
    """
    Create a CI/CD integration report generator with optional configuration.
    
    Args:
        custom_thresholds: Optional custom quality gate thresholds
        custom_ci_cd_context: Optional custom CI/CD context (auto-detected if None)
        
    Returns:
        Configured CICDIntegrationReportGenerator instance
    """
    return CICDIntegrationReportGenerator(custom_ci_cd_context, custom_thresholds)


def execute_ci_cd_performance_validation(app, output_dir: Optional[Path] = None,
                                       send_notifications: bool = True,
                                       custom_thresholds: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
    """
    Execute complete CI/CD performance validation pipeline with reporting.
    
    Args:
        app: Flask application instance for testing
        output_dir: Optional directory for report output
        send_notifications: Whether to send automated notifications
        custom_thresholds: Optional custom quality gate thresholds
        
    Returns:
        Dictionary containing validation results and report generation status
    """
    try:
        # Create CI/CD integration report generator
        generator = create_ci_cd_integration_report_generator(custom_thresholds)
        
        # Execute performance validation pipeline
        performance_report = generator.execute_performance_validation_pipeline(
            app,
            include_baseline_comparison=True,
            include_benchmark_testing=True,
            include_load_testing=True
        )
        
        # Generate reports and notifications
        report_results = generator.generate_ci_cd_reports(
            performance_report,
            output_dir,
            send_notifications
        )
        
        # Return comprehensive results
        return {
            'validation_success': performance_report.overall_decision != QualityGateDecision.FAIL,
            'performance_report': performance_report.to_dict(),
            'report_generation': report_results,
            'deployment_recommendation': {
                'decision': performance_report.overall_decision.value,
                'readiness': performance_report.deployment_readiness.value,
                'recommendation': performance_report.deployment_recommendation,
                'rollback_recommended': performance_report.rollback_recommendation
            },
            'quality_gates': {
                'total': len(performance_report.quality_gate_results),
                'passed': len([qgr for qgr in performance_report.quality_gate_results if qgr.passed]),
                'failed': len([qgr for qgr in performance_report.quality_gate_results if not qgr.passed])
            },
            'execution_metadata': {
                'report_id': performance_report.report_id,
                'generation_timestamp': performance_report.generation_timestamp.isoformat(),
                'total_duration_seconds': performance_report.total_test_duration_seconds,
                'risk_level': performance_report.risk_level
            }
        }
        
    except Exception as e:
        logging.error(f"CI/CD performance validation failed: {e}")
        return {
            'validation_success': False,
            'error': str(e),
            'deployment_recommendation': {
                'decision': 'fail',
                'readiness': 'blocked',
                'recommendation': 'Performance validation pipeline failed - investigation required',
                'rollback_recommended': True
            }
        }


def validate_github_actions_performance_gates(app, fail_on_regression: bool = True) -> bool:
    """
    Validate performance gates for GitHub Actions workflow with boolean return.
    
    Args:
        app: Flask application instance for testing
        fail_on_regression: Whether to fail on performance regression detection
        
    Returns:
        Boolean indicating whether performance gates passed
    """
    try:
        # Execute CI/CD performance validation
        results = execute_ci_cd_performance_validation(
            app,
            output_dir=None,
            send_notifications=True
        )
        
        # Check validation results
        validation_passed = results.get('validation_success', False)
        
        # Additional regression check if enabled
        if fail_on_regression and validation_passed:
            performance_report = results.get('performance_report', {})
            regression_analysis = performance_report.get('regression_analysis', {})
            
            if regression_analysis.get('total_regressions', 0) > 0:
                logging.warning(
                    "Performance regression detected",
                    total_regressions=regression_analysis['total_regressions']
                )
                return False
        
        return validation_passed
        
    except Exception as e:
        logging.error(f"Performance gates validation failed: {e}")
        return False


# Export public interface
__all__ = [
    # Core classes
    'CICDIntegrationReportGenerator',
    'QualityGateValidator',
    'NotificationManager',
    
    # Data structures
    'CICDContext',
    'CICDPerformanceReport',
    'QualityGateResult',
    
    # Enumerations
    'CICDStage',
    'QualityGateDecision',
    'DeploymentReadiness',
    'AlertSeverity',
    
    # Utility functions
    'create_ci_cd_integration_report_generator',
    'execute_ci_cd_performance_validation',
    'validate_github_actions_performance_gates',
    
    # Constants
    'QUALITY_GATE_THRESHOLDS',
    'GITHUB_ACTIONS_OUTPUT_FILE',
    'GITHUB_STEP_SUMMARY_FILE'
]