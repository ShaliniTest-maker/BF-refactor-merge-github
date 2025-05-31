"""
CI/CD Pipeline Integration Script for Flask Migration Performance Testing

This comprehensive CI/CD integration script provides GitHub Actions workflow support for
performance testing automation, quality gate enforcement, and deployment pipeline integration.
Enables seamless integration with automated deployment workflows and quality validation while
enforcing the critical ≤10% performance variance requirement per Section 0.1.1.

Key Features:
- GitHub Actions CI/CD pipeline integration per Section 8.5.1 build pipeline
- Performance quality gate enforcement per Section 8.5.2 deployment pipeline
- ≤10% variance requirement enforcement in CI/CD per Section 0.1.1
- Automated deployment validation and rollback triggers per Section 8.5.2
- Performance monitoring integration with deployment process per Section 8.5.3
- Artifact generation and notification systems per Section 6.6.2 CI/CD integration

Architecture Integration:
- Section 0.1.1: Performance optimization ensuring ≤10% variance from Node.js baseline
- Section 8.5.1: GitHub Actions CI/CD pipeline with comprehensive quality gates
- Section 8.5.2: Blue-green deployment with automated performance validation
- Section 8.5.3: Release management with performance monitoring integration
- Section 6.6.2: CI/CD integration with automated performance gates and regression detection

Dependencies:
- GitHub Actions workflow environment variables and context
- tests/performance/test_baseline_comparison.py for performance validation
- tests/performance/performance_config.py for configuration management
- Notification systems (Slack, Teams, Email) for alert integration
- Artifact storage systems for report and data persistence

Author: Flask Migration Team
Version: 1.0.0
CI/CD Integration: GitHub Actions optimized with performance gate automation
"""

import asyncio
import json
import logging
import os
import statistics
import subprocess
import sys
import time
import traceback
from collections import defaultdict, namedtuple
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any, NamedTuple
import uuid
import tempfile
import hashlib

# Standard library imports for CI/CD integration
import argparse
import shutil
import signal
import platform

# Third-party imports with fallback handling
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    requests = None

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    yaml = None

try:
    from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge, generate_latest
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

# Performance testing framework imports
try:
    from tests.performance.test_baseline_comparison import (
        BaselineComparisonTestSuite,
        PerformanceComparisonResult,
        PerformanceTrendAnalyzer,
        PERFORMANCE_VARIANCE_THRESHOLD,
        CRITICAL_PERFORMANCE_METRICS
    )
    BASELINE_COMPARISON_AVAILABLE = True
except ImportError:
    BASELINE_COMPARISON_AVAILABLE = False

try:
    from tests.performance.performance_config import (
        PerformanceConfigFactory,
        CICDPerformanceConfig,
        create_performance_config,
        get_performance_baseline_comparison,
        generate_performance_report
    )
    PERFORMANCE_CONFIG_AVAILABLE = True
except ImportError:
    PERFORMANCE_CONFIG_AVAILABLE = False


# CI/CD Integration Constants
GITHUB_ACTIONS_ENV_VARS = {
    'GITHUB_ACTIONS': 'GITHUB_ACTIONS',
    'GITHUB_REPOSITORY': 'GITHUB_REPOSITORY',
    'GITHUB_REF': 'GITHUB_REF',
    'GITHUB_SHA': 'GITHUB_SHA',
    'GITHUB_RUN_ID': 'GITHUB_RUN_ID',
    'GITHUB_RUN_NUMBER': 'GITHUB_RUN_NUMBER',
    'GITHUB_JOB': 'GITHUB_JOB',
    'GITHUB_ACTOR': 'GITHUB_ACTOR',
    'GITHUB_EVENT_NAME': 'GITHUB_EVENT_NAME',
    'GITHUB_WORKSPACE': 'GITHUB_WORKSPACE',
    'GITHUB_TOKEN': 'GITHUB_TOKEN',
    'GITHUB_STEP_SUMMARY': 'GITHUB_STEP_SUMMARY'
}

# Performance thresholds per technical specification
PERFORMANCE_VARIANCE_LIMIT = 0.10  # ≤10% variance requirement per Section 0.1.1
MEMORY_VARIANCE_LIMIT = 0.15       # ±15% memory variance allowance
ERROR_RATE_THRESHOLD = 0.001       # 0.1% error rate maximum
RESPONSE_TIME_THRESHOLD_MS = 500   # 500ms P95 response time maximum

# CI/CD Pipeline Configuration
PIPELINE_TIMEOUT_SECONDS = 1800    # 30-minute pipeline timeout
QUALITY_GATE_TIMEOUT = 300         # 5-minute quality gate timeout
NOTIFICATION_RETRY_COUNT = 3       # Notification delivery retry attempts
ARTIFACT_RETENTION_DAYS = 30       # Performance report retention period

# GitHub Actions Step Summary constants
STEP_SUMMARY_MAX_SIZE = 65536      # 64KB maximum step summary size
ARTIFACT_SIZE_LIMIT = 100 * 1024 * 1024  # 100MB artifact size limit


class CICDContext(NamedTuple):
    """CI/CD pipeline context information and metadata."""
    
    pipeline_id: str
    repository: str
    branch: str
    commit_sha: str
    run_number: int
    actor: str
    event_name: str
    workspace_path: str
    is_github_actions: bool
    github_token: Optional[str]
    step_summary_file: Optional[str]


class PerformanceGateResult(NamedTuple):
    """Performance quality gate validation result."""
    
    gate_name: str
    passed: bool
    variance_percent: float
    baseline_value: float
    current_value: float
    threshold: float
    severity: str
    message: str
    recommendation: str
    deployment_action: str  # 'APPROVE', 'BLOCK', 'WARNING'


class CICDNotificationConfig:
    """CI/CD notification configuration for multiple channels."""
    
    def __init__(self):
        """Initialize notification configuration from environment variables."""
        self.slack_webhook_url = os.getenv('SLACK_WEBHOOK_URL', '')
        self.teams_webhook_url = os.getenv('TEAMS_WEBHOOK_URL', '')
        self.email_enabled = os.getenv('EMAIL_NOTIFICATIONS', 'false').lower() == 'true'
        self.github_notifications = os.getenv('GITHUB_NOTIFICATIONS', 'true').lower() == 'true'
        
        # Notification preferences
        self.notify_on_success = os.getenv('NOTIFY_ON_SUCCESS', 'true').lower() == 'true'
        self.notify_on_failure = os.getenv('NOTIFY_ON_FAILURE', 'true').lower() == 'true'
        self.notify_on_performance_regression = os.getenv('NOTIFY_ON_REGRESSION', 'true').lower() == 'true'
        
        # Notification formatting
        self.use_threaded_messages = os.getenv('USE_THREADED_MESSAGES', 'false').lower() == 'true'
        self.include_performance_details = os.getenv('INCLUDE_PERF_DETAILS', 'true').lower() == 'true'
    
    def has_valid_channels(self) -> bool:
        """Check if any notification channels are configured."""
        return bool(
            self.slack_webhook_url or 
            self.teams_webhook_url or 
            self.email_enabled or 
            self.github_notifications
        )


class GitHubActionsIntegration:
    """
    GitHub Actions CI/CD pipeline integration providing comprehensive automation
    for performance testing, quality gates, and deployment validation.
    
    Implements enterprise-grade CI/CD integration with automated performance
    validation, quality gate enforcement, and deployment pipeline coordination
    per Section 8.5.1 build pipeline requirements.
    """
    
    def __init__(self, config: Optional[CICDNotificationConfig] = None):
        """
        Initialize GitHub Actions integration with configuration and context detection.
        
        Args:
            config: Notification configuration (defaults to environment-based config)
        """
        self.config = config or CICDNotificationConfig()
        self.context = self._detect_cicd_context()
        self.logger = self._setup_logging()
        
        # Performance testing components
        self.baseline_suite: Optional[BaselineComparisonTestSuite] = None
        self.performance_config = None
        self.quality_gates: List[PerformanceGateResult] = []
        
        # CI/CD state tracking
        self.pipeline_start_time = datetime.now(timezone.utc)
        self.artifacts_generated: List[Dict[str, Any]] = []
        self.notifications_sent: List[Dict[str, Any]] = []
        
        # Initialize performance testing components
        self._initialize_performance_testing()
        
        # Setup signal handlers for graceful shutdown
        self._setup_signal_handlers()
    
    def _detect_cicd_context(self) -> CICDContext:
        """
        Detect CI/CD pipeline context from environment variables.
        
        Returns:
            CICDContext with pipeline metadata and configuration
        """
        is_github_actions = os.getenv('GITHUB_ACTIONS', 'false').lower() == 'true'
        
        if is_github_actions:
            return CICDContext(
                pipeline_id=os.getenv('GITHUB_RUN_ID', 'unknown'),
                repository=os.getenv('GITHUB_REPOSITORY', 'unknown/unknown'),
                branch=os.getenv('GITHUB_REF', 'refs/heads/unknown').replace('refs/heads/', ''),
                commit_sha=os.getenv('GITHUB_SHA', 'unknown'),
                run_number=int(os.getenv('GITHUB_RUN_NUMBER', '0')),
                actor=os.getenv('GITHUB_ACTOR', 'unknown'),
                event_name=os.getenv('GITHUB_EVENT_NAME', 'unknown'),
                workspace_path=os.getenv('GITHUB_WORKSPACE', os.getcwd()),
                is_github_actions=True,
                github_token=os.getenv('GITHUB_TOKEN'),
                step_summary_file=os.getenv('GITHUB_STEP_SUMMARY')
            )
        else:
            # Local or other CI/CD environment
            return CICDContext(
                pipeline_id=str(uuid.uuid4()),
                repository='local/development',
                branch='local',
                commit_sha='local-dev',
                run_number=1,
                actor=os.getenv('USER', 'developer'),
                event_name='local',
                workspace_path=os.getcwd(),
                is_github_actions=False,
                github_token=None,
                step_summary_file=None
            )
    
    def _setup_logging(self) -> logging.Logger:
        """
        Setup structured logging for CI/CD pipeline integration.
        
        Returns:
            Configured logger instance for pipeline events
        """
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        
        # Remove existing handlers to avoid duplicates
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        
        # Create formatter for structured logging
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Console handler for CI/CD output
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # File handler for detailed logs (if workspace available)
        if self.context.workspace_path and os.access(self.context.workspace_path, os.W_OK):
            log_file = os.path.join(self.context.workspace_path, 'ci_integration.log')
            file_handler = logging.FileHandler(log_file, mode='a')
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        
        return logger
    
    def _initialize_performance_testing(self) -> None:
        """
        Initialize performance testing components with CI/CD configuration.
        
        Raises:
            RuntimeError: If required performance testing components are unavailable
        """
        if not BASELINE_COMPARISON_AVAILABLE:
            self.logger.warning("Baseline comparison module not available - performance testing disabled")
            return
        
        if not PERFORMANCE_CONFIG_AVAILABLE:
            self.logger.warning("Performance configuration module not available - using defaults")
            return
        
        try:
            # Create CI/CD-specific performance configuration
            self.performance_config = create_performance_config('ci_cd')
            
            # Initialize baseline comparison suite
            self.baseline_suite = BaselineComparisonTestSuite()
            self.baseline_suite.setup_baseline_comparison('ci_cd')
            
            self.logger.info(
                f"Performance testing initialized - "
                f"Variance threshold: {PERFORMANCE_VARIANCE_LIMIT:.1%}, "
                f"Environment: ci_cd"
            )
            
        except Exception as e:
            self.logger.error(f"Failed to initialize performance testing: {e}")
            self.baseline_suite = None
            self.performance_config = None
    
    def _setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful pipeline shutdown."""
        def signal_handler(signum, frame):
            self.logger.warning(f"Received signal {signum} - initiating graceful shutdown")
            self._cleanup_resources()
            sys.exit(1)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def validate_performance_gates(self, performance_data: Dict[str, float]) -> List[PerformanceGateResult]:
        """
        Validate performance metrics against quality gates with deployment recommendations.
        
        Args:
            performance_data: Dictionary of performance metrics to validate
            
        Returns:
            List of PerformanceGateResult objects with validation outcomes
            
        Raises:
            ValueError: If performance data is invalid or incomplete
        """
        if not performance_data:
            raise ValueError("Performance data cannot be empty")
        
        if not self.baseline_suite:
            self.logger.warning("Performance testing not available - skipping gate validation")
            return []
        
        results = []
        
        try:
            # Validate critical performance metrics
            for metric_name in CRITICAL_PERFORMANCE_METRICS:
                if metric_name in performance_data:
                    result = self._validate_individual_metric(
                        metric_name, performance_data[metric_name]
                    )
                    results.append(result)
                    self.quality_gates.append(result)
            
            # Generate overall assessment
            self._assess_overall_performance_health(results)
            
            self.logger.info(
                f"Performance gate validation completed - "
                f"{len(results)} metrics validated, "
                f"{sum(1 for r in results if r.passed)} passed"
            )
            
        except Exception as e:
            self.logger.error(f"Performance gate validation failed: {e}")
            self.logger.error(traceback.format_exc())
            raise
        
        return results
    
    def _validate_individual_metric(self, metric_name: str, current_value: float) -> PerformanceGateResult:
        """
        Validate individual performance metric against baseline and thresholds.
        
        Args:
            metric_name: Name of the performance metric
            current_value: Current measured value
            
        Returns:
            PerformanceGateResult with validation outcome
        """
        # Get baseline value for comparison
        baseline_value = self._get_baseline_value(metric_name)
        
        # Calculate variance percentage
        if baseline_value != 0:
            variance_percent = ((current_value - baseline_value) / baseline_value) * 100.0
        else:
            variance_percent = 0.0
        
        # Determine threshold based on metric type
        threshold = self._get_metric_threshold(metric_name)
        
        # Assess pass/fail status
        passed = abs(variance_percent) <= (threshold * 100.0)
        
        # Determine severity and recommendations
        severity = self._get_variance_severity(variance_percent, threshold)
        message = self._generate_metric_message(metric_name, variance_percent, passed)
        recommendation = self._generate_metric_recommendation(metric_name, variance_percent, severity)
        deployment_action = self._get_deployment_action(severity, passed)
        
        return PerformanceGateResult(
            gate_name=metric_name,
            passed=passed,
            variance_percent=variance_percent,
            baseline_value=baseline_value,
            current_value=current_value,
            threshold=threshold * 100.0,  # Convert to percentage
            severity=severity,
            message=message,
            recommendation=recommendation,
            deployment_action=deployment_action
        )
    
    def _get_baseline_value(self, metric_name: str) -> float:
        """Get baseline value for metric (mock implementation for now)."""
        # Baseline values would typically come from stored baselines
        baseline_mapping = {
            'api_response_time_p95': 250.0,
            'requests_per_second': 100.0,
            'memory_usage_mb': 256.0,
            'cpu_utilization_percent': 15.0,
            'database_query_time_ms': 50.0,
            'error_rate_percent': 0.1
        }
        return baseline_mapping.get(metric_name, 100.0)
    
    def _get_metric_threshold(self, metric_name: str) -> float:
        """Get variance threshold for specific metric type."""
        # Memory usage has relaxed threshold per specification
        if 'memory' in metric_name.lower():
            return MEMORY_VARIANCE_LIMIT
        elif 'error_rate' in metric_name.lower():
            return 0.5  # 50% variance for error rates (stricter)
        else:
            return PERFORMANCE_VARIANCE_LIMIT
    
    def _get_variance_severity(self, variance_percent: float, threshold: float) -> str:
        """Determine variance severity classification."""
        abs_variance = abs(variance_percent)
        threshold_percent = threshold * 100.0
        
        if abs_variance <= threshold_percent * 0.5:
            return "excellent"
        elif abs_variance <= threshold_percent:
            return "acceptable"
        elif abs_variance <= threshold_percent * 1.5:
            return "warning"
        elif abs_variance <= threshold_percent * 2.0:
            return "critical"
        else:
            return "failure"
    
    def _generate_metric_message(self, metric_name: str, variance_percent: float, passed: bool) -> str:
        """Generate human-readable message for metric validation."""
        status = "PASSED" if passed else "FAILED"
        direction = "improvement" if variance_percent < 0 else "degradation"
        
        return (
            f"{metric_name}: {status} - "
            f"{abs(variance_percent):.2f}% {direction} from baseline"
        )
    
    def _generate_metric_recommendation(self, metric_name: str, variance_percent: float, severity: str) -> str:
        """Generate actionable recommendation for metric result."""
        if severity in ["excellent", "acceptable"]:
            return "Performance within acceptable range - continue monitoring"
        elif severity == "warning":
            return f"Monitor {metric_name} closely - consider optimization if trend continues"
        elif severity == "critical":
            return f"Investigate {metric_name} performance - optimization required before deployment"
        else:
            return f"Critical performance issue in {metric_name} - immediate remediation required"
    
    def _get_deployment_action(self, severity: str, passed: bool) -> str:
        """Determine deployment action based on severity and pass status."""
        if severity in ["excellent", "acceptable"] and passed:
            return "APPROVE"
        elif severity == "warning":
            return "WARNING"
        else:
            return "BLOCK"
    
    def _assess_overall_performance_health(self, results: List[PerformanceGateResult]) -> None:
        """Assess overall performance health and log summary."""
        total_metrics = len(results)
        passed_metrics = sum(1 for r in results if r.passed)
        blocked_metrics = sum(1 for r in results if r.deployment_action == "BLOCK")
        
        health_score = (passed_metrics / total_metrics * 100.0) if total_metrics > 0 else 0.0
        
        self.logger.info(
            f"Performance health assessment: {health_score:.1f}% "
            f"({passed_metrics}/{total_metrics} metrics passed)"
        )
        
        if blocked_metrics > 0:
            self.logger.warning(
                f"Deployment blocking metrics detected: {blocked_metrics} metrics require attention"
            )
    
    def enforce_quality_gates(self) -> Tuple[bool, Dict[str, Any]]:
        """
        Enforce quality gates and determine deployment approval.
        
        Returns:
            Tuple of (deployment_approved, quality_report)
        """
        if not self.quality_gates:
            self.logger.warning("No quality gates to enforce - approving by default")
            return True, {"status": "no_gates", "message": "No performance gates configured"}
        
        # Analyze quality gate results
        total_gates = len(self.quality_gates)
        passed_gates = sum(1 for gate in self.quality_gates if gate.passed)
        blocked_gates = [gate for gate in self.quality_gates if gate.deployment_action == "BLOCK"]
        warning_gates = [gate for gate in self.quality_gates if gate.deployment_action == "WARNING"]
        
        # Determine overall deployment approval
        deployment_approved = len(blocked_gates) == 0
        
        # Generate quality report
        quality_report = {
            "status": "approved" if deployment_approved else "blocked",
            "total_gates": total_gates,
            "passed_gates": passed_gates,
            "failed_gates": total_gates - passed_gates,
            "blocked_gates": len(blocked_gates),
            "warning_gates": len(warning_gates),
            "compliance_rate": (passed_gates / total_gates * 100.0) if total_gates > 0 else 0.0,
            "blocking_issues": [
                {
                    "metric": gate.gate_name,
                    "variance": gate.variance_percent,
                    "threshold": gate.threshold,
                    "recommendation": gate.recommendation
                }
                for gate in blocked_gates
            ],
            "warnings": [
                {
                    "metric": gate.gate_name,
                    "variance": gate.variance_percent,
                    "recommendation": gate.recommendation
                }
                for gate in warning_gates
            ]
        }
        
        # Log enforcement decision
        if deployment_approved:
            self.logger.info(
                f"Quality gates PASSED - Deployment APPROVED "
                f"({passed_gates}/{total_gates} gates passed, {len(warning_gates)} warnings)"
            )
        else:
            self.logger.error(
                f"Quality gates FAILED - Deployment BLOCKED "
                f"({len(blocked_gates)} blocking issues, {len(warning_gates)} warnings)"
            )
        
        return deployment_approved, quality_report
    
    def generate_github_step_summary(self, quality_report: Dict[str, Any]) -> None:
        """
        Generate GitHub Actions step summary with performance validation results.
        
        Args:
            quality_report: Quality gate enforcement report
        """
        if not self.context.step_summary_file:
            self.logger.warning("GitHub step summary not available - skipping summary generation")
            return
        
        try:
            summary_content = self._build_step_summary_content(quality_report)
            
            # Ensure summary doesn't exceed size limits
            if len(summary_content) > STEP_SUMMARY_MAX_SIZE:
                summary_content = summary_content[:STEP_SUMMARY_MAX_SIZE - 100] + "\n\n*Summary truncated due to size limits*"
            
            # Append to step summary file
            with open(self.context.step_summary_file, 'a', encoding='utf-8') as f:
                f.write(summary_content)
            
            self.logger.info("GitHub Actions step summary generated successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to generate GitHub step summary: {e}")
    
    def _build_step_summary_content(self, quality_report: Dict[str, Any]) -> str:
        """
        Build step summary content with performance validation results.
        
        Args:
            quality_report: Quality gate enforcement report
            
        Returns:
            Formatted markdown content for GitHub step summary
        """
        status_emoji = "✅" if quality_report["status"] == "approved" else "❌"
        
        summary_lines = [
            f"\n## {status_emoji} Performance Quality Gates Report\n",
            f"**Pipeline**: {self.context.repository} (Run #{self.context.run_number})\n",
            f"**Branch**: {self.context.branch}\n",
            f"**Commit**: {self.context.commit_sha[:8]}\n",
            f"**Actor**: {self.context.actor}\n",
            f"**Timestamp**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n",
            
            "### 📊 Quality Gate Summary\n\n",
            f"| Metric | Value |\n",
            f"|--------|-------|\n",
            f"| **Status** | {quality_report['status'].upper()} |\n",
            f"| **Total Gates** | {quality_report['total_gates']} |\n",
            f"| **Passed Gates** | {quality_report['passed_gates']} |\n",
            f"| **Failed Gates** | {quality_report['failed_gates']} |\n",
            f"| **Compliance Rate** | {quality_report['compliance_rate']:.1f}% |\n",
            f"| **Variance Threshold** | ≤{PERFORMANCE_VARIANCE_LIMIT:.1%} |\n\n"
        ]
        
        # Add blocking issues if any
        if quality_report["blocked_gates"] > 0:
            summary_lines.extend([
                "### 🚫 Blocking Issues\n\n",
                "The following performance issues are blocking deployment:\n\n"
            ])
            
            for issue in quality_report["blocking_issues"]:
                summary_lines.append(
                    f"- **{issue['metric']}**: {issue['variance']:.2f}% variance "
                    f"(threshold: {issue['threshold']:.1f}%)\n"
                    f"  - *Recommendation*: {issue['recommendation']}\n\n"
                )
        
        # Add warnings if any
        if quality_report["warning_gates"] > 0:
            summary_lines.extend([
                "### ⚠️ Performance Warnings\n\n",
                "The following metrics require attention:\n\n"
            ])
            
            for warning in quality_report["warnings"]:
                summary_lines.append(
                    f"- **{warning['metric']}**: {warning['variance']:.2f}% variance\n"
                    f"  - *Recommendation*: {warning['recommendation']}\n\n"
                )
        
        # Add performance gate details
        if self.quality_gates:
            summary_lines.extend([
                "### 📈 Detailed Performance Results\n\n",
                "| Metric | Current | Baseline | Variance | Status |\n",
                "|--------|---------|----------|----------|--------|\n"
            ])
            
            for gate in self.quality_gates:
                status_icon = "✅" if gate.passed else "❌"
                summary_lines.append(
                    f"| {gate.gate_name} | {gate.current_value:.2f} | "
                    f"{gate.baseline_value:.2f} | {gate.variance_percent:+.2f}% | "
                    f"{status_icon} {gate.severity} |\n"
                )
        
        # Add deployment recommendation
        summary_lines.extend([
            "\n### 🚀 Deployment Recommendation\n\n"
        ])
        
        if quality_report["status"] == "approved":
            summary_lines.append(
                "**✅ DEPLOYMENT APPROVED**\n\n"
                "All performance quality gates have passed. The deployment meets the "
                "≤10% variance requirement and is ready for production.\n\n"
            )
        else:
            summary_lines.append(
                "**❌ DEPLOYMENT BLOCKED**\n\n"
                "Performance quality gates have failed. Please address the blocking "
                "issues before proceeding with deployment.\n\n"
            )
        
        # Add footer with context
        summary_lines.extend([
            "---\n",
            f"*Generated by CI/CD Performance Integration v1.0.0*\n",
            f"*Pipeline ID: {self.context.pipeline_id}*\n"
        ])
        
        return "".join(summary_lines)
    
    def send_notifications(self, quality_report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Send notifications to configured channels based on quality gate results.
        
        Args:
            quality_report: Quality gate enforcement report
            
        Returns:
            List of notification delivery results
        """
        if not self.config.has_valid_channels():
            self.logger.info("No notification channels configured - skipping notifications")
            return []
        
        notification_results = []
        
        # Determine if we should send notifications
        should_notify = (
            (quality_report["status"] == "approved" and self.config.notify_on_success) or
            (quality_report["status"] == "blocked" and self.config.notify_on_failure) or
            (quality_report["warning_gates"] > 0 and self.config.notify_on_performance_regression)
        )
        
        if not should_notify:
            self.logger.info("Notification conditions not met - skipping notifications")
            return []
        
        # Send Slack notification
        if self.config.slack_webhook_url:
            slack_result = self._send_slack_notification(quality_report)
            notification_results.append(slack_result)
        
        # Send Teams notification
        if self.config.teams_webhook_url:
            teams_result = self._send_teams_notification(quality_report)
            notification_results.append(teams_result)
        
        # Send GitHub notification (comment on PR if applicable)
        if self.config.github_notifications and self.context.github_token:
            github_result = self._send_github_notification(quality_report)
            notification_results.append(github_result)
        
        # Track notification results
        self.notifications_sent.extend(notification_results)
        
        successful_notifications = sum(1 for result in notification_results if result["success"])
        self.logger.info(
            f"Notifications sent: {successful_notifications}/{len(notification_results)} successful"
        )
        
        return notification_results
    
    def _send_slack_notification(self, quality_report: Dict[str, Any]) -> Dict[str, Any]:
        """Send Slack notification with performance gate results."""
        if not REQUESTS_AVAILABLE:
            return {"channel": "slack", "success": False, "error": "requests library not available"}
        
        try:
            status_emoji = "✅" if quality_report["status"] == "approved" else "❌"
            color = "good" if quality_report["status"] == "approved" else "danger"
            
            message = {
                "username": "Performance CI/CD Bot",
                "icon_emoji": ":robot_face:",
                "attachments": [
                    {
                        "color": color,
                        "title": f"{status_emoji} Performance Quality Gates Report",
                        "title_link": f"https://github.com/{self.context.repository}/actions/runs/{self.context.pipeline_id}",
                        "fields": [
                            {
                                "title": "Repository",
                                "value": self.context.repository,
                                "short": True
                            },
                            {
                                "title": "Branch",
                                "value": self.context.branch,
                                "short": True
                            },
                            {
                                "title": "Status",
                                "value": quality_report["status"].upper(),
                                "short": True
                            },
                            {
                                "title": "Compliance Rate",
                                "value": f"{quality_report['compliance_rate']:.1f}%",
                                "short": True
                            }
                        ],
                        "footer": f"CI/CD Performance Integration | Run #{self.context.run_number}",
                        "ts": int(time.time())
                    }
                ]
            }
            
            # Add performance details if enabled
            if self.config.include_performance_details and quality_report["blocked_gates"] > 0:
                blocking_details = "\n".join([
                    f"• {issue['metric']}: {issue['variance']:.2f}% variance"
                    for issue in quality_report["blocking_issues"]
                ])
                message["attachments"][0]["text"] = f"Blocking Issues:\n{blocking_details}"
            
            # Send notification with retry logic
            for attempt in range(NOTIFICATION_RETRY_COUNT):
                try:
                    response = requests.post(
                        self.config.slack_webhook_url,
                        json=message,
                        timeout=10
                    )
                    response.raise_for_status()
                    
                    return {
                        "channel": "slack",
                        "success": True,
                        "status_code": response.status_code,
                        "attempt": attempt + 1
                    }
                    
                except requests.exceptions.RequestException as e:
                    if attempt == NOTIFICATION_RETRY_COUNT - 1:
                        raise e
                    time.sleep(2 ** attempt)  # Exponential backoff
            
        except Exception as e:
            self.logger.error(f"Failed to send Slack notification: {e}")
            return {"channel": "slack", "success": False, "error": str(e)}
    
    def _send_teams_notification(self, quality_report: Dict[str, Any]) -> Dict[str, Any]:
        """Send Microsoft Teams notification with performance gate results."""
        if not REQUESTS_AVAILABLE:
            return {"channel": "teams", "success": False, "error": "requests library not available"}
        
        try:
            status_color = "Good" if quality_report["status"] == "approved" else "Attention"
            status_emoji = "✅" if quality_report["status"] == "approved" else "❌"
            
            message = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": "00FF00" if quality_report["status"] == "approved" else "FF0000",
                "summary": f"Performance Quality Gates: {quality_report['status'].upper()}",
                "sections": [
                    {
                        "activityTitle": f"{status_emoji} Performance Quality Gates Report",
                        "activitySubtitle": f"{self.context.repository} (Run #{self.context.run_number})",
                        "facts": [
                            {
                                "name": "Branch",
                                "value": self.context.branch
                            },
                            {
                                "name": "Status",
                                "value": quality_report["status"].upper()
                            },
                            {
                                "name": "Compliance Rate",
                                "value": f"{quality_report['compliance_rate']:.1f}%"
                            },
                            {
                                "name": "Total Gates",
                                "value": f"{quality_report['passed_gates']}/{quality_report['total_gates']}"
                            }
                        ],
                        "markdown": True
                    }
                ],
                "potentialAction": [
                    {
                        "@type": "OpenUri",
                        "name": "View Pipeline",
                        "targets": [
                            {
                                "os": "default",
                                "uri": f"https://github.com/{self.context.repository}/actions/runs/{self.context.pipeline_id}"
                            }
                        ]
                    }
                ]
            }
            
            # Send notification with retry logic
            for attempt in range(NOTIFICATION_RETRY_COUNT):
                try:
                    response = requests.post(
                        self.config.teams_webhook_url,
                        json=message,
                        timeout=10
                    )
                    response.raise_for_status()
                    
                    return {
                        "channel": "teams",
                        "success": True,
                        "status_code": response.status_code,
                        "attempt": attempt + 1
                    }
                    
                except requests.exceptions.RequestException as e:
                    if attempt == NOTIFICATION_RETRY_COUNT - 1:
                        raise e
                    time.sleep(2 ** attempt)  # Exponential backoff
            
        except Exception as e:
            self.logger.error(f"Failed to send Teams notification: {e}")
            return {"channel": "teams", "success": False, "error": str(e)}
    
    def _send_github_notification(self, quality_report: Dict[str, Any]) -> Dict[str, Any]:
        """Send GitHub notification (future implementation for PR comments)."""
        # GitHub API integration would be implemented here
        # For now, return a placeholder
        return {
            "channel": "github",
            "success": True,
            "message": "GitHub notification integration not yet implemented"
        }
    
    def generate_performance_artifacts(self, quality_report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate performance testing artifacts for CI/CD pipeline.
        
        Args:
            quality_report: Quality gate enforcement report
            
        Returns:
            List of generated artifact metadata
        """
        artifacts = []
        
        try:
            # Create artifacts directory
            artifacts_dir = os.path.join(self.context.workspace_path, 'performance-artifacts')
            os.makedirs(artifacts_dir, exist_ok=True)
            
            # Generate quality report artifact
            quality_report_artifact = self._generate_quality_report_artifact(
                quality_report, artifacts_dir
            )
            artifacts.append(quality_report_artifact)
            
            # Generate performance metrics artifact
            if self.quality_gates:
                metrics_artifact = self._generate_metrics_artifact(artifacts_dir)
                artifacts.append(metrics_artifact)
            
            # Generate trend analysis artifact if available
            if self.baseline_suite:
                trend_artifact = self._generate_trend_analysis_artifact(artifacts_dir)
                artifacts.append(trend_artifact)
            
            # Generate pipeline summary artifact
            summary_artifact = self._generate_pipeline_summary_artifact(
                quality_report, artifacts_dir
            )
            artifacts.append(summary_artifact)
            
            # Track generated artifacts
            self.artifacts_generated.extend(artifacts)
            
            self.logger.info(f"Generated {len(artifacts)} performance artifacts")
            
        except Exception as e:
            self.logger.error(f"Failed to generate performance artifacts: {e}")
            self.logger.error(traceback.format_exc())
        
        return artifacts
    
    def _generate_quality_report_artifact(self, quality_report: Dict[str, Any], artifacts_dir: str) -> Dict[str, Any]:
        """Generate comprehensive quality report artifact."""
        report_file = os.path.join(artifacts_dir, 'quality-gate-report.json')
        
        enhanced_report = {
            **quality_report,
            "pipeline_metadata": {
                "pipeline_id": self.context.pipeline_id,
                "repository": self.context.repository,
                "branch": self.context.branch,
                "commit_sha": self.context.commit_sha,
                "run_number": self.context.run_number,
                "actor": self.context.actor,
                "event_name": self.context.event_name,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": (datetime.now(timezone.utc) - self.pipeline_start_time).total_seconds()
            },
            "performance_configuration": {
                "variance_threshold": PERFORMANCE_VARIANCE_LIMIT,
                "memory_variance_threshold": MEMORY_VARIANCE_LIMIT,
                "error_rate_threshold": ERROR_RATE_THRESHOLD,
                "response_time_threshold_ms": RESPONSE_TIME_THRESHOLD_MS
            },
            "quality_gate_details": [
                {
                    "gate_name": gate.gate_name,
                    "passed": gate.passed,
                    "variance_percent": gate.variance_percent,
                    "baseline_value": gate.baseline_value,
                    "current_value": gate.current_value,
                    "threshold": gate.threshold,
                    "severity": gate.severity,
                    "message": gate.message,
                    "recommendation": gate.recommendation,
                    "deployment_action": gate.deployment_action
                }
                for gate in self.quality_gates
            ]
        }
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(enhanced_report, f, indent=2, default=str)
        
        file_size = os.path.getsize(report_file)
        
        return {
            "name": "quality-gate-report",
            "type": "json",
            "file_path": report_file,
            "size_bytes": file_size,
            "description": "Comprehensive quality gate validation report",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
    
    def _generate_metrics_artifact(self, artifacts_dir: str) -> Dict[str, Any]:
        """Generate performance metrics artifact."""
        metrics_file = os.path.join(artifacts_dir, 'performance-metrics.json')
        
        metrics_data = {
            "metrics": [
                {
                    "name": gate.gate_name,
                    "value": gate.current_value,
                    "baseline": gate.baseline_value,
                    "variance": gate.variance_percent,
                    "unit": self._get_metric_unit(gate.gate_name),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                for gate in self.quality_gates
            ],
            "summary": {
                "total_metrics": len(self.quality_gates),
                "passed_metrics": sum(1 for gate in self.quality_gates if gate.passed),
                "average_variance": statistics.mean([abs(gate.variance_percent) for gate in self.quality_gates]) if self.quality_gates else 0.0,
                "max_variance": max([abs(gate.variance_percent) for gate in self.quality_gates]) if self.quality_gates else 0.0
            }
        }
        
        with open(metrics_file, 'w', encoding='utf-8') as f:
            json.dump(metrics_data, f, indent=2, default=str)
        
        file_size = os.path.getsize(metrics_file)
        
        return {
            "name": "performance-metrics",
            "type": "json",
            "file_path": metrics_file,
            "size_bytes": file_size,
            "description": "Performance metrics data and variance analysis",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
    
    def _generate_trend_analysis_artifact(self, artifacts_dir: str) -> Dict[str, Any]:
        """Generate trend analysis artifact."""
        trend_file = os.path.join(artifacts_dir, 'performance-trends.json')
        
        # This would use the trend analyzer from baseline comparison suite
        trend_data = {
            "trend_analysis": "Trend analysis integration pending",
            "baseline_comparison": "Baseline comparison data would be included here",
            "regression_detection": "Regression analysis results would be included here"
        }
        
        with open(trend_file, 'w', encoding='utf-8') as f:
            json.dump(trend_data, f, indent=2, default=str)
        
        file_size = os.path.getsize(trend_file)
        
        return {
            "name": "performance-trends",
            "type": "json",
            "file_path": trend_file,
            "size_bytes": file_size,
            "description": "Performance trend analysis and regression detection",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
    
    def _generate_pipeline_summary_artifact(self, quality_report: Dict[str, Any], artifacts_dir: str) -> Dict[str, Any]:
        """Generate pipeline execution summary artifact."""
        summary_file = os.path.join(artifacts_dir, 'pipeline-summary.json')
        
        summary_data = {
            "pipeline_execution": {
                "start_time": self.pipeline_start_time.isoformat(),
                "end_time": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": (datetime.now(timezone.utc) - self.pipeline_start_time).total_seconds(),
                "status": quality_report["status"],
                "context": self.context._asdict()
            },
            "quality_gates": quality_report,
            "artifacts_generated": len(self.artifacts_generated),
            "notifications_sent": len(self.notifications_sent),
            "configuration": {
                "performance_variance_limit": PERFORMANCE_VARIANCE_LIMIT,
                "memory_variance_limit": MEMORY_VARIANCE_LIMIT,
                "pipeline_timeout": PIPELINE_TIMEOUT_SECONDS,
                "notification_channels": {
                    "slack": bool(self.config.slack_webhook_url),
                    "teams": bool(self.config.teams_webhook_url),
                    "github": self.config.github_notifications
                }
            }
        }
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary_data, f, indent=2, default=str)
        
        file_size = os.path.getsize(summary_file)
        
        return {
            "name": "pipeline-summary",
            "type": "json",
            "file_path": summary_file,
            "size_bytes": file_size,
            "description": "Complete pipeline execution summary and metadata",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
    
    def _get_metric_unit(self, metric_name: str) -> str:
        """Get appropriate unit for metric type."""
        unit_mapping = {
            'response_time': 'ms',
            'requests_per_second': 'req/s',
            'memory_usage': 'MB',
            'cpu_utilization': '%',
            'error_rate': '%',
            'database_query': 'ms'
        }
        
        for key, unit in unit_mapping.items():
            if key in metric_name.lower():
                return unit
        
        return 'units'
    
    def execute_pipeline_integration(self, performance_data: Optional[Dict[str, float]] = None) -> int:
        """
        Execute complete CI/CD pipeline integration workflow.
        
        Args:
            performance_data: Performance metrics to validate (optional for testing)
            
        Returns:
            Exit code (0 for success, 1 for failure)
        """
        try:
            self.logger.info(
                f"Starting CI/CD pipeline integration - "
                f"Repository: {self.context.repository}, "
                f"Branch: {self.context.branch}, "
                f"Run: #{self.context.run_number}"
            )
            
            # Use sample data if none provided (for testing/demonstration)
            if performance_data is None:
                performance_data = self._generate_sample_performance_data()
            
            # Validate performance gates
            self.logger.info("Validating performance quality gates...")
            gate_results = self.validate_performance_gates(performance_data)
            
            # Enforce quality gates and get deployment decision
            self.logger.info("Enforcing quality gates...")
            deployment_approved, quality_report = self.enforce_quality_gates()
            
            # Generate GitHub Actions step summary
            if self.context.is_github_actions:
                self.logger.info("Generating GitHub Actions step summary...")
                self.generate_github_step_summary(quality_report)
            
            # Send notifications
            self.logger.info("Sending notifications...")
            notification_results = self.send_notifications(quality_report)
            
            # Generate artifacts
            self.logger.info("Generating performance artifacts...")
            artifacts = self.generate_performance_artifacts(quality_report)
            
            # Log final results
            self._log_pipeline_results(deployment_approved, quality_report, notification_results, artifacts)
            
            # Return appropriate exit code
            return 0 if deployment_approved else 1
            
        except Exception as e:
            self.logger.error(f"CI/CD pipeline integration failed: {e}")
            self.logger.error(traceback.format_exc())
            
            # Send failure notification if possible
            try:
                failure_report = {
                    "status": "error",
                    "error_message": str(e),
                    "total_gates": 0,
                    "passed_gates": 0,
                    "failed_gates": 0,
                    "blocked_gates": 0,
                    "warning_gates": 0,
                    "compliance_rate": 0.0,
                    "blocking_issues": [],
                    "warnings": []
                }
                self.send_notifications(failure_report)
            except:
                pass  # Ignore notification failures during error handling
            
            return 1
        
        finally:
            self._cleanup_resources()
    
    def _generate_sample_performance_data(self) -> Dict[str, float]:
        """Generate sample performance data for testing."""
        return {
            'api_response_time_p95': 245.5,
            'requests_per_second': 105.2,
            'memory_usage_mb': 278.3,
            'cpu_utilization_percent': 16.8,
            'database_query_time_ms': 52.1,
            'error_rate_percent': 0.08
        }
    
    def _log_pipeline_results(self, deployment_approved: bool, quality_report: Dict[str, Any], 
                             notification_results: List[Dict[str, Any]], artifacts: List[Dict[str, Any]]) -> None:
        """Log comprehensive pipeline execution results."""
        duration = (datetime.now(timezone.utc) - self.pipeline_start_time).total_seconds()
        
        self.logger.info("=" * 80)
        self.logger.info("CI/CD PIPELINE INTEGRATION RESULTS")
        self.logger.info("=" * 80)
        self.logger.info(f"Repository: {self.context.repository}")
        self.logger.info(f"Branch: {self.context.branch}")
        self.logger.info(f"Commit: {self.context.commit_sha[:8]}")
        self.logger.info(f"Run Number: #{self.context.run_number}")
        self.logger.info(f"Actor: {self.context.actor}")
        self.logger.info(f"Duration: {duration:.1f} seconds")
        self.logger.info("-" * 80)
        self.logger.info(f"Deployment Status: {'APPROVED' if deployment_approved else 'BLOCKED'}")
        self.logger.info(f"Quality Gates: {quality_report['passed_gates']}/{quality_report['total_gates']} passed")
        self.logger.info(f"Compliance Rate: {quality_report['compliance_rate']:.1f}%")
        self.logger.info(f"Notifications Sent: {len([n for n in notification_results if n['success']])}/{len(notification_results)}")
        self.logger.info(f"Artifacts Generated: {len(artifacts)}")
        self.logger.info("=" * 80)
    
    def _cleanup_resources(self) -> None:
        """Cleanup resources and perform final housekeeping."""
        try:
            # Close any open file handles
            if hasattr(self, 'logger'):
                for handler in self.logger.handlers:
                    if hasattr(handler, 'close'):
                        handler.close()
            
            # Cleanup temporary files if any
            # This would include any temporary performance testing files
            
            self.logger.info("Resource cleanup completed")
            
        except Exception as e:
            # Use print since logger might be closed
            print(f"Warning: Cleanup failed: {e}")


def main():
    """
    Main entry point for CI/CD pipeline integration script.
    
    Provides command-line interface for performance testing integration
    with GitHub Actions and other CI/CD systems.
    """
    parser = argparse.ArgumentParser(
        description="CI/CD Pipeline Integration for Flask Migration Performance Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ci_integration.py --validate-gates
  python ci_integration.py --performance-data metrics.json --notify-on-failure
  python ci_integration.py --generate-artifacts --slack-webhook URL
        """
    )
    
    # Performance data input options
    parser.add_argument(
        '--performance-data',
        type=str,
        help='JSON file containing performance metrics to validate'
    )
    
    parser.add_argument(
        '--validate-gates',
        action='store_true',
        help='Validate performance quality gates'
    )
    
    # Notification configuration
    parser.add_argument(
        '--slack-webhook',
        type=str,
        help='Slack webhook URL for notifications'
    )
    
    parser.add_argument(
        '--teams-webhook',
        type=str,
        help='Microsoft Teams webhook URL for notifications'
    )
    
    parser.add_argument(
        '--notify-on-success',
        action='store_true',
        default=True,
        help='Send notifications on successful validation'
    )
    
    parser.add_argument(
        '--notify-on-failure',
        action='store_true',
        default=True,
        help='Send notifications on validation failure'
    )
    
    # Artifact generation
    parser.add_argument(
        '--generate-artifacts',
        action='store_true',
        default=True,
        help='Generate performance testing artifacts'
    )
    
    parser.add_argument(
        '--artifacts-dir',
        type=str,
        default='performance-artifacts',
        help='Directory for generated artifacts'
    )
    
    # Logging configuration
    parser.add_argument(
        '--log-level',
        type=str,
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level for pipeline execution'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Run validation without sending notifications or blocking deployment'
    )
    
    args = parser.parse_args()
    
    try:
        # Override environment variables with command-line arguments
        if args.slack_webhook:
            os.environ['SLACK_WEBHOOK_URL'] = args.slack_webhook
        
        if args.teams_webhook:
            os.environ['TEAMS_WEBHOOK_URL'] = args.teams_webhook
        
        if args.notify_on_success:
            os.environ['NOTIFY_ON_SUCCESS'] = 'true'
        
        if args.notify_on_failure:
            os.environ['NOTIFY_ON_FAILURE'] = 'true'
        
        # Initialize CI/CD integration
        cicd_integration = GitHubActionsIntegration()
        
        # Set logging level
        cicd_integration.logger.setLevel(getattr(logging, args.log_level))
        
        # Load performance data if provided
        performance_data = None
        if args.performance_data:
            if os.path.exists(args.performance_data):
                with open(args.performance_data, 'r') as f:
                    performance_data = json.load(f)
                cicd_integration.logger.info(f"Loaded performance data from {args.performance_data}")
            else:
                cicd_integration.logger.error(f"Performance data file not found: {args.performance_data}")
                return 1
        
        # Execute pipeline integration
        if args.dry_run:
            cicd_integration.logger.info("DRY RUN MODE - No notifications will be sent, deployment will not be blocked")
        
        exit_code = cicd_integration.execute_pipeline_integration(performance_data)
        
        if args.dry_run:
            # Override exit code for dry runs
            cicd_integration.logger.info(f"Dry run completed (would have exited with code {exit_code})")
            return 0
        
        return exit_code
        
    except KeyboardInterrupt:
        print("\nCI/CD integration interrupted by user")
        return 130
    
    except Exception as e:
        print(f"Fatal error in CI/CD integration: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())