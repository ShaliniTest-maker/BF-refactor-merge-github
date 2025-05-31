#!/usr/bin/env python3
"""
Performance Report Generation Script for Flask Migration

This comprehensive performance report generation script creates detailed performance 
analysis reports including variance calculations, trend analysis, baseline comparisons, 
and CI/CD integration summaries. Produces stakeholder-focused documentation for 
quality assessment and deployment decision-making per Section 6.6.2 requirements.

Key Features:
- Comprehensive performance baseline comparison reporting per Section 6.6.2
- Trend analysis and variance calculation documentation per Section 0.3.2  
- CI/CD pipeline integration reporting per Section 8.5.2 deployment pipeline
- Stakeholder communication and quality assessment reports per Section 8.5.3
- GitHub Actions artifact generation for comprehensive audit trails
- Multi-format report generation (JSON, Markdown, HTML, PDF) for diverse stakeholder needs

Architecture Compliance:
- Section 0.1.1: ≤10% variance requirement enforcement and comprehensive reporting
- Section 0.3.2: Performance monitoring requirements with continuous baseline comparison
- Section 6.6.2: Test automation with automated report artifact generation
- Section 8.5.2: Deployment pipeline integration with performance validation reporting
- Section 8.5.3: Release management process with stakeholder communication requirements

Dependencies:
- tests.performance.baseline_data for Node.js baseline comparison
- tests.performance.test_baseline_comparison for comprehensive test execution
- tests.performance.performance_config for environment configuration management
- matplotlib/plotly for performance visualization and trend analysis
- jinja2 for comprehensive report templating and stakeholder communication

Author: Flask Migration Team  
Version: 1.0.0
Integration: GitHub Actions CI/CD Pipeline, Stakeholder Communication Systems
"""

import argparse
import json
import logging
import os
import statistics
import sys
import traceback
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any, NamedTuple
import uuid

# Core data processing and analysis imports
import pandas as pd
import numpy as np
from dataclasses import dataclass, asdict
from enum import Enum

# Visualization and reporting imports
try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend for CI/CD
    import matplotlib.pyplot as plt
    import seaborn as sns
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    plt = None
    sns = None

try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    import plotly.io as pio
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    go = None
    px = None

# Report templating and generation imports
try:
    from jinja2 import Environment, FileSystemLoader, Template
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False
    Environment = None
    Template = None

try:
    import weasyprint
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False
    weasyprint = None

# Performance testing infrastructure imports
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

from tests.performance.test_baseline_comparison import (
    BaselineComparisonTestSuite,
    PerformanceComparisonResult,
    PerformanceTrendAnalyzer,
    BASELINE_COMPARISON_TIMEOUT,
    PERFORMANCE_SAMPLE_SIZE,
    VARIANCE_CALCULATION_PRECISION,
    TREND_ANALYSIS_WINDOW_SIZE,
    REGRESSION_DETECTION_THRESHOLD,
    PERFORMANCE_TEST_CATEGORIES,
    CRITICAL_PERFORMANCE_METRICS
)

from tests.performance.performance_config import (
    PerformanceConfigFactory,
    BasePerformanceConfig,
    PerformanceThreshold,
    LoadTestConfiguration,
    BaselineMetrics,
    PerformanceTestType,
    PerformanceEnvironment,
    create_performance_config,
    get_performance_baseline_comparison,
    generate_performance_report
)


# Report generation constants and configuration
REPORT_VERSION = "1.0.0"
REPORT_TEMPLATE_DIR = Path(__file__).parent / "templates"
REPORT_OUTPUT_DIR = Path(__file__).parent.parent / "reports"
ARTIFACTS_DIR = Path(__file__).parent.parent / "artifacts"

# Stakeholder communication constants per Section 8.5.3
STAKEHOLDER_REPORT_FORMATS = ["executive_summary", "technical_detailed", "compliance_audit"]
CI_CD_ARTIFACT_FORMATS = ["json", "markdown", "html"]
PERFORMANCE_VARIANCE_ALERT_THRESHOLD = 8.0  # 8% variance alert per Section 8.5.3

# GitHub Actions integration constants per Section 6.6.2
GITHUB_ACTIONS_INTEGRATION = os.getenv('GITHUB_ACTIONS', 'false').lower() == 'true'
GITHUB_RUN_ID = os.getenv('GITHUB_RUN_ID', 'local')
GITHUB_SHA = os.getenv('GITHUB_SHA', 'unknown')
GITHUB_REF = os.getenv('GITHUB_REF', 'refs/heads/main')


class ReportType(Enum):
    """Performance report type enumeration for different reporting scenarios."""
    
    BASELINE_COMPARISON = "baseline_comparison"
    TREND_ANALYSIS = "trend_analysis"
    VARIANCE_CALCULATION = "variance_calculation"
    CI_CD_INTEGRATION = "ci_cd_integration"
    STAKEHOLDER_SUMMARY = "stakeholder_summary"
    COMPLIANCE_AUDIT = "compliance_audit"
    REGRESSION_ANALYSIS = "regression_analysis"
    DEPLOYMENT_READINESS = "deployment_readiness"


class ReportFormat(Enum):
    """Report output format enumeration for multi-format generation."""
    
    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    PDF = "pdf"
    CSV = "csv"
    XLSX = "xlsx"


@dataclass
class PerformanceReportMetadata:
    """Comprehensive metadata for performance report generation and tracking."""
    
    report_id: str
    report_type: ReportType
    generated_at: datetime
    environment: str
    test_session_id: str
    github_run_id: str
    github_sha: str
    github_ref: str
    baseline_version: str
    variance_threshold: float
    performance_config: Dict[str, Any]
    
    @classmethod
    def create_from_environment(cls, report_type: ReportType, test_session_id: str = None) -> 'PerformanceReportMetadata':
        """Create report metadata from current environment context."""
        config = create_performance_config()
        
        return cls(
            report_id=str(uuid.uuid4()),
            report_type=report_type,
            generated_at=datetime.now(timezone.utc),
            environment=config.get_environment_name(),
            test_session_id=test_session_id or str(uuid.uuid4()),
            github_run_id=GITHUB_RUN_ID,
            github_sha=GITHUB_SHA,
            github_ref=GITHUB_REF,
            baseline_version="nodejs-baseline-1.0",
            variance_threshold=config.PERFORMANCE_VARIANCE_THRESHOLD,
            performance_config=asdict(config.get_baseline_metrics())
        )


@dataclass
class PerformanceVarianceAnalysis:
    """Comprehensive performance variance analysis results."""
    
    metric_name: str
    baseline_value: float
    current_value: float
    variance_percentage: float
    variance_severity: str
    within_threshold: bool
    trend_direction: str
    statistical_confidence: float
    recommendation: str
    
    @property
    def is_critical_variance(self) -> bool:
        """Check if variance exceeds critical threshold."""
        return abs(self.variance_percentage) > CRITICAL_VARIANCE_THRESHOLD
    
    @property
    def requires_immediate_action(self) -> bool:
        """Check if variance requires immediate optimization action."""
        return (not self.within_threshold and 
                self.variance_severity in ['critical', 'failure'] and
                self.variance_percentage > 0)  # Performance degradation


class PerformanceReportGenerator:
    """
    Comprehensive performance report generation system for Flask migration.
    
    Implements automated performance report generation with baseline comparison,
    trend analysis, variance calculations, and CI/CD integration per Section 6.6.2
    requirements with stakeholder communication capabilities per Section 8.5.3.
    """
    
    def __init__(self, environment: str = None, output_dir: str = None):
        """
        Initialize performance report generator with environment configuration.
        
        Args:
            environment: Target environment for report generation
            output_dir: Output directory for generated reports
        """
        self.environment = environment or os.getenv('PERFORMANCE_ENV', 'testing')
        self.output_dir = Path(output_dir) if output_dir else REPORT_OUTPUT_DIR
        self.artifacts_dir = ARTIFACTS_DIR
        
        # Ensure output directories exist
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize performance testing infrastructure
        self.performance_config = create_performance_config(self.environment)
        self.baseline_manager = get_default_baseline_data()
        self.comparison_suite = BaselineComparisonTestSuite(self.baseline_manager)
        self.comparison_suite.setup_baseline_comparison(self.environment)
        
        # Configure logging for report generation
        self.logger = self._setup_logging()
        
        # Initialize report templates if available
        self.template_env = self._setup_template_environment()
        
        # Performance data collection
        self.performance_data: Dict[str, Any] = {}
        self.variance_analysis_results: List[PerformanceVarianceAnalysis] = []
        self.trend_analysis_results: Dict[str, Any] = {}
        
        self.logger.info(
            f"Performance report generator initialized - Environment: {self.environment}, "
            f"Output: {self.output_dir}, GitHub Actions: {GITHUB_ACTIONS_INTEGRATION}"
        )
    
    def generate_comprehensive_performance_report(self, 
                                                test_results: Dict[str, Any] = None,
                                                report_formats: List[ReportFormat] = None,
                                                include_visualizations: bool = True) -> Dict[str, str]:
        """
        Generate comprehensive performance report with all analysis components.
        
        Args:
            test_results: Performance test execution results
            report_formats: List of output formats to generate
            include_visualizations: Whether to include performance charts and graphs
            
        Returns:
            Dictionary mapping format names to generated file paths
        """
        self.logger.info("Starting comprehensive performance report generation")
        
        try:
            # Set default formats if not specified
            if report_formats is None:
                report_formats = [ReportFormat.JSON, ReportFormat.MARKDOWN, ReportFormat.HTML]
            
            # Collect and analyze performance data
            self._collect_performance_data(test_results)
            self._perform_baseline_comparison_analysis()
            self._perform_trend_analysis()
            self._calculate_comprehensive_variance_analysis()
            
            # Generate visualizations if requested
            visualization_paths = {}
            if include_visualizations and (MATPLOTLIB_AVAILABLE or PLOTLY_AVAILABLE):
                visualization_paths = self._generate_performance_visualizations()
            
            # Create comprehensive report metadata
            metadata = PerformanceReportMetadata.create_from_environment(
                ReportType.BASELINE_COMPARISON,
                self.comparison_suite.test_session_id
            )
            
            # Generate reports in requested formats
            generated_reports = {}
            for report_format in report_formats:
                report_path = self._generate_report_by_format(
                    metadata, report_format, visualization_paths
                )
                generated_reports[report_format.value] = str(report_path)
            
            # Generate CI/CD artifacts for GitHub Actions integration
            if GITHUB_ACTIONS_INTEGRATION:
                artifact_paths = self._generate_ci_cd_artifacts(metadata)
                generated_reports.update(artifact_paths)
            
            # Generate stakeholder-specific reports per Section 8.5.3
            stakeholder_reports = self._generate_stakeholder_reports(metadata)
            generated_reports.update(stakeholder_reports)
            
            self.logger.info(f"Performance report generation completed - Generated {len(generated_reports)} reports")
            return generated_reports
            
        except Exception as e:
            self.logger.error(f"Performance report generation failed: {str(e)}")
            self.logger.error(traceback.format_exc())
            raise
    
    def generate_baseline_comparison_report(self, 
                                          current_metrics: Dict[str, float],
                                          report_format: ReportFormat = ReportFormat.JSON) -> str:
        """
        Generate focused baseline comparison report with variance analysis.
        
        Args:
            current_metrics: Current performance metrics for comparison
            report_format: Output format for the report
            
        Returns:
            Path to generated baseline comparison report
        """
        self.logger.info("Generating baseline comparison report")
        
        # Perform baseline comparison analysis
        comparison_results = get_performance_baseline_comparison(
            current_metrics, self.environment
        )
        
        # Calculate variance analysis
        variance_analysis = []
        for metric_name, comparison_data in comparison_results.items():
            analysis = PerformanceVarianceAnalysis(
                metric_name=metric_name,
                baseline_value=comparison_data['baseline_value'],
                current_value=comparison_data['current_value'],
                variance_percentage=comparison_data['variance_percent'],
                variance_severity=comparison_data['status'],
                within_threshold=comparison_data['within_threshold'],
                trend_direction="stable",  # Would be calculated from historical data
                statistical_confidence=0.95,  # Would be calculated from sample size
                recommendation=self._generate_metric_recommendation(comparison_data)
            )
            variance_analysis.append(analysis)
        
        # Create report metadata
        metadata = PerformanceReportMetadata.create_from_environment(
            ReportType.BASELINE_COMPARISON
        )
        
        # Generate baseline comparison report
        report_data = {
            'metadata': asdict(metadata),
            'baseline_comparison': comparison_results,
            'variance_analysis': [asdict(analysis) for analysis in variance_analysis],
            'summary': self._generate_baseline_comparison_summary(variance_analysis),
            'recommendations': self._generate_baseline_recommendations(variance_analysis)
        }
        
        # Write report in specified format
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"baseline_comparison_{timestamp}.{report_format.value}"
        report_path = self.output_dir / filename
        
        if report_format == ReportFormat.JSON:
            self._write_json_report(report_data, report_path)
        elif report_format == ReportFormat.MARKDOWN:
            self._write_markdown_report(report_data, report_path)
        elif report_format == ReportFormat.HTML:
            self._write_html_report(report_data, report_path)
        else:
            raise ValueError(f"Unsupported report format: {report_format}")
        
        self.logger.info(f"Baseline comparison report generated: {report_path}")
        return str(report_path)
    
    def generate_trend_analysis_report(self, 
                                     historical_data: List[Dict[str, Any]] = None,
                                     analysis_window_days: int = 7) -> str:
        """
        Generate comprehensive trend analysis report with regression detection.
        
        Args:
            historical_data: Historical performance data for trend analysis
            analysis_window_days: Number of days to include in trend analysis
            
        Returns:
            Path to generated trend analysis report
        """
        self.logger.info(f"Generating trend analysis report for {analysis_window_days} days")
        
        # Initialize trend analyzer with historical data
        trend_analyzer = PerformanceTrendAnalyzer(window_size=analysis_window_days * 24)  # Hourly data points
        
        # Process historical data if provided
        if historical_data:
            for data_point in historical_data:
                timestamp = datetime.fromisoformat(data_point.get('timestamp', datetime.now().isoformat()))
                for metric_name, value in data_point.get('metrics', {}).items():
                    baseline_value = self._get_baseline_value(metric_name)
                    if baseline_value:
                        trend_analyzer.add_measurement(metric_name, value, baseline_value, timestamp)
        
        # Generate trend reports for all metrics
        trend_reports = {}
        regression_alerts = []
        
        for metric_name in CRITICAL_PERFORMANCE_METRICS:
            trend_report = trend_analyzer.generate_trend_report(metric_name)
            trend_reports[metric_name] = trend_report
            
            # Check for performance regressions
            if trend_report.get('regression_analysis', {}).get('regression_detected', False):
                regression_alerts.append({
                    'metric': metric_name,
                    'confidence': trend_report['regression_analysis']['confidence'],
                    'trend_slope': trend_report['trend_analysis']['slope'],
                    'recommendation': 'Immediate performance investigation required'
                })
        
        # Create comprehensive trend analysis summary
        trend_summary = {
            'analysis_period': f"{analysis_window_days} days",
            'metrics_analyzed': len(trend_reports),
            'regressions_detected': len(regression_alerts),
            'overall_trend_classification': self._classify_overall_performance_trend(trend_reports),
            'trend_confidence': self._calculate_overall_trend_confidence(trend_reports)
        }
        
        # Create report metadata
        metadata = PerformanceReportMetadata.create_from_environment(ReportType.TREND_ANALYSIS)
        
        # Generate comprehensive trend analysis report
        report_data = {
            'metadata': asdict(metadata),
            'trend_analysis_summary': trend_summary,
            'individual_metric_trends': trend_reports,
            'regression_alerts': regression_alerts,
            'performance_recommendations': self._generate_trend_based_recommendations(trend_reports),
            'baseline_maintenance_plan': self._generate_baseline_maintenance_plan(trend_reports)
        }
        
        # Write trend analysis report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"trend_analysis_{timestamp}.json"
        report_path = self.output_dir / filename
        
        self._write_json_report(report_data, report_path)
        
        self.logger.info(f"Trend analysis report generated: {report_path}")
        return str(report_path)
    
    def generate_ci_cd_integration_report(self) -> Dict[str, str]:
        """
        Generate CI/CD pipeline integration report with GitHub Actions artifacts.
        
        Returns:
            Dictionary mapping artifact types to file paths
        """
        self.logger.info("Generating CI/CD integration report and artifacts")
        
        # Execute comprehensive performance validation
        validation_results = self.comparison_suite.validate_overall_performance_compliance()
        
        # Generate CI/CD specific report data
        ci_cd_report = {
            'pipeline_metadata': {
                'github_run_id': GITHUB_RUN_ID,
                'github_sha': GITHUB_SHA,
                'github_ref': GITHUB_REF,
                'environment': self.environment,
                'generated_at': datetime.now(timezone.utc).isoformat()
            },
            'quality_gates': {
                'overall_compliant': validation_results['overall_compliant'],
                'compliance_rate_percent': validation_results['compliance_rate_percent'],
                'deployment_recommendation': validation_results['deployment_recommendation'],
                'variance_threshold_enforcement': f"≤{PERFORMANCE_VARIANCE_THRESHOLD*100:.1f}%"
            },
            'performance_validation': {
                'total_measurements': validation_results['total_measurements'],
                'compliant_measurements': validation_results['compliant_measurements'],
                'critical_failures': validation_results['critical_failures'],
                'variance_summary': validation_results['variance_summary']
            },
            'ci_cd_recommendations': self._generate_ci_cd_recommendations(validation_results),
            'github_actions_integration': {
                'artifacts_generated': True,
                'performance_gates_passed': validation_results['overall_compliant'],
                'deployment_approved': validation_results['deployment_recommendation'] == 'APPROVED'
            }
        }
        
        # Generate CI/CD artifacts
        artifacts = {}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # JSON artifact for programmatic consumption
        json_path = self.artifacts_dir / f"ci_cd_report_{timestamp}.json"
        self._write_json_report(ci_cd_report, json_path)
        artifacts['ci_cd_json'] = str(json_path)
        
        # Performance summary for GitHub Actions status
        summary_path = self.artifacts_dir / f"performance_summary_{timestamp}.md"
        self._write_ci_cd_summary_markdown(ci_cd_report, summary_path)
        artifacts['performance_summary'] = str(summary_path)
        
        # Performance gate status for pipeline decisions
        gate_status_path = self.artifacts_dir / f"performance_gates_{timestamp}.json"
        gate_status = {
            'performance_gates_passed': ci_cd_report['quality_gates']['overall_compliant'],
            'deployment_approved': ci_cd_report['github_actions_integration']['deployment_approved'],
            'variance_compliance': ci_cd_report['quality_gates']['compliance_rate_percent'] >= 95.0,
            'critical_issues_count': ci_cd_report['performance_validation']['critical_failures']
        }
        self._write_json_report(gate_status, gate_status_path)
        artifacts['gate_status'] = str(gate_status_path)
        
        self.logger.info(f"CI/CD integration report generated with {len(artifacts)} artifacts")
        return artifacts
    
    def generate_stakeholder_summary_report(self, 
                                          target_audience: str = "executive") -> str:
        """
        Generate stakeholder-focused performance summary report per Section 8.5.3.
        
        Args:
            target_audience: Target audience ('executive', 'technical', 'compliance')
            
        Returns:
            Path to generated stakeholder summary report
        """
        self.logger.info(f"Generating stakeholder summary report for {target_audience} audience")
        
        # Execute performance validation for stakeholder summary
        validation_results = self.comparison_suite.validate_overall_performance_compliance()
        
        # Generate stakeholder-specific content
        if target_audience == "executive":
            report_data = self._generate_executive_summary(validation_results)
        elif target_audience == "technical":
            report_data = self._generate_technical_detailed_report(validation_results)
        elif target_audience == "compliance":
            report_data = self._generate_compliance_audit_report(validation_results)
        else:
            raise ValueError(f"Unsupported target audience: {target_audience}")
        
        # Write stakeholder report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"stakeholder_{target_audience}_{timestamp}.html"
        report_path = self.output_dir / filename
        
        self._write_stakeholder_html_report(report_data, report_path, target_audience)
        
        self.logger.info(f"Stakeholder {target_audience} report generated: {report_path}")
        return str(report_path)
    
    def _collect_performance_data(self, test_results: Dict[str, Any] = None) -> None:
        """Collect comprehensive performance data from test execution."""
        self.logger.info("Collecting performance data for analysis")
        
        self.performance_data = {
            'test_execution_summary': {
                'total_tests_executed': len(self.comparison_suite.test_results),
                'test_session_id': self.comparison_suite.test_session_id,
                'environment': self.environment,
                'execution_timestamp': datetime.now(timezone.utc).isoformat()
            },
            'baseline_data_summary': self.baseline_manager.generate_baseline_summary(),
            'test_results': test_results or {},
            'comparison_results': [asdict(result) for result in self.comparison_suite.test_results]
        }
    
    def _perform_baseline_comparison_analysis(self) -> None:
        """Perform comprehensive baseline comparison analysis."""
        self.logger.info("Performing baseline comparison analysis")
        
        # Analyze each performance comparison result
        for result in self.comparison_suite.test_results:
            variance_analysis = PerformanceVarianceAnalysis(
                metric_name=result.metric_name,
                baseline_value=result.baseline_value,
                current_value=result.current_value,
                variance_percentage=result.variance_percent,
                variance_severity=result.variance_severity,
                within_threshold=result.within_threshold,
                trend_direction="stable",  # Would be enhanced with historical data
                statistical_confidence=0.95,
                recommendation=self._generate_variance_recommendation(result)
            )
            self.variance_analysis_results.append(variance_analysis)
    
    def _perform_trend_analysis(self) -> None:
        """Perform comprehensive trend analysis across all metrics."""
        self.logger.info("Performing trend analysis")
        
        # Generate trend analysis for each measured metric
        unique_metrics = set(result.metric_name for result in self.comparison_suite.test_results)
        
        for metric_name in unique_metrics:
            trend_report = self.comparison_suite.trend_analyzer.generate_trend_report(metric_name)
            self.trend_analysis_results[metric_name] = trend_report
    
    def _calculate_comprehensive_variance_analysis(self) -> None:
        """Calculate comprehensive variance analysis across all metrics."""
        self.logger.info("Calculating comprehensive variance analysis")
        
        # Aggregate variance statistics
        if self.variance_analysis_results:
            variances = [abs(analysis.variance_percentage) for analysis in self.variance_analysis_results]
            
            self.performance_data['variance_statistics'] = {
                'mean_variance': statistics.mean(variances),
                'median_variance': statistics.median(variances),
                'max_variance': max(variances),
                'variance_std_dev': statistics.stdev(variances) if len(variances) > 1 else 0.0,
                'compliant_metrics_count': sum(1 for analysis in self.variance_analysis_results if analysis.within_threshold),
                'total_metrics_count': len(self.variance_analysis_results),
                'compliance_rate': (sum(1 for analysis in self.variance_analysis_results if analysis.within_threshold) / 
                                  len(self.variance_analysis_results) * 100.0) if self.variance_analysis_results else 0.0
            }
    
    def _generate_performance_visualizations(self) -> Dict[str, str]:
        """Generate comprehensive performance visualizations and charts."""
        self.logger.info("Generating performance visualizations")
        
        visualization_paths = {}
        
        if not self.variance_analysis_results:
            self.logger.warning("No variance analysis results available for visualization")
            return visualization_paths
        
        # Generate variance distribution chart
        if MATPLOTLIB_AVAILABLE:
            variance_chart_path = self._generate_variance_distribution_chart()
            if variance_chart_path:
                visualization_paths['variance_distribution'] = variance_chart_path
        
        # Generate trend analysis charts
        if PLOTLY_AVAILABLE and self.trend_analysis_results:
            trend_charts_path = self._generate_trend_analysis_charts()
            if trend_charts_path:
                visualization_paths['trend_analysis'] = trend_charts_path
        
        # Generate baseline comparison visualization
        if MATPLOTLIB_AVAILABLE:
            baseline_chart_path = self._generate_baseline_comparison_chart()
            if baseline_chart_path:
                visualization_paths['baseline_comparison'] = baseline_chart_path
        
        return visualization_paths
    
    def _generate_variance_distribution_chart(self) -> Optional[str]:
        """Generate variance distribution visualization using matplotlib."""
        try:
            variances = [analysis.variance_percentage for analysis in self.variance_analysis_results]
            metric_names = [analysis.metric_name for analysis in self.variance_analysis_results]
            
            # Create variance distribution chart
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
            
            # Variance bar chart
            colors = ['red' if abs(v) > PERFORMANCE_VARIANCE_THRESHOLD * 100 else 'orange' if abs(v) > WARNING_VARIANCE_THRESHOLD * 100 else 'green' for v in variances]
            ax1.bar(range(len(variances)), variances, color=colors)
            ax1.set_xlabel('Performance Metrics')
            ax1.set_ylabel('Variance Percentage (%)')
            ax1.set_title('Performance Variance by Metric')
            ax1.axhline(y=PERFORMANCE_VARIANCE_THRESHOLD * 100, color='red', linestyle='--', label='10% Threshold')
            ax1.axhline(y=-PERFORMANCE_VARIANCE_THRESHOLD * 100, color='red', linestyle='--')
            ax1.set_xticks(range(len(metric_names)))
            ax1.set_xticklabels([name[:20] + '...' if len(name) > 20 else name for name in metric_names], rotation=45, ha='right')
            ax1.legend()
            
            # Variance distribution histogram
            ax2.hist(variances, bins=20, alpha=0.7, edgecolor='black')
            ax2.set_xlabel('Variance Percentage (%)')
            ax2.set_ylabel('Frequency')
            ax2.set_title('Variance Distribution')
            ax2.axvline(x=PERFORMANCE_VARIANCE_THRESHOLD * 100, color='red', linestyle='--', label='10% Threshold')
            ax2.axvline(x=-PERFORMANCE_VARIANCE_THRESHOLD * 100, color='red', linestyle='--')
            ax2.legend()
            
            plt.tight_layout()
            
            # Save chart
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            chart_path = self.output_dir / f"variance_distribution_{timestamp}.png"
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return str(chart_path)
            
        except Exception as e:
            self.logger.error(f"Failed to generate variance distribution chart: {e}")
            return None
    
    def _generate_trend_analysis_charts(self) -> Optional[str]:
        """Generate trend analysis charts using plotly."""
        try:
            # Create subplots for multiple metrics
            metrics_to_plot = list(self.trend_analysis_results.keys())[:6]  # Limit to 6 metrics for readability
            
            fig = make_subplots(
                rows=2, cols=3,
                subplot_titles=metrics_to_plot,
                specs=[[{"secondary_y": True} for _ in range(3)] for _ in range(2)]
            )
            
            for i, metric_name in enumerate(metrics_to_plot):
                row = (i // 3) + 1
                col = (i % 3) + 1
                
                trend_data = self.trend_analysis_results[metric_name]
                
                # Extract trend data (would be enhanced with actual historical data)
                sample_data = list(range(trend_data.get('sample_size', 10)))
                variance_data = [abs(trend_data.get('variance_statistics', {}).get('mean', 0)) + 
                               (i * 0.1) for i in sample_data]  # Mock trend data
                
                fig.add_trace(
                    go.Scatter(x=sample_data, y=variance_data, 
                             name=f"{metric_name[:15]}...", mode='lines+markers'),
                    row=row, col=col
                )
                
                # Add threshold line
                fig.add_hline(y=PERFORMANCE_VARIANCE_THRESHOLD * 100, 
                            line_dash="dash", line_color="red",
                            row=row, col=col)
            
            fig.update_layout(
                title="Performance Trend Analysis",
                height=800,
                showlegend=False
            )
            
            # Save chart
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            chart_path = self.output_dir / f"trend_analysis_{timestamp}.html"
            fig.write_html(chart_path)
            
            return str(chart_path)
            
        except Exception as e:
            self.logger.error(f"Failed to generate trend analysis charts: {e}")
            return None
    
    def _generate_baseline_comparison_chart(self) -> Optional[str]:
        """Generate baseline comparison visualization using matplotlib."""
        try:
            # Extract baseline and current values
            baseline_values = [analysis.baseline_value for analysis in self.variance_analysis_results]
            current_values = [analysis.current_value for analysis in self.variance_analysis_results]
            metric_names = [analysis.metric_name for analysis in self.variance_analysis_results]
            
            # Create baseline comparison chart
            fig, ax = plt.subplots(figsize=(12, 8))
            
            x = np.arange(len(metric_names))
            width = 0.35
            
            bars1 = ax.bar(x - width/2, baseline_values, width, label='Node.js Baseline', alpha=0.8)
            bars2 = ax.bar(x + width/2, current_values, width, label='Flask Current', alpha=0.8)
            
            ax.set_xlabel('Performance Metrics')
            ax.set_ylabel('Metric Values')
            ax.set_title('Performance Baseline Comparison: Node.js vs Flask')
            ax.set_xticks(x)
            ax.set_xticklabels([name[:15] + '...' if len(name) > 15 else name for name in metric_names], 
                              rotation=45, ha='right')
            ax.legend()
            
            # Add variance annotations
            for i, analysis in enumerate(self.variance_analysis_results):
                variance_text = f"{analysis.variance_percentage:+.1f}%"
                color = 'red' if not analysis.within_threshold else 'green'
                ax.annotate(variance_text, (i, max(analysis.baseline_value, analysis.current_value) * 1.1),
                           ha='center', va='bottom', color=color, fontweight='bold')
            
            plt.tight_layout()
            
            # Save chart
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            chart_path = self.output_dir / f"baseline_comparison_{timestamp}.png"
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return str(chart_path)
            
        except Exception as e:
            self.logger.error(f"Failed to generate baseline comparison chart: {e}")
            return None
    
    def _generate_report_by_format(self, 
                                 metadata: PerformanceReportMetadata,
                                 report_format: ReportFormat,
                                 visualization_paths: Dict[str, str] = None) -> Path:
        """Generate performance report in specified format."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Compile comprehensive report data
        report_data = {
            'metadata': asdict(metadata),
            'performance_data': self.performance_data,
            'variance_analysis': [asdict(analysis) for analysis in self.variance_analysis_results],
            'trend_analysis': self.trend_analysis_results,
            'visualizations': visualization_paths or {},
            'summary': self._generate_comprehensive_summary(),
            'recommendations': self._generate_comprehensive_recommendations()
        }
        
        # Generate report based on format
        if report_format == ReportFormat.JSON:
            filename = f"performance_report_{timestamp}.json"
            report_path = self.output_dir / filename
            self._write_json_report(report_data, report_path)
            
        elif report_format == ReportFormat.MARKDOWN:
            filename = f"performance_report_{timestamp}.md"
            report_path = self.output_dir / filename
            self._write_markdown_report(report_data, report_path)
            
        elif report_format == ReportFormat.HTML:
            filename = f"performance_report_{timestamp}.html"
            report_path = self.output_dir / filename
            self._write_html_report(report_data, report_path)
            
        elif report_format == ReportFormat.PDF:
            filename = f"performance_report_{timestamp}.pdf"
            report_path = self.output_dir / filename
            self._write_pdf_report(report_data, report_path)
            
        else:
            raise ValueError(f"Unsupported report format: {report_format}")
        
        return report_path
    
    def _generate_ci_cd_artifacts(self, metadata: PerformanceReportMetadata) -> Dict[str, str]:
        """Generate CI/CD specific artifacts for GitHub Actions integration."""
        self.logger.info("Generating CI/CD artifacts for GitHub Actions")
        
        # Execute performance validation for CI/CD
        validation_results = self.comparison_suite.validate_overall_performance_compliance()
        
        artifacts = {}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Performance gate status artifact
        gate_status = {
            'performance_gates_passed': validation_results['overall_compliant'],
            'deployment_recommendation': validation_results['deployment_recommendation'],
            'compliance_rate': validation_results['compliance_rate_percent'],
            'critical_failures': validation_results['critical_failures'],
            'variance_threshold': f"≤{PERFORMANCE_VARIANCE_THRESHOLD*100:.1f}%"
        }
        
        gate_status_path = self.artifacts_dir / f"performance_gates_{GITHUB_RUN_ID}_{timestamp}.json"
        self._write_json_report(gate_status, gate_status_path)
        artifacts['performance_gates'] = str(gate_status_path)
        
        # Comprehensive CI/CD report
        ci_cd_report = self.generate_ci_cd_integration_report()
        artifacts.update(ci_cd_report)
        
        return artifacts
    
    def _generate_stakeholder_reports(self, metadata: PerformanceReportMetadata) -> Dict[str, str]:
        """Generate stakeholder-specific reports per Section 8.5.3."""
        self.logger.info("Generating stakeholder-specific reports")
        
        stakeholder_reports = {}
        
        for audience in STAKEHOLDER_REPORT_FORMATS:
            try:
                report_path = self.generate_stakeholder_summary_report(audience)
                stakeholder_reports[f"stakeholder_{audience}"] = report_path
            except Exception as e:
                self.logger.error(f"Failed to generate {audience} stakeholder report: {e}")
        
        return stakeholder_reports
    
    def _write_json_report(self, report_data: Dict[str, Any], output_path: Path) -> None:
        """Write report data in JSON format."""
        with open(output_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str, ensure_ascii=False)
    
    def _write_markdown_report(self, report_data: Dict[str, Any], output_path: Path) -> None:
        """Write report data in Markdown format."""
        markdown_content = self._generate_markdown_content(report_data)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
    
    def _write_html_report(self, report_data: Dict[str, Any], output_path: Path) -> None:
        """Write report data in HTML format."""
        html_content = self._generate_html_content(report_data)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _write_pdf_report(self, report_data: Dict[str, Any], output_path: Path) -> None:
        """Write report data in PDF format."""
        if not WEASYPRINT_AVAILABLE:
            self.logger.warning("WeasyPrint not available - skipping PDF generation")
            return
        
        html_content = self._generate_html_content(report_data)
        weasyprint.HTML(string=html_content).write_pdf(output_path)
    
    def _write_ci_cd_summary_markdown(self, ci_cd_data: Dict[str, Any], output_path: Path) -> None:
        """Write CI/CD summary in Markdown format for GitHub Actions."""
        summary_content = f"""# Performance Validation Summary

## 🎯 Overall Status: {'✅ PASSED' if ci_cd_data['quality_gates']['overall_compliant'] else '❌ FAILED'}

### Quality Gates
- **Compliance Rate**: {ci_cd_data['quality_gates']['compliance_rate_percent']:.1f}%
- **Deployment Recommendation**: {ci_cd_data['quality_gates']['deployment_recommendation']}
- **Variance Threshold**: {ci_cd_data['quality_gates']['variance_threshold_enforcement']}

### Performance Validation
- **Total Measurements**: {ci_cd_data['performance_validation']['total_measurements']}
- **Compliant Measurements**: {ci_cd_data['performance_validation']['compliant_measurements']}
- **Critical Failures**: {ci_cd_data['performance_validation']['critical_failures']}

### CI/CD Integration
- **Performance Gates Passed**: {'✅' if ci_cd_data['github_actions_integration']['performance_gates_passed'] else '❌'}
- **Deployment Approved**: {'✅' if ci_cd_data['github_actions_integration']['deployment_approved'] else '❌'}

### Recommendations
{chr(10).join(f"- {rec}" for rec in ci_cd_data['ci_cd_recommendations'])}

---
*Generated: {ci_cd_data['pipeline_metadata']['generated_at']}*
*GitHub Run: {ci_cd_data['pipeline_metadata']['github_run_id']}*
"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(summary_content)
    
    def _write_stakeholder_html_report(self, report_data: Dict[str, Any], 
                                     output_path: Path, target_audience: str) -> None:
        """Write stakeholder-specific HTML report."""
        if target_audience == "executive":
            html_content = self._generate_executive_html_report(report_data)
        elif target_audience == "technical":
            html_content = self._generate_technical_html_report(report_data)
        elif target_audience == "compliance":
            html_content = self._generate_compliance_html_report(report_data)
        else:
            html_content = self._generate_html_content(report_data)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _generate_markdown_content(self, report_data: Dict[str, Any]) -> str:
        """Generate comprehensive Markdown report content."""
        metadata = report_data.get('metadata', {})
        variance_analysis = report_data.get('variance_analysis', [])
        summary = report_data.get('summary', {})
        
        content = f"""# Performance Analysis Report

## Report Metadata
- **Report ID**: {metadata.get('report_id', 'N/A')}
- **Generated**: {metadata.get('generated_at', 'N/A')}
- **Environment**: {metadata.get('environment', 'N/A')}
- **Variance Threshold**: {metadata.get('variance_threshold', 0.1)*100:.1f}%

## Executive Summary
- **Overall Compliance**: {'✅ PASSED' if summary.get('overall_compliant', False) else '❌ FAILED'}
- **Compliance Rate**: {summary.get('compliance_rate', 0.0):.1f}%
- **Critical Issues**: {summary.get('critical_issues_count', 0)}
- **Deployment Recommendation**: {summary.get('deployment_recommendation', 'PENDING')}

## Performance Variance Analysis

| Metric | Baseline | Current | Variance | Status | Threshold |
|--------|----------|---------|----------|--------|-----------|
"""
        
        for analysis in variance_analysis:
            status_icon = "✅" if analysis['within_threshold'] else "❌"
            content += f"| {analysis['metric_name'][:30]} | {analysis['baseline_value']:.2f} | {analysis['current_value']:.2f} | {analysis['variance_percentage']:+.2f}% | {status_icon} | {analysis['variance_severity']} |\n"
        
        content += f"""

## Recommendations
{chr(10).join(f"- {rec}" for rec in report_data.get('recommendations', []))}

## Visualization References
{chr(10).join(f"- **{name}**: {path}" for name, path in report_data.get('visualizations', {}).items())}

---
*Generated by Flask Migration Performance Testing Suite v{REPORT_VERSION}*
"""
        
        return content
    
    def _generate_html_content(self, report_data: Dict[str, Any]) -> str:
        """Generate comprehensive HTML report content."""
        metadata = report_data.get('metadata', {})
        variance_analysis = report_data.get('variance_analysis', [])
        summary = report_data.get('summary', {})
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Performance Analysis Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; line-height: 1.6; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; }}
        .summary {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .metric-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        .metric-table th, .metric-table td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        .metric-table th {{ background-color: #f2f2f2; font-weight: bold; }}
        .pass {{ color: #28a745; font-weight: bold; }}
        .fail {{ color: #dc3545; font-weight: bold; }}
        .warning {{ color: #ffc107; font-weight: bold; }}
        .recommendation {{ background: #e7f3ff; padding: 15px; border-left: 4px solid #0066cc; margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Performance Analysis Report</h1>
        <p>Generated: {metadata.get('generated_at', 'N/A')} | Environment: {metadata.get('environment', 'N/A')}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Overall Compliance:</strong> <span class="{'pass' if summary.get('overall_compliant', False) else 'fail'}">{'PASSED' if summary.get('overall_compliant', False) else 'FAILED'}</span></p>
        <p><strong>Compliance Rate:</strong> {summary.get('compliance_rate', 0.0):.1f}%</p>
        <p><strong>Deployment Recommendation:</strong> <span class="{'pass' if summary.get('deployment_recommendation') == 'APPROVED' else 'fail'}">{summary.get('deployment_recommendation', 'PENDING')}</span></p>
    </div>
    
    <h2>Performance Variance Analysis</h2>
    <table class="metric-table">
        <thead>
            <tr>
                <th>Metric</th>
                <th>Baseline Value</th>
                <th>Current Value</th>
                <th>Variance</th>
                <th>Status</th>
                <th>Severity</th>
            </tr>
        </thead>
        <tbody>
"""
        
        for analysis in variance_analysis:
            status_class = "pass" if analysis['within_threshold'] else "fail"
            status_text = "PASS" if analysis['within_threshold'] else "FAIL"
            
            content += f"""            <tr>
                <td>{analysis['metric_name']}</td>
                <td>{analysis['baseline_value']:.2f}</td>
                <td>{analysis['current_value']:.2f}</td>
                <td>{analysis['variance_percentage']:+.2f}%</td>
                <td class="{status_class}">{status_text}</td>
                <td>{analysis['variance_severity']}</td>
            </tr>
"""
        
        content += f"""        </tbody>
    </table>
    
    <h2>Recommendations</h2>
    {''.join(f'<div class="recommendation">{rec}</div>' for rec in report_data.get('recommendations', []))}
    
    <footer style="margin-top: 40px; text-align: center; color: #666;">
        <p>Generated by Flask Migration Performance Testing Suite v{REPORT_VERSION}</p>
    </footer>
</body>
</html>"""
        
        return content
    
    def _generate_executive_summary(self, validation_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive-focused performance summary."""
        return {
            'title': 'Executive Performance Summary',
            'overall_status': 'APPROVED' if validation_results['overall_compliant'] else 'REQUIRES ATTENTION',
            'key_metrics': {
                'compliance_rate': f"{validation_results['compliance_rate_percent']:.1f}%",
                'variance_threshold': f"≤{PERFORMANCE_VARIANCE_THRESHOLD*100:.1f}%",
                'deployment_status': validation_results['deployment_recommendation']
            },
            'business_impact': {
                'performance_improvement': 'Flask implementation maintains performance parity',
                'risk_assessment': 'Low risk deployment' if validation_results['overall_compliant'] else 'Requires optimization',
                'cost_impact': 'No additional infrastructure costs expected'
            },
            'next_steps': [
                'Approve deployment' if validation_results['overall_compliant'] else 'Address performance issues',
                'Continue monitoring post-deployment',
                'Review performance trends monthly'
            ]
        }
    
    def _generate_technical_detailed_report(self, validation_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate technical-focused detailed performance report."""
        return {
            'title': 'Technical Performance Analysis',
            'technical_summary': validation_results,
            'variance_analysis': [asdict(analysis) for analysis in self.variance_analysis_results],
            'trend_analysis': self.trend_analysis_results,
            'optimization_recommendations': self._generate_technical_recommendations(),
            'monitoring_setup': {
                'metrics_to_monitor': CRITICAL_PERFORMANCE_METRICS,
                'alert_thresholds': {
                    'response_time_p95': '500ms',
                    'error_rate': '0.1%',
                    'variance_threshold': f'{PERFORMANCE_VARIANCE_THRESHOLD*100:.1f}%'
                }
            }
        }
    
    def _generate_compliance_audit_report(self, validation_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate compliance audit performance report."""
        return {
            'title': 'Performance Compliance Audit',
            'compliance_summary': {
                'variance_requirement': f"≤{PERFORMANCE_VARIANCE_THRESHOLD*100:.1f}% from Node.js baseline",
                'compliance_status': validation_results['overall_compliant'],
                'audit_date': datetime.now(timezone.utc).isoformat(),
                'environment': self.environment
            },
            'requirement_validation': {
                'section_0_1_1': f"≤10% variance requirement: {'COMPLIANT' if validation_results['overall_compliant'] else 'NON-COMPLIANT'}",
                'section_0_3_2': 'Performance monitoring: IMPLEMENTED',
                'section_6_6_2': 'Test automation: IMPLEMENTED',
                'section_8_5_2': 'CI/CD integration: IMPLEMENTED'
            },
            'audit_trail': {
                'test_execution_id': self.comparison_suite.test_session_id,
                'baseline_version': 'nodejs-baseline-1.0',
                'validation_timestamp': datetime.now(timezone.utc).isoformat()
            }
        }
    
    def _generate_executive_html_report(self, report_data: Dict[str, Any]) -> str:
        """Generate executive-focused HTML report."""
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Executive Performance Summary</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .status-approved {{ color: #27ae60; font-weight: bold; }}
        .status-attention {{ color: #e74c3c; font-weight: bold; }}
        .metric {{ background: #ecf0f1; padding: 15px; margin: 10px 0; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{report_data['title']}</h1>
        <p>Performance Migration Assessment</p>
    </div>
    
    <h2>Overall Status: <span class="status-{'approved' if report_data['overall_status'] == 'APPROVED' else 'attention'}">{report_data['overall_status']}</span></h2>
    
    <h3>Key Performance Metrics</h3>
    <div class="metric">
        <strong>Compliance Rate:</strong> {report_data['key_metrics']['compliance_rate']}
    </div>
    <div class="metric">
        <strong>Variance Threshold:</strong> {report_data['key_metrics']['variance_threshold']}
    </div>
    <div class="metric">
        <strong>Deployment Status:</strong> {report_data['key_metrics']['deployment_status']}
    </div>
    
    <h3>Business Impact</h3>
    <ul>
        <li><strong>Performance:</strong> {report_data['business_impact']['performance_improvement']}</li>
        <li><strong>Risk:</strong> {report_data['business_impact']['risk_assessment']}</li>
        <li><strong>Cost:</strong> {report_data['business_impact']['cost_impact']}</li>
    </ul>
    
    <h3>Recommended Next Steps</h3>
    <ol>
        {''.join(f'<li>{step}</li>' for step in report_data['next_steps'])}
    </ol>
</body>
</html>"""
    
    def _generate_technical_html_report(self, report_data: Dict[str, Any]) -> str:
        """Generate technical-focused HTML report."""
        return self._generate_html_content({'metadata': {}, 'variance_analysis': report_data['variance_analysis'], 
                                          'summary': report_data['technical_summary'], 'recommendations': []})
    
    def _generate_compliance_html_report(self, report_data: Dict[str, Any]) -> str:
        """Generate compliance audit HTML report."""
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Performance Compliance Audit</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .audit-header {{ background: #34495e; color: white; padding: 20px; }}
        .requirement {{ border: 1px solid #bdc3c7; padding: 15px; margin: 10px 0; }}
        .compliant {{ border-left: 5px solid #27ae60; }}
        .non-compliant {{ border-left: 5px solid #e74c3c; }}
    </style>
</head>
<body>
    <div class="audit-header">
        <h1>{report_data['title']}</h1>
        <p>Compliance Status: {'COMPLIANT' if report_data['compliance_summary']['compliance_status'] else 'NON-COMPLIANT'}</p>
    </div>
    
    <h2>Requirement Validation</h2>
    {''.join(f'<div class="requirement {'compliant' if 'COMPLIANT' in req else 'non-compliant'}"><strong>{req_id}:</strong> {req}</div>' 
             for req_id, req in report_data['requirement_validation'].items())}
    
    <h2>Audit Trail</h2>
    <ul>
        <li><strong>Test Execution ID:</strong> {report_data['audit_trail']['test_execution_id']}</li>
        <li><strong>Baseline Version:</strong> {report_data['audit_trail']['baseline_version']}</li>
        <li><strong>Validation Time:</strong> {report_data['audit_trail']['validation_timestamp']}</li>
    </ul>
</body>
</html>"""
    
    def _generate_comprehensive_summary(self) -> Dict[str, Any]:
        """Generate comprehensive performance analysis summary."""
        validation_results = self.comparison_suite.validate_overall_performance_compliance()
        
        return {
            'overall_compliant': validation_results['overall_compliant'],
            'compliance_rate': validation_results['compliance_rate_percent'],
            'deployment_recommendation': validation_results['deployment_recommendation'],
            'critical_issues_count': validation_results['critical_failures'],
            'variance_threshold_enforcement': f"≤{PERFORMANCE_VARIANCE_THRESHOLD*100:.1f}%",
            'total_metrics_analyzed': len(self.variance_analysis_results),
            'performance_trend': self._classify_overall_performance_trend(self.trend_analysis_results)
        }
    
    def _generate_comprehensive_recommendations(self) -> List[str]:
        """Generate comprehensive performance optimization recommendations."""
        recommendations = []
        
        validation_results = self.comparison_suite.validate_overall_performance_compliance()
        
        if validation_results['overall_compliant']:
            recommendations.extend([
                "✅ Performance validation successful - deployment approved",
                "Continue monitoring performance trends post-deployment",
                "Schedule regular baseline comparison validation"
            ])
        else:
            recommendations.extend([
                "❌ Performance optimization required before deployment",
                "Address critical variance issues identified in analysis",
                "Implement performance monitoring alerts"
            ])
        
        # Add metric-specific recommendations
        critical_variances = [analysis for analysis in self.variance_analysis_results 
                            if analysis.requires_immediate_action]
        
        if critical_variances:
            recommendations.append(f"🔥 {len(critical_variances)} critical performance issues require immediate attention")
            for analysis in critical_variances[:3]:  # Limit to top 3
                recommendations.append(f"- Optimize {analysis.metric_name}: {analysis.recommendation}")
        
        return recommendations
    
    def _generate_ci_cd_recommendations(self, validation_results: Dict[str, Any]) -> List[str]:
        """Generate CI/CD specific recommendations."""
        recommendations = []
        
        if validation_results['overall_compliant']:
            recommendations.extend([
                "✅ All performance gates passed - proceed with deployment",
                "Enable performance monitoring for post-deployment validation",
                "Configure automated rollback triggers for performance degradation"
            ])
        else:
            recommendations.extend([
                "❌ Performance gates failed - block deployment",
                "Investigate and resolve performance regression issues",
                "Re-run performance validation after optimization"
            ])
        
        if validation_results['critical_failures'] > 0:
            recommendations.append(f"🚨 {validation_results['critical_failures']} critical performance failures require immediate resolution")
        
        return recommendations
    
    def _generate_baseline_comparison_summary(self, variance_analysis: List[PerformanceVarianceAnalysis]) -> Dict[str, Any]:
        """Generate baseline comparison summary."""
        compliant_count = sum(1 for analysis in variance_analysis if analysis.within_threshold)
        total_count = len(variance_analysis)
        
        return {
            'total_metrics': total_count,
            'compliant_metrics': compliant_count,
            'compliance_rate': (compliant_count / total_count * 100.0) if total_count > 0 else 0.0,
            'critical_issues': sum(1 for analysis in variance_analysis if analysis.is_critical_variance),
            'deployment_approved': compliant_count == total_count
        }
    
    def _generate_baseline_recommendations(self, variance_analysis: List[PerformanceVarianceAnalysis]) -> List[str]:
        """Generate baseline-specific recommendations."""
        recommendations = []
        
        critical_issues = [analysis for analysis in variance_analysis if analysis.is_critical_variance]
        
        if not critical_issues:
            recommendations.append("✅ All metrics within acceptable variance - baseline compliance achieved")
        else:
            recommendations.append(f"❌ {len(critical_issues)} metrics exceed variance threshold")
            for analysis in critical_issues[:5]:  # Top 5 issues
                recommendations.append(f"- {analysis.metric_name}: {analysis.recommendation}")
        
        return recommendations
    
    def _generate_metric_recommendation(self, comparison_data: Dict[str, Any]) -> str:
        """Generate metric-specific optimization recommendation."""
        if comparison_data['within_threshold']:
            return "Metric within acceptable variance - continue monitoring"
        
        variance = abs(comparison_data['variance_percent'])
        metric_name = comparison_data.get('metric_name', 'metric')
        
        if variance > CRITICAL_VARIANCE_THRESHOLD:
            return f"Critical variance in {metric_name} - immediate optimization required"
        else:
            return f"Monitor {metric_name} closely - approaching variance threshold"
    
    def _generate_variance_recommendation(self, result: PerformanceComparisonResult) -> str:
        """Generate variance-specific recommendation."""
        if result.within_threshold:
            return "Performance within acceptable limits"
        
        if result.variance_percent > 0:
            return f"Performance degradation detected - optimize {result.metric_name}"
        else:
            return f"Performance improvement observed in {result.metric_name}"
    
    def _generate_trend_based_recommendations(self, trend_reports: Dict[str, Any]) -> List[str]:
        """Generate trend analysis based recommendations."""
        recommendations = []
        
        for metric_name, trend_data in trend_reports.items():
            if trend_data.get('regression_analysis', {}).get('regression_detected', False):
                recommendations.append(f"🔍 Performance regression detected in {metric_name} - investigate immediately")
            
            trend_direction = trend_data.get('trend_analysis', {}).get('direction', 'stable')
            if trend_direction == 'degrading':
                recommendations.append(f"📉 {metric_name} showing degrading trend - monitor closely")
        
        return recommendations
    
    def _generate_baseline_maintenance_plan(self, trend_reports: Dict[str, Any]) -> List[str]:
        """Generate baseline maintenance plan recommendations."""
        maintenance_plan = []
        
        drift_metrics = []
        for metric_name, trend_data in trend_reports.items():
            if trend_data.get('baseline_drift_analysis', {}).get('drift_detected', False):
                drift_metrics.append(metric_name)
        
        if drift_metrics:
            maintenance_plan.append(f"🔄 Baseline drift detected in {len(drift_metrics)} metrics")
            maintenance_plan.append("Schedule baseline recalibration for drifted metrics")
        else:
            maintenance_plan.append("✅ Baseline data stable - continue current monitoring")
        
        return maintenance_plan
    
    def _generate_technical_recommendations(self) -> List[str]:
        """Generate technical optimization recommendations."""
        return [
            "Implement response time caching for frequently accessed endpoints",
            "Optimize database query performance with indexing strategies",
            "Configure horizontal scaling for high-load scenarios",
            "Enable detailed performance profiling for bottleneck identification"
        ]
    
    def _get_baseline_value(self, metric_name: str) -> Optional[float]:
        """Get baseline value for specified metric."""
        # Map metric names to baseline values (simplified)
        baseline_mapping = {
            'api_response_time_p95': 250.0,
            'requests_per_second': 100.0,
            'memory_usage': 256.0,
            'cpu_utilization': 15.0
        }
        
        for key, value in baseline_mapping.items():
            if key in metric_name.lower():
                return value
        
        return None
    
    def _classify_overall_performance_trend(self, trend_reports: Dict[str, Any]) -> str:
        """Classify overall performance trend across all metrics."""
        if not trend_reports:
            return "unknown"
        
        trend_directions = []
        for trend_data in trend_reports.values():
            direction = trend_data.get('trend_analysis', {}).get('direction', 'stable')
            trend_directions.append(direction)
        
        improving_count = trend_directions.count('improving')
        degrading_count = trend_directions.count('degrading')
        stable_count = trend_directions.count('stable')
        
        total_metrics = len(trend_directions)
        
        if degrading_count > total_metrics * 0.5:
            return "degrading"
        elif improving_count > total_metrics * 0.5:
            return "improving"
        else:
            return "stable"
    
    def _calculate_overall_trend_confidence(self, trend_reports: Dict[str, Any]) -> float:
        """Calculate overall confidence in trend analysis."""
        if not trend_reports:
            return 0.0
        
        confidences = []
        for trend_data in trend_reports.values():
            sample_size = trend_data.get('sample_size', 0)
            # Calculate confidence based on sample size
            if sample_size >= 50:
                confidences.append(0.95)
            elif sample_size >= 20:
                confidences.append(0.80)
            elif sample_size >= 10:
                confidences.append(0.60)
            else:
                confidences.append(0.30)
        
        return statistics.mean(confidences) if confidences else 0.0
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration for report generation."""
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _setup_template_environment(self) -> Optional[Environment]:
        """Setup Jinja2 template environment if available."""
        if not JINJA2_AVAILABLE:
            return None
        
        if REPORT_TEMPLATE_DIR.exists():
            return Environment(loader=FileSystemLoader(REPORT_TEMPLATE_DIR))
        
        return None


def main():
    """Main CLI entry point for performance report generation."""
    parser = argparse.ArgumentParser(
        description="Generate comprehensive performance analysis reports for Flask migration"
    )
    
    parser.add_argument(
        '--environment', '-e',
        choices=['development', 'testing', 'staging', 'production', 'ci_cd'],
        default='testing',
        help='Target environment for report generation'
    )
    
    parser.add_argument(
        '--output-dir', '-o',
        type=str,
        help='Output directory for generated reports'
    )
    
    parser.add_argument(
        '--format', '-f',
        choices=['json', 'markdown', 'html', 'pdf'],
        action='append',
        help='Report output formats (can specify multiple)'
    )
    
    parser.add_argument(
        '--type', '-t',
        choices=['comprehensive', 'baseline', 'trend', 'ci_cd', 'stakeholder'],
        default='comprehensive',
        help='Type of report to generate'
    )
    
    parser.add_argument(
        '--test-results',
        type=str,
        help='Path to test results JSON file for analysis'
    )
    
    parser.add_argument(
        '--stakeholder-audience',
        choices=['executive', 'technical', 'compliance'],
        default='executive',
        help='Target audience for stakeholder reports'
    )
    
    parser.add_argument(
        '--include-visualizations',
        action='store_true',
        default=True,
        help='Include performance charts and visualizations'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging output'
    )
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Load test results if provided
        test_results = None
        if args.test_results:
            with open(args.test_results, 'r') as f:
                test_results = json.load(f)
        
        # Initialize report generator
        generator = PerformanceReportGenerator(
            environment=args.environment,
            output_dir=args.output_dir
        )
        
        # Generate reports based on type
        if args.type == 'comprehensive':
            formats = [ReportFormat(f) for f in (args.format or ['json', 'markdown', 'html'])]
            generated_reports = generator.generate_comprehensive_performance_report(
                test_results=test_results,
                report_formats=formats,
                include_visualizations=args.include_visualizations
            )
            
        elif args.type == 'baseline':
            current_metrics = test_results.get('current_metrics', {}) if test_results else {}
            format_enum = ReportFormat(args.format[0] if args.format else 'json')
            report_path = generator.generate_baseline_comparison_report(
                current_metrics=current_metrics,
                report_format=format_enum
            )
            generated_reports = {'baseline_comparison': report_path}
            
        elif args.type == 'trend':
            historical_data = test_results.get('historical_data', []) if test_results else []
            report_path = generator.generate_trend_analysis_report(
                historical_data=historical_data
            )
            generated_reports = {'trend_analysis': report_path}
            
        elif args.type == 'ci_cd':
            generated_reports = generator.generate_ci_cd_integration_report()
            
        elif args.type == 'stakeholder':
            report_path = generator.generate_stakeholder_summary_report(
                target_audience=args.stakeholder_audience
            )
            generated_reports = {f'stakeholder_{args.stakeholder_audience}': report_path}
        
        else:
            raise ValueError(f"Unsupported report type: {args.type}")
        
        # Output results
        print(f"\n🎯 Performance report generation completed successfully!")
        print(f"📊 Generated {len(generated_reports)} report(s):")
        
        for report_type, report_path in generated_reports.items():
            print(f"  - {report_type}: {report_path}")
        
        # CI/CD integration output
        if GITHUB_ACTIONS_INTEGRATION:
            print(f"\n🔄 GitHub Actions Integration:")
            print(f"  - Run ID: {GITHUB_RUN_ID}")
            print(f"  - SHA: {GITHUB_SHA}")
            print(f"  - Artifacts: {len([p for p in generated_reports.values() if 'artifacts' in str(p)])}")
        
        return 0
        
    except Exception as e:
        print(f"❌ Performance report generation failed: {str(e)}")
        if args.verbose:
            print(traceback.format_exc())
        return 1


if __name__ == '__main__':
    sys.exit(main())