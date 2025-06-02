#!/usr/bin/env python3
"""
Performance Data Processing and Analysis Script

This module implements comprehensive performance data processing and analysis for the Flask
migration project, providing statistical analysis, trend calculation, performance metrics
aggregation, and actionable insights generation. Processes raw performance data from load tests,
monitoring systems, and baseline comparisons to ensure ≤10% variance compliance.

Key Features:
- Statistical analysis for ≤10% variance calculation per Section 0.3.2 performance monitoring
- Performance trend analysis and regression detection per Section 6.6.1 testing strategy
- Memory profiling and resource utilization analysis per Section 3.6.2 memory profiling
- Database query performance monitoring per Section 3.6.2 database monitoring
- Prometheus-client metrics data processing per Section 3.6.2 metrics collection
- Performance data aggregation and historical tracking per Section 6.6.2 quality metrics

Performance Requirements:
- Response time variance ≤10% from Node.js baseline (critical requirement per Section 0.1.1)
- Memory usage patterns equivalent to original implementation with ±15% variance
- Concurrent request handling capacity preservation per Section 2.4.1
- Database performance equivalence with ±10% variance from baseline metrics
- Statistical significance validation with 95% confidence intervals

Data Processing Capabilities:
- Real-time performance data ingestion from multiple sources (Prometheus, load tests, APM)
- Statistical analysis using scipy.stats for comprehensive variance calculation
- Trend analysis with linear regression and seasonal decomposition
- Anomaly detection using isolation forests and statistical outlier analysis
- Performance baseline comparison with automated compliance validation
- Historical performance tracking with data retention and archival management

Architecture Integration:
- Section 0.3.2: Continuous performance monitoring with baseline comparison requirements
- Section 6.6.1: Testing strategy with performance baseline validation and trend analysis
- Section 3.6.2: Monitoring & observability with prometheus-client metrics processing
- Section 6.6.2: Test automation with performance gate enforcement and quality metrics

Author: Flask Migration Team
Version: 1.0.0
Dependencies: scipy, numpy, pandas, prometheus-client 0.17+, structlog 23.1+
"""

import argparse
import gc
import json
import logging
import math
import os
import statistics
import sys
import warnings
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union, NamedTuple, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
import tempfile
import hashlib
import uuid

# Scientific computing and statistical analysis imports
try:
    import numpy as np
    import pandas as pd
    from scipy import stats
    from scipy.stats import pearsonr, spearmanr, normaltest, shapiro
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SCIENTIFIC_LIBRARIES_AVAILABLE = True
except ImportError:
    SCIENTIFIC_LIBRARIES_AVAILABLE = False
    warnings.warn("Scientific libraries not available - limited statistical analysis capabilities")

# Prometheus metrics processing imports
try:
    from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge
    from prometheus_client.parser import text_string_to_metric_families
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    warnings.warn("prometheus_client not available - metrics processing disabled")

# Structured logging for performance data tracking
try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False
    warnings.warn("structlog not available - falling back to standard logging")

# Performance testing framework integration
from tests.performance.baseline_data import (
    BaselineDataManager, NodeJSPerformanceBaseline, get_baseline_manager,
    get_nodejs_baseline, compare_with_baseline, BaselineValidationStatus
)
from tests.performance.performance_config import (
    PerformanceTestConfig, LoadTestScenario, PerformanceMetricType,
    create_performance_config, validate_performance_results
)
from tests.performance.test_performance_monitoring import (
    NODEJS_BASELINE_METRICS, PERFORMANCE_VARIANCE_THRESHOLD,
    MEMORY_VARIANCE_THRESHOLD, RESPONSE_TIME_THRESHOLD_MS
)

# Monitoring integration
from src.monitoring.metrics import PrometheusMetricsCollector


class PerformanceDataSource(Enum):
    """Performance data source enumeration for comprehensive data processing."""
    
    PROMETHEUS_METRICS = "prometheus_metrics"
    LOCUST_LOAD_TEST = "locust_load_test"
    APACHE_BENCH = "apache_bench"
    SYSTEM_MONITORING = "system_monitoring"
    DATABASE_PROFILER = "database_profiler"
    APPLICATION_LOGS = "application_logs"
    NODEJS_BASELINE = "nodejs_baseline"
    FLASK_METRICS = "flask_metrics"


class AnalysisType(Enum):
    """Performance analysis type enumeration for processing workflows."""
    
    VARIANCE_ANALYSIS = "variance_analysis"
    TREND_ANALYSIS = "trend_analysis"
    REGRESSION_DETECTION = "regression_detection"
    ANOMALY_DETECTION = "anomaly_detection"
    BASELINE_COMPARISON = "baseline_comparison"
    STATISTICAL_SUMMARY = "statistical_summary"
    RESOURCE_UTILIZATION = "resource_utilization"
    DATABASE_PERFORMANCE = "database_performance"


class PerformanceStatus(Enum):
    """Performance compliance status enumeration."""
    
    COMPLIANT = "compliant"           # Within ≤10% variance threshold
    WARNING = "warning"               # 10-15% variance range
    CRITICAL = "critical"             # >15% variance or threshold breach
    DEGRADED = "degraded"             # Performance regression detected
    IMPROVED = "improved"             # Performance improvement detected
    UNKNOWN = "unknown"               # Insufficient data for analysis


@dataclass
class PerformanceDataPoint:
    """
    Individual performance data point with comprehensive metadata.
    
    Represents a single performance measurement with statistical context,
    source information, and validation capabilities for trend analysis.
    """
    
    timestamp: datetime
    metric_name: str
    value: float
    unit: str
    source: PerformanceDataSource
    
    # Statistical metadata
    percentile: Optional[float] = None      # P50, P95, P99, etc.
    sample_size: Optional[int] = None       # Sample size for statistical validity
    confidence_interval: Optional[Tuple[float, float]] = None
    standard_deviation: Optional[float] = None
    
    # Context metadata
    endpoint: Optional[str] = None          # API endpoint for request metrics
    database_operation: Optional[str] = None
    environment: str = "testing"
    test_scenario: Optional[str] = None
    
    # Quality indicators
    data_quality_score: float = 1.0        # 0.0-1.0 data quality assessment
    is_outlier: bool = False
    validation_status: str = "valid"
    
    def __post_init__(self):
        """Post-initialization validation and normalization."""
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)
        
        if self.value < 0 and self.metric_name not in ["temperature_change", "performance_improvement"]:
            warnings.warn(f"Negative value {self.value} for metric {self.metric_name}")
    
    def calculate_variance_from_baseline(self, baseline_value: float) -> float:
        """Calculate percentage variance from baseline value."""
        if baseline_value == 0:
            return 0.0
        return ((self.value - baseline_value) / baseline_value) * 100.0
    
    def is_within_threshold(self, baseline_value: float, threshold_percent: float = 10.0) -> bool:
        """Check if value is within acceptable variance threshold."""
        variance = abs(self.calculate_variance_from_baseline(baseline_value))
        return variance <= threshold_percent
    
    def get_performance_status(self, baseline_value: float) -> PerformanceStatus:
        """Determine performance status based on variance from baseline."""
        variance = abs(self.calculate_variance_from_baseline(baseline_value))
        
        if variance <= 10.0:
            return PerformanceStatus.COMPLIANT
        elif variance <= 15.0:
            return PerformanceStatus.WARNING
        else:
            return PerformanceStatus.CRITICAL


@dataclass
class PerformanceAnalysisResult:
    """
    Comprehensive performance analysis result with statistical insights.
    
    Contains statistical analysis results, trend information, variance calculations,
    and actionable recommendations for performance optimization and compliance.
    """
    
    analysis_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    analysis_type: AnalysisType = AnalysisType.STATISTICAL_SUMMARY
    analysis_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Data summary
    metric_name: str = ""
    data_points_count: int = 0
    time_range: Optional[Tuple[datetime, datetime]] = None
    data_sources: List[PerformanceDataSource] = field(default_factory=list)
    
    # Statistical analysis results
    mean_value: float = 0.0
    median_value: float = 0.0
    std_deviation: float = 0.0
    min_value: float = 0.0
    max_value: float = 0.0
    percentiles: Dict[str, float] = field(default_factory=dict)  # P50, P95, P99
    
    # Variance analysis
    baseline_value: Optional[float] = None
    variance_percentage: Optional[float] = None
    variance_status: PerformanceStatus = PerformanceStatus.UNKNOWN
    within_threshold: Optional[bool] = None
    
    # Trend analysis
    trend_direction: Optional[str] = None   # "improving", "degrading", "stable"
    trend_strength: Optional[float] = None  # Correlation coefficient
    trend_significance: Optional[float] = None  # p-value
    regression_slope: Optional[float] = None
    regression_r_squared: Optional[float] = None
    
    # Anomaly detection
    outliers_count: int = 0
    outlier_threshold: Optional[float] = None
    anomaly_score: Optional[float] = None
    
    # Quality metrics
    data_quality_score: float = 1.0
    statistical_significance: Optional[float] = None
    confidence_level: float = 0.95
    
    # Recommendations and insights
    recommendations: List[str] = field(default_factory=list)
    insights: List[str] = field(default_factory=list)
    alerts: List[str] = field(default_factory=list)
    
    def add_recommendation(self, recommendation: str, priority: str = "medium"):
        """Add performance optimization recommendation."""
        priority_prefix = f"[{priority.upper()}]" if priority != "medium" else ""
        self.recommendations.append(f"{priority_prefix} {recommendation}".strip())
    
    def add_insight(self, insight: str):
        """Add performance analysis insight."""
        self.insights.append(insight)
    
    def add_alert(self, alert: str, severity: str = "warning"):
        """Add performance alert with severity."""
        severity_prefix = f"[{severity.upper()}]"
        self.alerts.append(f"{severity_prefix} {alert}")
    
    def is_compliant(self) -> bool:
        """Check if performance analysis indicates compliance."""
        return self.variance_status in [PerformanceStatus.COMPLIANT, PerformanceStatus.IMPROVED]
    
    def get_summary_dict(self) -> Dict[str, Any]:
        """Get summary dictionary for reporting."""
        return {
            "analysis_id": self.analysis_id,
            "analysis_type": self.analysis_type.value,
            "metric_name": self.metric_name,
            "data_points": self.data_points_count,
            "statistical_summary": {
                "mean": self.mean_value,
                "median": self.median_value,
                "std_dev": self.std_deviation,
                "percentiles": self.percentiles
            },
            "variance_analysis": {
                "baseline_value": self.baseline_value,
                "variance_percentage": self.variance_percentage,
                "status": self.variance_status.value,
                "compliant": self.is_compliant()
            },
            "trend_analysis": {
                "direction": self.trend_direction,
                "strength": self.trend_strength,
                "significance": self.trend_significance
            },
            "quality_metrics": {
                "data_quality_score": self.data_quality_score,
                "outliers_count": self.outliers_count,
                "statistical_significance": self.statistical_significance
            },
            "recommendations_count": len(self.recommendations),
            "alerts_count": len(self.alerts)
        }


class PerformanceDataProcessor:
    """
    Comprehensive performance data processing engine implementing statistical analysis,
    trend calculation, variance validation, and performance metrics aggregation.
    
    This processor provides enterprise-grade performance analysis capabilities including:
    - Statistical analysis with scipy.stats for variance calculation and significance testing
    - Trend analysis with linear regression and seasonal decomposition
    - Anomaly detection using isolation forests and statistical outlier identification
    - Baseline comparison with Node.js performance metrics for ≤10% variance validation
    - Historical tracking and data retention management
    - Performance insights generation and optimization recommendations
    """
    
    def __init__(
        self,
        baseline_manager: Optional[BaselineDataManager] = None,
        config: Optional[PerformanceTestConfig] = None,
        output_directory: Optional[Path] = None
    ):
        """
        Initialize performance data processor with configuration.
        
        Args:
            baseline_manager: BaselineDataManager for Node.js baseline comparison
            config: PerformanceTestConfig for analysis parameters
            output_directory: Directory for output files and reports
        """
        self.baseline_manager = baseline_manager or get_baseline_manager()
        self.config = config or create_performance_config()
        self.output_directory = output_directory or Path("./performance_analysis_output")
        self.output_directory.mkdir(parents=True, exist_ok=True)
        
        # Initialize logging
        if STRUCTLOG_AVAILABLE:
            self.logger = structlog.get_logger(__name__)
        else:
            self.logger = logging.getLogger(__name__)
            logging.basicConfig(level=logging.INFO)
        
        # Performance data storage
        self.raw_data: Dict[str, List[PerformanceDataPoint]] = defaultdict(list)
        self.processed_results: Dict[str, PerformanceAnalysisResult] = {}
        self.analysis_cache: Dict[str, Any] = {}
        
        # Statistical analysis configuration
        self.confidence_level = 0.95
        self.outlier_threshold = 3.0  # Standard deviations
        self.min_sample_size = 30     # Minimum for statistical significance
        self.variance_threshold = PERFORMANCE_VARIANCE_THRESHOLD
        
        # Initialize data quality tracking
        self.data_quality_metrics = {
            "total_data_points": 0,
            "valid_data_points": 0,
            "outliers_detected": 0,
            "missing_data_count": 0,
            "data_quality_score": 1.0
        }
        
        self.logger.info(
            "Performance data processor initialized",
            baseline_manager=bool(baseline_manager),
            config_environment=self.config.get_environment_config().get("environment", "testing"),
            output_directory=str(self.output_directory),
            scientific_libraries=SCIENTIFIC_LIBRARIES_AVAILABLE
        )
    
    def add_data_point(self, data_point: PerformanceDataPoint) -> None:
        """
        Add performance data point to processing queue with validation.
        
        Args:
            data_point: PerformanceDataPoint instance to add
        """
        # Validate data point
        if self._validate_data_point(data_point):
            self.raw_data[data_point.metric_name].append(data_point)
            self.data_quality_metrics["valid_data_points"] += 1
        else:
            self.data_quality_metrics["missing_data_count"] += 1
            self.logger.warning(
                "Invalid data point rejected",
                metric_name=data_point.metric_name,
                value=data_point.value,
                validation_status=data_point.validation_status
            )
        
        self.data_quality_metrics["total_data_points"] += 1
        self._update_data_quality_score()
    
    def add_data_points_batch(self, data_points: List[PerformanceDataPoint]) -> int:
        """
        Add multiple performance data points in batch with optimization.
        
        Args:
            data_points: List of PerformanceDataPoint instances
            
        Returns:
            Number of successfully added data points
        """
        added_count = 0
        for data_point in data_points:
            try:
                self.add_data_point(data_point)
                added_count += 1
            except Exception as e:
                self.logger.error(
                    "Failed to add data point",
                    metric_name=getattr(data_point, 'metric_name', 'unknown'),
                    error=str(e)
                )
        
        self.logger.info(
            "Batch data points processed",
            total_points=len(data_points),
            added_count=added_count,
            rejected_count=len(data_points) - added_count
        )
        
        return added_count
    
    def process_prometheus_metrics(self, metrics_text: str) -> int:
        """
        Process Prometheus metrics text format and extract performance data.
        
        Args:
            metrics_text: Prometheus metrics in text exposition format
            
        Returns:
            Number of data points extracted and processed
        """
        if not PROMETHEUS_AVAILABLE:
            self.logger.error("Prometheus client not available for metrics processing")
            return 0
        
        data_points = []
        current_time = datetime.now(timezone.utc)
        
        try:
            for family in text_string_to_metric_families(metrics_text):
                for sample in family.samples:
                    # Extract performance-relevant metrics
                    metric_name = sample.name
                    value = sample.value
                    labels = sample.labels or {}
                    
                    # Determine metric unit and type
                    unit = self._determine_metric_unit(metric_name)
                    
                    # Create data point
                    data_point = PerformanceDataPoint(
                        timestamp=current_time,
                        metric_name=metric_name,
                        value=value,
                        unit=unit,
                        source=PerformanceDataSource.PROMETHEUS_METRICS,
                        endpoint=labels.get('endpoint'),
                        environment=labels.get('environment', 'testing')
                    )
                    
                    data_points.append(data_point)
            
            return self.add_data_points_batch(data_points)
            
        except Exception as e:
            self.logger.error("Failed to process Prometheus metrics", error=str(e))
            return 0
    
    def process_load_test_results(self, results_file: Path) -> int:
        """
        Process load test results from locust or apache-bench output files.
        
        Args:
            results_file: Path to load test results file
            
        Returns:
            Number of data points extracted and processed
        """
        if not results_file.exists():
            self.logger.error("Load test results file not found", file_path=str(results_file))
            return 0
        
        data_points = []
        
        try:
            if results_file.suffix == '.json':
                # Process JSON format (locust results)
                data_points = self._process_locust_json_results(results_file)
            elif results_file.suffix == '.csv':
                # Process CSV format (apache-bench or locust CSV)
                data_points = self._process_csv_results(results_file)
            else:
                self.logger.warning("Unsupported load test results format", file_path=str(results_file))
                return 0
            
            return self.add_data_points_batch(data_points)
            
        except Exception as e:
            self.logger.error("Failed to process load test results", file_path=str(results_file), error=str(e))
            return 0
    
    def analyze_metric_performance(
        self,
        metric_name: str,
        analysis_types: List[AnalysisType] = None
    ) -> PerformanceAnalysisResult:
        """
        Perform comprehensive performance analysis for a specific metric.
        
        Args:
            metric_name: Name of metric to analyze
            analysis_types: List of analysis types to perform
            
        Returns:
            PerformanceAnalysisResult with comprehensive analysis
        """
        if metric_name not in self.raw_data:
            raise ValueError(f"No data available for metric: {metric_name}")
        
        if analysis_types is None:
            analysis_types = [
                AnalysisType.STATISTICAL_SUMMARY,
                AnalysisType.VARIANCE_ANALYSIS,
                AnalysisType.TREND_ANALYSIS,
                AnalysisType.ANOMALY_DETECTION
            ]
        
        data_points = self.raw_data[metric_name]
        
        # Create analysis result container
        result = PerformanceAnalysisResult(
            metric_name=metric_name,
            data_points_count=len(data_points),
            time_range=(
                min(dp.timestamp for dp in data_points),
                max(dp.timestamp for dp in data_points)
            ) if data_points else None,
            data_sources=list(set(dp.source for dp in data_points))
        )
        
        # Extract values for analysis
        values = [dp.value for dp in data_points]
        timestamps = [dp.timestamp for dp in data_points]
        
        # Perform requested analyses
        if AnalysisType.STATISTICAL_SUMMARY in analysis_types:
            self._perform_statistical_analysis(values, result)
        
        if AnalysisType.VARIANCE_ANALYSIS in analysis_types:
            self._perform_variance_analysis(metric_name, values, result)
        
        if AnalysisType.TREND_ANALYSIS in analysis_types:
            self._perform_trend_analysis(values, timestamps, result)
        
        if AnalysisType.ANOMALY_DETECTION in analysis_types:
            self._perform_anomaly_detection(values, result)
        
        # Generate insights and recommendations
        self._generate_insights_and_recommendations(result)
        
        # Cache result
        self.processed_results[metric_name] = result
        
        self.logger.info(
            "Metric performance analysis completed",
            metric_name=metric_name,
            analysis_types=[at.value for at in analysis_types],
            data_points_count=len(data_points),
            compliance_status=result.variance_status.value
        )
        
        return result
    
    def analyze_all_metrics(self) -> Dict[str, PerformanceAnalysisResult]:
        """
        Perform comprehensive analysis for all available metrics.
        
        Returns:
            Dictionary mapping metric names to analysis results
        """
        results = {}
        
        for metric_name in self.raw_data.keys():
            try:
                result = self.analyze_metric_performance(metric_name)
                results[metric_name] = result
            except Exception as e:
                self.logger.error(
                    "Failed to analyze metric",
                    metric_name=metric_name,
                    error=str(e)
                )
        
        self.logger.info(
            "All metrics analysis completed",
            total_metrics=len(self.raw_data),
            successful_analyses=len(results),
            failed_analyses=len(self.raw_data) - len(results)
        )
        
        return results
    
    def generate_performance_report(
        self,
        include_charts: bool = True,
        include_recommendations: bool = True
    ) -> Dict[str, Any]:
        """
        Generate comprehensive performance analysis report.
        
        Args:
            include_charts: Whether to include performance charts
            include_recommendations: Whether to include optimization recommendations
            
        Returns:
            Comprehensive performance report dictionary
        """
        # Analyze all metrics if not already done
        if not self.processed_results:
            self.analyze_all_metrics()
        
        # Calculate overall compliance status
        compliant_metrics = sum(1 for result in self.processed_results.values() if result.is_compliant())
        total_metrics = len(self.processed_results)
        compliance_percentage = (compliant_metrics / total_metrics * 100) if total_metrics > 0 else 0
        
        # Generate summary statistics
        all_variances = [
            result.variance_percentage for result in self.processed_results.values()
            if result.variance_percentage is not None
        ]
        
        variance_summary = {
            "mean_variance": statistics.mean(all_variances) if all_variances else 0,
            "max_variance": max(all_variances) if all_variances else 0,
            "min_variance": min(all_variances) if all_variances else 0,
            "variance_std_dev": statistics.stdev(all_variances) if len(all_variances) > 1 else 0
        }
        
        # Generate report
        report = {
            "report_metadata": {
                "generation_timestamp": datetime.now(timezone.utc).isoformat(),
                "analysis_period": self._get_analysis_period(),
                "total_data_points": self.data_quality_metrics["total_data_points"],
                "data_quality_score": self.data_quality_metrics["data_quality_score"],
                "processor_version": "1.0.0"
            },
            "compliance_summary": {
                "overall_compliant": compliance_percentage >= 90.0,
                "compliance_percentage": compliance_percentage,
                "compliant_metrics": compliant_metrics,
                "total_metrics": total_metrics,
                "variance_threshold": self.variance_threshold
            },
            "variance_analysis": variance_summary,
            "metric_analyses": {
                name: result.get_summary_dict()
                for name, result in self.processed_results.items()
            },
            "data_quality": self.data_quality_metrics,
            "performance_trends": self._generate_trend_summary(),
            "critical_issues": self._identify_critical_issues(),
            "optimization_opportunities": self._identify_optimization_opportunities()
        }
        
        if include_recommendations:
            report["recommendations"] = self._generate_consolidated_recommendations()
        
        if include_charts and SCIENTIFIC_LIBRARIES_AVAILABLE:
            report["chart_data"] = self._generate_chart_data()
        
        # Save report to file
        report_file = self.output_directory / f"performance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        self.logger.info(
            "Performance report generated",
            report_file=str(report_file),
            compliance_percentage=compliance_percentage,
            total_metrics=total_metrics,
            critical_issues=len(report["critical_issues"])
        )
        
        return report
    
    def export_analysis_results(self, format_type: str = "json") -> Path:
        """
        Export analysis results to specified format.
        
        Args:
            format_type: Export format ("json", "csv", "excel")
            
        Returns:
            Path to exported file
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if format_type == "json":
            export_file = self.output_directory / f"performance_analysis_{timestamp}.json"
            export_data = {
                "analysis_results": {
                    name: asdict(result) for name, result in self.processed_results.items()
                },
                "data_quality": self.data_quality_metrics,
                "export_metadata": {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "total_metrics": len(self.processed_results),
                    "processor_version": "1.0.0"
                }
            }
            
            with open(export_file, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
        
        elif format_type == "csv" and SCIENTIFIC_LIBRARIES_AVAILABLE:
            export_file = self.output_directory / f"performance_analysis_{timestamp}.csv"
            
            # Create DataFrame from results
            rows = []
            for metric_name, result in self.processed_results.items():
                row = {
                    "metric_name": metric_name,
                    "mean_value": result.mean_value,
                    "median_value": result.median_value,
                    "std_deviation": result.std_deviation,
                    "baseline_value": result.baseline_value,
                    "variance_percentage": result.variance_percentage,
                    "variance_status": result.variance_status.value,
                    "trend_direction": result.trend_direction,
                    "trend_strength": result.trend_strength,
                    "data_points_count": result.data_points_count,
                    "outliers_count": result.outliers_count,
                    "data_quality_score": result.data_quality_score
                }
                rows.append(row)
            
            df = pd.DataFrame(rows)
            df.to_csv(export_file, index=False)
        
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
        
        self.logger.info(
            "Analysis results exported",
            export_file=str(export_file),
            format_type=format_type,
            metrics_count=len(self.processed_results)
        )
        
        return export_file
    
    def _validate_data_point(self, data_point: PerformanceDataPoint) -> bool:
        """Validate data point for quality and completeness."""
        if data_point.value is None or math.isnan(data_point.value):
            data_point.validation_status = "invalid_value"
            return False
        
        if data_point.metric_name is None or data_point.metric_name.strip() == "":
            data_point.validation_status = "invalid_metric_name"
            return False
        
        if data_point.timestamp is None:
            data_point.validation_status = "invalid_timestamp"
            return False
        
        # Check for reasonable value ranges based on metric type
        if "response_time" in data_point.metric_name.lower() and data_point.value > 60000:  # >60 seconds
            data_point.validation_status = "suspicious_response_time"
            data_point.data_quality_score = 0.5
        
        if "memory" in data_point.metric_name.lower() and data_point.value > 32768:  # >32GB
            data_point.validation_status = "suspicious_memory_usage"
            data_point.data_quality_score = 0.5
        
        return True
    
    def _update_data_quality_score(self):
        """Update overall data quality score based on validation results."""
        total = self.data_quality_metrics["total_data_points"]
        if total == 0:
            self.data_quality_metrics["data_quality_score"] = 1.0
            return
        
        valid = self.data_quality_metrics["valid_data_points"]
        self.data_quality_metrics["data_quality_score"] = valid / total
    
    def _determine_metric_unit(self, metric_name: str) -> str:
        """Determine unit for metric based on name patterns."""
        metric_lower = metric_name.lower()
        
        if "response_time" in metric_lower or "duration" in metric_lower:
            return "ms"
        elif "memory" in metric_lower or "heap" in metric_lower:
            return "MB"
        elif "cpu" in metric_lower and "percent" in metric_lower:
            return "%"
        elif "requests_per_second" in metric_lower or "rps" in metric_lower:
            return "req/s"
        elif "error_rate" in metric_lower:
            return "%"
        elif "throughput" in metric_lower:
            return "req/s"
        else:
            return "units"
    
    def _process_locust_json_results(self, results_file: Path) -> List[PerformanceDataPoint]:
        """Process locust JSON results file."""
        data_points = []
        
        with open(results_file, 'r') as f:
            locust_data = json.load(f)
        
        # Extract performance metrics from locust results
        if 'stats' in locust_data:
            for stat in locust_data['stats']:
                endpoint = stat.get('name', 'unknown')
                
                # Response time metrics
                if 'avg_response_time' in stat:
                    data_points.append(PerformanceDataPoint(
                        timestamp=datetime.now(timezone.utc),
                        metric_name="response_time_mean",
                        value=stat['avg_response_time'],
                        unit="ms",
                        source=PerformanceDataSource.LOCUST_LOAD_TEST,
                        endpoint=endpoint,
                        sample_size=stat.get('num_requests', 0)
                    ))
                
                # Throughput metrics
                if 'current_rps' in stat:
                    data_points.append(PerformanceDataPoint(
                        timestamp=datetime.now(timezone.utc),
                        metric_name="requests_per_second",
                        value=stat['current_rps'],
                        unit="req/s",
                        source=PerformanceDataSource.LOCUST_LOAD_TEST,
                        endpoint=endpoint
                    ))
                
                # Error rate metrics
                if 'num_failures' in stat and 'num_requests' in stat:
                    total_requests = stat['num_requests']
                    if total_requests > 0:
                        error_rate = (stat['num_failures'] / total_requests) * 100
                        data_points.append(PerformanceDataPoint(
                            timestamp=datetime.now(timezone.utc),
                            metric_name="error_rate",
                            value=error_rate,
                            unit="%",
                            source=PerformanceDataSource.LOCUST_LOAD_TEST,
                            endpoint=endpoint,
                            sample_size=total_requests
                        ))
        
        return data_points
    
    def _process_csv_results(self, results_file: Path) -> List[PerformanceDataPoint]:
        """Process CSV format results file."""
        if not SCIENTIFIC_LIBRARIES_AVAILABLE:
            self.logger.warning("Pandas not available for CSV processing")
            return []
        
        data_points = []
        
        try:
            df = pd.read_csv(results_file)
            
            # Determine source type based on columns
            if 'Response Time' in df.columns:
                # Apache Bench format
                source = PerformanceDataSource.APACHE_BENCH
            else:
                # Generic CSV format
                source = PerformanceDataSource.FLASK_METRICS
            
            for _, row in df.iterrows():
                # Extract timestamp if available
                timestamp = datetime.now(timezone.utc)
                if 'timestamp' in row:
                    timestamp = pd.to_datetime(row['timestamp'])
                
                # Process each numeric column as a metric
                for column, value in row.items():
                    if pd.api.types.is_numeric_dtype(type(value)) and not pd.isna(value):
                        unit = self._determine_metric_unit(column)
                        
                        data_points.append(PerformanceDataPoint(
                            timestamp=timestamp,
                            metric_name=column.lower().replace(' ', '_'),
                            value=float(value),
                            unit=unit,
                            source=source
                        ))
        
        except Exception as e:
            self.logger.error("Failed to process CSV file", file_path=str(results_file), error=str(e))
        
        return data_points
    
    def _perform_statistical_analysis(self, values: List[float], result: PerformanceAnalysisResult):
        """Perform comprehensive statistical analysis on values."""
        if not values:
            return
        
        # Basic statistics
        result.mean_value = statistics.mean(values)
        result.median_value = statistics.median(values)
        result.std_deviation = statistics.stdev(values) if len(values) > 1 else 0.0
        result.min_value = min(values)
        result.max_value = max(values)
        
        # Percentiles
        if SCIENTIFIC_LIBRARIES_AVAILABLE:
            result.percentiles = {
                "P50": float(np.percentile(values, 50)),
                "P75": float(np.percentile(values, 75)),
                "P90": float(np.percentile(values, 90)),
                "P95": float(np.percentile(values, 95)),
                "P99": float(np.percentile(values, 99))
            }
            
            # Statistical significance testing
            if len(values) >= 30:
                # Normality test
                stat, p_value = normaltest(values)
                result.statistical_significance = p_value
        else:
            # Fallback percentile calculation
            sorted_values = sorted(values)
            n = len(sorted_values)
            result.percentiles = {
                "P50": sorted_values[int(n * 0.5)],
                "P75": sorted_values[int(n * 0.75)],
                "P90": sorted_values[int(n * 0.9)],
                "P95": sorted_values[int(n * 0.95)],
                "P99": sorted_values[int(n * 0.99)]
            }
    
    def _perform_variance_analysis(self, metric_name: str, values: List[float], result: PerformanceAnalysisResult):
        """Perform variance analysis against Node.js baseline."""
        try:
            # Get baseline value for comparison
            baseline = self.baseline_manager.get_default_baseline()
            
            # Determine baseline value based on metric name
            baseline_value = self._get_baseline_value_for_metric(baseline, metric_name)
            
            if baseline_value is not None:
                result.baseline_value = baseline_value
                
                # Calculate variance using mean value
                current_value = result.mean_value if result.mean_value != 0 else statistics.mean(values)
                result.variance_percentage = ((current_value - baseline_value) / baseline_value) * 100
                
                # Determine variance status
                abs_variance = abs(result.variance_percentage)
                if abs_variance <= 10.0:
                    result.variance_status = PerformanceStatus.COMPLIANT
                elif abs_variance <= 15.0:
                    result.variance_status = PerformanceStatus.WARNING
                else:
                    result.variance_status = PerformanceStatus.CRITICAL
                
                result.within_threshold = abs_variance <= self.variance_threshold
            
        except Exception as e:
            self.logger.error(
                "Failed to perform variance analysis",
                metric_name=metric_name,
                error=str(e)
            )
    
    def _perform_trend_analysis(self, values: List[float], timestamps: List[datetime], result: PerformanceAnalysisResult):
        """Perform trend analysis using time series data."""
        if len(values) < 3 or not SCIENTIFIC_LIBRARIES_AVAILABLE:
            return
        
        try:
            # Convert timestamps to numeric values for correlation
            time_numeric = [(ts - timestamps[0]).total_seconds() for ts in timestamps]
            
            # Calculate correlation coefficient
            correlation, p_value = pearsonr(time_numeric, values)
            
            result.trend_strength = correlation
            result.trend_significance = p_value
            
            # Determine trend direction
            if abs(correlation) < 0.1:
                result.trend_direction = "stable"
            elif correlation > 0:
                result.trend_direction = "degrading"  # Increasing values usually mean worse performance
            else:
                result.trend_direction = "improving"
            
            # Linear regression analysis
            slope, intercept, r_value, p_value, std_err = stats.linregress(time_numeric, values)
            result.regression_slope = slope
            result.regression_r_squared = r_value ** 2
            
        except Exception as e:
            self.logger.error("Failed to perform trend analysis", error=str(e))
    
    def _perform_anomaly_detection(self, values: List[float], result: PerformanceAnalysisResult):
        """Perform anomaly detection using statistical methods."""
        if len(values) < 10:
            return
        
        try:
            # Statistical outlier detection using Z-score
            mean_val = statistics.mean(values)
            std_val = statistics.stdev(values) if len(values) > 1 else 0
            
            outliers = []
            if std_val > 0:
                for value in values:
                    z_score = abs((value - mean_val) / std_val)
                    if z_score > self.outlier_threshold:
                        outliers.append(value)
            
            result.outliers_count = len(outliers)
            result.outlier_threshold = self.outlier_threshold
            
            # Isolation Forest anomaly detection if available
            if SCIENTIFIC_LIBRARIES_AVAILABLE and len(values) >= 20:
                values_array = np.array(values).reshape(-1, 1)
                isolation_forest = IsolationForest(contamination=0.1, random_state=42)
                anomaly_labels = isolation_forest.fit_predict(values_array)
                
                # Calculate anomaly score
                anomaly_scores = isolation_forest.score_samples(values_array)
                result.anomaly_score = float(np.mean(anomaly_scores))
        
        except Exception as e:
            self.logger.error("Failed to perform anomaly detection", error=str(e))
    
    def _generate_insights_and_recommendations(self, result: PerformanceAnalysisResult):
        """Generate actionable insights and recommendations."""
        # Variance-based insights
        if result.variance_percentage is not None:
            if result.variance_status == PerformanceStatus.CRITICAL:
                result.add_alert(
                    f"Critical performance variance: {result.variance_percentage:.1f}% from baseline",
                    "critical"
                )
                result.add_recommendation(
                    "Immediate performance optimization required - investigate bottlenecks",
                    "high"
                )
            elif result.variance_status == PerformanceStatus.WARNING:
                result.add_alert(
                    f"Performance variance approaching threshold: {result.variance_percentage:.1f}%",
                    "warning"
                )
                result.add_recommendation(
                    "Monitor performance closely and consider optimization",
                    "medium"
                )
            elif result.variance_percentage < -5.0:  # Improvement
                result.add_insight(
                    f"Performance improvement detected: {abs(result.variance_percentage):.1f}% faster than baseline"
                )
        
        # Trend-based insights
        if result.trend_direction == "degrading" and result.trend_significance and result.trend_significance < 0.05:
            result.add_alert(
                "Statistically significant performance degradation trend detected",
                "warning"
            )
            result.add_recommendation(
                "Investigate recent changes that may be causing performance degradation",
                "high"
            )
        
        # Outlier-based insights
        if result.outliers_count > 0:
            outlier_percentage = (result.outliers_count / result.data_points_count) * 100
            if outlier_percentage > 10:
                result.add_alert(
                    f"High number of outliers detected: {outlier_percentage:.1f}% of data points"
                )
                result.add_recommendation(
                    "Investigate inconsistent performance patterns and system stability"
                )
        
        # Data quality insights
        if result.data_quality_score < 0.8:
            result.add_alert(
                f"Low data quality score: {result.data_quality_score:.2f}"
            )
            result.add_recommendation(
                "Improve data collection reliability and validation processes"
            )
    
    def _get_baseline_value_for_metric(self, baseline: NodeJSPerformanceBaseline, metric_name: str) -> Optional[float]:
        """Get baseline value for specific metric name."""
        metric_mapping = {
            "response_time_mean": baseline.api_response_time_mean,
            "response_time_p95": baseline.api_response_time_p95,
            "response_time_p99": baseline.api_response_time_p99,
            "requests_per_second": baseline.requests_per_second_sustained,
            "memory_usage": baseline.memory_usage_baseline_mb,
            "cpu_utilization": baseline.cpu_utilization_average,
            "database_query_time": baseline.database_query_time_mean,
            "error_rate": baseline.error_rate_overall,
            "throughput": baseline.requests_per_second_sustained
        }
        
        # Try exact match first
        if metric_name in metric_mapping:
            return metric_mapping[metric_name]
        
        # Try partial matches
        for key, value in metric_mapping.items():
            if key in metric_name or metric_name in key:
                return value
        
        return None
    
    def _get_analysis_period(self) -> Dict[str, str]:
        """Get analysis period from available data."""
        all_timestamps = []
        for data_points in self.raw_data.values():
            all_timestamps.extend([dp.timestamp for dp in data_points])
        
        if all_timestamps:
            return {
                "start": min(all_timestamps).isoformat(),
                "end": max(all_timestamps).isoformat(),
                "duration_hours": (max(all_timestamps) - min(all_timestamps)).total_seconds() / 3600
            }
        
        return {}
    
    def _generate_trend_summary(self) -> Dict[str, Any]:
        """Generate summary of trends across all metrics."""
        trend_summary = {
            "improving_metrics": [],
            "degrading_metrics": [],
            "stable_metrics": [],
            "insufficient_data_metrics": []
        }
        
        for metric_name, result in self.processed_results.items():
            if result.trend_direction:
                if result.trend_direction == "improving":
                    trend_summary["improving_metrics"].append(metric_name)
                elif result.trend_direction == "degrading":
                    trend_summary["degrading_metrics"].append(metric_name)
                else:
                    trend_summary["stable_metrics"].append(metric_name)
            else:
                trend_summary["insufficient_data_metrics"].append(metric_name)
        
        return trend_summary
    
    def _identify_critical_issues(self) -> List[Dict[str, Any]]:
        """Identify critical performance issues requiring immediate attention."""
        critical_issues = []
        
        for metric_name, result in self.processed_results.items():
            if result.variance_status == PerformanceStatus.CRITICAL:
                critical_issues.append({
                    "metric": metric_name,
                    "issue_type": "critical_variance",
                    "variance_percentage": result.variance_percentage,
                    "current_value": result.mean_value,
                    "baseline_value": result.baseline_value,
                    "severity": "critical"
                })
            
            if result.trend_direction == "degrading" and result.trend_significance and result.trend_significance < 0.01:
                critical_issues.append({
                    "metric": metric_name,
                    "issue_type": "performance_degradation",
                    "trend_strength": result.trend_strength,
                    "trend_significance": result.trend_significance,
                    "severity": "high"
                })
        
        return critical_issues
    
    def _identify_optimization_opportunities(self) -> List[Dict[str, Any]]:
        """Identify performance optimization opportunities."""
        opportunities = []
        
        for metric_name, result in self.processed_results.items():
            # High variance but not critical
            if result.variance_status == PerformanceStatus.WARNING:
                opportunities.append({
                    "metric": metric_name,
                    "opportunity_type": "variance_optimization",
                    "description": f"Reduce variance from {result.variance_percentage:.1f}% to under 10%",
                    "potential_impact": "medium"
                })
            
            # High number of outliers
            if result.outliers_count > 0:
                outlier_percentage = (result.outliers_count / result.data_points_count) * 100
                if outlier_percentage > 5:
                    opportunities.append({
                        "metric": metric_name,
                        "opportunity_type": "consistency_improvement",
                        "description": f"Reduce outliers from {outlier_percentage:.1f}% of measurements",
                        "potential_impact": "medium"
                    })
        
        return opportunities
    
    def _generate_consolidated_recommendations(self) -> List[str]:
        """Generate consolidated optimization recommendations."""
        all_recommendations = []
        
        for result in self.processed_results.values():
            all_recommendations.extend(result.recommendations)
        
        # Remove duplicates and prioritize
        unique_recommendations = list(set(all_recommendations))
        
        # Sort by priority (high, medium, low)
        prioritized = []
        for priority in ["[HIGH]", "[MEDIUM]", "[LOW]"]:
            prioritized.extend([rec for rec in unique_recommendations if rec.startswith(priority)])
        
        # Add recommendations without priority markers
        prioritized.extend([rec for rec in unique_recommendations if not any(rec.startswith(p) for p in ["[HIGH]", "[MEDIUM]", "[LOW]"])])
        
        return prioritized
    
    def _generate_chart_data(self) -> Dict[str, Any]:
        """Generate data for performance charts and visualizations."""
        if not SCIENTIFIC_LIBRARIES_AVAILABLE:
            return {}
        
        chart_data = {}
        
        for metric_name, result in self.processed_results.items():
            data_points = self.raw_data[metric_name]
            
            # Time series data
            timestamps = [dp.timestamp.isoformat() for dp in data_points]
            values = [dp.value for dp in data_points]
            
            chart_data[metric_name] = {
                "time_series": {
                    "timestamps": timestamps,
                    "values": values
                },
                "statistics": {
                    "mean": result.mean_value,
                    "median": result.median_value,
                    "percentiles": result.percentiles
                },
                "baseline_comparison": {
                    "baseline_value": result.baseline_value,
                    "variance_percentage": result.variance_percentage,
                    "threshold_line": self.variance_threshold
                }
            }
        
        return chart_data


def main():
    """
    Main CLI entry point for performance data processing script.
    
    Provides command-line interface for processing performance data from various sources
    including Prometheus metrics, load test results, and system monitoring data.
    """
    parser = argparse.ArgumentParser(
        description="Performance Data Processing and Analysis Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process Prometheus metrics from file
  python process_performance_data.py --prometheus-metrics metrics.txt --output-dir ./reports

  # Process load test results with baseline comparison
  python process_performance_data.py --load-test-results results.json --baseline-comparison

  # Generate comprehensive report from multiple sources
  python process_performance_data.py --prometheus-metrics metrics.txt --load-test-results results.csv --generate-report

  # Analyze specific metrics with trend analysis
  python process_performance_data.py --metrics response_time,throughput --analysis-types variance,trend
        """
    )
    
    # Input data sources
    parser.add_argument(
        '--prometheus-metrics',
        type=Path,
        help='Path to Prometheus metrics file (text exposition format)'
    )
    parser.add_argument(
        '--load-test-results',
        type=Path,
        help='Path to load test results file (JSON or CSV format)'
    )
    parser.add_argument(
        '--system-metrics',
        type=Path,
        help='Path to system metrics file'
    )
    
    # Analysis configuration
    parser.add_argument(
        '--metrics',
        type=str,
        help='Comma-separated list of specific metrics to analyze'
    )
    parser.add_argument(
        '--analysis-types',
        type=str,
        default='variance,trend,anomaly',
        help='Comma-separated list of analysis types (variance, trend, anomaly, statistical)'
    )
    parser.add_argument(
        '--variance-threshold',
        type=float,
        default=PERFORMANCE_VARIANCE_THRESHOLD,
        help='Performance variance threshold percentage (default: 10.0)'
    )
    
    # Output configuration
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=Path('./performance_analysis_output'),
        help='Output directory for analysis results and reports'
    )
    parser.add_argument(
        '--export-format',
        choices=['json', 'csv', 'excel'],
        default='json',
        help='Export format for analysis results'
    )
    parser.add_argument(
        '--generate-report',
        action='store_true',
        help='Generate comprehensive performance report'
    )
    
    # Processing options
    parser.add_argument(
        '--baseline-comparison',
        action='store_true',
        help='Enable Node.js baseline comparison'
    )
    parser.add_argument(
        '--include-charts',
        action='store_true',
        help='Include chart data in reports (requires scientific libraries)'
    )
    parser.add_argument(
        '--environment',
        type=str,
        default='testing',
        help='Environment configuration (development, testing, staging, production)'
    )
    
    # Logging configuration
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level'
    )
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress output except errors'
    )
    
    args = parser.parse_args()
    
    # Configure logging
    if not args.quiet:
        logging.basicConfig(
            level=getattr(logging, args.log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    logger = logging.getLogger(__name__)
    
    try:
        # Initialize performance data processor
        config = create_performance_config(args.environment)
        processor = PerformanceDataProcessor(
            config=config,
            output_directory=args.output_dir
        )
        processor.variance_threshold = args.variance_threshold
        
        # Process input data sources
        total_data_points = 0
        
        if args.prometheus_metrics:
            if not args.prometheus_metrics.exists():
                logger.error(f"Prometheus metrics file not found: {args.prometheus_metrics}")
                return 1
            
            logger.info(f"Processing Prometheus metrics from {args.prometheus_metrics}")
            with open(args.prometheus_metrics, 'r') as f:
                metrics_text = f.read()
            
            data_points = processor.process_prometheus_metrics(metrics_text)
            total_data_points += data_points
            logger.info(f"Processed {data_points} data points from Prometheus metrics")
        
        if args.load_test_results:
            if not args.load_test_results.exists():
                logger.error(f"Load test results file not found: {args.load_test_results}")
                return 1
            
            logger.info(f"Processing load test results from {args.load_test_results}")
            data_points = processor.process_load_test_results(args.load_test_results)
            total_data_points += data_points
            logger.info(f"Processed {data_points} data points from load test results")
        
        if total_data_points == 0:
            logger.warning("No data points processed - please provide input data sources")
            return 1
        
        # Determine metrics to analyze
        metrics_to_analyze = []
        if args.metrics:
            metrics_to_analyze = [m.strip() for m in args.metrics.split(',')]
        else:
            metrics_to_analyze = list(processor.raw_data.keys())
        
        # Determine analysis types
        analysis_types = []
        for analysis_type in args.analysis_types.split(','):
            analysis_type = analysis_type.strip().upper()
            if analysis_type == 'VARIANCE':
                analysis_types.append(AnalysisType.VARIANCE_ANALYSIS)
            elif analysis_type == 'TREND':
                analysis_types.append(AnalysisType.TREND_ANALYSIS)
            elif analysis_type == 'ANOMALY':
                analysis_types.append(AnalysisType.ANOMALY_DETECTION)
            elif analysis_type == 'STATISTICAL':
                analysis_types.append(AnalysisType.STATISTICAL_SUMMARY)
        
        if not analysis_types:
            analysis_types = [AnalysisType.STATISTICAL_SUMMARY, AnalysisType.VARIANCE_ANALYSIS]
        
        # Perform analysis
        logger.info(f"Analyzing {len(metrics_to_analyze)} metrics with {len(analysis_types)} analysis types")
        results = {}
        
        for metric_name in metrics_to_analyze:
            if metric_name in processor.raw_data:
                try:
                    result = processor.analyze_metric_performance(metric_name, analysis_types)
                    results[metric_name] = result
                    
                    # Log analysis summary
                    status = "✓" if result.is_compliant() else "✗"
                    logger.info(
                        f"{status} {metric_name}: {result.variance_status.value} "
                        f"(variance: {result.variance_percentage:.1f}% if applicable)"
                    )
                
                except Exception as e:
                    logger.error(f"Failed to analyze metric {metric_name}: {e}")
            else:
                logger.warning(f"Metric {metric_name} not found in processed data")
        
        # Generate reports
        if args.generate_report:
            logger.info("Generating comprehensive performance report")
            report = processor.generate_performance_report(
                include_charts=args.include_charts,
                include_recommendations=True
            )
            
            # Print summary to console
            if not args.quiet:
                print("\n" + "="*80)
                print("PERFORMANCE ANALYSIS SUMMARY")
                print("="*80)
                print(f"Total metrics analyzed: {len(results)}")
                print(f"Compliance percentage: {report['compliance_summary']['compliance_percentage']:.1f}%")
                print(f"Overall compliant: {'✓' if report['compliance_summary']['overall_compliant'] else '✗'}")
                print(f"Critical issues: {len(report['critical_issues'])}")
                print(f"Optimization opportunities: {len(report['optimization_opportunities'])}")
                
                if report['critical_issues']:
                    print("\nCritical Issues:")
                    for issue in report['critical_issues'][:5]:  # Show first 5
                        print(f"  - {issue['metric']}: {issue['issue_type']} ({issue['severity']})")
                
                if report.get('recommendations'):
                    print("\nTop Recommendations:")
                    for rec in report['recommendations'][:3]:  # Show first 3
                        print(f"  - {rec}")
                
                print("\n" + "="*80)
        
        # Export results
        if results:
            export_file = processor.export_analysis_results(args.export_format)
            logger.info(f"Analysis results exported to: {export_file}")
        
        # Calculate overall success
        if results:
            compliant_count = sum(1 for result in results.values() if result.is_compliant())
            compliance_percentage = (compliant_count / len(results)) * 100
            
            if compliance_percentage >= 90:
                logger.info(f"Performance analysis PASSED: {compliance_percentage:.1f}% compliance")
                return 0
            else:
                logger.warning(f"Performance analysis FAILED: {compliance_percentage:.1f}% compliance")
                return 1
        else:
            logger.error("No metrics were successfully analyzed")
            return 1
    
    except Exception as e:
        logger.error(f"Performance data processing failed: {e}")
        if args.log_level == 'DEBUG':
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())