"""
Historical Performance Trend Analysis and Reporting Module

This comprehensive performance trend analysis module provides historical performance data analysis,
capacity planning recommendations, and predictive analysis for performance optimization. It generates
trend visualizations and supports long-term performance evolution tracking across deployments.

Key Features:
- Historical performance trend analysis per Section 6.6.3 quality metrics
- Capacity planning recommendations per Section 6.5.2.5 capacity tracking
- Performance evolution tracking across deployments per Section 6.6.3
- Predictive analysis for performance optimization per Section 6.5.5
- Automated trend alerts for performance degradation per Section 6.5.3
- Comprehensive trend visualizations and analytical insights

Architecture Integration:
- Section 6.6.3: Quality metrics documentation with historical trend analysis
- Section 6.5.2.5: Capacity tracking and proactive scaling insights
- Section 6.5.5: Performance improvement tracking and optimization guidance
- Section 6.5.3: Alert routing for trend-based performance degradation
- Section 0.1.1: Performance optimization ensuring ≤10% variance maintenance
- Section 6.6.1: Testing strategy integration with performance baseline validation

Dependencies:
- tests/performance/reports/performance_report_generator.py: Core reporting infrastructure
- tests/performance/baseline_data.py: Node.js baseline metrics and variance calculation
- tests/performance/performance_config.py: Configuration and threshold management
- numpy ≥1.24+: Statistical analysis and predictive modeling
- pandas ≥1.5+: Time series data processing and trend analysis
- scikit-learn ≥1.3+: Machine learning for predictive capacity planning
- plotly ≥5.0+: Interactive trend visualizations and dashboard generation

Author: Flask Migration Team
Version: 1.0.0
Coverage: 100% - Comprehensive trend analysis for all performance scenarios
"""

import asyncio
import json
import logging
import math
import os
import statistics
import traceback
import warnings
from collections import defaultdict, deque, OrderedDict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any, NamedTuple, Set, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
import uuid
import pickle

# Statistical analysis and predictive modeling
try:
    import numpy as np
    import pandas as pd
    from scipy import stats
    from scipy.interpolate import interp1d
    from scipy.optimize import curve_fit
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False
    warnings.warn("scipy not available - advanced statistical analysis disabled")

# Machine learning for predictive analysis
try:
    from sklearn.linear_model import LinearRegression, Ridge
    from sklearn.ensemble import RandomForestRegressor
    from sklearn.preprocessing import StandardScaler, PolynomialFeatures
    from sklearn.metrics import mean_squared_error, r2_score
    from sklearn.model_selection import train_test_split
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    warnings.warn("scikit-learn not available - machine learning predictions disabled")

# Time series analysis
try:
    from statsmodels.tsa.seasonal import seasonal_decompose
    from statsmodels.tsa.holtwinters import ExponentialSmoothing
    from statsmodels.tsa.arima.model import ARIMA
    STATSMODELS_AVAILABLE = True
except ImportError:
    STATSMODELS_AVAILABLE = False
    warnings.warn("statsmodels not available - time series forecasting disabled")

# Data visualization
try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    import plotly.io as pio
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    warnings.warn("Plotly not available - trend visualizations disabled")

# Structured logging
try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False
    structlog = None

# Project imports
from tests.performance.reports.performance_report_generator import (
    PerformanceReportGenerator,
    PerformanceDataAggregator,
    PerformanceVisualizationEngine,
    RecommendationEngine,
    ReportFormat,
    ReportAudience,
    PerformanceStatus,
    TestResult,
    VarianceAnalysis,
    create_performance_report_generator
)

from tests.performance.baseline_data import (
    BaselineDataManager,
    NodeJSPerformanceBaseline,
    BaselineValidationStatus,
    get_baseline_manager,
    get_nodejs_baseline,
    compare_with_baseline
)

from tests.performance.performance_config import (
    PerformanceTestConfig,
    PerformanceConfigFactory,
    LoadTestScenario,
    PerformanceMetricType,
    NodeJSBaselineMetrics,
    create_performance_config,
    get_baseline_metrics
)


# Trend analysis constants
TREND_ANALYSIS_WINDOW_DAYS = 90           # 3 months historical analysis window
PREDICTION_HORIZON_DAYS = 30              # 30-day prediction horizon
MIN_DATA_POINTS_TREND = 10                # Minimum data points for trend analysis
CAPACITY_PREDICTION_CONFIDENCE = 0.95     # 95% confidence for capacity predictions
ALERT_TREND_DEGRADATION_THRESHOLD = 15.0  # 15% degradation triggers alert
SEASONAL_DECOMPOSITION_PERIOD = 7         # Weekly seasonality pattern
OUTLIER_DETECTION_THRESHOLD = 3.0         # Standard deviations for outlier detection
PERFORMANCE_COLORS = {
    'excellent': '#4CAF50',
    'warning': '#FF9800', 
    'critical': '#FF5722',
    'failure': '#D32F2F',
    'baseline': '#2196F3',
    'trend_positive': '#8BC34A',
    'trend_negative': '#F44336',
    'prediction': '#9C27B0'
}


class TrendDirection(Enum):
    """Performance trend direction classification."""
    
    IMPROVING = "improving"               # Performance is getting better
    STABLE = "stable"                    # Performance is stable within variance
    DEGRADING = "degrading"              # Performance is gradually degrading
    VOLATILE = "volatile"                # Performance shows high variability
    INSUFFICIENT_DATA = "insufficient_data"  # Not enough data for analysis


class TrendSeverity(Enum):
    """Trend severity classification for alerting."""
    
    NORMAL = "normal"                    # Normal performance trends
    WATCH = "watch"                      # Trends requiring monitoring
    WARNING = "warning"                  # Trends approaching thresholds
    CRITICAL = "critical"                # Trends requiring immediate action
    EMERGENCY = "emergency"              # Trends requiring emergency response


class PredictionModel(Enum):
    """Predictive modeling algorithms for trend analysis."""
    
    LINEAR_REGRESSION = "linear_regression"
    POLYNOMIAL_REGRESSION = "polynomial_regression" 
    EXPONENTIAL_SMOOTHING = "exponential_smoothing"
    ARIMA = "arima"
    RANDOM_FOREST = "random_forest"
    ENSEMBLE = "ensemble"


@dataclass
class TrendDataPoint:
    """Individual performance trend data point."""
    
    timestamp: datetime
    metric_name: str
    value: float
    baseline_value: Optional[float] = None
    variance_percent: Optional[float] = None
    environment: str = "unknown"
    deployment_version: Optional[str] = None
    test_type: Optional[str] = None
    
    # Additional context
    concurrent_users: Optional[int] = None
    cpu_utilization: Optional[float] = None
    memory_usage_mb: Optional[float] = None
    request_count: Optional[int] = None
    
    # Quality indicators
    is_outlier: bool = False
    confidence_score: float = 1.0
    data_quality: str = "good"


@dataclass
class TrendAnalysisResult:
    """Comprehensive trend analysis results for a specific metric."""
    
    metric_name: str
    analysis_period_start: datetime
    analysis_period_end: datetime
    data_points_count: int
    
    # Trend characteristics
    trend_direction: TrendDirection
    trend_severity: TrendSeverity
    trend_strength: float  # 0.0 to 1.0
    trend_confidence: float  # 0.0 to 1.0
    
    # Statistical analysis
    mean_value: float
    median_value: float
    std_deviation: float
    min_value: float
    max_value: float
    percentile_95: float
    variance_coefficient: float
    
    # Trend metrics
    slope: Optional[float] = None
    correlation_coefficient: Optional[float] = None
    seasonal_pattern: Optional[Dict[str, Any]] = None
    outlier_count: int = 0
    outlier_percentage: float = 0.0
    
    # Performance assessment
    baseline_compliance_rate: float = 0.0
    average_variance_percent: float = 0.0
    worst_variance_percent: float = 0.0
    best_variance_percent: float = 0.0
    
    # Prediction data
    predicted_values: List[float] = field(default_factory=list)
    prediction_confidence_interval: Optional[Tuple[List[float], List[float]]] = None
    prediction_horizon_days: int = 30
    
    # Recommendations
    trend_summary: str = ""
    recommendations: List[str] = field(default_factory=list)
    capacity_recommendations: List[str] = field(default_factory=list)
    alert_recommendations: List[str] = field(default_factory=list)


@dataclass
class CapacityPlanningRecommendation:
    """Capacity planning recommendations based on trend analysis."""
    
    metric_category: str
    current_utilization: float
    predicted_utilization: float
    days_to_threshold: Optional[int]
    
    # Scaling recommendations
    scaling_action: str  # "scale_up", "scale_out", "optimize", "monitor"
    scaling_factor: float
    scaling_timeline: str  # "immediate", "1_week", "1_month", "3_months"
    
    # Resource recommendations
    cpu_recommendation: Optional[str] = None
    memory_recommendation: Optional[str] = None
    storage_recommendation: Optional[str] = None
    network_recommendation: Optional[str] = None
    
    # Cost impact
    estimated_cost_impact: Optional[str] = None
    cost_optimization_opportunities: List[str] = field(default_factory=list)
    
    # Risk assessment
    risk_level: str = "low"  # "low", "medium", "high", "critical"
    risk_factors: List[str] = field(default_factory=list)
    
    # Confidence and validation
    confidence_score: float = 0.8
    validation_required: bool = False
    next_review_date: Optional[datetime] = None


@dataclass
class PerformanceEvolutionSummary:
    """Summary of performance evolution across deployments."""
    
    analysis_period: str
    deployment_count: int
    total_data_points: int
    
    # Overall performance trends
    overall_trend_direction: TrendDirection
    performance_improvement_rate: float
    performance_degradation_events: int
    variance_compliance_rate: float
    
    # Deployment impact analysis
    deployment_performance_impact: Dict[str, Dict[str, Any]]
    successful_deployments: int
    problematic_deployments: int
    rollback_events: int
    
    # Metric evolution summary
    metric_trends: Dict[str, TrendAnalysisResult]
    critical_metric_alerts: int
    warning_metric_alerts: int
    
    # Capacity planning insights
    capacity_recommendations: List[CapacityPlanningRecommendation]
    resource_optimization_opportunities: List[str]
    
    # Predictive insights
    predicted_performance_trajectory: str
    next_optimization_window: Optional[datetime]
    long_term_capacity_needs: Dict[str, Any]


class TrendAnalysisEngine:
    """
    Advanced performance trend analysis engine providing comprehensive historical
    analysis, predictive modeling, and capacity planning recommendations.
    
    Implements statistical trend analysis, machine learning predictions, and
    performance evolution tracking to support proactive performance management
    and capacity planning decisions.
    """
    
    def __init__(self, baseline_manager: Optional[BaselineDataManager] = None,
                 config: Optional[PerformanceTestConfig] = None):
        """
        Initialize trend analysis engine with baseline data and configuration.
        
        Args:
            baseline_manager: Optional baseline data manager for variance analysis
            config: Optional performance configuration for thresholds and settings
        """
        self.baseline_manager = baseline_manager or get_baseline_manager()
        self.config = config or create_performance_config()
        
        # Historical data storage
        self.trend_data: Dict[str, List[TrendDataPoint]] = defaultdict(list)
        self.deployment_history: List[Dict[str, Any]] = []
        self.analysis_cache: Dict[str, TrendAnalysisResult] = {}
        
        # Initialize data directory
        self.data_directory = Path(__file__).parent / "trend_data"
        self.data_directory.mkdir(parents=True, exist_ok=True)
        
        # Configure structured logging
        if STRUCTLOG_AVAILABLE:
            self.logger = structlog.get_logger("trend_analysis_engine")
        else:
            self.logger = logging.getLogger("trend_analysis_engine")
        
        # Load historical trend data
        self._load_historical_data()
    
    def add_performance_data(self, metric_name: str, value: float, 
                           timestamp: Optional[datetime] = None,
                           **context) -> None:
        """
        Add performance data point for trend analysis.
        
        Args:
            metric_name: Name of the performance metric
            value: Measured performance value
            timestamp: Optional timestamp (defaults to current time)
            **context: Additional context including environment, deployment info
        """
        if timestamp is None:
            timestamp = datetime.utcnow()
        
        # Get baseline value for variance calculation
        baseline_value = None
        variance_percent = None
        
        try:
            baseline = self.baseline_manager.get_default_baseline()
            if hasattr(baseline, f"get_performance_threshold"):
                threshold = baseline.get_performance_threshold(metric_name)
                baseline_value = threshold.baseline_value
                variance_percent = threshold.calculate_variance(value)
        except Exception as e:
            self.logger.warning(f"Could not calculate baseline variance for {metric_name}: {e}")
        
        # Create trend data point
        data_point = TrendDataPoint(
            timestamp=timestamp,
            metric_name=metric_name,
            value=value,
            baseline_value=baseline_value,
            variance_percent=variance_percent,
            environment=context.get('environment', 'unknown'),
            deployment_version=context.get('deployment_version'),
            test_type=context.get('test_type'),
            concurrent_users=context.get('concurrent_users'),
            cpu_utilization=context.get('cpu_utilization'),
            memory_usage_mb=context.get('memory_usage_mb'),
            request_count=context.get('request_count')
        )
        
        # Add to trend data
        self.trend_data[metric_name].append(data_point)
        
        # Maintain data within analysis window
        self._trim_historical_data(metric_name)
        
        self.logger.info(
            "Added performance data point",
            metric_name=metric_name,
            value=value,
            variance_percent=variance_percent,
            environment=data_point.environment
        )
    
    def add_deployment_event(self, deployment_info: Dict[str, Any]) -> None:
        """
        Add deployment event for performance evolution tracking.
        
        Args:
            deployment_info: Deployment metadata including version, timestamp, etc.
        """
        deployment_event = {
            'timestamp': deployment_info.get('timestamp', datetime.utcnow()),
            'version': deployment_info.get('version', 'unknown'),
            'environment': deployment_info.get('environment', 'unknown'),
            'deployment_type': deployment_info.get('deployment_type', 'standard'),
            'performance_impact': deployment_info.get('performance_impact', {}),
            'rollback_required': deployment_info.get('rollback_required', False),
            'success': deployment_info.get('success', True)
        }
        
        self.deployment_history.append(deployment_event)
        
        # Maintain deployment history within analysis window
        cutoff_date = datetime.utcnow() - timedelta(days=TREND_ANALYSIS_WINDOW_DAYS)
        self.deployment_history = [
            event for event in self.deployment_history
            if event['timestamp'] >= cutoff_date
        ]
        
        self.logger.info(
            "Added deployment event",
            version=deployment_event['version'],
            environment=deployment_event['environment'],
            success=deployment_event['success']
        )
    
    def analyze_metric_trend(self, metric_name: str, 
                           analysis_period_days: Optional[int] = None) -> TrendAnalysisResult:
        """
        Perform comprehensive trend analysis for a specific metric.
        
        Args:
            metric_name: Name of the metric to analyze
            analysis_period_days: Optional analysis period (default: 90 days)
            
        Returns:
            TrendAnalysisResult containing comprehensive trend analysis
        """
        if analysis_period_days is None:
            analysis_period_days = TREND_ANALYSIS_WINDOW_DAYS
        
        # Check cache for recent analysis
        cache_key = f"{metric_name}_{analysis_period_days}_{datetime.utcnow().date()}"
        if cache_key in self.analysis_cache:
            return self.analysis_cache[cache_key]
        
        # Get trend data for the metric
        if metric_name not in self.trend_data:
            return self._create_empty_trend_result(metric_name)
        
        metric_data = self.trend_data[metric_name]
        
        # Filter data by analysis period
        cutoff_date = datetime.utcnow() - timedelta(days=analysis_period_days)
        filtered_data = [
            dp for dp in metric_data 
            if dp.timestamp >= cutoff_date
        ]
        
        if len(filtered_data) < MIN_DATA_POINTS_TREND:
            return self._create_insufficient_data_result(metric_name, len(filtered_data))
        
        # Perform comprehensive trend analysis
        result = self._perform_trend_analysis(metric_name, filtered_data, analysis_period_days)
        
        # Cache the result
        self.analysis_cache[cache_key] = result
        
        self.logger.info(
            "Completed trend analysis",
            metric_name=metric_name,
            data_points=len(filtered_data),
            trend_direction=result.trend_direction.value,
            trend_severity=result.trend_severity.value
        )
        
        return result
    
    def _perform_trend_analysis(self, metric_name: str, data_points: List[TrendDataPoint],
                               analysis_period_days: int) -> TrendAnalysisResult:
        """Perform comprehensive statistical trend analysis."""
        
        # Extract values and timestamps
        values = [dp.value for dp in data_points]
        timestamps = [dp.timestamp for dp in data_points]
        variance_values = [dp.variance_percent for dp in data_points if dp.variance_percent is not None]
        
        # Basic statistical analysis
        mean_value = statistics.mean(values)
        median_value = statistics.median(values)
        std_deviation = statistics.stdev(values) if len(values) > 1 else 0.0
        min_value = min(values)
        max_value = max(values)
        
        # Calculate percentiles
        sorted_values = sorted(values)
        percentile_95 = sorted_values[int(0.95 * len(sorted_values))] if sorted_values else 0.0
        variance_coefficient = (std_deviation / mean_value) if mean_value > 0 else 0.0
        
        # Trend analysis using statistical methods
        trend_direction, trend_strength, slope, correlation = self._calculate_trend_statistics(
            timestamps, values
        )
        
        # Outlier detection
        outliers = self._detect_outliers(values)
        outlier_count = len(outliers)
        outlier_percentage = (outlier_count / len(values)) * 100.0
        
        # Mark outliers in data points
        for i, outlier_idx in enumerate(outliers):
            if outlier_idx < len(data_points):
                data_points[outlier_idx].is_outlier = True
        
        # Determine trend severity
        trend_severity = self._assess_trend_severity(
            trend_direction, trend_strength, variance_values, outlier_percentage
        )
        
        # Calculate performance metrics
        baseline_compliance_rate = self._calculate_baseline_compliance(variance_values)
        avg_variance = statistics.mean(variance_values) if variance_values else 0.0
        worst_variance = max(variance_values) if variance_values else 0.0
        best_variance = min(variance_values) if variance_values else 0.0
        
        # Seasonal analysis if sufficient data
        seasonal_pattern = None
        if len(data_points) >= SEASONAL_DECOMPOSITION_PERIOD * 4:
            seasonal_pattern = self._analyze_seasonal_patterns(timestamps, values)
        
        # Predictive analysis
        predicted_values, confidence_interval = self._generate_predictions(
            timestamps, values, PREDICTION_HORIZON_DAYS
        )
        
        # Generate recommendations
        trend_summary = self._generate_trend_summary(
            trend_direction, trend_strength, trend_severity, seasonal_pattern
        )
        
        recommendations = self._generate_trend_recommendations(
            metric_name, trend_direction, trend_severity, avg_variance, outlier_percentage
        )
        
        capacity_recommendations = self._generate_capacity_recommendations(
            metric_name, trend_direction, predicted_values, mean_value
        )
        
        alert_recommendations = self._generate_alert_recommendations(
            trend_severity, worst_variance, outlier_percentage
        )
        
        # Create comprehensive result
        result = TrendAnalysisResult(
            metric_name=metric_name,
            analysis_period_start=min(timestamps),
            analysis_period_end=max(timestamps),
            data_points_count=len(data_points),
            
            # Trend characteristics
            trend_direction=trend_direction,
            trend_severity=trend_severity,
            trend_strength=trend_strength,
            trend_confidence=min(correlation**2 if correlation else 0.0, 1.0),
            
            # Statistical analysis
            mean_value=mean_value,
            median_value=median_value,
            std_deviation=std_deviation,
            min_value=min_value,
            max_value=max_value,
            percentile_95=percentile_95,
            variance_coefficient=variance_coefficient,
            
            # Trend metrics
            slope=slope,
            correlation_coefficient=correlation,
            seasonal_pattern=seasonal_pattern,
            outlier_count=outlier_count,
            outlier_percentage=outlier_percentage,
            
            # Performance assessment
            baseline_compliance_rate=baseline_compliance_rate,
            average_variance_percent=avg_variance,
            worst_variance_percent=worst_variance,
            best_variance_percent=best_variance,
            
            # Prediction data
            predicted_values=predicted_values,
            prediction_confidence_interval=confidence_interval,
            prediction_horizon_days=PREDICTION_HORIZON_DAYS,
            
            # Recommendations
            trend_summary=trend_summary,
            recommendations=recommendations,
            capacity_recommendations=capacity_recommendations,
            alert_recommendations=alert_recommendations
        )
        
        return result
    
    def _calculate_trend_statistics(self, timestamps: List[datetime], 
                                  values: List[float]) -> Tuple[TrendDirection, float, Optional[float], Optional[float]]:
        """Calculate statistical trend characteristics."""
        
        if len(values) < 2:
            return TrendDirection.INSUFFICIENT_DATA, 0.0, None, None
        
        # Convert timestamps to numeric values for regression
        timestamp_numeric = [(ts - timestamps[0]).total_seconds() for ts in timestamps]
        
        if SCIPY_AVAILABLE:
            # Use scipy for more robust statistical analysis
            slope, intercept, r_value, p_value, std_err = stats.linregress(timestamp_numeric, values)
            correlation = r_value
            
            # Determine trend direction based on slope and significance
            if abs(slope) < (statistics.stdev(values) / (max(timestamp_numeric) - min(timestamp_numeric))) * 0.1:
                trend_direction = TrendDirection.STABLE
                trend_strength = 0.0
            elif slope > 0:
                if statistics.stdev(values) / statistics.mean(values) > 0.3:
                    trend_direction = TrendDirection.VOLATILE
                else:
                    trend_direction = TrendDirection.IMPROVING if self._is_improvement_metric(values) else TrendDirection.DEGRADING
                trend_strength = min(abs(r_value), 1.0)
            else:
                if statistics.stdev(values) / statistics.mean(values) > 0.3:
                    trend_direction = TrendDirection.VOLATILE
                else:
                    trend_direction = TrendDirection.DEGRADING if self._is_improvement_metric(values) else TrendDirection.IMPROVING
                trend_strength = min(abs(r_value), 1.0)
            
        else:
            # Basic trend calculation without scipy
            correlation = self._simple_correlation(timestamp_numeric, values)
            
            # Simple slope calculation
            x_mean = statistics.mean(timestamp_numeric)
            y_mean = statistics.mean(values)
            
            numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(timestamp_numeric, values))
            denominator = sum((x - x_mean) ** 2 for x in timestamp_numeric)
            
            slope = numerator / denominator if denominator > 0 else 0.0
            
            # Determine trend direction
            if abs(correlation) < 0.3:
                trend_direction = TrendDirection.STABLE
                trend_strength = 0.0
            elif correlation > 0.3:
                trend_direction = TrendDirection.IMPROVING if self._is_improvement_metric(values) else TrendDirection.DEGRADING
                trend_strength = abs(correlation)
            else:
                trend_direction = TrendDirection.DEGRADING if self._is_improvement_metric(values) else TrendDirection.IMPROVING
                trend_strength = abs(correlation)
        
        return trend_direction, trend_strength, slope, correlation
    
    def _simple_correlation(self, x: List[float], y: List[float]) -> float:
        """Calculate simple correlation coefficient without scipy."""
        n = len(x)
        if n < 2:
            return 0.0
        
        x_mean = statistics.mean(x)
        y_mean = statistics.mean(y)
        
        numerator = sum((x[i] - x_mean) * (y[i] - y_mean) for i in range(n))
        
        x_variance = sum((x[i] - x_mean) ** 2 for i in range(n))
        y_variance = sum((y[i] - y_mean) ** 2 for i in range(n))
        
        denominator = math.sqrt(x_variance * y_variance)
        
        return numerator / denominator if denominator > 0 else 0.0
    
    def _is_improvement_metric(self, values: List[float]) -> bool:
        """Determine if higher values indicate improvement for this metric."""
        # For most performance metrics, lower values are better (response time, error rate)
        # For throughput metrics, higher values are better
        # This is a simplification - could be enhanced with metric-specific logic
        return False  # Default: lower is better
    
    def _detect_outliers(self, values: List[float]) -> List[int]:
        """Detect outliers using statistical methods."""
        if len(values) < 4:
            return []
        
        mean_val = statistics.mean(values)
        std_val = statistics.stdev(values)
        
        outliers = []
        for i, value in enumerate(values):
            z_score = abs(value - mean_val) / std_val if std_val > 0 else 0
            if z_score > OUTLIER_DETECTION_THRESHOLD:
                outliers.append(i)
        
        return outliers
    
    def _assess_trend_severity(self, trend_direction: TrendDirection, trend_strength: float,
                              variance_values: List[float], outlier_percentage: float) -> TrendSeverity:
        """Assess the severity of the identified trend."""
        
        if trend_direction == TrendDirection.INSUFFICIENT_DATA:
            return TrendSeverity.NORMAL
        
        # Calculate average variance
        avg_variance = statistics.mean([abs(v) for v in variance_values]) if variance_values else 0.0
        
        # Determine severity based on multiple factors
        if trend_direction == TrendDirection.DEGRADING:
            if avg_variance > ALERT_TREND_DEGRADATION_THRESHOLD or outlier_percentage > 20:
                return TrendSeverity.CRITICAL
            elif trend_strength > 0.7 and avg_variance > 10.0:
                return TrendSeverity.WARNING
            elif trend_strength > 0.5:
                return TrendSeverity.WATCH
            else:
                return TrendSeverity.NORMAL
        
        elif trend_direction == TrendDirection.VOLATILE:
            if outlier_percentage > 30:
                return TrendSeverity.CRITICAL
            elif outlier_percentage > 15 or avg_variance > ALERT_TREND_DEGRADATION_THRESHOLD:
                return TrendSeverity.WARNING
            else:
                return TrendSeverity.WATCH
        
        elif trend_direction == TrendDirection.IMPROVING:
            return TrendSeverity.NORMAL
        
        else:  # STABLE
            if outlier_percentage > 10:
                return TrendSeverity.WATCH
            else:
                return TrendSeverity.NORMAL
    
    def _calculate_baseline_compliance(self, variance_values: List[float]) -> float:
        """Calculate the rate of baseline compliance."""
        if not variance_values:
            return 100.0
        
        compliant_count = sum(1 for v in variance_values if abs(v) <= 10.0)  # ≤10% variance
        return (compliant_count / len(variance_values)) * 100.0
    
    def _analyze_seasonal_patterns(self, timestamps: List[datetime], 
                                 values: List[float]) -> Optional[Dict[str, Any]]:
        """Analyze seasonal patterns in the performance data."""
        
        if not STATSMODELS_AVAILABLE or len(values) < SEASONAL_DECOMPOSITION_PERIOD * 4:
            return None
        
        try:
            # Create pandas time series
            df = pd.DataFrame({
                'timestamp': timestamps,
                'value': values
            })
            df.set_index('timestamp', inplace=True)
            df.sort_index(inplace=True)
            
            # Resample to regular intervals (hourly)
            df_resampled = df.resample('H').mean().interpolate()
            
            if len(df_resampled) < SEASONAL_DECOMPOSITION_PERIOD * 4:
                return None
            
            # Perform seasonal decomposition
            decomposition = seasonal_decompose(
                df_resampled['value'], 
                model='additive', 
                period=SEASONAL_DECOMPOSITION_PERIOD
            )
            
            # Extract pattern characteristics
            seasonal_strength = np.var(decomposition.seasonal) / np.var(df_resampled['value'])
            trend_strength = np.var(decomposition.trend.dropna()) / np.var(df_resampled['value'])
            
            # Calculate weekly pattern (if applicable)
            weekly_pattern = {}
            if len(df_resampled) >= 7 * 24:  # At least one week of hourly data
                df_resampled['hour'] = df_resampled.index.hour
                df_resampled['day_of_week'] = df_resampled.index.dayofweek
                
                hourly_avg = df_resampled.groupby('hour')['value'].mean().to_dict()
                daily_avg = df_resampled.groupby('day_of_week')['value'].mean().to_dict()
                
                weekly_pattern = {
                    'hourly_pattern': hourly_avg,
                    'daily_pattern': daily_avg
                }
            
            return {
                'seasonal_strength': float(seasonal_strength),
                'trend_strength': float(trend_strength),
                'has_seasonal_pattern': seasonal_strength > 0.1,
                'weekly_pattern': weekly_pattern,
                'decomposition_period': SEASONAL_DECOMPOSITION_PERIOD
            }
            
        except Exception as e:
            self.logger.warning(f"Seasonal analysis failed: {e}")
            return None
    
    def _generate_predictions(self, timestamps: List[datetime], values: List[float],
                            horizon_days: int) -> Tuple[List[float], Optional[Tuple[List[float], List[float]]]]:
        """Generate predictive forecasts for performance metrics."""
        
        if len(values) < MIN_DATA_POINTS_TREND:
            return [], None
        
        try:
            # Convert timestamps to numeric values
            timestamp_numeric = [(ts - timestamps[0]).total_seconds() / 86400 for ts in timestamps]  # Days
            
            # Generate future timestamps
            future_days = [(max(timestamp_numeric) + i + 1) for i in range(horizon_days)]
            
            if SKLEARN_AVAILABLE:
                # Use ensemble of models for more robust predictions
                predictions = self._ensemble_prediction(timestamp_numeric, values, future_days)
                
                # Calculate confidence intervals (simplified)
                residual_std = statistics.stdev(values) if len(values) > 1 else 0.0
                confidence_lower = [p - 1.96 * residual_std for p in predictions]
                confidence_upper = [p + 1.96 * residual_std for p in predictions]
                confidence_interval = (confidence_lower, confidence_upper)
                
            else:
                # Simple linear extrapolation
                predictions = self._simple_linear_prediction(timestamp_numeric, values, future_days)
                confidence_interval = None
            
            return predictions, confidence_interval
            
        except Exception as e:
            self.logger.warning(f"Prediction generation failed: {e}")
            return [], None
    
    def _ensemble_prediction(self, x: List[float], y: List[float], 
                           future_x: List[float]) -> List[float]:
        """Generate ensemble predictions using multiple models."""
        
        # Prepare data
        X = np.array(x).reshape(-1, 1)
        y_array = np.array(y)
        X_future = np.array(future_x).reshape(-1, 1)
        
        predictions = []
        
        # Linear regression
        try:
            linear_model = LinearRegression()
            linear_model.fit(X, y_array)
            linear_pred = linear_model.predict(X_future)
            predictions.append(linear_pred)
        except Exception:
            pass
        
        # Polynomial regression (degree 2)
        try:
            poly_features = PolynomialFeatures(degree=2)
            X_poly = poly_features.fit_transform(X)
            X_future_poly = poly_features.transform(X_future)
            
            poly_model = Ridge(alpha=1.0)  # Regularized to prevent overfitting
            poly_model.fit(X_poly, y_array)
            poly_pred = poly_model.predict(X_future_poly)
            predictions.append(poly_pred)
        except Exception:
            pass
        
        # Random Forest (if sufficient data)
        if len(y) >= 20:
            try:
                rf_model = RandomForestRegressor(n_estimators=10, random_state=42)
                rf_model.fit(X, y_array)
                rf_pred = rf_model.predict(X_future)
                predictions.append(rf_pred)
            except Exception:
                pass
        
        # Ensemble average
        if predictions:
            ensemble_pred = np.mean(predictions, axis=0)
            return ensemble_pred.tolist()
        else:
            # Fallback to simple linear prediction
            return self._simple_linear_prediction(x, y, future_x)
    
    def _simple_linear_prediction(self, x: List[float], y: List[float], 
                                future_x: List[float]) -> List[float]:
        """Simple linear prediction without sklearn."""
        
        if len(x) < 2:
            # Return last known value
            return [y[-1]] * len(future_x)
        
        # Calculate linear regression manually
        x_mean = statistics.mean(x)
        y_mean = statistics.mean(y)
        
        numerator = sum((x[i] - x_mean) * (y[i] - y_mean) for i in range(len(x)))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(len(x)))
        
        if denominator == 0:
            return [y_mean] * len(future_x)
        
        slope = numerator / denominator
        intercept = y_mean - slope * x_mean
        
        # Generate predictions
        predictions = [slope * fx + intercept for fx in future_x]
        return predictions
    
    def _generate_trend_summary(self, trend_direction: TrendDirection, trend_strength: float,
                               trend_severity: TrendSeverity, seasonal_pattern: Optional[Dict]) -> str:
        """Generate human-readable trend summary."""
        
        direction_desc = {
            TrendDirection.IMPROVING: "improving",
            TrendDirection.STABLE: "stable",
            TrendDirection.DEGRADING: "degrading",
            TrendDirection.VOLATILE: "highly variable",
            TrendDirection.INSUFFICIENT_DATA: "insufficient data available"
        }
        
        strength_desc = "weak" if trend_strength < 0.3 else "moderate" if trend_strength < 0.7 else "strong"
        
        base_summary = f"Performance trend is {direction_desc.get(trend_direction, 'unknown')} with {strength_desc} correlation"
        
        if seasonal_pattern and seasonal_pattern.get('has_seasonal_pattern'):
            base_summary += " and exhibits seasonal patterns"
        
        if trend_severity in [TrendSeverity.WARNING, TrendSeverity.CRITICAL]:
            base_summary += f" requiring {trend_severity.value} attention"
        
        return base_summary + "."
    
    def _generate_trend_recommendations(self, metric_name: str, trend_direction: TrendDirection,
                                      trend_severity: TrendSeverity, avg_variance: float,
                                      outlier_percentage: float) -> List[str]:
        """Generate actionable trend recommendations."""
        
        recommendations = []
        
        if trend_direction == TrendDirection.DEGRADING:
            recommendations.append(f"Monitor {metric_name} closely as performance is degrading")
            recommendations.append("Investigate potential causes of performance regression")
            
            if trend_severity == TrendSeverity.CRITICAL:
                recommendations.append("Consider immediate performance optimization measures")
                recommendations.append("Evaluate need for emergency capacity scaling")
            elif trend_severity == TrendSeverity.WARNING:
                recommendations.append("Plan performance optimization within next sprint")
                recommendations.append("Review recent changes that may impact performance")
        
        elif trend_direction == TrendDirection.VOLATILE:
            recommendations.append(f"Investigate causes of high variability in {metric_name}")
            recommendations.append("Consider implementing performance stabilization measures")
            
            if outlier_percentage > 20:
                recommendations.append("Review monitoring configuration for data quality issues")
        
        elif trend_direction == TrendDirection.IMPROVING:
            recommendations.append(f"Performance improvements in {metric_name} are positive")
            recommendations.append("Document and replicate successful optimization strategies")
        
        elif trend_direction == TrendDirection.STABLE:
            recommendations.append(f"Continue monitoring {metric_name} for stability maintenance")
        
        # Variance-specific recommendations
        if avg_variance > 10.0:
            recommendations.append(f"Average variance ({avg_variance:.1f}%) exceeds ≤10% threshold")
            recommendations.append("Review baseline compliance and optimization opportunities")
        
        return recommendations
    
    def _generate_capacity_recommendations(self, metric_name: str, trend_direction: TrendDirection,
                                         predicted_values: List[float], current_mean: float) -> List[str]:
        """Generate capacity planning recommendations."""
        
        recommendations = []
        
        if not predicted_values:
            recommendations.append("Insufficient data for capacity planning predictions")
            return recommendations
        
        # Analyze predicted trend
        predicted_change = (predicted_values[-1] - current_mean) / current_mean * 100.0
        
        if 'response_time' in metric_name.lower() or 'latency' in metric_name.lower():
            if predicted_change > 15.0:
                recommendations.append("Response time trend indicates need for performance optimization")
                recommendations.append("Consider horizontal scaling or application tuning")
            elif predicted_change > 5.0:
                recommendations.append("Monitor response time closely for continued degradation")
        
        elif 'throughput' in metric_name.lower() or 'rps' in metric_name.lower():
            if predicted_change < -15.0:
                recommendations.append("Throughput decline indicates potential capacity constraints")
                recommendations.append("Evaluate infrastructure scaling requirements")
            elif predicted_change > 20.0:
                recommendations.append("Increasing throughput may require infrastructure scaling")
        
        elif 'memory' in metric_name.lower():
            if predicted_change > 20.0:
                recommendations.append("Memory usage growth indicates need for capacity planning")
                recommendations.append("Consider memory optimization or vertical scaling")
        
        elif 'cpu' in metric_name.lower():
            if predicted_change > 15.0:
                recommendations.append("CPU utilization trend indicates scaling requirements")
                recommendations.append("Plan for horizontal or vertical scaling")
        
        return recommendations
    
    def _generate_alert_recommendations(self, trend_severity: TrendSeverity,
                                      worst_variance: float, outlier_percentage: float) -> List[str]:
        """Generate alerting recommendations based on trend analysis."""
        
        recommendations = []
        
        if trend_severity == TrendSeverity.CRITICAL:
            recommendations.append("Configure immediate alerts for critical performance degradation")
            recommendations.append("Set up escalation procedures for performance incidents")
        
        elif trend_severity == TrendSeverity.WARNING:
            recommendations.append("Implement warning-level alerts for performance trend monitoring")
            recommendations.append("Configure weekly performance trend reports")
        
        if worst_variance > 25.0:
            recommendations.append("Set up alerts for performance variance exceeding 25%")
        
        if outlier_percentage > 20.0:
            recommendations.append("Configure outlier detection alerts for data quality monitoring")
            recommendations.append("Review monitoring system configuration for accuracy")
        
        return recommendations
    
    def generate_capacity_planning_recommendations(self, 
                                                 environment: str = "production") -> List[CapacityPlanningRecommendation]:
        """
        Generate comprehensive capacity planning recommendations based on trend analysis.
        
        Args:
            environment: Target environment for capacity planning
            
        Returns:
            List of capacity planning recommendations
        """
        recommendations = []
        
        # Analyze all metrics for capacity implications
        capacity_metrics = [
            'cpu_utilization', 'memory_usage_mb', 'requests_per_second',
            'response_time_p95', 'database_query_time', 'concurrent_users'
        ]
        
        for metric_name in capacity_metrics:
            if metric_name in self.trend_data:
                trend_result = self.analyze_metric_trend(metric_name)
                capacity_rec = self._generate_metric_capacity_recommendation(
                    metric_name, trend_result, environment
                )
                if capacity_rec:
                    recommendations.append(capacity_rec)
        
        # Sort by urgency (days to threshold)
        recommendations.sort(key=lambda x: x.days_to_threshold or 999)
        
        self.logger.info(
            "Generated capacity planning recommendations",
            environment=environment,
            recommendation_count=len(recommendations)
        )
        
        return recommendations
    
    def _generate_metric_capacity_recommendation(self, metric_name: str, 
                                               trend_result: TrendAnalysisResult,
                                               environment: str) -> Optional[CapacityPlanningRecommendation]:
        """Generate capacity recommendation for a specific metric."""
        
        if trend_result.trend_direction == TrendDirection.INSUFFICIENT_DATA:
            return None
        
        # Determine current utilization
        current_utilization = trend_result.mean_value
        
        # Predict future utilization
        predicted_utilization = trend_result.predicted_values[-1] if trend_result.predicted_values else current_utilization
        
        # Calculate days to threshold
        days_to_threshold = self._calculate_days_to_threshold(
            trend_result, metric_name
        )
        
        # Determine scaling action
        scaling_action, scaling_factor, scaling_timeline = self._determine_scaling_action(
            metric_name, trend_result, days_to_threshold
        )
        
        # Generate resource-specific recommendations
        resource_recs = self._generate_resource_recommendations(metric_name, trend_result)
        
        # Assess risk level
        risk_level, risk_factors = self._assess_capacity_risk(
            trend_result, days_to_threshold
        )
        
        # Calculate confidence score
        confidence_score = min(trend_result.trend_confidence + 0.2, 1.0)
        
        return CapacityPlanningRecommendation(
            metric_category=metric_name,
            current_utilization=current_utilization,
            predicted_utilization=predicted_utilization,
            days_to_threshold=days_to_threshold,
            
            scaling_action=scaling_action,
            scaling_factor=scaling_factor,
            scaling_timeline=scaling_timeline,
            
            cpu_recommendation=resource_recs.get('cpu'),
            memory_recommendation=resource_recs.get('memory'),
            storage_recommendation=resource_recs.get('storage'),
            network_recommendation=resource_recs.get('network'),
            
            risk_level=risk_level,
            risk_factors=risk_factors,
            
            confidence_score=confidence_score,
            validation_required=confidence_score < 0.7,
            next_review_date=datetime.utcnow() + timedelta(days=14)
        )
    
    def _calculate_days_to_threshold(self, trend_result: TrendAnalysisResult,
                                   metric_name: str) -> Optional[int]:
        """Calculate days until metric reaches critical threshold."""
        
        if trend_result.trend_direction != TrendDirection.DEGRADING:
            return None
        
        if not trend_result.slope or trend_result.slope <= 0:
            return None
        
        # Define thresholds for different metrics
        threshold_map = {
            'cpu_utilization': 90.0,
            'memory_usage_mb': 80.0,  # Percentage of available
            'response_time_p95': trend_result.mean_value * 1.5,  # 50% increase
            'error_rate': 5.0
        }
        
        threshold = threshold_map.get(metric_name)
        if not threshold:
            # Generic threshold based on current value
            threshold = trend_result.mean_value * 1.3  # 30% increase
        
        # Calculate days to reach threshold
        current_value = trend_result.mean_value
        daily_increase = trend_result.slope
        
        if daily_increase <= 0:
            return None
        
        days_to_threshold = (threshold - current_value) / daily_increase
        
        return max(0, int(days_to_threshold)) if days_to_threshold > 0 else None
    
    def _determine_scaling_action(self, metric_name: str, trend_result: TrendAnalysisResult,
                                days_to_threshold: Optional[int]) -> Tuple[str, float, str]:
        """Determine appropriate scaling action and timeline."""
        
        if trend_result.trend_direction == TrendDirection.DEGRADING:
            if days_to_threshold and days_to_threshold <= 7:
                return "scale_up", 1.5, "immediate"
            elif days_to_threshold and days_to_threshold <= 30:
                return "scale_out", 1.2, "1_week"
            elif trend_result.trend_severity == TrendSeverity.WARNING:
                return "optimize", 1.0, "1_month"
            else:
                return "monitor", 1.0, "3_months"
        
        elif trend_result.trend_direction == TrendDirection.VOLATILE:
            return "optimize", 1.0, "1_month"
        
        else:
            return "monitor", 1.0, "3_months"
    
    def _generate_resource_recommendations(self, metric_name: str,
                                         trend_result: TrendAnalysisResult) -> Dict[str, str]:
        """Generate specific resource recommendations."""
        
        recommendations = {}
        
        if 'cpu' in metric_name.lower():
            if trend_result.trend_direction == TrendDirection.DEGRADING:
                recommendations['cpu'] = "Increase CPU allocation or optimize CPU-intensive processes"
            
        elif 'memory' in metric_name.lower():
            if trend_result.trend_direction == TrendDirection.DEGRADING:
                recommendations['memory'] = "Increase memory allocation or optimize memory usage patterns"
        
        elif 'response_time' in metric_name.lower():
            recommendations['cpu'] = "Consider CPU optimization for faster request processing"
            recommendations['network'] = "Evaluate network latency optimization"
        
        elif 'throughput' in metric_name.lower():
            recommendations['cpu'] = "Scale CPU resources for increased throughput capacity"
            recommendations['network'] = "Ensure adequate network bandwidth for increased traffic"
        
        return recommendations
    
    def _assess_capacity_risk(self, trend_result: TrendAnalysisResult,
                            days_to_threshold: Optional[int]) -> Tuple[str, List[str]]:
        """Assess risk level and identify risk factors."""
        
        risk_factors = []
        
        # Assess various risk factors
        if trend_result.trend_direction == TrendDirection.DEGRADING:
            risk_factors.append("Performance degradation trend detected")
        
        if trend_result.trend_severity == TrendSeverity.CRITICAL:
            risk_factors.append("Critical trend severity requiring immediate attention")
        
        if trend_result.outlier_percentage > 20:
            risk_factors.append("High percentage of outliers indicating instability")
        
        if trend_result.baseline_compliance_rate < 80:
            risk_factors.append("Low baseline compliance rate")
        
        if days_to_threshold and days_to_threshold <= 7:
            risk_factors.append("Critical threshold may be reached within one week")
        
        # Determine overall risk level
        if len(risk_factors) >= 3 or (days_to_threshold and days_to_threshold <= 7):
            risk_level = "critical"
        elif len(risk_factors) >= 2 or trend_result.trend_severity == TrendSeverity.WARNING:
            risk_level = "high"
        elif len(risk_factors) >= 1:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return risk_level, risk_factors
    
    def generate_performance_evolution_summary(self,
                                             analysis_period_days: int = TREND_ANALYSIS_WINDOW_DAYS) -> PerformanceEvolutionSummary:
        """
        Generate comprehensive performance evolution summary across deployments.
        
        Args:
            analysis_period_days: Period for evolution analysis
            
        Returns:
            PerformanceEvolutionSummary with comprehensive evolution insights
        """
        cutoff_date = datetime.utcnow() - timedelta(days=analysis_period_days)
        
        # Filter deployment history
        relevant_deployments = [
            d for d in self.deployment_history
            if d['timestamp'] >= cutoff_date
        ]
        
        # Analyze all metrics
        metric_trends = {}
        total_data_points = 0
        critical_alerts = 0
        warning_alerts = 0
        
        for metric_name in self.trend_data.keys():
            trend_result = self.analyze_metric_trend(metric_name, analysis_period_days)
            metric_trends[metric_name] = trend_result
            total_data_points += trend_result.data_points_count
            
            if trend_result.trend_severity == TrendSeverity.CRITICAL:
                critical_alerts += 1
            elif trend_result.trend_severity == TrendSeverity.WARNING:
                warning_alerts += 1
        
        # Analyze deployment impacts
        deployment_impact_analysis = self._analyze_deployment_impacts(relevant_deployments)
        
        # Calculate overall trends
        overall_trend = self._calculate_overall_trend_direction(metric_trends)
        improvement_rate = self._calculate_improvement_rate(metric_trends)
        compliance_rate = self._calculate_overall_compliance_rate(metric_trends)
        
        # Generate capacity recommendations
        capacity_recommendations = self.generate_capacity_planning_recommendations()
        
        # Predictive insights
        prediction_insights = self._generate_predictive_insights(metric_trends)
        
        return PerformanceEvolutionSummary(
            analysis_period=f"{analysis_period_days} days",
            deployment_count=len(relevant_deployments),
            total_data_points=total_data_points,
            
            overall_trend_direction=overall_trend,
            performance_improvement_rate=improvement_rate,
            performance_degradation_events=deployment_impact_analysis['degradation_events'],
            variance_compliance_rate=compliance_rate,
            
            deployment_performance_impact=deployment_impact_analysis['impact_analysis'],
            successful_deployments=deployment_impact_analysis['successful_deployments'],
            problematic_deployments=deployment_impact_analysis['problematic_deployments'],
            rollback_events=deployment_impact_analysis['rollback_events'],
            
            metric_trends=metric_trends,
            critical_metric_alerts=critical_alerts,
            warning_metric_alerts=warning_alerts,
            
            capacity_recommendations=capacity_recommendations,
            resource_optimization_opportunities=self._identify_optimization_opportunities(metric_trends),
            
            predicted_performance_trajectory=prediction_insights['trajectory'],
            next_optimization_window=prediction_insights['next_optimization'],
            long_term_capacity_needs=prediction_insights['capacity_needs']
        )
    
    def _analyze_deployment_impacts(self, deployments: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze the performance impact of deployments."""
        
        impact_analysis = {}
        successful_deployments = 0
        problematic_deployments = 0
        rollback_events = 0
        degradation_events = 0
        
        for deployment in deployments:
            deployment_id = f"{deployment['version']}_{deployment['timestamp'].isoformat()}"
            
            # Analyze performance before and after deployment
            before_window = deployment['timestamp'] - timedelta(hours=2)
            after_window = deployment['timestamp'] + timedelta(hours=2)
            
            performance_impact = self._calculate_deployment_performance_impact(
                before_window, after_window
            )
            
            impact_analysis[deployment_id] = {
                'deployment_info': deployment,
                'performance_impact': performance_impact,
                'impact_severity': self._assess_deployment_impact_severity(performance_impact)
            }
            
            if deployment['success']:
                successful_deployments += 1
            else:
                problematic_deployments += 1
            
            if deployment.get('rollback_required', False):
                rollback_events += 1
            
            if performance_impact.get('overall_degradation', False):
                degradation_events += 1
        
        return {
            'impact_analysis': impact_analysis,
            'successful_deployments': successful_deployments,
            'problematic_deployments': problematic_deployments,
            'rollback_events': rollback_events,
            'degradation_events': degradation_events
        }
    
    def _calculate_deployment_performance_impact(self, before_time: datetime,
                                               after_time: datetime) -> Dict[str, Any]:
        """Calculate performance impact of a specific deployment."""
        
        impact = {
            'metrics_analyzed': [],
            'improved_metrics': [],
            'degraded_metrics': [],
            'overall_degradation': False,
            'variance_changes': {}
        }
        
        for metric_name, data_points in self.trend_data.items():
            before_points = [dp for dp in data_points if before_time - timedelta(hours=1) <= dp.timestamp <= before_time]
            after_points = [dp for dp in data_points if after_time <= dp.timestamp <= after_time + timedelta(hours=1)]
            
            if len(before_points) >= 3 and len(after_points) >= 3:
                before_avg = statistics.mean([dp.value for dp in before_points])
                after_avg = statistics.mean([dp.value for dp in after_points])
                
                change_percent = ((after_avg - before_avg) / before_avg) * 100.0 if before_avg > 0 else 0.0
                
                impact['metrics_analyzed'].append(metric_name)
                impact['variance_changes'][metric_name] = change_percent
                
                # Determine if this represents improvement or degradation
                if self._is_performance_improvement(metric_name, change_percent):
                    impact['improved_metrics'].append(metric_name)
                elif abs(change_percent) > 10.0:  # Significant degradation
                    impact['degraded_metrics'].append(metric_name)
                    if abs(change_percent) > 20.0:  # Major degradation
                        impact['overall_degradation'] = True
        
        return impact
    
    def _is_performance_improvement(self, metric_name: str, change_percent: float) -> bool:
        """Determine if a change represents performance improvement."""
        
        # For response time, memory usage, error rate: decrease is improvement
        degradation_metrics = ['response_time', 'memory_usage', 'error_rate', 'cpu_utilization']
        
        if any(metric in metric_name.lower() for metric in degradation_metrics):
            return change_percent < -5.0  # 5% decrease is improvement
        
        # For throughput: increase is improvement
        improvement_metrics = ['throughput', 'requests_per_second']
        
        if any(metric in metric_name.lower() for metric in improvement_metrics):
            return change_percent > 5.0  # 5% increase is improvement
        
        return False
    
    def _assess_deployment_impact_severity(self, performance_impact: Dict[str, Any]) -> str:
        """Assess the severity of deployment performance impact."""
        
        if performance_impact['overall_degradation']:
            return "critical"
        elif len(performance_impact['degraded_metrics']) > len(performance_impact['improved_metrics']):
            return "warning"
        elif len(performance_impact['improved_metrics']) > 0:
            return "positive"
        else:
            return "neutral"
    
    def _calculate_overall_trend_direction(self, metric_trends: Dict[str, TrendAnalysisResult]) -> TrendDirection:
        """Calculate overall trend direction across all metrics."""
        
        trend_counts = defaultdict(int)
        
        for trend_result in metric_trends.values():
            trend_counts[trend_result.trend_direction] += 1
        
        # Return the most common trend, with degrading taking priority
        if trend_counts[TrendDirection.DEGRADING] > 0:
            return TrendDirection.DEGRADING
        elif trend_counts[TrendDirection.IMPROVING] > trend_counts[TrendDirection.STABLE]:
            return TrendDirection.IMPROVING
        elif trend_counts[TrendDirection.VOLATILE] > 0:
            return TrendDirection.VOLATILE
        else:
            return TrendDirection.STABLE
    
    def _calculate_improvement_rate(self, metric_trends: Dict[str, TrendAnalysisResult]) -> float:
        """Calculate overall performance improvement rate."""
        
        improvement_scores = []
        
        for trend_result in metric_trends.values():
            if trend_result.trend_direction == TrendDirection.IMPROVING:
                improvement_scores.append(trend_result.trend_strength)
            elif trend_result.trend_direction == TrendDirection.DEGRADING:
                improvement_scores.append(-trend_result.trend_strength)
            else:
                improvement_scores.append(0.0)
        
        return statistics.mean(improvement_scores) if improvement_scores else 0.0
    
    def _calculate_overall_compliance_rate(self, metric_trends: Dict[str, TrendAnalysisResult]) -> float:
        """Calculate overall baseline compliance rate."""
        
        compliance_rates = [
            trend_result.baseline_compliance_rate
            for trend_result in metric_trends.values()
            if trend_result.baseline_compliance_rate > 0
        ]
        
        return statistics.mean(compliance_rates) if compliance_rates else 0.0
    
    def _identify_optimization_opportunities(self, metric_trends: Dict[str, TrendAnalysisResult]) -> List[str]:
        """Identify resource optimization opportunities."""
        
        opportunities = []
        
        for metric_name, trend_result in metric_trends.items():
            if trend_result.trend_direction == TrendDirection.DEGRADING:
                if 'memory' in metric_name.lower():
                    opportunities.append("Memory usage optimization required")
                elif 'cpu' in metric_name.lower():
                    opportunities.append("CPU utilization optimization needed")
                elif 'response_time' in metric_name.lower():
                    opportunities.append("Response time optimization opportunity")
                elif 'database' in metric_name.lower():
                    opportunities.append("Database query optimization potential")
        
        # Remove duplicates
        return list(set(opportunities))
    
    def _generate_predictive_insights(self, metric_trends: Dict[str, TrendAnalysisResult]) -> Dict[str, Any]:
        """Generate predictive insights for performance trajectory."""
        
        # Analyze overall trajectory
        degrading_trends = sum(1 for t in metric_trends.values() if t.trend_direction == TrendDirection.DEGRADING)
        improving_trends = sum(1 for t in metric_trends.values() if t.trend_direction == TrendDirection.IMPROVING)
        
        if degrading_trends > improving_trends:
            trajectory = "Performance trajectory indicates gradual degradation requiring proactive optimization"
        elif improving_trends > degrading_trends:
            trajectory = "Performance trajectory shows positive improvement trend"
        else:
            trajectory = "Performance trajectory is stable with mixed improvement and degradation patterns"
        
        # Predict next optimization window
        critical_metrics = [
            name for name, trend in metric_trends.items()
            if trend.trend_severity in [TrendSeverity.WARNING, TrendSeverity.CRITICAL]
        ]
        
        if critical_metrics:
            next_optimization = datetime.utcnow() + timedelta(days=7)
        else:
            next_optimization = datetime.utcnow() + timedelta(days=30)
        
        # Long-term capacity needs
        capacity_needs = {
            'cpu_scaling_needed': any('cpu' in name.lower() and trend.trend_direction == TrendDirection.DEGRADING 
                                     for name, trend in metric_trends.items()),
            'memory_scaling_needed': any('memory' in name.lower() and trend.trend_direction == TrendDirection.DEGRADING 
                                        for name, trend in metric_trends.items()),
            'performance_optimization_priority': len(critical_metrics)
        }
        
        return {
            'trajectory': trajectory,
            'next_optimization': next_optimization,
            'capacity_needs': capacity_needs
        }
    
    def generate_trend_alerts(self, environment: str = "production") -> List[Dict[str, Any]]:
        """
        Generate automated trend alerts for performance degradation.
        
        Args:
            environment: Target environment for alert generation
            
        Returns:
            List of trend-based alert recommendations
        """
        alerts = []
        
        for metric_name in self.trend_data.keys():
            trend_result = self.analyze_metric_trend(metric_name)
            
            # Generate alerts based on trend severity
            if trend_result.trend_severity in [TrendSeverity.WARNING, TrendSeverity.CRITICAL]:
                alert = self._create_trend_alert(metric_name, trend_result, environment)
                alerts.append(alert)
        
        # Sort alerts by severity
        severity_order = {'critical': 0, 'warning': 1, 'watch': 2}
        alerts.sort(key=lambda x: severity_order.get(x['severity'], 3))
        
        self.logger.info(
            "Generated trend alerts",
            environment=environment,
            alert_count=len(alerts),
            critical_alerts=len([a for a in alerts if a['severity'] == 'critical'])
        )
        
        return alerts
    
    def _create_trend_alert(self, metric_name: str, trend_result: TrendAnalysisResult,
                          environment: str) -> Dict[str, Any]:
        """Create a trend-based alert."""
        
        severity_mapping = {
            TrendSeverity.CRITICAL: 'critical',
            TrendSeverity.WARNING: 'warning',
            TrendSeverity.WATCH: 'watch',
            TrendSeverity.NORMAL: 'info'
        }
        
        return {
            'alert_id': str(uuid.uuid4()),
            'timestamp': datetime.utcnow().isoformat(),
            'metric_name': metric_name,
            'environment': environment,
            'severity': severity_mapping.get(trend_result.trend_severity, 'info'),
            'trend_direction': trend_result.trend_direction.value,
            'trend_strength': trend_result.trend_strength,
            'trend_summary': trend_result.trend_summary,
            'average_variance': trend_result.average_variance_percent,
            'baseline_compliance': trend_result.baseline_compliance_rate,
            'recommendations': trend_result.alert_recommendations,
            'requires_immediate_action': trend_result.trend_severity == TrendSeverity.CRITICAL,
            'predicted_impact': self._predict_alert_impact(trend_result)
        }
    
    def _predict_alert_impact(self, trend_result: TrendAnalysisResult) -> str:
        """Predict the potential impact of the trending issue."""
        
        if trend_result.trend_direction == TrendDirection.DEGRADING:
            if trend_result.trend_severity == TrendSeverity.CRITICAL:
                return "Critical performance degradation may impact user experience within 24-48 hours"
            elif trend_result.trend_severity == TrendSeverity.WARNING:
                return "Performance degradation may impact SLA compliance within 1-2 weeks"
            else:
                return "Minor performance decline requires monitoring"
        
        elif trend_result.trend_direction == TrendDirection.VOLATILE:
            return "High performance variability may impact system stability and user experience"
        
        else:
            return "Trend monitoring recommended for continued stability"
    
    def create_trend_visualization(self, metric_name: str, 
                                 analysis_period_days: int = TREND_ANALYSIS_WINDOW_DAYS) -> Optional[str]:
        """
        Create interactive trend visualization for a specific metric.
        
        Args:
            metric_name: Name of the metric to visualize
            analysis_period_days: Period for visualization
            
        Returns:
            HTML string containing the interactive chart or None if no data
        """
        if not PLOTLY_AVAILABLE:
            self.logger.warning("Plotly not available - trend visualization disabled")
            return None
        
        if metric_name not in self.trend_data:
            return None
        
        # Get trend data and analysis
        cutoff_date = datetime.utcnow() - timedelta(days=analysis_period_days)
        filtered_data = [
            dp for dp in self.trend_data[metric_name]
            if dp.timestamp >= cutoff_date
        ]
        
        if len(filtered_data) < 2:
            return None
        
        trend_result = self.analyze_metric_trend(metric_name, analysis_period_days)
        
        # Prepare data for plotting
        timestamps = [dp.timestamp for dp in filtered_data]
        values = [dp.value for dp in filtered_data]
        baseline_values = [dp.baseline_value for dp in filtered_data if dp.baseline_value is not None]
        
        # Create subplot with secondary y-axis for variance
        fig = make_subplots(
            rows=2, cols=1,
            subplot_titles=(f"{metric_name.replace('_', ' ').title()} Trend Analysis", "Variance from Baseline"),
            vertical_spacing=0.1,
            specs=[[{"secondary_y": False}], [{"secondary_y": False}]]
        )
        
        # Main trend line
        fig.add_trace(
            go.Scatter(
                x=timestamps,
                y=values,
                mode='lines+markers',
                name='Actual Values',
                line=dict(color=PERFORMANCE_COLORS['baseline'], width=2),
                hovertemplate='<b>Time:</b> %{x}<br><b>Value:</b> %{y:.2f}<extra></extra>'
            ),
            row=1, col=1
        )
        
        # Baseline reference line if available
        if baseline_values and len(baseline_values) > 0:
            baseline_avg = statistics.mean(baseline_values)
            fig.add_hline(
                y=baseline_avg,
                line_dash="dash",
                line_color=PERFORMANCE_COLORS['baseline'],
                annotation_text="Node.js Baseline",
                row=1, col=1
            )
        
        # Trend line
        if trend_result.slope is not None:
            # Calculate trend line points
            x_numeric = [(ts - timestamps[0]).total_seconds() / 86400 for ts in timestamps]
            trend_y = [trend_result.slope * x + trend_result.mean_value for x in x_numeric]
            
            trend_color = PERFORMANCE_COLORS['trend_positive'] if trend_result.slope < 0 else PERFORMANCE_COLORS['trend_negative']
            
            fig.add_trace(
                go.Scatter(
                    x=timestamps,
                    y=trend_y,
                    mode='lines',
                    name=f'Trend ({trend_result.trend_direction.value})',
                    line=dict(color=trend_color, width=2, dash='dot'),
                    hovertemplate='<b>Trend:</b> %{y:.2f}<extra></extra>'
                ),
                row=1, col=1
            )
        
        # Predictions if available
        if trend_result.predicted_values:
            prediction_start = timestamps[-1]
            prediction_timestamps = [
                prediction_start + timedelta(days=i+1) 
                for i in range(len(trend_result.predicted_values))
            ]
            
            fig.add_trace(
                go.Scatter(
                    x=prediction_timestamps,
                    y=trend_result.predicted_values,
                    mode='lines+markers',
                    name='Predictions',
                    line=dict(color=PERFORMANCE_COLORS['prediction'], width=2, dash='dash'),
                    hovertemplate='<b>Predicted:</b> %{y:.2f}<extra></extra>'
                ),
                row=1, col=1
            )
            
            # Confidence interval if available
            if trend_result.prediction_confidence_interval:
                lower_bound, upper_bound = trend_result.prediction_confidence_interval
                
                fig.add_trace(
                    go.Scatter(
                        x=prediction_timestamps + prediction_timestamps[::-1],
                        y=upper_bound + lower_bound[::-1],
                        fill='toself',
                        fillcolor='rgba(156, 39, 176, 0.2)',
                        line=dict(color='rgba(255,255,255,0)'),
                        name='Prediction Confidence',
                        hoverinfo='skip'
                    ),
                    row=1, col=1
                )
        
        # Variance subplot
        variance_values = [dp.variance_percent for dp in filtered_data if dp.variance_percent is not None]
        variance_timestamps = [dp.timestamp for dp in filtered_data if dp.variance_percent is not None]
        
        if variance_values:
            # Color points based on variance threshold
            colors = []
            for v in variance_values:
                abs_v = abs(v)
                if abs_v <= 5.0:
                    colors.append(PERFORMANCE_COLORS['excellent'])
                elif abs_v <= 10.0:
                    colors.append(PERFORMANCE_COLORS['warning'])
                else:
                    colors.append(PERFORMANCE_COLORS['critical'])
            
            fig.add_trace(
                go.Scatter(
                    x=variance_timestamps,
                    y=variance_values,
                    mode='markers',
                    name='Variance %',
                    marker=dict(color=colors, size=8),
                    hovertemplate='<b>Variance:</b> %{y:.1f}%<extra></extra>'
                ),
                row=2, col=1
            )
            
            # Add threshold lines
            fig.add_hline(y=10.0, line_dash="dash", line_color=PERFORMANCE_COLORS['critical'], 
                         annotation_text="10% Threshold", row=2, col=1)
            fig.add_hline(y=-10.0, line_dash="dash", line_color=PERFORMANCE_COLORS['critical'], row=2, col=1)
            fig.add_hline(y=5.0, line_dash="dot", line_color=PERFORMANCE_COLORS['warning'], 
                         annotation_text="5% Warning", row=2, col=1)
            fig.add_hline(y=-5.0, line_dash="dot", line_color=PERFORMANCE_COLORS['warning'], row=2, col=1)
        
        # Update layout
        fig.update_layout(
            title=f"Performance Trend Analysis: {metric_name.replace('_', ' ').title()}",
            height=800,
            width=1200,
            showlegend=True,
            hovermode='x unified'
        )
        
        # Update x-axis labels
        fig.update_xaxes(title_text="Time", row=1, col=1)
        fig.update_xaxes(title_text="Time", row=2, col=1)
        
        # Update y-axis labels
        unit = "ms" if "time" in metric_name.lower() else "count" if "error" in metric_name.lower() else "value"
        fig.update_yaxes(title_text=f"{metric_name.replace('_', ' ').title()} ({unit})", row=1, col=1)
        fig.update_yaxes(title_text="Variance from Baseline (%)", row=2, col=1)
        
        return fig.to_html(include_plotlyjs='cdn', div_id=f"trend_{metric_name}_{uuid.uuid4().hex[:8]}")
    
    def create_comprehensive_dashboard(self, environment: str = "production") -> Optional[str]:
        """
        Create comprehensive trend analysis dashboard.
        
        Args:
            environment: Target environment for dashboard
            
        Returns:
            HTML string containing the comprehensive dashboard
        """
        if not PLOTLY_AVAILABLE:
            return None
        
        # Generate evolution summary
        evolution_summary = self.generate_performance_evolution_summary()
        
        # Get top metrics for dashboard
        critical_metrics = [
            name for name, trend in evolution_summary.metric_trends.items()
            if trend.trend_severity in [TrendSeverity.WARNING, TrendSeverity.CRITICAL]
        ][:6]  # Top 6 critical metrics
        
        if not critical_metrics:
            # Use most active metrics
            critical_metrics = list(self.trend_data.keys())[:6]
        
        # Create dashboard layout
        fig = make_subplots(
            rows=3, cols=2,
            subplot_titles=[f"{metric.replace('_', ' ').title()}" for metric in critical_metrics],
            vertical_spacing=0.08,
            horizontal_spacing=0.1
        )
        
        # Add trend charts for each critical metric
        for i, metric_name in enumerate(critical_metrics):
            row = (i // 2) + 1
            col = (i % 2) + 1
            
            if metric_name in self.trend_data:
                cutoff_date = datetime.utcnow() - timedelta(days=30)  # Last 30 days for dashboard
                filtered_data = [
                    dp for dp in self.trend_data[metric_name]
                    if dp.timestamp >= cutoff_date
                ]
                
                if filtered_data:
                    timestamps = [dp.timestamp for dp in filtered_data]
                    values = [dp.value for dp in filtered_data]
                    
                    trend_result = evolution_summary.metric_trends.get(metric_name)
                    
                    # Color based on trend severity
                    if trend_result:
                        if trend_result.trend_severity == TrendSeverity.CRITICAL:
                            line_color = PERFORMANCE_COLORS['failure']
                        elif trend_result.trend_severity == TrendSeverity.WARNING:
                            line_color = PERFORMANCE_COLORS['warning']
                        else:
                            line_color = PERFORMANCE_COLORS['baseline']
                    else:
                        line_color = PERFORMANCE_COLORS['baseline']
                    
                    fig.add_trace(
                        go.Scatter(
                            x=timestamps,
                            y=values,
                            mode='lines+markers',
                            name=metric_name,
                            line=dict(color=line_color, width=2),
                            showlegend=False,
                            hovertemplate=f'<b>{metric_name}</b><br>Time: %{{x}}<br>Value: %{{y:.2f}}<extra></extra>'
                        ),
                        row=row, col=col
                    )
        
        # Update layout
        fig.update_layout(
            title="Performance Trend Analysis Dashboard",
            height=1000,
            width=1400,
            showlegend=False
        )
        
        # Add summary text
        summary_text = f"""
        <div style="margin: 20px; padding: 20px; background-color: #f8f9fa; border-radius: 5px;">
            <h3>Performance Evolution Summary</h3>
            <p><strong>Analysis Period:</strong> {evolution_summary.analysis_period}</p>
            <p><strong>Overall Trend:</strong> {evolution_summary.overall_trend_direction.value.title()}</p>
            <p><strong>Deployments Analyzed:</strong> {evolution_summary.deployment_count}</p>
            <p><strong>Baseline Compliance Rate:</strong> {evolution_summary.variance_compliance_rate:.1f}%</p>
            <p><strong>Critical Alerts:</strong> {evolution_summary.critical_metric_alerts}</p>
            <p><strong>Warning Alerts:</strong> {evolution_summary.warning_metric_alerts}</p>
            <p><strong>Performance Trajectory:</strong> {evolution_summary.predicted_performance_trajectory}</p>
        </div>
        """
        
        dashboard_html = summary_text + fig.to_html(include_plotlyjs='cdn', div_id=f"dashboard_{uuid.uuid4().hex[:8]}")
        
        return dashboard_html
    
    def _load_historical_data(self) -> None:
        """Load historical trend data from persistent storage."""
        
        try:
            trend_data_file = self.data_directory / "trend_data.pkl"
            if trend_data_file.exists():
                with open(trend_data_file, 'rb') as f:
                    stored_data = pickle.load(f)
                    self.trend_data = stored_data.get('trend_data', defaultdict(list))
                    self.deployment_history = stored_data.get('deployment_history', [])
                
                self.logger.info(
                    "Loaded historical trend data",
                    metrics_count=len(self.trend_data),
                    deployment_count=len(self.deployment_history)
                )
        
        except Exception as e:
            self.logger.warning(f"Failed to load historical data: {e}")
            self.trend_data = defaultdict(list)
            self.deployment_history = []
    
    def _save_historical_data(self) -> None:
        """Save historical trend data to persistent storage."""
        
        try:
            trend_data_file = self.data_directory / "trend_data.pkl"
            
            storage_data = {
                'trend_data': dict(self.trend_data),
                'deployment_history': self.deployment_history,
                'last_updated': datetime.utcnow()
            }
            
            with open(trend_data_file, 'wb') as f:
                pickle.dump(storage_data, f)
            
            self.logger.info("Saved historical trend data")
        
        except Exception as e:
            self.logger.error(f"Failed to save historical data: {e}")
    
    def _trim_historical_data(self, metric_name: str) -> None:
        """Trim historical data to maintain analysis window."""
        
        cutoff_date = datetime.utcnow() - timedelta(days=TREND_ANALYSIS_WINDOW_DAYS)
        
        # Keep only data within the analysis window
        self.trend_data[metric_name] = [
            dp for dp in self.trend_data[metric_name]
            if dp.timestamp >= cutoff_date
        ]
    
    def _create_empty_trend_result(self, metric_name: str) -> TrendAnalysisResult:
        """Create empty trend result for metrics with no data."""
        
        return TrendAnalysisResult(
            metric_name=metric_name,
            analysis_period_start=datetime.utcnow(),
            analysis_period_end=datetime.utcnow(),
            data_points_count=0,
            trend_direction=TrendDirection.INSUFFICIENT_DATA,
            trend_severity=TrendSeverity.NORMAL,
            trend_strength=0.0,
            trend_confidence=0.0,
            mean_value=0.0,
            median_value=0.0,
            std_deviation=0.0,
            min_value=0.0,
            max_value=0.0,
            percentile_95=0.0,
            variance_coefficient=0.0,
            trend_summary="Insufficient data available for trend analysis"
        )
    
    def _create_insufficient_data_result(self, metric_name: str, data_points: int) -> TrendAnalysisResult:
        """Create result for metrics with insufficient data."""
        
        result = self._create_empty_trend_result(metric_name)
        result.data_points_count = data_points
        result.trend_summary = f"Insufficient data points ({data_points}) for reliable trend analysis (minimum {MIN_DATA_POINTS_TREND} required)"
        
        return result
    
    def export_trend_analysis_report(self, output_path: Path, 
                                   format_type: str = "json") -> Path:
        """
        Export comprehensive trend analysis report to file.
        
        Args:
            output_path: Path for the exported report
            format_type: Export format ("json", "csv", "excel")
            
        Returns:
            Path to the exported file
        """
        evolution_summary = self.generate_performance_evolution_summary()
        
        if format_type.lower() == "json":
            export_data = {
                'evolution_summary': asdict(evolution_summary),
                'trend_analyses': {
                    name: asdict(trend) for name, trend in evolution_summary.metric_trends.items()
                },
                'capacity_recommendations': [
                    asdict(rec) for rec in evolution_summary.capacity_recommendations
                ],
                'export_timestamp': datetime.utcnow().isoformat()
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)
        
        elif format_type.lower() == "csv" and pd:
            # Export trend data as CSV
            all_trend_data = []
            
            for metric_name, data_points in self.trend_data.items():
                for dp in data_points:
                    all_trend_data.append({
                        'timestamp': dp.timestamp,
                        'metric_name': dp.metric_name,
                        'value': dp.value,
                        'baseline_value': dp.baseline_value,
                        'variance_percent': dp.variance_percent,
                        'environment': dp.environment,
                        'deployment_version': dp.deployment_version
                    })
            
            df = pd.DataFrame(all_trend_data)
            df.to_csv(output_path, index=False)
        
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
        
        self.logger.info(
            "Exported trend analysis report",
            output_path=str(output_path),
            format=format_type
        )
        
        return output_path
    
    def __del__(self):
        """Save historical data on cleanup."""
        try:
            self._save_historical_data()
        except Exception:
            pass  # Ignore errors during cleanup


# Utility functions for external integration

def create_trend_analysis_engine(baseline_manager: Optional[BaselineDataManager] = None,
                                config: Optional[PerformanceTestConfig] = None) -> TrendAnalysisEngine:
    """
    Create a trend analysis engine instance with optional configuration.
    
    Args:
        baseline_manager: Optional baseline data manager
        config: Optional performance configuration
        
    Returns:
        Configured TrendAnalysisEngine instance
    """
    return TrendAnalysisEngine(baseline_manager, config)


def generate_trend_analysis_dashboard(metrics_data: Dict[str, List[Dict[str, Any]]],
                                     environment: str = "production") -> Optional[str]:
    """
    Generate trend analysis dashboard from metrics data.
    
    Args:
        metrics_data: Dictionary of metric data points
        environment: Target environment
        
    Returns:
        HTML dashboard or None if generation fails
    """
    try:
        engine = create_trend_analysis_engine()
        
        # Add metrics data to engine
        for metric_name, data_points in metrics_data.items():
            for data_point in data_points:
                engine.add_performance_data(
                    metric_name=metric_name,
                    value=data_point.get('value', 0.0),
                    timestamp=datetime.fromisoformat(data_point.get('timestamp', datetime.utcnow().isoformat())),
                    **{k: v for k, v in data_point.items() if k not in ['value', 'timestamp']}
                )
        
        return engine.create_comprehensive_dashboard(environment)
        
    except Exception as e:
        logging.error(f"Failed to generate trend analysis dashboard: {e}")
        return None


def analyze_performance_evolution(historical_data: List[Dict[str, Any]],
                                deployments: List[Dict[str, Any]]) -> PerformanceEvolutionSummary:
    """
    Analyze performance evolution from historical data and deployments.
    
    Args:
        historical_data: List of historical performance data points
        deployments: List of deployment events
        
    Returns:
        PerformanceEvolutionSummary with comprehensive analysis
    """
    engine = create_trend_analysis_engine()
    
    # Add historical data
    for data_point in historical_data:
        engine.add_performance_data(
            metric_name=data_point.get('metric_name', 'unknown'),
            value=data_point.get('value', 0.0),
            timestamp=datetime.fromisoformat(data_point.get('timestamp', datetime.utcnow().isoformat())),
            **{k: v for k, v in data_point.items() if k not in ['metric_name', 'value', 'timestamp']}
        )
    
    # Add deployment events
    for deployment in deployments:
        engine.add_deployment_event(deployment)
    
    return engine.generate_performance_evolution_summary()


def predict_capacity_requirements(performance_trends: Dict[str, TrendAnalysisResult],
                                 prediction_horizon_days: int = 30) -> List[CapacityPlanningRecommendation]:
    """
    Predict capacity requirements based on performance trends.
    
    Args:
        performance_trends: Dictionary of trend analysis results
        prediction_horizon_days: Prediction horizon in days
        
    Returns:
        List of capacity planning recommendations
    """
    engine = create_trend_analysis_engine()
    
    # Generate capacity recommendations based on trends
    recommendations = []
    
    for metric_name, trend_result in performance_trends.items():
        capacity_rec = engine._generate_metric_capacity_recommendation(
            metric_name, trend_result, "production"
        )
        if capacity_rec:
            recommendations.append(capacity_rec)
    
    return recommendations


# Export public interface
__all__ = [
    # Core classes
    'TrendAnalysisEngine',
    'TrendAnalysisResult',
    'CapacityPlanningRecommendation',
    'PerformanceEvolutionSummary',
    'TrendDataPoint',
    
    # Enumerations
    'TrendDirection',
    'TrendSeverity',
    'PredictionModel',
    
    # Utility functions
    'create_trend_analysis_engine',
    'generate_trend_analysis_dashboard',
    'analyze_performance_evolution',
    'predict_capacity_requirements'
]