#!/usr/bin/env python3
"""
Performance Data Processing and Analysis Script

Comprehensive performance data processing and analysis implementation providing statistical
analysis, trend calculation, and performance metrics aggregation for the Flask migration.
Processes raw performance data from load tests, monitoring systems, and baseline comparisons
to generate actionable insights and variance calculations ensuring ≤10% compliance.

Key Features:
- Statistical analysis for ≤10% variance calculation per Section 0.3.2
- Performance trend analysis and regression detection per Section 6.6.1  
- Memory profiling and resource utilization analysis per Section 3.6.2
- Database query performance monitoring per Section 3.6.2
- Prometheus-client metrics data processing per Section 3.6.2
- Performance data aggregation and historical tracking per Section 6.6.2

Technical Implementation:
- Real-time statistical analysis with sliding window calculations
- Regression detection using statistical process control methods
- Memory leak detection through heap growth pattern analysis
- Database performance anomaly detection with query time clustering
- Time-series analysis for performance trend identification
- Automated performance report generation with actionable recommendations

Dependencies:
- numpy ≥1.24.0: Statistical computations and array operations
- scipy ≥1.10.0: Advanced statistical analysis and hypothesis testing
- pandas ≥1.5.0: Time-series data manipulation and analysis
- matplotlib ≥3.6.0: Performance trend visualization
- prometheus-client ≥0.17.0: Metrics data parsing and processing
- psutil ≥5.9.0: System resource monitoring data collection

Author: Performance Engineering Team
Version: 1.0.0
"""

import sys
import os
import json
import time
import statistics
import warnings
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple, Optional, Any, Union, NamedTuple
from dataclasses import dataclass, field, asdict
from collections import defaultdict, deque
from pathlib import Path
import argparse
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import math

# Scientific computing imports
try:
    import numpy as np
    import pandas as pd
    from scipy import stats
    from scipy.stats import normaltest, jarque_bera, anderson
    import matplotlib.pyplot as plt
    import seaborn as sns
    SCIENTIFIC_LIBRARIES_AVAILABLE = True
except ImportError as e:
    warnings.warn(f"Scientific libraries not available: {e}. Some features will be limited.")
    SCIENTIFIC_LIBRARIES_AVAILABLE = False

# Prometheus metrics parsing
try:
    from prometheus_client.parser import text_string_to_metric_families
    from prometheus_client import CollectorRegistry, generate_latest
    PROMETHEUS_CLIENT_AVAILABLE = True
except ImportError:
    warnings.warn("prometheus-client not available. Metrics parsing will be limited.")
    PROMETHEUS_CLIENT_AVAILABLE = False

# System monitoring
try:
    import psutil
    import gc
    SYSTEM_MONITORING_AVAILABLE = True
except ImportError:
    warnings.warn("psutil not available. System monitoring will be limited.")
    SYSTEM_MONITORING_AVAILABLE = False

# Application imports
try:
    from tests.performance.baseline_data import (
        BaselineDataManager, default_baseline_manager,
        validate_flask_performance_against_baseline,
        PERFORMANCE_VARIANCE_THRESHOLD, MEMORY_VARIANCE_THRESHOLD,
        WARNING_VARIANCE_THRESHOLD, CRITICAL_VARIANCE_THRESHOLD
    )
    from tests.performance.performance_config import (
        PerformanceConfigFactory, BasePerformanceConfig,
        PerformanceThreshold, BaselineMetrics
    )
    from src.monitoring.metrics import FlaskMetricsCollector
    INTERNAL_MODULES_AVAILABLE = True
except ImportError as e:
    warnings.warn(f"Internal modules not available: {e}. Using fallback implementations.")
    INTERNAL_MODULES_AVAILABLE = False
    # Define fallback constants
    PERFORMANCE_VARIANCE_THRESHOLD = 10.0
    MEMORY_VARIANCE_THRESHOLD = 15.0
    WARNING_VARIANCE_THRESHOLD = 5.0
    CRITICAL_VARIANCE_THRESHOLD = 10.0

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('performance_analysis.log')
    ]
)
logger = logging.getLogger(__name__)


class StatisticalAnalysisEngine:
    """
    Advanced statistical analysis engine for performance data processing.
    
    Implements comprehensive statistical methods for variance calculation,
    trend analysis, and performance regression detection ensuring ≤10%
    variance compliance per Section 0.3.2.
    """
    
    def __init__(self, confidence_level: float = 0.95, significance_level: float = 0.05):
        """
        Initialize statistical analysis engine with configurable parameters.
        
        Args:
            confidence_level: Statistical confidence level for analysis (default: 95%)
            significance_level: Statistical significance level for hypothesis testing (default: 5%)
        """
        self.confidence_level = confidence_level
        self.significance_level = significance_level
        self.analysis_cache: Dict[str, Any] = {}
        self.cache_lock = threading.Lock()
        
        logger.info(f"StatisticalAnalysisEngine initialized with confidence={confidence_level}, significance={significance_level}")
    
    def calculate_performance_variance(
        self, 
        current_values: List[float], 
        baseline_value: float,
        metric_name: str = "performance_metric"
    ) -> Dict[str, Any]:
        """
        Calculate comprehensive performance variance statistics with confidence intervals.
        
        Args:
            current_values: List of current performance measurements
            baseline_value: Node.js baseline value for comparison
            metric_name: Name of the performance metric for reporting
            
        Returns:
            Dictionary containing variance statistics, confidence intervals, and compliance status
        """
        if not current_values or baseline_value <= 0:
            return {
                'error': 'Invalid input data for variance calculation',
                'metric_name': metric_name,
                'sample_size': len(current_values) if current_values else 0
            }
        
        try:
            # Basic statistical measures
            mean_current = statistics.mean(current_values)
            median_current = statistics.median(current_values)
            std_current = statistics.stdev(current_values) if len(current_values) > 1 else 0.0
            
            # Variance calculations
            mean_variance = ((mean_current - baseline_value) / baseline_value) * 100.0
            median_variance = ((median_current - baseline_value) / baseline_value) * 100.0
            
            # Statistical distribution analysis
            distribution_analysis = self._analyze_distribution(current_values)
            
            # Confidence intervals for variance
            confidence_intervals = self._calculate_confidence_intervals(
                current_values, baseline_value, self.confidence_level
            )
            
            # Outlier detection
            outliers = self._detect_outliers(current_values)
            
            # Compliance assessment
            compliance = self._assess_variance_compliance(
                mean_variance, median_variance, outliers
            )
            
            # Trend analysis if sufficient data points
            trend_analysis = self._calculate_trend_statistics(current_values)
            
            result = {
                'metric_name': metric_name,
                'baseline_value': baseline_value,
                'sample_statistics': {
                    'sample_size': len(current_values),
                    'mean': mean_current,
                    'median': median_current,
                    'std_deviation': std_current,
                    'min': min(current_values),
                    'max': max(current_values),
                    'range': max(current_values) - min(current_values)
                },
                'variance_analysis': {
                    'mean_variance_percent': mean_variance,
                    'median_variance_percent': median_variance,
                    'variance_std_deviation': std_current / baseline_value * 100.0 if baseline_value > 0 else 0.0
                },
                'confidence_intervals': confidence_intervals,
                'distribution_analysis': distribution_analysis,
                'outlier_analysis': outliers,
                'compliance_assessment': compliance,
                'trend_analysis': trend_analysis,
                'analysis_timestamp': datetime.utcnow().isoformat()
            }
            
            # Cache result for performance optimization
            with self.cache_lock:
                cache_key = f"{metric_name}_{len(current_values)}_{baseline_value}"
                self.analysis_cache[cache_key] = result
            
            return result
            
        except Exception as e:
            logger.error(f"Error calculating performance variance for {metric_name}: {str(e)}")
            return {
                'error': f'Variance calculation failed: {str(e)}',
                'metric_name': metric_name,
                'sample_size': len(current_values)
            }
    
    def _analyze_distribution(self, values: List[float]) -> Dict[str, Any]:
        """
        Analyze statistical distribution characteristics of performance data.
        
        Args:
            values: List of performance measurements
            
        Returns:
            Distribution analysis results including normality tests
        """
        if len(values) < 8:  # Minimum sample size for reliable distribution analysis
            return {'note': 'Insufficient data for distribution analysis (minimum 8 samples required)'}
        
        try:
            if SCIENTIFIC_LIBRARIES_AVAILABLE:
                # Normality tests
                shapiro_stat, shapiro_p = stats.shapiro(values) if len(values) <= 5000 else (None, None)
                jarque_bera_stat, jarque_bera_p = jarque_bera(values)
                anderson_stat, anderson_critical, anderson_significance = anderson(values, dist='norm')
                
                # Descriptive statistics
                skewness = stats.skew(values)
                kurtosis = stats.kurtosis(values)
                
                # Percentile analysis
                percentiles = {
                    'p5': np.percentile(values, 5),
                    'p25': np.percentile(values, 25),
                    'p50': np.percentile(values, 50),
                    'p75': np.percentile(values, 75),
                    'p95': np.percentile(values, 95),
                    'p99': np.percentile(values, 99)
                }
                
                return {
                    'normality_tests': {
                        'shapiro_wilk': {
                            'statistic': shapiro_stat,
                            'p_value': shapiro_p,
                            'is_normal': shapiro_p > self.significance_level if shapiro_p else None
                        },
                        'jarque_bera': {
                            'statistic': jarque_bera_stat,
                            'p_value': jarque_bera_p,
                            'is_normal': jarque_bera_p > self.significance_level
                        },
                        'anderson_darling': {
                            'statistic': anderson_stat,
                            'critical_values': anderson_critical.tolist(),
                            'significance_levels': anderson_significance.tolist()
                        }
                    },
                    'distribution_characteristics': {
                        'skewness': skewness,
                        'kurtosis': kurtosis,
                        'is_symmetric': abs(skewness) < 0.5,
                        'tail_behavior': 'heavy' if kurtosis > 3 else 'light' if kurtosis < 3 else 'normal'
                    },
                    'percentiles': percentiles
                }
            else:
                # Fallback analysis without scipy
                sorted_values = sorted(values)
                n = len(sorted_values)
                
                return {
                    'basic_percentiles': {
                        'p25': sorted_values[int(0.25 * n)],
                        'p50': sorted_values[int(0.50 * n)],
                        'p75': sorted_values[int(0.75 * n)],
                        'p95': sorted_values[int(0.95 * n)]
                    },
                    'note': 'Limited distribution analysis (scipy not available)'
                }
                
        except Exception as e:
            logger.warning(f"Distribution analysis failed: {str(e)}")
            return {'error': f'Distribution analysis failed: {str(e)}'}
    
    def _calculate_confidence_intervals(
        self, 
        values: List[float], 
        baseline: float, 
        confidence: float
    ) -> Dict[str, Any]:
        """
        Calculate confidence intervals for performance variance estimates.
        
        Args:
            values: Performance measurement values
            baseline: Baseline value for variance calculation
            confidence: Confidence level (e.g., 0.95 for 95%)
            
        Returns:
            Confidence interval analysis results
        """
        if len(values) < 2:
            return {'note': 'Insufficient data for confidence interval calculation'}
        
        try:
            if SCIENTIFIC_LIBRARIES_AVAILABLE:
                # Convert to numpy array for calculations
                data = np.array(values)
                n = len(data)
                
                # Sample statistics
                mean_val = np.mean(data)
                std_val = np.std(data, ddof=1)  # Sample standard deviation
                se_mean = std_val / np.sqrt(n)  # Standard error of mean
                
                # T-distribution critical value
                alpha = 1 - confidence
                t_critical = stats.t.ppf(1 - alpha/2, df=n-1)
                
                # Confidence interval for mean
                ci_lower = mean_val - t_critical * se_mean
                ci_upper = mean_val + t_critical * se_mean
                
                # Convert to variance percentages
                variance_ci_lower = ((ci_lower - baseline) / baseline) * 100.0
                variance_ci_upper = ((ci_upper - baseline) / baseline) * 100.0
                
                # Bootstrap confidence intervals for robust estimation
                bootstrap_results = self._bootstrap_confidence_interval(values, baseline, confidence)
                
                return {
                    'confidence_level': confidence,
                    'sample_size': n,
                    'parametric_ci': {
                        'mean_ci_lower': ci_lower,
                        'mean_ci_upper': ci_upper,
                        'variance_ci_lower_percent': variance_ci_lower,
                        'variance_ci_upper_percent': variance_ci_upper,
                        't_critical': t_critical,
                        'standard_error': se_mean
                    },
                    'bootstrap_ci': bootstrap_results,
                    'interpretation': {
                        'within_threshold': abs(variance_ci_upper) <= PERFORMANCE_VARIANCE_THRESHOLD,
                        'margin_of_error_percent': abs(variance_ci_upper - variance_ci_lower) / 2
                    }
                }
            else:
                # Simplified confidence interval without scipy
                mean_val = statistics.mean(values)
                std_val = statistics.stdev(values)
                n = len(values)
                
                # Approximate 95% CI using normal approximation
                margin_error = 1.96 * std_val / math.sqrt(n)
                ci_lower = mean_val - margin_error
                ci_upper = mean_val + margin_error
                
                variance_ci_lower = ((ci_lower - baseline) / baseline) * 100.0
                variance_ci_upper = ((ci_upper - baseline) / baseline) * 100.0
                
                return {
                    'confidence_level': confidence,
                    'sample_size': n,
                    'approximate_ci': {
                        'variance_ci_lower_percent': variance_ci_lower,
                        'variance_ci_upper_percent': variance_ci_upper,
                        'margin_of_error': margin_error
                    },
                    'note': 'Approximate confidence interval (scipy not available)'
                }
                
        except Exception as e:
            logger.warning(f"Confidence interval calculation failed: {str(e)}")
            return {'error': f'Confidence interval calculation failed: {str(e)}'}
    
    def _bootstrap_confidence_interval(
        self, 
        values: List[float], 
        baseline: float, 
        confidence: float, 
        n_bootstrap: int = 1000
    ) -> Dict[str, Any]:
        """
        Calculate bootstrap confidence intervals for robust variance estimation.
        
        Args:
            values: Performance measurement values
            baseline: Baseline value for variance calculation
            confidence: Confidence level
            n_bootstrap: Number of bootstrap samples
            
        Returns:
            Bootstrap confidence interval results
        """
        if not SCIENTIFIC_LIBRARIES_AVAILABLE:
            return {'note': 'Bootstrap analysis requires numpy'}
        
        try:
            data = np.array(values)
            n = len(data)
            bootstrap_variances = []
            
            # Generate bootstrap samples
            for _ in range(n_bootstrap):
                bootstrap_sample = np.random.choice(data, size=n, replace=True)
                bootstrap_mean = np.mean(bootstrap_sample)
                bootstrap_variance = ((bootstrap_mean - baseline) / baseline) * 100.0
                bootstrap_variances.append(bootstrap_variance)
            
            # Calculate percentile-based confidence intervals
            alpha = 1 - confidence
            ci_lower_percentile = (alpha/2) * 100
            ci_upper_percentile = (1 - alpha/2) * 100
            
            ci_lower = np.percentile(bootstrap_variances, ci_lower_percentile)
            ci_upper = np.percentile(bootstrap_variances, ci_upper_percentile)
            
            return {
                'n_bootstrap': n_bootstrap,
                'variance_ci_lower_percent': ci_lower,
                'variance_ci_upper_percent': ci_upper,
                'bootstrap_mean_variance': np.mean(bootstrap_variances),
                'bootstrap_std_variance': np.std(bootstrap_variances),
                'within_threshold': abs(ci_upper) <= PERFORMANCE_VARIANCE_THRESHOLD
            }
            
        except Exception as e:
            logger.warning(f"Bootstrap confidence interval failed: {str(e)}")
            return {'error': f'Bootstrap analysis failed: {str(e)}'}
    
    def _detect_outliers(self, values: List[float]) -> Dict[str, Any]:
        """
        Detect outliers in performance data using multiple statistical methods.
        
        Args:
            values: Performance measurement values
            
        Returns:
            Outlier detection results with multiple methods
        """
        if len(values) < 4:
            return {'note': 'Insufficient data for outlier detection'}
        
        try:
            # IQR-based outlier detection
            q1 = statistics.quantiles(values, n=4)[0] if len(values) >= 4 else min(values)
            q3 = statistics.quantiles(values, n=4)[2] if len(values) >= 4 else max(values)
            iqr = q3 - q1
            
            lower_bound = q1 - 1.5 * iqr
            upper_bound = q3 + 1.5 * iqr
            
            iqr_outliers = [v for v in values if v < lower_bound or v > upper_bound]
            
            # Z-score based outlier detection
            mean_val = statistics.mean(values)
            std_val = statistics.stdev(values) if len(values) > 1 else 0
            
            z_score_outliers = []
            if std_val > 0:
                z_score_outliers = [v for v in values if abs((v - mean_val) / std_val) > 2.5]
            
            # Modified Z-score using median absolute deviation
            median_val = statistics.median(values)
            mad = statistics.median([abs(v - median_val) for v in values])
            modified_z_outliers = []
            
            if mad > 0:
                modified_z_outliers = [
                    v for v in values 
                    if abs(0.6745 * (v - median_val) / mad) > 3.5
                ]
            
            return {
                'iqr_method': {
                    'outliers': iqr_outliers,
                    'count': len(iqr_outliers),
                    'percentage': len(iqr_outliers) / len(values) * 100,
                    'bounds': {'lower': lower_bound, 'upper': upper_bound}
                },
                'z_score_method': {
                    'outliers': z_score_outliers,
                    'count': len(z_score_outliers),
                    'percentage': len(z_score_outliers) / len(values) * 100,
                    'threshold': 2.5
                },
                'modified_z_score_method': {
                    'outliers': modified_z_outliers,
                    'count': len(modified_z_outliers),
                    'percentage': len(modified_z_outliers) / len(values) * 100,
                    'threshold': 3.5
                },
                'summary': {
                    'total_unique_outliers': len(set(iqr_outliers + z_score_outliers + modified_z_outliers)),
                    'consensus_outliers': len(set(iqr_outliers) & set(z_score_outliers) & set(modified_z_outliers)),
                    'outlier_impact': 'high' if len(iqr_outliers) / len(values) > 0.1 else 'moderate' if len(iqr_outliers) / len(values) > 0.05 else 'low'
                }
            }
            
        except Exception as e:
            logger.warning(f"Outlier detection failed: {str(e)}")
            return {'error': f'Outlier detection failed: {str(e)}'}
    
    def _assess_variance_compliance(
        self, 
        mean_variance: float, 
        median_variance: float, 
        outlier_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Assess compliance with ≤10% variance threshold requirements.
        
        Args:
            mean_variance: Mean variance percentage
            median_variance: Median variance percentage  
            outlier_analysis: Outlier detection results
            
        Returns:
            Compliance assessment with recommendations
        """
        try:
            # Determine compliance status
            mean_compliant = abs(mean_variance) <= PERFORMANCE_VARIANCE_THRESHOLD
            median_compliant = abs(median_variance) <= PERFORMANCE_VARIANCE_THRESHOLD
            
            # Risk assessment based on variance levels and outliers
            risk_level = 'low'
            if abs(mean_variance) > CRITICAL_VARIANCE_THRESHOLD:
                risk_level = 'critical'
            elif abs(mean_variance) > WARNING_VARIANCE_THRESHOLD:
                risk_level = 'high'
            elif abs(mean_variance) > WARNING_VARIANCE_THRESHOLD / 2:
                risk_level = 'moderate'
            
            # Outlier impact on compliance
            outlier_impact = outlier_analysis.get('summary', {}).get('outlier_impact', 'unknown')
            outlier_count = outlier_analysis.get('iqr_method', {}).get('count', 0)
            
            # Generate recommendations
            recommendations = []
            if not mean_compliant:
                recommendations.append(f"Mean variance {mean_variance:.2f}% exceeds ≤{PERFORMANCE_VARIANCE_THRESHOLD}% threshold")
            if not median_compliant:
                recommendations.append(f"Median variance {median_variance:.2f}% exceeds ≤{PERFORMANCE_VARIANCE_THRESHOLD}% threshold")
            if outlier_count > 0:
                recommendations.append(f"Found {outlier_count} performance outliers requiring investigation")
            if risk_level in ['high', 'critical']:
                recommendations.append("Immediate performance optimization required")
                recommendations.append("Consider rolling back to Node.js implementation")
            
            if not recommendations:
                recommendations.append("Performance variance within acceptable limits - proceed with migration")
            
            return {
                'overall_compliant': mean_compliant and median_compliant,
                'mean_variance_compliant': mean_compliant,
                'median_variance_compliant': median_compliant,
                'risk_level': risk_level,
                'variance_values': {
                    'mean_variance_percent': mean_variance,
                    'median_variance_percent': median_variance,
                    'threshold_percent': PERFORMANCE_VARIANCE_THRESHOLD
                },
                'outlier_impact': {
                    'impact_level': outlier_impact,
                    'outlier_count': outlier_count,
                    'affects_compliance': outlier_count > 0 and outlier_impact in ['high', 'moderate']
                },
                'recommendations': recommendations,
                'action_required': risk_level in ['high', 'critical'] or not (mean_compliant and median_compliant)
            }
            
        except Exception as e:
            logger.error(f"Compliance assessment failed: {str(e)}")
            return {
                'error': f'Compliance assessment failed: {str(e)}',
                'overall_compliant': False,
                'action_required': True
            }
    
    def _calculate_trend_statistics(self, values: List[float]) -> Dict[str, Any]:
        """
        Calculate trend statistics for performance regression detection.
        
        Args:
            values: Performance measurement values (time-ordered)
            
        Returns:
            Trend analysis results including regression detection
        """
        if len(values) < 5:
            return {'note': 'Insufficient data for trend analysis (minimum 5 points required)'}
        
        try:
            if SCIENTIFIC_LIBRARIES_AVAILABLE:
                # Time-series trend analysis
                x = np.arange(len(values))
                y = np.array(values)
                
                # Linear regression
                slope, intercept, r_value, p_value, std_err = stats.linregress(x, y)
                
                # Mann-Kendall trend test
                def mann_kendall_test(data):
                    n = len(data)
                    s = 0
                    for i in range(n-1):
                        for j in range(i+1, n):
                            s += np.sign(data[j] - data[i])
                    
                    var_s = n * (n-1) * (2*n+5) / 18
                    z = s / np.sqrt(var_s) if var_s > 0 else 0
                    
                    return s, z, abs(z) > 1.96  # 95% confidence
                
                mk_s, mk_z, mk_significant = mann_kendall_test(values)
                
                # Change point detection (simple approach)
                changes = [abs(values[i] - values[i-1]) for i in range(1, len(values))]
                avg_change = statistics.mean(changes)
                large_changes = [i for i, change in enumerate(changes) if change > 2 * avg_change]
                
                return {
                    'linear_trend': {
                        'slope': slope,
                        'intercept': intercept,
                        'r_squared': r_value ** 2,
                        'p_value': p_value,
                        'std_error': std_err,
                        'trend_direction': 'improving' if slope < 0 else 'degrading' if slope > 0 else 'stable',
                        'trend_significant': p_value < self.significance_level
                    },
                    'mann_kendall_test': {
                        'statistic': mk_s,
                        'z_score': mk_z,
                        'trend_significant': mk_significant,
                        'trend_direction': 'improving' if mk_s < 0 else 'degrading' if mk_s > 0 else 'no_trend'
                    },
                    'change_point_analysis': {
                        'significant_changes': large_changes,
                        'change_count': len(large_changes),
                        'average_change': avg_change,
                        'stability_score': 1 - (len(large_changes) / (len(values) - 1))
                    },
                    'trend_summary': {
                        'overall_trend': 'degrading' if slope > 0 and mk_s > 0 else 'improving' if slope < 0 and mk_s < 0 else 'stable',
                        'trend_strength': 'strong' if abs(r_value) > 0.7 else 'moderate' if abs(r_value) > 0.3 else 'weak',
                        'requires_attention': mk_significant and slope > 0
                    }
                }
            else:
                # Simple trend analysis without scipy
                first_half = values[:len(values)//2]
                second_half = values[len(values)//2:]
                
                first_avg = statistics.mean(first_half)
                second_avg = statistics.mean(second_half)
                
                trend_direction = 'improving' if second_avg < first_avg else 'degrading' if second_avg > first_avg else 'stable'
                change_percent = ((second_avg - first_avg) / first_avg) * 100 if first_avg > 0 else 0
                
                return {
                    'simple_trend': {
                        'first_half_avg': first_avg,
                        'second_half_avg': second_avg,
                        'change_percent': change_percent,
                        'trend_direction': trend_direction
                    },
                    'note': 'Simplified trend analysis (scipy not available)'
                }
                
        except Exception as e:
            logger.warning(f"Trend analysis failed: {str(e)}")
            return {'error': f'Trend analysis failed: {str(e)}'}


class MemoryProfiler:
    """
    Comprehensive memory profiling and resource utilization analysis engine.
    
    Implements memory leak detection, heap growth pattern analysis, and
    resource utilization monitoring per Section 3.6.2 memory profiling
    requirements for ≤10% variance compliance.
    """
    
    def __init__(self, monitoring_interval: float = 1.0):
        """
        Initialize memory profiler with configurable monitoring parameters.
        
        Args:
            monitoring_interval: Interval in seconds for memory monitoring
        """
        self.monitoring_interval = monitoring_interval
        self.memory_snapshots: List[Dict[str, Any]] = []
        self.gc_statistics: List[Dict[str, Any]] = []
        self.monitoring_active = False
        self.monitoring_thread: Optional[threading.Thread] = None
        self.lock = threading.Lock()
        
        logger.info(f"MemoryProfiler initialized with interval={monitoring_interval}s")
    
    def start_monitoring(self) -> None:
        """Start continuous memory monitoring in background thread."""
        if self.monitoring_active:
            logger.warning("Memory monitoring already active")
            return
        
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        logger.info("Memory monitoring started")
    
    def stop_monitoring(self) -> None:
        """Stop continuous memory monitoring."""
        self.monitoring_active = False
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=5.0)
        logger.info("Memory monitoring stopped")
    
    def _monitoring_loop(self) -> None:
        """Background monitoring loop for continuous memory tracking."""
        while self.monitoring_active:
            try:
                snapshot = self._capture_memory_snapshot()
                gc_stats = self._capture_gc_statistics()
                
                with self.lock:
                    self.memory_snapshots.append(snapshot)
                    self.gc_statistics.append(gc_stats)
                    
                    # Limit history to prevent memory growth
                    if len(self.memory_snapshots) > 10000:
                        self.memory_snapshots = self.memory_snapshots[-5000:]
                    if len(self.gc_statistics) > 10000:
                        self.gc_statistics = self.gc_statistics[-5000:]
                
                time.sleep(self.monitoring_interval)
                
            except Exception as e:
                logger.error(f"Memory monitoring error: {str(e)}")
                time.sleep(self.monitoring_interval)
    
    def _capture_memory_snapshot(self) -> Dict[str, Any]:
        """
        Capture comprehensive memory usage snapshot.
        
        Returns:
            Memory usage statistics including system and process metrics
        """
        timestamp = datetime.utcnow()
        
        try:
            if SYSTEM_MONITORING_AVAILABLE:
                # Process memory information
                process = psutil.Process()
                memory_info = process.memory_info()
                memory_percent = process.memory_percent()
                
                # System memory information
                system_memory = psutil.virtual_memory()
                
                snapshot = {
                    'timestamp': timestamp.isoformat(),
                    'process_memory': {
                        'rss_bytes': memory_info.rss,
                        'vms_bytes': memory_info.vms,
                        'rss_mb': memory_info.rss / (1024 * 1024),
                        'vms_mb': memory_info.vms / (1024 * 1024),
                        'percent': memory_percent
                    },
                    'system_memory': {
                        'total_bytes': system_memory.total,
                        'available_bytes': system_memory.available,
                        'used_bytes': system_memory.used,
                        'free_bytes': system_memory.free,
                        'percent': system_memory.percent,
                        'total_gb': system_memory.total / (1024**3),
                        'available_gb': system_memory.available / (1024**3)
                    }
                }
                
                # Add garbage collection information
                gc_info = gc.get_stats()
                snapshot['gc_info'] = {
                    'generation_stats': gc_info,
                    'object_count': len(gc.get_objects()),
                    'garbage_count': len(gc.garbage)
                }
                
                return snapshot
            else:
                # Fallback without psutil
                return {
                    'timestamp': timestamp.isoformat(),
                    'note': 'Limited memory monitoring (psutil not available)',
                    'gc_info': {
                        'object_count': len(gc.get_objects()),
                        'garbage_count': len(gc.garbage)
                    }
                }
                
        except Exception as e:
            logger.error(f"Memory snapshot capture failed: {str(e)}")
            return {
                'timestamp': timestamp.isoformat(),
                'error': f'Memory snapshot failed: {str(e)}'
            }
    
    def _capture_gc_statistics(self) -> Dict[str, Any]:
        """
        Capture garbage collection statistics.
        
        Returns:
            Garbage collection performance metrics
        """
        timestamp = datetime.utcnow()
        
        try:
            # Force garbage collection and measure time
            start_time = time.perf_counter()
            collected = gc.collect()
            gc_time = time.perf_counter() - start_time
            
            # Get GC statistics
            gc_stats = gc.get_stats()
            
            return {
                'timestamp': timestamp.isoformat(),
                'collection_time_ms': gc_time * 1000,
                'objects_collected': collected,
                'generation_stats': gc_stats,
                'threshold': gc.get_threshold(),
                'count': gc.get_count()
            }
            
        except Exception as e:
            logger.error(f"GC statistics capture failed: {str(e)}")
            return {
                'timestamp': timestamp.isoformat(),
                'error': f'GC statistics failed: {str(e)}'
            }
    
    def analyze_memory_patterns(self, baseline_memory_mb: Optional[float] = None) -> Dict[str, Any]:
        """
        Analyze memory usage patterns for leak detection and performance assessment.
        
        Args:
            baseline_memory_mb: Baseline memory usage in MB for comparison
            
        Returns:
            Comprehensive memory pattern analysis results
        """
        with self.lock:
            snapshots = self.memory_snapshots.copy()
            gc_stats = self.gc_statistics.copy()
        
        if len(snapshots) < 5:
            return {'note': 'Insufficient memory data for pattern analysis'}
        
        try:
            # Extract memory usage values
            memory_values = []
            timestamps = []
            
            for snapshot in snapshots:
                if 'process_memory' in snapshot and 'rss_mb' in snapshot['process_memory']:
                    memory_values.append(snapshot['process_memory']['rss_mb'])
                    timestamps.append(datetime.fromisoformat(snapshot['timestamp']))
            
            if not memory_values:
                return {'error': 'No valid memory data found for analysis'}
            
            # Memory usage statistics
            memory_stats = {
                'min_mb': min(memory_values),
                'max_mb': max(memory_values),
                'mean_mb': statistics.mean(memory_values),
                'median_mb': statistics.median(memory_values),
                'std_dev_mb': statistics.stdev(memory_values) if len(memory_values) > 1 else 0,
                'growth_mb': memory_values[-1] - memory_values[0],
                'growth_percent': ((memory_values[-1] - memory_values[0]) / memory_values[0]) * 100 if memory_values[0] > 0 else 0
            }
            
            # Memory leak detection
            leak_analysis = self._detect_memory_leaks(memory_values, timestamps)
            
            # Memory variance analysis against baseline
            variance_analysis = {}
            if baseline_memory_mb:
                variance_analysis = self._analyze_memory_variance(memory_values, baseline_memory_mb)
            
            # Garbage collection analysis
            gc_analysis = self._analyze_gc_performance(gc_stats)
            
            # Memory efficiency assessment
            efficiency_analysis = self._assess_memory_efficiency(memory_stats, leak_analysis)
            
            return {
                'analysis_period': {
                    'start_time': timestamps[0].isoformat() if timestamps else None,
                    'end_time': timestamps[-1].isoformat() if timestamps else None,
                    'duration_minutes': (timestamps[-1] - timestamps[0]).total_seconds() / 60 if len(timestamps) > 1 else 0,
                    'sample_count': len(memory_values)
                },
                'memory_statistics': memory_stats,
                'leak_analysis': leak_analysis,
                'variance_analysis': variance_analysis,
                'gc_analysis': gc_analysis,
                'efficiency_assessment': efficiency_analysis,
                'recommendations': self._generate_memory_recommendations(memory_stats, leak_analysis, variance_analysis)
            }
            
        except Exception as e:
            logger.error(f"Memory pattern analysis failed: {str(e)}")
            return {'error': f'Memory pattern analysis failed: {str(e)}'}
    
    def _detect_memory_leaks(self, memory_values: List[float], timestamps: List[datetime]) -> Dict[str, Any]:
        """
        Detect potential memory leaks using trend analysis and growth patterns.
        
        Args:
            memory_values: Memory usage values in MB
            timestamps: Corresponding timestamps
            
        Returns:
            Memory leak detection results
        """
        try:
            if len(memory_values) < 10:
                return {'note': 'Insufficient data for memory leak detection'}
            
            # Calculate memory growth rate
            time_diffs = [(timestamps[i] - timestamps[i-1]).total_seconds() for i in range(1, len(timestamps))]
            memory_diffs = [memory_values[i] - memory_values[i-1] for i in range(1, len(memory_values))]
            
            # Growth rate in MB per minute
            growth_rates = [
                (mem_diff / time_diff) * 60 if time_diff > 0 else 0
                for mem_diff, time_diff in zip(memory_diffs, time_diffs)
            ]
            
            avg_growth_rate = statistics.mean(growth_rates) if growth_rates else 0
            
            # Trend analysis
            if SCIENTIFIC_LIBRARIES_AVAILABLE:
                x = np.arange(len(memory_values))
                y = np.array(memory_values)
                slope, intercept, r_value, p_value, std_err = stats.linregress(x, y)
                
                trend_analysis = {
                    'slope_mb_per_sample': slope,
                    'r_squared': r_value ** 2,
                    'trend_significant': p_value < 0.05,
                    'projected_growth_1h': slope * 60,  # Assuming 1 sample per minute
                    'trend_direction': 'increasing' if slope > 0 else 'decreasing' if slope < 0 else 'stable'
                }
            else:
                # Simple trend analysis
                first_quarter = memory_values[:len(memory_values)//4]
                last_quarter = memory_values[-len(memory_values)//4:]
                
                avg_first = statistics.mean(first_quarter)
                avg_last = statistics.mean(last_quarter)
                simple_trend = (avg_last - avg_first) / avg_first * 100 if avg_first > 0 else 0
                
                trend_analysis = {
                    'simple_trend_percent': simple_trend,
                    'trend_direction': 'increasing' if simple_trend > 0 else 'decreasing' if simple_trend < 0 else 'stable',
                    'note': 'Simplified trend analysis (scipy not available)'
                }
            
            # Leak severity assessment
            leak_indicators = []
            if avg_growth_rate > 1.0:  # More than 1 MB/minute growth
                leak_indicators.append('High sustained memory growth rate')
            if trend_analysis.get('trend_significant', False) and trend_analysis.get('slope_mb_per_sample', 0) > 0.1:
                leak_indicators.append('Statistically significant upward memory trend')
            if memory_values[-1] > memory_values[0] * 1.5:  # 50% memory increase
                leak_indicators.append('Significant total memory increase during monitoring')
            
            leak_severity = 'critical' if len(leak_indicators) >= 3 else 'high' if len(leak_indicators) == 2 else 'moderate' if len(leak_indicators) == 1 else 'low'
            
            return {
                'growth_rate_mb_per_minute': avg_growth_rate,
                'trend_analysis': trend_analysis,
                'leak_indicators': leak_indicators,
                'leak_severity': leak_severity,
                'leak_detected': len(leak_indicators) > 0,
                'memory_growth_total_mb': memory_values[-1] - memory_values[0],
                'memory_growth_percent': ((memory_values[-1] - memory_values[0]) / memory_values[0]) * 100 if memory_values[0] > 0 else 0
            }
            
        except Exception as e:
            logger.error(f"Memory leak detection failed: {str(e)}")
            return {'error': f'Memory leak detection failed: {str(e)}'}
    
    def _analyze_memory_variance(self, memory_values: List[float], baseline_mb: float) -> Dict[str, Any]:
        """
        Analyze memory usage variance against baseline for compliance checking.
        
        Args:
            memory_values: Memory usage values in MB
            baseline_mb: Baseline memory usage in MB
            
        Returns:
            Memory variance analysis results
        """
        try:
            if baseline_mb <= 0:
                return {'error': 'Invalid baseline memory value'}
            
            # Calculate variance statistics
            mean_memory = statistics.mean(memory_values)
            median_memory = statistics.median(memory_values)
            max_memory = max(memory_values)
            
            mean_variance = ((mean_memory - baseline_mb) / baseline_mb) * 100
            median_variance = ((median_memory - baseline_mb) / baseline_mb) * 100
            max_variance = ((max_memory - baseline_mb) / baseline_mb) * 100
            
            # Compliance assessment
            mean_compliant = abs(mean_variance) <= MEMORY_VARIANCE_THRESHOLD
            median_compliant = abs(median_variance) <= MEMORY_VARIANCE_THRESHOLD
            max_compliant = abs(max_variance) <= MEMORY_VARIANCE_THRESHOLD
            
            overall_compliant = mean_compliant and median_compliant
            
            return {
                'baseline_memory_mb': baseline_mb,
                'current_statistics': {
                    'mean_mb': mean_memory,
                    'median_mb': median_memory,
                    'max_mb': max_memory
                },
                'variance_analysis': {
                    'mean_variance_percent': mean_variance,
                    'median_variance_percent': median_variance,
                    'max_variance_percent': max_variance
                },
                'compliance_status': {
                    'overall_compliant': overall_compliant,
                    'mean_compliant': mean_compliant,
                    'median_compliant': median_compliant,
                    'max_compliant': max_compliant,
                    'threshold_percent': MEMORY_VARIANCE_THRESHOLD
                },
                'risk_assessment': {
                    'risk_level': 'high' if not overall_compliant else 'moderate' if abs(mean_variance) > MEMORY_VARIANCE_THRESHOLD / 2 else 'low',
                    'action_required': not overall_compliant
                }
            }
            
        except Exception as e:
            logger.error(f"Memory variance analysis failed: {str(e)}")
            return {'error': f'Memory variance analysis failed: {str(e)}'}
    
    def _analyze_gc_performance(self, gc_stats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze garbage collection performance and impact.
        
        Args:
            gc_stats: List of garbage collection statistics
            
        Returns:
            GC performance analysis results
        """
        try:
            if not gc_stats:
                return {'note': 'No garbage collection data available'}
            
            # Extract GC times
            gc_times = []
            objects_collected = []
            
            for stat in gc_stats:
                if 'collection_time_ms' in stat:
                    gc_times.append(stat['collection_time_ms'])
                if 'objects_collected' in stat:
                    objects_collected.append(stat['objects_collected'])
            
            if not gc_times:
                return {'note': 'No valid GC timing data found'}
            
            # GC performance statistics
            gc_stats_analysis = {
                'total_collections': len(gc_times),
                'mean_gc_time_ms': statistics.mean(gc_times),
                'median_gc_time_ms': statistics.median(gc_times),
                'max_gc_time_ms': max(gc_times),
                'total_gc_time_ms': sum(gc_times),
                'gc_frequency_per_minute': len(gc_times) / ((gc_stats[-1]['timestamp'] - gc_stats[0]['timestamp']) / 60) if len(gc_stats) > 1 else 0
            }
            
            if objects_collected:
                gc_stats_analysis.update({
                    'mean_objects_collected': statistics.mean(objects_collected),
                    'total_objects_collected': sum(objects_collected)
                })
            
            # GC impact assessment
            impact_assessment = {
                'gc_overhead_high': gc_stats_analysis['mean_gc_time_ms'] > 100,  # >100ms average
                'frequent_collections': gc_stats_analysis['gc_frequency_per_minute'] > 10,  # >10 per minute
                'long_pauses': any(t > 500 for t in gc_times),  # Any pause >500ms
                'performance_impact': 'high' if gc_stats_analysis['mean_gc_time_ms'] > 100 else 'moderate' if gc_stats_analysis['mean_gc_time_ms'] > 50 else 'low'
            }
            
            return {
                'gc_statistics': gc_stats_analysis,
                'impact_assessment': impact_assessment,
                'recommendations': self._generate_gc_recommendations(gc_stats_analysis, impact_assessment)
            }
            
        except Exception as e:
            logger.error(f"GC performance analysis failed: {str(e)}")
            return {'error': f'GC performance analysis failed: {str(e)}'}
    
    def _assess_memory_efficiency(self, memory_stats: Dict[str, Any], leak_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess overall memory usage efficiency and performance impact.
        
        Args:
            memory_stats: Memory usage statistics
            leak_analysis: Memory leak analysis results
            
        Returns:
            Memory efficiency assessment
        """
        try:
            # Memory stability score
            stability_score = 1.0
            if memory_stats['std_dev_mb'] > 0:
                coefficient_of_variation = memory_stats['std_dev_mb'] / memory_stats['mean_mb']
                stability_score = max(0, 1 - coefficient_of_variation)
            
            # Memory growth assessment
            growth_score = 1.0
            if abs(memory_stats['growth_percent']) > 0:
                growth_score = max(0, 1 - abs(memory_stats['growth_percent']) / 100)
            
            # Leak impact score
            leak_score = 1.0
            if leak_analysis.get('leak_detected', False):
                leak_severity = leak_analysis.get('leak_severity', 'low')
                leak_score = 0.2 if leak_severity == 'critical' else 0.4 if leak_severity == 'high' else 0.6 if leak_severity == 'moderate' else 0.8
            
            # Overall efficiency score
            efficiency_score = (stability_score * 0.4 + growth_score * 0.4 + leak_score * 0.2)
            
            efficiency_grade = 'A' if efficiency_score >= 0.9 else 'B' if efficiency_score >= 0.8 else 'C' if efficiency_score >= 0.7 else 'D' if efficiency_score >= 0.6 else 'F'
            
            return {
                'efficiency_score': efficiency_score,
                'efficiency_grade': efficiency_grade,
                'component_scores': {
                    'stability_score': stability_score,
                    'growth_score': growth_score,
                    'leak_score': leak_score
                },
                'memory_characteristics': {
                    'stable': stability_score > 0.8,
                    'controlled_growth': growth_score > 0.8,
                    'leak_free': leak_score > 0.8
                },
                'performance_impact': 'minimal' if efficiency_score > 0.8 else 'moderate' if efficiency_score > 0.6 else 'significant'
            }
            
        except Exception as e:
            logger.error(f"Memory efficiency assessment failed: {str(e)}")
            return {'error': f'Memory efficiency assessment failed: {str(e)}'}
    
    def _generate_memory_recommendations(
        self, 
        memory_stats: Dict[str, Any], 
        leak_analysis: Dict[str, Any], 
        variance_analysis: Dict[str, Any]
    ) -> List[str]:
        """
        Generate actionable recommendations based on memory analysis results.
        
        Args:
            memory_stats: Memory usage statistics
            leak_analysis: Memory leak analysis results
            variance_analysis: Memory variance analysis results
            
        Returns:
            List of actionable recommendations
        """
        recommendations = []
        
        try:
            # Memory leak recommendations
            if leak_analysis.get('leak_detected', False):
                severity = leak_analysis.get('leak_severity', 'low')
                if severity == 'critical':
                    recommendations.append("CRITICAL: Severe memory leak detected - immediate investigation required")
                    recommendations.append("Consider reverting to Node.js implementation until leak is resolved")
                elif severity == 'high':
                    recommendations.append("HIGH: Significant memory leak detected - prioritize leak investigation")
                    recommendations.append("Implement memory monitoring alerts for production deployment")
                else:
                    recommendations.append("Monitor memory growth patterns closely")
            
            # Variance compliance recommendations
            if variance_analysis and not variance_analysis.get('compliance_status', {}).get('overall_compliant', True):
                recommendations.append(f"Memory usage exceeds ±{MEMORY_VARIANCE_THRESHOLD}% baseline variance threshold")
                recommendations.append("Optimize memory allocation patterns and object lifecycle management")
            
            # Memory efficiency recommendations
            if memory_stats['std_dev_mb'] > memory_stats['mean_mb'] * 0.3:
                recommendations.append("High memory usage variability detected - investigate memory allocation patterns")
            
            if memory_stats['growth_percent'] > 20:
                recommendations.append("Significant memory growth detected - review for potential optimizations")
            
            # General optimization recommendations
            if not recommendations:
                recommendations.append("Memory usage patterns within acceptable limits")
                recommendations.append("Continue monitoring memory trends for regression detection")
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Memory recommendations generation failed: {str(e)}")
            return ["Error generating memory recommendations - manual analysis required"]
    
    def _generate_gc_recommendations(self, gc_stats: Dict[str, Any], impact_assessment: Dict[str, Any]) -> List[str]:
        """
        Generate garbage collection optimization recommendations.
        
        Args:
            gc_stats: GC performance statistics
            impact_assessment: GC impact assessment results
            
        Returns:
            List of GC optimization recommendations
        """
        recommendations = []
        
        try:
            if impact_assessment['performance_impact'] == 'high':
                recommendations.append("High GC overhead detected - consider memory optimization")
                if impact_assessment['frequent_collections']:
                    recommendations.append("Frequent GC collections - review object allocation patterns")
                if impact_assessment['long_pauses']:
                    recommendations.append("Long GC pauses detected - consider incremental GC strategies")
            
            if gc_stats['mean_gc_time_ms'] > 50:
                recommendations.append("GC pause times affecting performance - optimize object lifecycle")
            
            if not recommendations:
                recommendations.append("GC performance within acceptable limits")
            
            return recommendations
            
        except Exception as e:
            logger.error(f"GC recommendations generation failed: {str(e)}")
            return ["Error generating GC recommendations"]


class DatabasePerformanceAnalyzer:
    """
    Comprehensive database query performance analysis and monitoring engine.
    
    Implements database performance monitoring per Section 3.6.2 with query
    execution time analysis, connection pool monitoring, and performance
    anomaly detection for database operations variance tracking.
    """
    
    def __init__(self):
        """Initialize database performance analyzer with monitoring capabilities."""
        self.query_metrics: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.connection_metrics: List[Dict[str, Any]] = []
        self.performance_baselines: Dict[str, float] = {}
        self.lock = threading.Lock()
        
        logger.info("DatabasePerformanceAnalyzer initialized")
    
    def record_query_performance(
        self, 
        operation_type: str, 
        collection: str, 
        execution_time_ms: float,
        query_size: Optional[int] = None,
        result_count: Optional[int] = None,
        index_used: Optional[bool] = None,
        additional_metrics: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Record database query performance metrics for analysis.
        
        Args:
            operation_type: Type of database operation (find, insert, update, delete, aggregate)
            collection: Database collection/table name
            execution_time_ms: Query execution time in milliseconds
            query_size: Size of query document in bytes
            result_count: Number of results returned
            index_used: Whether query used an index
            additional_metrics: Additional performance metrics
        """
        try:
            query_key = f"{operation_type}_{collection}"
            
            metric_record = {
                'timestamp': datetime.utcnow().isoformat(),
                'operation_type': operation_type,
                'collection': collection,
                'execution_time_ms': execution_time_ms,
                'query_size_bytes': query_size,
                'result_count': result_count,
                'index_used': index_used,
                'additional_metrics': additional_metrics or {}
            }
            
            with self.lock:
                self.query_metrics[query_key].append(metric_record)
                
                # Limit history to prevent memory growth
                if len(self.query_metrics[query_key]) > 10000:
                    self.query_metrics[query_key] = self.query_metrics[query_key][-5000:]
            
            logger.debug(f"Recorded query performance: {operation_type} on {collection} - {execution_time_ms}ms")
            
        except Exception as e:
            logger.error(f"Failed to record query performance: {str(e)}")
    
    def record_connection_metrics(
        self, 
        active_connections: int,
        pool_size: int,
        queue_size: int,
        wait_time_ms: Optional[float] = None,
        additional_metrics: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Record database connection pool performance metrics.
        
        Args:
            active_connections: Number of active database connections
            pool_size: Total connection pool size
            queue_size: Number of queued connection requests
            wait_time_ms: Connection wait time in milliseconds
            additional_metrics: Additional connection metrics
        """
        try:
            connection_record = {
                'timestamp': datetime.utcnow().isoformat(),
                'active_connections': active_connections,
                'pool_size': pool_size,
                'queue_size': queue_size,
                'utilization_percent': (active_connections / pool_size) * 100 if pool_size > 0 else 0,
                'wait_time_ms': wait_time_ms,
                'additional_metrics': additional_metrics or {}
            }
            
            with self.lock:
                self.connection_metrics.append(connection_record)
                
                # Limit history to prevent memory growth
                if len(self.connection_metrics) > 10000:
                    self.connection_metrics = self.connection_metrics[-5000:]
            
            logger.debug(f"Recorded connection metrics: {active_connections}/{pool_size} active, {queue_size} queued")
            
        except Exception as e:
            logger.error(f"Failed to record connection metrics: {str(e)}")
    
    def set_performance_baseline(self, operation_collection: str, baseline_time_ms: float) -> None:
        """
        Set performance baseline for specific database operation.
        
        Args:
            operation_collection: Operation and collection identifier (e.g., "find_users")
            baseline_time_ms: Baseline execution time in milliseconds
        """
        with self.lock:
            self.performance_baselines[operation_collection] = baseline_time_ms
        
        logger.info(f"Set performance baseline for {operation_collection}: {baseline_time_ms}ms")
    
    def analyze_query_performance(
        self, 
        operation_collection: Optional[str] = None,
        time_window_hours: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Analyze database query performance with statistical analysis and variance calculation.
        
        Args:
            operation_collection: Specific operation to analyze (None for all)
            time_window_hours: Time window for analysis in hours
            
        Returns:
            Comprehensive query performance analysis results
        """
        try:
            with self.lock:
                query_data = dict(self.query_metrics)
            
            if not query_data:
                return {'note': 'No query performance data available for analysis'}
            
            # Filter by time window if specified
            if time_window_hours:
                cutoff_time = datetime.utcnow() - timedelta(hours=time_window_hours)
                for key in query_data:
                    query_data[key] = [
                        metric for metric in query_data[key]
                        if datetime.fromisoformat(metric['timestamp']) >= cutoff_time
                    ]
            
            # Filter by specific operation if specified
            if operation_collection:
                if operation_collection in query_data:
                    query_data = {operation_collection: query_data[operation_collection]}
                else:
                    return {'error': f'No data found for operation: {operation_collection}'}
            
            analysis_results = {}
            
            for query_key, metrics in query_data.items():
                if not metrics:
                    continue
                
                # Extract execution times
                execution_times = [m['execution_time_ms'] for m in metrics]
                
                # Basic statistics
                query_stats = {
                    'sample_count': len(execution_times),
                    'mean_execution_time_ms': statistics.mean(execution_times),
                    'median_execution_time_ms': statistics.median(execution_times),
                    'min_execution_time_ms': min(execution_times),
                    'max_execution_time_ms': max(execution_times),
                    'std_deviation_ms': statistics.stdev(execution_times) if len(execution_times) > 1 else 0
                }
                
                # Percentile analysis
                if SCIENTIFIC_LIBRARIES_AVAILABLE:
                    execution_array = np.array(execution_times)
                    percentiles = {
                        'p50': np.percentile(execution_array, 50),
                        'p75': np.percentile(execution_array, 75),
                        'p90': np.percentile(execution_array, 90),
                        'p95': np.percentile(execution_array, 95),
                        'p99': np.percentile(execution_array, 99)
                    }
                    query_stats['percentiles'] = percentiles
                
                # Baseline comparison if available
                baseline_analysis = {}
                if query_key in self.performance_baselines:
                    baseline = self.performance_baselines[query_key]
                    variance_percent = ((query_stats['mean_execution_time_ms'] - baseline) / baseline) * 100
                    
                    baseline_analysis = {
                        'baseline_time_ms': baseline,
                        'variance_percent': variance_percent,
                        'within_threshold': abs(variance_percent) <= PERFORMANCE_VARIANCE_THRESHOLD,
                        'performance_status': 'degraded' if variance_percent > PERFORMANCE_VARIANCE_THRESHOLD else 'improved' if variance_percent < -WARNING_VARIANCE_THRESHOLD else 'stable'
                    }
                
                # Performance anomaly detection
                anomaly_analysis = self._detect_query_anomalies(execution_times)
                
                # Index usage analysis
                index_analysis = self._analyze_index_usage(metrics)
                
                # Query size correlation
                size_correlation = self._analyze_query_size_correlation(metrics)
                
                analysis_results[query_key] = {
                    'query_statistics': query_stats,
                    'baseline_analysis': baseline_analysis,
                    'anomaly_analysis': anomaly_analysis,
                    'index_analysis': index_analysis,
                    'size_correlation': size_correlation,
                    'recommendations': self._generate_query_recommendations(query_stats, baseline_analysis, anomaly_analysis)
                }
            
            # Overall database performance summary
            overall_summary = self._generate_overall_db_summary(analysis_results)
            
            return {
                'analysis_timestamp': datetime.utcnow().isoformat(),
                'analysis_window_hours': time_window_hours,
                'query_analysis': analysis_results,
                'overall_summary': overall_summary
            }
            
        except Exception as e:
            logger.error(f"Database performance analysis failed: {str(e)}")
            return {'error': f'Database performance analysis failed: {str(e)}'}
    
    def _detect_query_anomalies(self, execution_times: List[float]) -> Dict[str, Any]:
        """
        Detect performance anomalies in query execution times.
        
        Args:
            execution_times: List of query execution times
            
        Returns:
            Anomaly detection results
        """
        try:
            if len(execution_times) < 10:
                return {'note': 'Insufficient data for anomaly detection'}
            
            # Statistical anomaly detection using Z-score
            mean_time = statistics.mean(execution_times)
            std_time = statistics.stdev(execution_times)
            
            if std_time == 0:
                return {'note': 'No variance in execution times - no anomalies detected'}
            
            anomalies = []
            for i, time_val in enumerate(execution_times):
                z_score = abs((time_val - mean_time) / std_time)
                if z_score > 3:  # 3-sigma rule
                    anomalies.append({
                        'index': i,
                        'execution_time_ms': time_val,
                        'z_score': z_score,
                        'severity': 'high' if z_score > 4 else 'moderate'
                    })
            
            # Time-based anomaly detection
            if SCIENTIFIC_LIBRARIES_AVAILABLE:
                # Moving average-based anomaly detection
                window_size = min(10, len(execution_times) // 4)
                moving_avg = pd.Series(execution_times).rolling(window=window_size).mean().tolist()
                
                trend_anomalies = []
                for i in range(window_size, len(execution_times)):
                    if execution_times[i] > moving_avg[i] * 2:  # 2x moving average threshold
                        trend_anomalies.append({
                            'index': i,
                            'execution_time_ms': execution_times[i],
                            'moving_average': moving_avg[i],
                            'deviation_ratio': execution_times[i] / moving_avg[i]
                        })
                
                return {
                    'statistical_anomalies': anomalies,
                    'trend_anomalies': trend_anomalies,
                    'total_anomalies': len(anomalies) + len(trend_anomalies),
                    'anomaly_percentage': (len(anomalies) + len(trend_anomalies)) / len(execution_times) * 100,
                    'severity_assessment': 'high' if len(anomalies) > len(execution_times) * 0.05 else 'moderate' if len(anomalies) > 0 else 'low'
                }
            else:
                return {
                    'statistical_anomalies': anomalies,
                    'total_anomalies': len(anomalies),
                    'anomaly_percentage': len(anomalies) / len(execution_times) * 100,
                    'severity_assessment': 'high' if len(anomalies) > len(execution_times) * 0.05 else 'moderate' if len(anomalies) > 0 else 'low'
                }
                
        except Exception as e:
            logger.error(f"Query anomaly detection failed: {str(e)}")
            return {'error': f'Anomaly detection failed: {str(e)}'}
    
    def _analyze_index_usage(self, metrics: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze database index usage patterns and performance impact.
        
        Args:
            metrics: List of query performance metrics
            
        Returns:
            Index usage analysis results
        """
        try:
            index_data = [m for m in metrics if 'index_used' in m and m['index_used'] is not None]
            
            if not index_data:
                return {'note': 'No index usage data available'}
            
            indexed_queries = [m for m in index_data if m['index_used']]
            non_indexed_queries = [m for m in index_data if not m['index_used']]
            
            index_usage_rate = len(indexed_queries) / len(index_data) * 100
            
            # Performance comparison
            performance_comparison = {}
            if indexed_queries and non_indexed_queries:
                indexed_times = [m['execution_time_ms'] for m in indexed_queries]
                non_indexed_times = [m['execution_time_ms'] for m in non_indexed_queries]
                
                performance_comparison = {
                    'indexed_mean_time_ms': statistics.mean(indexed_times),
                    'non_indexed_mean_time_ms': statistics.mean(non_indexed_times),
                    'performance_improvement_ratio': statistics.mean(non_indexed_times) / statistics.mean(indexed_times) if statistics.mean(indexed_times) > 0 else 0,
                    'index_effectiveness': 'high' if statistics.mean(non_indexed_times) > statistics.mean(indexed_times) * 2 else 'moderate' if statistics.mean(non_indexed_times) > statistics.mean(indexed_times) * 1.5 else 'low'
                }
            
            return {
                'total_queries_with_index_data': len(index_data),
                'indexed_queries': len(indexed_queries),
                'non_indexed_queries': len(non_indexed_queries),
                'index_usage_rate_percent': index_usage_rate,
                'performance_comparison': performance_comparison,
                'recommendations': self._generate_index_recommendations(index_usage_rate, performance_comparison)
            }
            
        except Exception as e:
            logger.error(f"Index usage analysis failed: {str(e)}")
            return {'error': f'Index usage analysis failed: {str(e)}'}
    
    def _analyze_query_size_correlation(self, metrics: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze correlation between query size and execution time.
        
        Args:
            metrics: List of query performance metrics
            
        Returns:
            Query size correlation analysis results
        """
        try:
            size_data = [
                m for m in metrics 
                if 'query_size_bytes' in m and m['query_size_bytes'] is not None and m['query_size_bytes'] > 0
            ]
            
            if len(size_data) < 5:
                return {'note': 'Insufficient data for size correlation analysis'}
            
            sizes = [m['query_size_bytes'] for m in size_data]
            times = [m['execution_time_ms'] for m in size_data]
            
            if SCIENTIFIC_LIBRARIES_AVAILABLE:
                # Calculate Pearson correlation
                correlation_coeff, p_value = stats.pearsonr(sizes, times)
                
                # Linear regression
                slope, intercept, r_value, reg_p_value, std_err = stats.linregress(sizes, times)
                
                return {
                    'sample_count': len(size_data),
                    'correlation_coefficient': correlation_coeff,
                    'correlation_p_value': p_value,
                    'correlation_significant': p_value < 0.05,
                    'correlation_strength': 'strong' if abs(correlation_coeff) > 0.7 else 'moderate' if abs(correlation_coeff) > 0.3 else 'weak',
                    'linear_regression': {
                        'slope': slope,
                        'intercept': intercept,
                        'r_squared': r_value ** 2,
                        'p_value': reg_p_value
                    },
                    'interpretation': 'Query size significantly impacts execution time' if p_value < 0.05 and correlation_coeff > 0.3 else 'No significant size-time correlation'
                }
            else:
                # Simple correlation calculation
                mean_size = statistics.mean(sizes)
                mean_time = statistics.mean(times)
                
                numerator = sum((s - mean_size) * (t - mean_time) for s, t in zip(sizes, times))
                denominator = (sum((s - mean_size) ** 2 for s in sizes) * sum((t - mean_time) ** 2 for t in times)) ** 0.5
                
                correlation = numerator / denominator if denominator > 0 else 0
                
                return {
                    'sample_count': len(size_data),
                    'correlation_coefficient': correlation,
                    'correlation_strength': 'strong' if abs(correlation) > 0.7 else 'moderate' if abs(correlation) > 0.3 else 'weak',
                    'note': 'Simplified correlation analysis (scipy not available)'
                }
                
        except Exception as e:
            logger.error(f"Query size correlation analysis failed: {str(e)}")
            return {'error': f'Size correlation analysis failed: {str(e)}'}
    
    def _generate_query_recommendations(
        self, 
        query_stats: Dict[str, Any], 
        baseline_analysis: Dict[str, Any], 
        anomaly_analysis: Dict[str, Any]
    ) -> List[str]:
        """
        Generate actionable recommendations for query performance optimization.
        
        Args:
            query_stats: Query performance statistics
            baseline_analysis: Baseline comparison results
            anomaly_analysis: Anomaly detection results
            
        Returns:
            List of actionable recommendations
        """
        recommendations = []
        
        try:
            # Baseline variance recommendations
            if baseline_analysis and not baseline_analysis.get('within_threshold', True):
                variance = baseline_analysis.get('variance_percent', 0)
                if variance > CRITICAL_VARIANCE_THRESHOLD:
                    recommendations.append(f"CRITICAL: Query performance degraded by {variance:.1f}% - immediate optimization required")
                elif variance > WARNING_VARIANCE_THRESHOLD:
                    recommendations.append(f"WARNING: Query performance degraded by {variance:.1f}% - optimization recommended")
            
            # Performance threshold recommendations
            mean_time = query_stats.get('mean_execution_time_ms', 0)
            if mean_time > 1000:  # >1 second average
                recommendations.append("High average execution time detected - consider query optimization")
            elif mean_time > 500:  # >500ms average
                recommendations.append("Moderate execution time - monitor for further degradation")
            
            # Variability recommendations
            std_dev = query_stats.get('std_deviation_ms', 0)
            if std_dev > mean_time * 0.5:  # High variability
                recommendations.append("High execution time variability - investigate query consistency")
            
            # Anomaly recommendations
            if anomaly_analysis and anomaly_analysis.get('severity_assessment') in ['high', 'moderate']:
                anomaly_count = anomaly_analysis.get('total_anomalies', 0)
                recommendations.append(f"Found {anomaly_count} performance anomalies - investigate query optimization")
            
            # General optimization recommendations
            if not recommendations:
                recommendations.append("Query performance within acceptable limits")
                recommendations.append("Continue monitoring for performance regressions")
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Query recommendations generation failed: {str(e)}")
            return ["Error generating query recommendations - manual analysis required"]
    
    def _generate_index_recommendations(
        self, 
        index_usage_rate: float, 
        performance_comparison: Dict[str, Any]
    ) -> List[str]:
        """
        Generate index optimization recommendations.
        
        Args:
            index_usage_rate: Percentage of queries using indexes
            performance_comparison: Performance comparison between indexed and non-indexed queries
            
        Returns:
            List of index optimization recommendations
        """
        recommendations = []
        
        try:
            if index_usage_rate < 80:  # Less than 80% index usage
                recommendations.append(f"Low index usage rate ({index_usage_rate:.1f}%) - review indexing strategy")
            
            if performance_comparison and performance_comparison.get('index_effectiveness') == 'low':
                recommendations.append("Low index effectiveness - review index design and query patterns")
            
            if performance_comparison and performance_comparison.get('performance_improvement_ratio', 0) > 5:
                recommendations.append("High performance gain from indexes - ensure all critical queries are indexed")
            
            if not recommendations:
                recommendations.append("Index usage patterns appear optimal")
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Index recommendations generation failed: {str(e)}")
            return ["Error generating index recommendations"]
    
    def _generate_overall_db_summary(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate overall database performance summary across all operations.
        
        Args:
            analysis_results: Analysis results for all database operations
            
        Returns:
            Overall database performance summary
        """
        try:
            if not analysis_results:
                return {'note': 'No analysis results available for summary'}
            
            # Aggregate statistics
            all_mean_times = []
            variance_violations = 0
            total_operations = 0
            high_anomaly_operations = 0
            
            for operation, results in analysis_results.items():
                query_stats = results.get('query_statistics', {})
                baseline_analysis = results.get('baseline_analysis', {})
                anomaly_analysis = results.get('anomaly_analysis', {})
                
                if query_stats.get('mean_execution_time_ms'):
                    all_mean_times.append(query_stats['mean_execution_time_ms'])
                
                total_operations += 1
                
                if not baseline_analysis.get('within_threshold', True):
                    variance_violations += 1
                
                if anomaly_analysis.get('severity_assessment') in ['high', 'moderate']:
                    high_anomaly_operations += 1
            
            # Overall performance metrics
            overall_metrics = {}
            if all_mean_times:
                overall_metrics = {
                    'average_query_time_ms': statistics.mean(all_mean_times),
                    'fastest_operation_ms': min(all_mean_times),
                    'slowest_operation_ms': max(all_mean_times),
                    'query_time_std_dev': statistics.stdev(all_mean_times) if len(all_mean_times) > 1 else 0
                }
            
            # Compliance assessment
            compliance_rate = ((total_operations - variance_violations) / total_operations * 100) if total_operations > 0 else 100
            anomaly_rate = (high_anomaly_operations / total_operations * 100) if total_operations > 0 else 0
            
            # Overall performance grade
            performance_grade = 'A'
            if compliance_rate < 90 or anomaly_rate > 10:
                performance_grade = 'D'
            elif compliance_rate < 95 or anomaly_rate > 5:
                performance_grade = 'C'
            elif compliance_rate < 98 or anomaly_rate > 2:
                performance_grade = 'B'
            
            return {
                'total_operations_analyzed': total_operations,
                'overall_metrics': overall_metrics,
                'compliance_assessment': {
                    'compliance_rate_percent': compliance_rate,
                    'variance_violations': variance_violations,
                    'anomaly_rate_percent': anomaly_rate,
                    'high_anomaly_operations': high_anomaly_operations
                },
                'performance_grade': performance_grade,
                'overall_status': 'excellent' if performance_grade == 'A' else 'good' if performance_grade == 'B' else 'needs_improvement' if performance_grade == 'C' else 'critical',
                'summary_recommendations': self._generate_overall_recommendations(compliance_rate, anomaly_rate, performance_grade)
            }
            
        except Exception as e:
            logger.error(f"Overall database summary generation failed: {str(e)}")
            return {'error': f'Overall summary generation failed: {str(e)}'}
    
    def _generate_overall_recommendations(self, compliance_rate: float, anomaly_rate: float, performance_grade: str) -> List[str]:
        """
        Generate overall database performance recommendations.
        
        Args:
            compliance_rate: Percentage of operations within performance thresholds
            anomaly_rate: Percentage of operations with anomalies
            performance_grade: Overall performance grade
            
        Returns:
            List of overall recommendations
        """
        recommendations = []
        
        try:
            if performance_grade in ['D', 'C']:
                recommendations.append("Database performance requires immediate attention")
                if compliance_rate < 90:
                    recommendations.append("Multiple operations exceed performance variance thresholds")
                if anomaly_rate > 10:
                    recommendations.append("High rate of performance anomalies detected")
            elif performance_grade == 'B':
                recommendations.append("Database performance is good but has room for improvement")
                recommendations.append("Monitor performance trends closely")
            else:
                recommendations.append("Database performance is excellent")
                recommendations.append("Continue current monitoring and optimization practices")
            
            # Specific action items
            if compliance_rate < 95:
                recommendations.append("Review indexing strategy for underperforming operations")
                recommendations.append("Consider query optimization for operations exceeding thresholds")
            
            if anomaly_rate > 5:
                recommendations.append("Investigate root causes of performance anomalies")
                recommendations.append("Implement more granular performance monitoring")
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Overall recommendations generation failed: {str(e)}")
            return ["Error generating overall recommendations"]


class PrometheusMetricsProcessor:
    """
    Prometheus metrics data processing and analysis engine.
    
    Implements prometheus-client 0.17+ metrics parsing, processing, and analysis
    per Section 3.6.2 metrics collection requirements with comprehensive
    performance data aggregation and trend analysis capabilities.
    """
    
    def __init__(self):
        """Initialize Prometheus metrics processor with parsing capabilities."""
        self.metrics_cache: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.registry_snapshots: List[Dict[str, Any]] = []
        self.processing_lock = threading.Lock()
        
        logger.info("PrometheusMetricsProcessor initialized")
    
    def parse_metrics_text(self, metrics_text: str) -> Dict[str, Any]:
        """
        Parse Prometheus metrics text format into structured data.
        
        Args:
            metrics_text: Prometheus metrics in text format
            
        Returns:
            Parsed metrics data with metadata and values
        """
        try:
            if not PROMETHEUS_CLIENT_AVAILABLE:
                return {'error': 'prometheus-client not available for metrics parsing'}
            
            parsed_metrics = {}
            timestamp = datetime.utcnow()
            
            # Parse metrics using prometheus_client parser
            for family in text_string_to_metric_families(metrics_text):
                metric_name = family.name
                metric_type = family.type
                metric_help = family.documentation
                
                metric_samples = []
                for sample in family.samples:
                    sample_data = {
                        'name': sample.name,
                        'labels': sample.labels,
                        'value': sample.value,
                        'timestamp': sample.timestamp
                    }
                    metric_samples.append(sample_data)
                
                parsed_metrics[metric_name] = {
                    'type': metric_type,
                    'help': metric_help,
                    'samples': metric_samples,
                    'parsed_at': timestamp.isoformat()
                }
            
            # Cache parsed metrics
            with self.processing_lock:
                self.registry_snapshots.append({
                    'timestamp': timestamp.isoformat(),
                    'metrics': parsed_metrics,
                    'total_metrics': len(parsed_metrics)
                })
                
                # Limit cache size
                if len(self.registry_snapshots) > 1000:
                    self.registry_snapshots = self.registry_snapshots[-500:]
            
            logger.info(f"Parsed {len(parsed_metrics)} metric families from Prometheus text")
            
            return {
                'parsed_metrics': parsed_metrics,
                'parsing_metadata': {
                    'total_metric_families': len(parsed_metrics),
                    'total_samples': sum(len(m['samples']) for m in parsed_metrics.values()),
                    'parsed_at': timestamp.isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"Metrics text parsing failed: {str(e)}")
            return {'error': f'Metrics parsing failed: {str(e)}'}
    
    def extract_performance_metrics(self, parsed_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract performance-specific metrics from parsed Prometheus data.
        
        Args:
            parsed_metrics: Parsed Prometheus metrics data
            
        Returns:
            Extracted performance metrics relevant to ≤10% variance analysis
        """
        try:
            if 'parsed_metrics' in parsed_metrics:
                metrics_data = parsed_metrics['parsed_metrics']
            else:
                metrics_data = parsed_metrics
            
            performance_metrics = {
                'response_time_metrics': {},
                'throughput_metrics': {},
                'error_metrics': {},
                'resource_metrics': {},
                'custom_metrics': {}
            }
            
            for metric_name, metric_data in metrics_data.items():
                samples = metric_data.get('samples', [])
                
                # Response time metrics (histograms and summaries)
                if 'response' in metric_name.lower() and 'time' in metric_name.lower():
                    performance_metrics['response_time_metrics'][metric_name] = self._process_timing_metric(samples)
                
                # Throughput metrics (counters and rates)
                elif 'request' in metric_name.lower() and ('total' in metric_name.lower() or 'count' in metric_name.lower()):
                    performance_metrics['throughput_metrics'][metric_name] = self._process_counter_metric(samples)
                
                # Error metrics
                elif 'error' in metric_name.lower() or 'fail' in metric_name.lower():
                    performance_metrics['error_metrics'][metric_name] = self._process_counter_metric(samples)
                
                # Resource utilization metrics
                elif any(resource in metric_name.lower() for resource in ['cpu', 'memory', 'disk', 'network']):
                    performance_metrics['resource_metrics'][metric_name] = self._process_gauge_metric(samples)
                
                # Custom Flask migration metrics
                elif 'flask' in metric_name.lower() or 'migration' in metric_name.lower():
                    performance_metrics['custom_metrics'][metric_name] = self._process_custom_metric(samples)
            
            # Performance summary calculation
            performance_summary = self._calculate_performance_summary(performance_metrics)
            
            return {
                'performance_metrics': performance_metrics,
                'performance_summary': performance_summary,
                'extraction_metadata': {
                    'extracted_at': datetime.utcnow().isoformat(),
                    'response_time_metrics_count': len(performance_metrics['response_time_metrics']),
                    'throughput_metrics_count': len(performance_metrics['throughput_metrics']),
                    'error_metrics_count': len(performance_metrics['error_metrics']),
                    'resource_metrics_count': len(performance_metrics['resource_metrics']),
                    'custom_metrics_count': len(performance_metrics['custom_metrics'])
                }
            }
            
        except Exception as e:
            logger.error(f"Performance metrics extraction failed: {str(e)}")
            return {'error': f'Performance metrics extraction failed: {str(e)}'}
    
    def _process_timing_metric(self, samples: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Process timing-related metrics (histograms and summaries).
        
        Args:
            samples: List of metric samples
            
        Returns:
            Processed timing metric data
        """
        try:
            timing_data = {
                'buckets': {},
                'quantiles': {},
                'count': 0,
                'sum': 0.0
            }
            
            for sample in samples:
                sample_name = sample['name']
                sample_value = sample['value']
                sample_labels = sample.get('labels', {})
                
                # Histogram buckets
                if '_bucket' in sample_name:
                    le_value = sample_labels.get('le', 'inf')
                    timing_data['buckets'][le_value] = sample_value
                
                # Summary quantiles
                elif '_quantile' in sample_name or 'quantile' in sample_labels:
                    quantile = sample_labels.get('quantile', 'unknown')
                    timing_data['quantiles'][quantile] = sample_value
                
                # Count and sum
                elif '_count' in sample_name:
                    timing_data['count'] = sample_value
                elif '_sum' in sample_name:
                    timing_data['sum'] = sample_value
            
            # Calculate derived metrics
            if timing_data['count'] > 0:
                timing_data['average'] = timing_data['sum'] / timing_data['count']
            
            return timing_data
            
        except Exception as e:
            logger.error(f"Timing metric processing failed: {str(e)}")
            return {'error': f'Timing metric processing failed: {str(e)}'}
    
    def _process_counter_metric(self, samples: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Process counter-type metrics.
        
        Args:
            samples: List of metric samples
            
        Returns:
            Processed counter metric data
        """
        try:
            counter_data = {
                'total_value': 0.0,
                'by_labels': {},
                'sample_count': len(samples)
            }
            
            for sample in samples:
                sample_value = sample['value']
                sample_labels = sample.get('labels', {})
                
                counter_data['total_value'] += sample_value
                
                # Group by label combinations
                label_key = '_'.join(f"{k}:{v}" for k, v in sorted(sample_labels.items()))
                if label_key not in counter_data['by_labels']:
                    counter_data['by_labels'][label_key] = 0.0
                counter_data['by_labels'][label_key] += sample_value
            
            return counter_data
            
        except Exception as e:
            logger.error(f"Counter metric processing failed: {str(e)}")
            return {'error': f'Counter metric processing failed: {str(e)}'}
    
    def _process_gauge_metric(self, samples: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Process gauge-type metrics.
        
        Args:
            samples: List of metric samples
            
        Returns:
            Processed gauge metric data
        """
        try:
            gauge_data = {
                'current_values': [],
                'by_labels': {},
                'sample_count': len(samples)
            }
            
            for sample in samples:
                sample_value = sample['value']
                sample_labels = sample.get('labels', {})
                
                gauge_data['current_values'].append(sample_value)
                
                # Group by label combinations
                label_key = '_'.join(f"{k}:{v}" for k, v in sorted(sample_labels.items()))
                gauge_data['by_labels'][label_key] = sample_value
            
            # Calculate statistics if multiple values
            if gauge_data['current_values']:
                gauge_data['statistics'] = {
                    'min': min(gauge_data['current_values']),
                    'max': max(gauge_data['current_values']),
                    'mean': statistics.mean(gauge_data['current_values']),
                    'median': statistics.median(gauge_data['current_values'])
                }
                
                if len(gauge_data['current_values']) > 1:
                    gauge_data['statistics']['std_dev'] = statistics.stdev(gauge_data['current_values'])
            
            return gauge_data
            
        except Exception as e:
            logger.error(f"Gauge metric processing failed: {str(e)}")
            return {'error': f'Gauge metric processing failed: {str(e)}'}
    
    def _process_custom_metric(self, samples: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Process custom Flask migration metrics.
        
        Args:
            samples: List of metric samples
            
        Returns:
            Processed custom metric data
        """
        try:
            custom_data = {
                'samples': samples,
                'sample_count': len(samples),
                'processed_at': datetime.utcnow().isoformat()
            }
            
            # Extract values for analysis
            values = [sample['value'] for sample in samples if isinstance(sample['value'], (int, float))]
            
            if values:
                custom_data['value_statistics'] = {
                    'count': len(values),
                    'sum': sum(values),
                    'min': min(values),
                    'max': max(values),
                    'mean': statistics.mean(values),
                    'median': statistics.median(values)
                }
                
                if len(values) > 1:
                    custom_data['value_statistics']['std_dev'] = statistics.stdev(values)
            
            return custom_data
            
        except Exception as e:
            logger.error(f"Custom metric processing failed: {str(e)}")
            return {'error': f'Custom metric processing failed: {str(e)}'}
    
    def _calculate_performance_summary(self, performance_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate overall performance summary from extracted metrics.
        
        Args:
            performance_metrics: Extracted performance metrics
            
        Returns:
            Performance summary with key indicators
        """
        try:
            summary = {
                'timestamp': datetime.utcnow().isoformat(),
                'metrics_availability': {},
                'performance_indicators': {},
                'health_status': 'unknown'
            }
            
            # Check metrics availability
            for category, metrics in performance_metrics.items():
                summary['metrics_availability'][category] = {
                    'available': len(metrics) > 0,
                    'count': len(metrics)
                }
            
            # Calculate performance indicators
            response_metrics = performance_metrics.get('response_time_metrics', {})
            if response_metrics:
                # Aggregate response time data
                all_averages = []
                all_p95s = []
                
                for metric_name, metric_data in response_metrics.items():
                    if 'average' in metric_data:
                        all_averages.append(metric_data['average'])
                    
                    quantiles = metric_data.get('quantiles', {})
                    if '0.95' in quantiles:
                        all_p95s.append(quantiles['0.95'])
                
                if all_averages:
                    summary['performance_indicators']['avg_response_time'] = statistics.mean(all_averages)
                if all_p95s:
                    summary['performance_indicators']['p95_response_time'] = statistics.mean(all_p95s)
            
            # Calculate throughput indicators
            throughput_metrics = performance_metrics.get('throughput_metrics', {})
            if throughput_metrics:
                total_requests = 0
                for metric_name, metric_data in throughput_metrics.items():
                    total_requests += metric_data.get('total_value', 0)
                summary['performance_indicators']['total_requests'] = total_requests
            
            # Calculate error rate
            error_metrics = performance_metrics.get('error_metrics', {})
            if error_metrics and throughput_metrics:
                total_errors = 0
                for metric_name, metric_data in error_metrics.items():
                    total_errors += metric_data.get('total_value', 0)
                
                total_requests = summary['performance_indicators'].get('total_requests', 0)
                if total_requests > 0:
                    summary['performance_indicators']['error_rate_percent'] = (total_errors / total_requests) * 100
            
            # Determine health status
            health_status = 'healthy'
            p95_response = summary['performance_indicators'].get('p95_response_time', 0)
            error_rate = summary['performance_indicators'].get('error_rate_percent', 0)
            
            if p95_response > 1.0 or error_rate > 1.0:  # >1s response time or >1% error rate
                health_status = 'critical'
            elif p95_response > 0.5 or error_rate > 0.5:  # >500ms response time or >0.5% error rate
                health_status = 'warning'
            
            summary['health_status'] = health_status
            
            return summary
            
        except Exception as e:
            logger.error(f"Performance summary calculation failed: {str(e)}")
            return {'error': f'Performance summary calculation failed: {str(e)}'}


class PerformanceDataProcessor:
    """
    Main performance data processing orchestration engine.
    
    Integrates all performance analysis components to provide comprehensive
    performance data processing, analysis, and reporting capabilities for
    the Flask migration project with ≤10% variance compliance validation.
    """
    
    def __init__(self, config_environment: Optional[str] = None):
        """
        Initialize performance data processor with comprehensive analysis engines.
        
        Args:
            config_environment: Performance configuration environment (development, testing, staging, production)
        """
        self.config_environment = config_environment or 'development'
        
        # Initialize analysis engines
        self.statistical_engine = StatisticalAnalysisEngine()
        self.memory_profiler = MemoryProfiler()
        self.db_analyzer = DatabasePerformanceAnalyzer()
        self.metrics_processor = PrometheusMetricsProcessor()
        
        # Load performance configuration
        try:
            if INTERNAL_MODULES_AVAILABLE:
                self.performance_config = PerformanceConfigFactory.get_config(self.config_environment)
                self.baseline_manager = default_baseline_manager
                logger.info(f"Loaded performance configuration for environment: {self.config_environment}")
            else:
                self.performance_config = None
                self.baseline_manager = None
                logger.warning("Internal modules not available - using fallback configuration")
        except Exception as e:
            logger.error(f"Failed to load performance configuration: {str(e)}")
            self.performance_config = None
            self.baseline_manager = None
        
        # Processing state
        self.processing_active = False
        self.processing_results: Dict[str, Any] = {}
        self.processing_lock = threading.Lock()
        
        logger.info(f"PerformanceDataProcessor initialized for environment: {self.config_environment}")
    
    def start_monitoring(self) -> None:
        """Start continuous performance monitoring across all components."""
        try:
            self.processing_active = True
            
            # Start memory monitoring
            self.memory_profiler.start_monitoring()
            
            logger.info("Performance monitoring started across all components")
            
        except Exception as e:
            logger.error(f"Failed to start performance monitoring: {str(e)}")
            raise
    
    def stop_monitoring(self) -> None:
        """Stop continuous performance monitoring."""
        try:
            self.processing_active = False
            
            # Stop memory monitoring
            self.memory_profiler.stop_monitoring()
            
            logger.info("Performance monitoring stopped")
            
        except Exception as e:
            logger.error(f"Failed to stop performance monitoring: {str(e)}")
    
    def process_response_time_data(
        self, 
        response_times: List[float], 
        endpoint: str, 
        method: str = 'GET'
    ) -> Dict[str, Any]:
        """
        Process response time data with comprehensive statistical analysis.
        
        Args:
            response_times: List of response time measurements in milliseconds
            endpoint: API endpoint being analyzed
            method: HTTP method
            
        Returns:
            Comprehensive response time analysis results
        """
        try:
            logger.info(f"Processing response time data for {method} {endpoint} - {len(response_times)} samples")
            
            # Get baseline for comparison
            baseline_value = None
            if self.baseline_manager:
                baseline = self.baseline_manager.get_response_time_baseline(endpoint, method)
                if baseline:
                    baseline_value = baseline.mean_response_time_ms
            
            if not baseline_value:
                # Use default baseline if no specific baseline available
                baseline_value = 100.0  # Default 100ms baseline
                logger.warning(f"No specific baseline found for {method} {endpoint}, using default {baseline_value}ms")
            
            # Statistical analysis
            statistical_results = self.statistical_engine.calculate_performance_variance(
                response_times, baseline_value, f"response_time_{method}_{endpoint}"
            )
            
            # Additional response time specific analysis
            response_analysis = self._analyze_response_time_patterns(response_times, endpoint, method)
            
            # Compliance validation
            compliance_results = self._validate_response_time_compliance(
                statistical_results, response_analysis, baseline_value
            )
            
            result = {
                'analysis_type': 'response_time',
                'endpoint': endpoint,
                'method': method,
                'baseline_value_ms': baseline_value,
                'sample_count': len(response_times),
                'statistical_analysis': statistical_results,
                'response_time_analysis': response_analysis,
                'compliance_validation': compliance_results,
                'processing_timestamp': datetime.utcnow().isoformat()
            }
            
            # Cache results
            with self.processing_lock:
                result_key = f"response_time_{method}_{endpoint}"
                self.processing_results[result_key] = result
            
            logger.info(f"Response time analysis completed for {method} {endpoint}")
            return result
            
        except Exception as e:
            logger.error(f"Response time data processing failed: {str(e)}")
            return {
                'error': f'Response time processing failed: {str(e)}',
                'endpoint': endpoint,
                'method': method,
                'sample_count': len(response_times) if response_times else 0
            }
    
    def process_memory_usage_data(self, baseline_memory_mb: Optional[float] = None) -> Dict[str, Any]:
        """
        Process memory usage data with leak detection and variance analysis.
        
        Args:
            baseline_memory_mb: Baseline memory usage in MB for comparison
            
        Returns:
            Comprehensive memory usage analysis results
        """
        try:
            logger.info("Processing memory usage data with leak detection")
            
            # Analyze memory patterns
            memory_analysis = self.memory_profiler.analyze_memory_patterns(baseline_memory_mb)
            
            # Additional memory-specific processing
            memory_trends = self._analyze_memory_trends(memory_analysis)
            
            # Resource efficiency assessment
            efficiency_assessment = self._assess_memory_efficiency_detailed(memory_analysis)
            
            result = {
                'analysis_type': 'memory_usage',
                'baseline_memory_mb': baseline_memory_mb,
                'memory_analysis': memory_analysis,
                'memory_trends': memory_trends,
                'efficiency_assessment': efficiency_assessment,
                'processing_timestamp': datetime.utcnow().isoformat()
            }
            
            # Cache results
            with self.processing_lock:
                self.processing_results['memory_usage'] = result
            
            logger.info("Memory usage analysis completed")
            return result
            
        except Exception as e:
            logger.error(f"Memory usage data processing failed: {str(e)}")
            return {
                'error': f'Memory usage processing failed: {str(e)}',
                'baseline_memory_mb': baseline_memory_mb
            }
    
    def process_database_performance_data(self, time_window_hours: Optional[int] = None) -> Dict[str, Any]:
        """
        Process database performance data with query optimization analysis.
        
        Args:
            time_window_hours: Time window for analysis in hours
            
        Returns:
            Comprehensive database performance analysis results
        """
        try:
            logger.info(f"Processing database performance data - window: {time_window_hours} hours")
            
            # Analyze database performance
            db_analysis = self.db_analyzer.analyze_query_performance(time_window_hours=time_window_hours)
            
            # Additional database-specific processing
            optimization_recommendations = self._generate_db_optimization_recommendations(db_analysis)
            
            # Performance trend analysis
            db_trends = self._analyze_database_trends(db_analysis)
            
            result = {
                'analysis_type': 'database_performance',
                'time_window_hours': time_window_hours,
                'database_analysis': db_analysis,
                'optimization_recommendations': optimization_recommendations,
                'database_trends': db_trends,
                'processing_timestamp': datetime.utcnow().isoformat()
            }
            
            # Cache results
            with self.processing_lock:
                self.processing_results['database_performance'] = result
            
            logger.info("Database performance analysis completed")
            return result
            
        except Exception as e:
            logger.error(f"Database performance data processing failed: {str(e)}")
            return {
                'error': f'Database performance processing failed: {str(e)}',
                'time_window_hours': time_window_hours
            }
    
    def process_prometheus_metrics_data(self, metrics_text: str) -> Dict[str, Any]:
        """
        Process Prometheus metrics data with performance extraction and analysis.
        
        Args:
            metrics_text: Prometheus metrics in text format
            
        Returns:
            Comprehensive Prometheus metrics analysis results
        """
        try:
            logger.info("Processing Prometheus metrics data")
            
            # Parse metrics text
            parsed_metrics = self.metrics_processor.parse_metrics_text(metrics_text)
            
            if 'error' in parsed_metrics:
                return parsed_metrics
            
            # Extract performance metrics
            performance_metrics = self.metrics_processor.extract_performance_metrics(parsed_metrics)
            
            # Analyze performance indicators
            performance_indicators = self._analyze_prometheus_performance_indicators(performance_metrics)
            
            # Variance analysis against baselines
            variance_analysis = self._analyze_prometheus_variance(performance_metrics)
            
            result = {
                'analysis_type': 'prometheus_metrics',
                'parsed_metrics': parsed_metrics,
                'performance_metrics': performance_metrics,
                'performance_indicators': performance_indicators,
                'variance_analysis': variance_analysis,
                'processing_timestamp': datetime.utcnow().isoformat()
            }
            
            # Cache results
            with self.processing_lock:
                self.processing_results['prometheus_metrics'] = result
            
            logger.info("Prometheus metrics analysis completed")
            return result
            
        except Exception as e:
            logger.error(f"Prometheus metrics data processing failed: {str(e)}")
            return {
                'error': f'Prometheus metrics processing failed: {str(e)}',
                'metrics_text_length': len(metrics_text) if metrics_text else 0
            }
    
    def generate_comprehensive_report(self, include_visualizations: bool = False) -> Dict[str, Any]:
        """
        Generate comprehensive performance analysis report across all data sources.
        
        Args:
            include_visualizations: Whether to include performance trend visualizations
            
        Returns:
            Comprehensive performance analysis report
        """
        try:
            logger.info("Generating comprehensive performance analysis report")
            
            with self.processing_lock:
                processing_results = dict(self.processing_results)
            
            # Report metadata
            report = {
                'report_metadata': {
                    'generated_at': datetime.utcnow().isoformat(),
                    'config_environment': self.config_environment,
                    'analysis_components': list(processing_results.keys()),
                    'total_analyses': len(processing_results)
                },
                'executive_summary': {},
                'detailed_analysis': processing_results,
                'compliance_assessment': {},
                'recommendations': {},
                'performance_trends': {}
            }
            
            # Generate executive summary
            report['executive_summary'] = self._generate_executive_summary(processing_results)
            
            # Comprehensive compliance assessment
            report['compliance_assessment'] = self._assess_overall_compliance(processing_results)
            
            # Actionable recommendations
            report['recommendations'] = self._generate_comprehensive_recommendations(processing_results)
            
            # Performance trends analysis
            report['performance_trends'] = self._analyze_comprehensive_trends(processing_results)
            
            # Include visualizations if requested
            if include_visualizations and SCIENTIFIC_LIBRARIES_AVAILABLE:
                report['visualizations'] = self._generate_performance_visualizations(processing_results)
            
            # Overall assessment
            report['overall_assessment'] = self._generate_overall_assessment(report)
            
            logger.info("Comprehensive performance report generated successfully")
            return report
            
        except Exception as e:
            logger.error(f"Comprehensive report generation failed: {str(e)}")
            return {
                'error': f'Report generation failed: {str(e)}',
                'partial_results': processing_results if 'processing_results' in locals() else {}
            }
    
    def _analyze_response_time_patterns(self, response_times: List[float], endpoint: str, method: str) -> Dict[str, Any]:
        """
        Analyze response time patterns for endpoint-specific insights.
        
        Args:
            response_times: List of response time measurements
            endpoint: API endpoint
            method: HTTP method
            
        Returns:
            Response time pattern analysis results
        """
        try:
            if len(response_times) < 3:
                return {'note': 'Insufficient data for pattern analysis'}
            
            # Performance characteristics
            sorted_times = sorted(response_times)
            n = len(sorted_times)
            
            characteristics = {
                'fastest_10_percent': statistics.mean(sorted_times[:max(1, n//10)]),
                'slowest_10_percent': statistics.mean(sorted_times[-max(1, n//10):]),
                'performance_consistency': 1 - (statistics.stdev(response_times) / statistics.mean(response_times)) if statistics.mean(response_times) > 0 else 0
            }
            
            # Threshold compliance
            mean_time = statistics.mean(response_times)
            threshold_compliance = {
                'under_100ms': sum(1 for t in response_times if t < 100) / len(response_times) * 100,
                'under_500ms': sum(1 for t in response_times if t < 500) / len(response_times) * 100,
                'under_1000ms': sum(1 for t in response_times if t < 1000) / len(response_times) * 100,
                'over_2000ms': sum(1 for t in response_times if t > 2000) / len(response_times) * 100
            }
            
            # Performance grade
            if mean_time < 100:
                performance_grade = 'A'
            elif mean_time < 250:
                performance_grade = 'B'
            elif mean_time < 500:
                performance_grade = 'C'
            elif mean_time < 1000:
                performance_grade = 'D'
            else:
                performance_grade = 'F'
            
            return {
                'characteristics': characteristics,
                'threshold_compliance': threshold_compliance,
                'performance_grade': performance_grade,
                'endpoint_specific_insights': {
                    'endpoint': endpoint,
                    'method': method,
                    'performance_category': 'excellent' if performance_grade in ['A', 'B'] else 'good' if performance_grade == 'C' else 'needs_improvement'
                }
            }
            
        except Exception as e:
            logger.error(f"Response time pattern analysis failed: {str(e)}")
            return {'error': f'Pattern analysis failed: {str(e)}'}
    
    def _validate_response_time_compliance(
        self, 
        statistical_results: Dict[str, Any], 
        response_analysis: Dict[str, Any], 
        baseline_value: float
    ) -> Dict[str, Any]:
        """
        Validate response time compliance against ≤10% variance threshold.
        
        Args:
            statistical_results: Statistical analysis results
            response_analysis: Response time pattern analysis
            baseline_value: Baseline response time value
            
        Returns:
            Compliance validation results
        """
        try:
            # Extract variance information
            variance_analysis = statistical_results.get('variance_analysis', {})
            mean_variance = variance_analysis.get('mean_variance_percent', 0)
            
            # Compliance status
            variance_compliant = abs(mean_variance) <= PERFORMANCE_VARIANCE_THRESHOLD
            
            # Performance grade compliance
            performance_grade = response_analysis.get('performance_grade', 'F')
            grade_compliant = performance_grade in ['A', 'B', 'C']
            
            # Overall compliance
            overall_compliant = variance_compliant and grade_compliant
            
            # Risk assessment
            risk_level = 'low'
            if not variance_compliant and abs(mean_variance) > CRITICAL_VARIANCE_THRESHOLD:
                risk_level = 'critical'
            elif not variance_compliant:
                risk_level = 'high'
            elif not grade_compliant:
                risk_level = 'moderate'
            
            # Compliance recommendations
            recommendations = []
            if not variance_compliant:
                recommendations.append(f"Response time variance {mean_variance:.1f}% exceeds ±{PERFORMANCE_VARIANCE_THRESHOLD}% threshold")
            if not grade_compliant:
                recommendations.append(f"Performance grade {performance_grade} below acceptable level")
            if not overall_compliant:
                recommendations.append("Immediate performance optimization required")
            
            if not recommendations:
                recommendations.append("Response time performance within acceptable limits")
            
            return {
                'overall_compliant': overall_compliant,
                'variance_compliant': variance_compliant,
                'grade_compliant': grade_compliant,
                'risk_level': risk_level,
                'compliance_details': {
                    'mean_variance_percent': mean_variance,
                    'variance_threshold': PERFORMANCE_VARIANCE_THRESHOLD,
                    'performance_grade': performance_grade,
                    'baseline_value_ms': baseline_value
                },
                'recommendations': recommendations
            }
            
        except Exception as e:
            logger.error(f"Response time compliance validation failed: {str(e)}")
            return {'error': f'Compliance validation failed: {str(e)}'}
    
    def _analyze_memory_trends(self, memory_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze memory usage trends for pattern identification.
        
        Args:
            memory_analysis: Memory analysis results
            
        Returns:
            Memory trend analysis results
        """
        try:
            memory_stats = memory_analysis.get('memory_statistics', {})
            leak_analysis = memory_analysis.get('leak_analysis', {})
            
            if not memory_stats:
                return {'note': 'No memory statistics available for trend analysis'}
            
            # Trend classification
            growth_percent = memory_stats.get('growth_percent', 0)
            
            trend_classification = 'stable'
            if growth_percent > 20:
                trend_classification = 'increasing_high'
            elif growth_percent > 10:
                trend_classification = 'increasing_moderate'
            elif growth_percent < -10:
                trend_classification = 'decreasing'
            
            # Memory efficiency trends
            std_dev = memory_stats.get('std_dev_mb', 0)
            mean_memory = memory_stats.get('mean_mb', 1)
            
            efficiency_trends = {
                'stability_trend': 'stable' if std_dev / mean_memory < 0.1 else 'volatile',
                'growth_trend': trend_classification,
                'leak_trend': leak_analysis.get('leak_severity', 'low')
            }
            
            # Future projections
            growth_rate = leak_analysis.get('growth_rate_mb_per_minute', 0)
            projections = {
                'projected_1h_mb': memory_stats.get('mean_mb', 0) + (growth_rate * 60),
                'projected_24h_mb': memory_stats.get('mean_mb', 0) + (growth_rate * 60 * 24),
                'sustainability': 'sustainable' if growth_rate < 0.1 else 'concerning' if growth_rate < 1.0 else 'unsustainable'
            }
            
            return {
                'trend_classification': trend_classification,
                'efficiency_trends': efficiency_trends,
                'projections': projections,
                'trend_summary': {
                    'overall_trend': 'concerning' if trend_classification.startswith('increasing') and leak_analysis.get('leak_detected', False) else 'stable',
                    'requires_attention': growth_percent > 15 or leak_analysis.get('leak_detected', False)
                }
            }
            
        except Exception as e:
            logger.error(f"Memory trends analysis failed: {str(e)}")
            return {'error': f'Memory trends analysis failed: {str(e)}'}
    
    def _assess_memory_efficiency_detailed(self, memory_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detailed memory efficiency assessment with optimization recommendations.
        
        Args:
            memory_analysis: Memory analysis results
            
        Returns:
            Detailed memory efficiency assessment
        """
        try:
            efficiency_assessment = memory_analysis.get('efficiency_assessment', {})
            memory_stats = memory_analysis.get('memory_statistics', {})
            
            if not efficiency_assessment or not memory_stats:
                return {'note': 'Insufficient data for detailed efficiency assessment'}
            
            # Enhanced efficiency metrics
            efficiency_score = efficiency_assessment.get('efficiency_score', 0)
            efficiency_grade = efficiency_assessment.get('efficiency_grade', 'F')
            
            # Memory usage patterns
            usage_patterns = {
                'memory_range_mb': memory_stats.get('max_mb', 0) - memory_stats.get('min_mb', 0),
                'memory_stability': 'high' if memory_stats.get('std_dev_mb', 0) / memory_stats.get('mean_mb', 1) < 0.1 else 'moderate' if memory_stats.get('std_dev_mb', 0) / memory_stats.get('mean_mb', 1) < 0.2 else 'low',
                'peak_usage_factor': memory_stats.get('max_mb', 0) / memory_stats.get('mean_mb', 1) if memory_stats.get('mean_mb', 0) > 0 else 1
            }
            
            # Optimization potential
            optimization_potential = {
                'memory_optimization_score': max(0, 1 - efficiency_score),
                'priority_level': 'high' if efficiency_score < 0.6 else 'medium' if efficiency_score < 0.8 else 'low',
                'estimated_improvement_percent': (1 - efficiency_score) * 50  # Potential improvement
            }
            
            # Resource recommendations
            resource_recommendations = []
            if usage_patterns['peak_usage_factor'] > 1.5:
                resource_recommendations.append("High peak memory usage detected - consider memory pooling")
            if usage_patterns['memory_stability'] == 'low':
                resource_recommendations.append("Memory usage volatility detected - review allocation patterns")
            if efficiency_score < 0.7:
                resource_recommendations.append("Memory efficiency below optimal - implement optimization strategies")
            
            return {
                'enhanced_efficiency_metrics': {
                    'efficiency_score': efficiency_score,
                    'efficiency_grade': efficiency_grade,
                    'optimization_potential': optimization_potential
                },
                'usage_patterns': usage_patterns,
                'resource_recommendations': resource_recommendations,
                'performance_impact_assessment': {
                    'current_impact': efficiency_assessment.get('performance_impact', 'unknown'),
                    'optimization_benefit': 'high' if optimization_potential['priority_level'] == 'high' else 'moderate'
                }
            }
            
        except Exception as e:
            logger.error(f"Detailed memory efficiency assessment failed: {str(e)}")
            return {'error': f'Detailed efficiency assessment failed: {str(e)}'}
    
    def _generate_db_optimization_recommendations(self, db_analysis: Dict[str, Any]) -> List[str]:
        """
        Generate database optimization recommendations based on analysis results.
        
        Args:
            db_analysis: Database performance analysis results
            
        Returns:
            List of actionable database optimization recommendations
        """
        recommendations = []
        
        try:
            query_analysis = db_analysis.get('query_analysis', {})
            overall_summary = db_analysis.get('overall_summary', {})
            
            # Overall performance recommendations
            performance_grade = overall_summary.get('performance_grade', 'F')
            if performance_grade in ['D', 'F']:
                recommendations.append("Critical database performance issues detected - immediate optimization required")
                recommendations.append("Consider implementing query optimization and indexing improvements")
            elif performance_grade == 'C':
                recommendations.append("Database performance has room for improvement")
                recommendations.append("Review slow queries and implement targeted optimizations")
            
            # Query-specific recommendations
            for query_key, query_results in query_analysis.items():
                query_recommendations = query_results.get('recommendations', [])
                if query_recommendations:
                    recommendations.append(f"Query {query_key}:")
                    recommendations.extend([f"  - {rec}" for rec in query_recommendations])
            
            # Index optimization
            compliance_rate = overall_summary.get('compliance_assessment', {}).get('compliance_rate_percent', 100)
            if compliance_rate < 90:
                recommendations.append("Low query performance compliance - review indexing strategy")
                recommendations.append("Consider implementing composite indexes for complex queries")
            
            # Connection pool optimization
            recommendations.append("Monitor connection pool utilization for optimal sizing")
            recommendations.append("Implement connection pool monitoring and alerting")
            
            if not recommendations:
                recommendations.append("Database performance is optimal - continue monitoring")
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Database optimization recommendations generation failed: {str(e)}")
            return ["Error generating database recommendations - manual analysis required"]
    
    def _analyze_database_trends(self, db_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze database performance trends for regression detection.
        
        Args:
            db_analysis: Database performance analysis results
            
        Returns:
            Database trend analysis results
        """
        try:
            overall_summary = db_analysis.get('overall_summary', {})
            
            if not overall_summary:
                return {'note': 'No database summary available for trend analysis'}
            
            # Performance trend assessment
            performance_grade = overall_summary.get('performance_grade', 'F')
            compliance_rate = overall_summary.get('compliance_assessment', {}).get('compliance_rate_percent', 0)
            
            trend_assessment = {
                'performance_trend': 'stable',  # Would need historical data for actual trend
                'compliance_trend': 'stable',   # Would need historical data for actual trend
                'overall_health': 'excellent' if performance_grade == 'A' else 'good' if performance_grade == 'B' else 'needs_improvement'
            }
            
            # Risk indicators
            risk_indicators = []
            if compliance_rate < 90:
                risk_indicators.append('Low compliance rate indicating potential performance regression')
            if performance_grade in ['D', 'F']:
                risk_indicators.append('Poor performance grade indicating critical issues')
            
            # Future outlook
            future_outlook = {
                'short_term': 'stable' if not risk_indicators else 'concerning',
                'optimization_needed': len(risk_indicators) > 0,
                'monitoring_priority': 'high' if len(risk_indicators) > 1 else 'medium' if len(risk_indicators) == 1 else 'low'
            }
            
            return {
                'trend_assessment': trend_assessment,
                'risk_indicators': risk_indicators,
                'future_outlook': future_outlook,
                'recommendation': 'Continue current monitoring practices' if not risk_indicators else 'Implement immediate optimization measures'
            }
            
        except Exception as e:
            logger.error(f"Database trends analysis failed: {str(e)}")
            return {'error': f'Database trends analysis failed: {str(e)}'}
    
    def _analyze_prometheus_performance_indicators(self, performance_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze Prometheus performance indicators for system health assessment.
        
        Args:
            performance_metrics: Extracted Prometheus performance metrics
            
        Returns:
            Performance indicators analysis results
        """
        try:
            performance_summary = performance_metrics.get('performance_summary', {})
            performance_indicators = performance_summary.get('performance_indicators', {})
            
            if not performance_indicators:
                return {'note': 'No performance indicators available from Prometheus metrics'}
            
            # Response time analysis
            response_time_analysis = {}
            avg_response_time = performance_indicators.get('avg_response_time')
            p95_response_time = performance_indicators.get('p95_response_time')
            
            if avg_response_time is not None:
                response_time_analysis['avg_response_time_ms'] = avg_response_time * 1000  # Convert to ms
                response_time_analysis['avg_response_grade'] = (
                    'A' if avg_response_time < 0.1 else
                    'B' if avg_response_time < 0.25 else
                    'C' if avg_response_time < 0.5 else
                    'D' if avg_response_time < 1.0 else 'F'
                )
            
            if p95_response_time is not None:
                response_time_analysis['p95_response_time_ms'] = p95_response_time * 1000
                response_time_analysis['p95_response_grade'] = (
                    'A' if p95_response_time < 0.5 else
                    'B' if p95_response_time < 1.0 else
                    'C' if p95_response_time < 2.0 else
                    'D' if p95_response_time < 5.0 else 'F'
                )
            
            # Throughput analysis
            throughput_analysis = {}
            total_requests = performance_indicators.get('total_requests')
            
            if total_requests is not None:
                throughput_analysis['total_requests'] = total_requests
                throughput_analysis['throughput_category'] = (
                    'high' if total_requests > 10000 else
                    'medium' if total_requests > 1000 else
                    'low'
                )
            
            # Error rate analysis
            error_analysis = {}
            error_rate = performance_indicators.get('error_rate_percent')
            
            if error_rate is not None:
                error_analysis['error_rate_percent'] = error_rate
                error_analysis['error_grade'] = (
                    'A' if error_rate < 0.1 else
                    'B' if error_rate < 0.5 else
                    'C' if error_rate < 1.0 else
                    'D' if error_rate < 5.0 else 'F'
                )
            
            # Overall system health
            health_status = performance_summary.get('health_status', 'unknown')
            
            system_health = {
                'overall_status': health_status,
                'health_score': 1.0 if health_status == 'healthy' else 0.5 if health_status == 'warning' else 0.0,
                'system_grade': 'A' if health_status == 'healthy' else 'C' if health_status == 'warning' else 'F'
            }
            
            return {
                'response_time_analysis': response_time_analysis,
                'throughput_analysis': throughput_analysis,
                'error_analysis': error_analysis,
                'system_health': system_health,
                'metrics_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Prometheus performance indicators analysis failed: {str(e)}")
            return {'error': f'Performance indicators analysis failed: {str(e)}'}
    
    def _analyze_prometheus_variance(self, performance_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze Prometheus metrics variance against baselines.
        
        Args:
            performance_metrics: Extracted Prometheus performance metrics
            
        Returns:
            Variance analysis results
        """
        try:
            performance_summary = performance_metrics.get('performance_summary', {})
            performance_indicators = performance_summary.get('performance_indicators', {})
            
            if not performance_indicators:
                return {'note': 'No performance indicators available for variance analysis'}
            
            variance_results = {}
            
            # Response time variance analysis
            p95_response_time = performance_indicators.get('p95_response_time')
            if p95_response_time is not None:
                # Convert to milliseconds and compare against baseline
                p95_ms = p95_response_time * 1000
                baseline_p95 = 250.0  # Default baseline 250ms
                
                variance_percent = ((p95_ms - baseline_p95) / baseline_p95) * 100
                variance_results['p95_response_time'] = {
                    'current_value_ms': p95_ms,
                    'baseline_value_ms': baseline_p95,
                    'variance_percent': variance_percent,
                    'within_threshold': abs(variance_percent) <= PERFORMANCE_VARIANCE_THRESHOLD,
                    'compliance_status': 'compliant' if abs(variance_percent) <= PERFORMANCE_VARIANCE_THRESHOLD else 'non_compliant'
                }
            
            # Error rate variance analysis
            error_rate = performance_indicators.get('error_rate_percent')
            if error_rate is not None:
                baseline_error_rate = 0.1  # Default baseline 0.1%
                
                if baseline_error_rate > 0:
                    variance_percent = ((error_rate - baseline_error_rate) / baseline_error_rate) * 100
                else:
                    variance_percent = error_rate * 100  # If baseline is 0, use absolute percentage
                
                variance_results['error_rate'] = {
                    'current_value_percent': error_rate,
                    'baseline_value_percent': baseline_error_rate,
                    'variance_percent': variance_percent,
                    'within_threshold': error_rate <= baseline_error_rate * 2,  # Allow 2x baseline for errors
                    'compliance_status': 'compliant' if error_rate <= baseline_error_rate * 2 else 'non_compliant'
                }
            
            # Overall variance assessment
            all_compliant = all(
                result.get('within_threshold', True) 
                for result in variance_results.values()
            )
            
            overall_assessment = {
                'overall_compliant': all_compliant,
                'total_metrics_analyzed': len(variance_results),
                'compliant_metrics': sum(1 for result in variance_results.values() if result.get('within_threshold', True)),
                'compliance_rate_percent': (sum(1 for result in variance_results.values() if result.get('within_threshold', True)) / len(variance_results) * 100) if variance_results else 100
            }
            
            return {
                'variance_results': variance_results,
                'overall_assessment': overall_assessment,
                'analysis_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Prometheus variance analysis failed: {str(e)}")
            return {'error': f'Prometheus variance analysis failed: {str(e)}'}
    
    def _generate_executive_summary(self, processing_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate executive summary of all performance analysis results.
        
        Args:
            processing_results: All processing results
            
        Returns:
            Executive summary with key findings and recommendations
        """
        try:
            summary = {
                'overall_performance_status': 'unknown',
                'key_findings': [],
                'critical_issues': [],
                'compliance_status': 'unknown',
                'recommendation_summary': 'Analysis pending'
            }
            
            # Analyze compliance across all components
            compliance_statuses = []
            critical_issues = []
            key_findings = []
            
            # Response time analysis
            for key, result in processing_results.items():
                if key.startswith('response_time_'):
                    compliance_validation = result.get('compliance_validation', {})
                    if compliance_validation:
                        overall_compliant = compliance_validation.get('overall_compliant', False)
                        compliance_statuses.append(overall_compliant)
                        
                        if not overall_compliant:
                            risk_level = compliance_validation.get('risk_level', 'unknown')
                            if risk_level in ['critical', 'high']:
                                critical_issues.append(f"Response time performance issue: {key}")
                        
                        variance_details = compliance_validation.get('compliance_details', {})
                        variance_percent = variance_details.get('mean_variance_percent', 0)
                        key_findings.append(f"{key}: {variance_percent:.1f}% variance from baseline")
            
            # Memory analysis
            memory_result = processing_results.get('memory_usage')
            if memory_result:
                memory_analysis = memory_result.get('memory_analysis', {})
                variance_analysis = memory_analysis.get('variance_analysis', {})
                if variance_analysis:
                    overall_compliant = variance_analysis.get('compliance_status', {}).get('overall_compliant', True)
                    compliance_statuses.append(overall_compliant)
                    
                    if not overall_compliant:
                        critical_issues.append("Memory usage exceeds variance threshold")
                
                leak_analysis = memory_analysis.get('leak_analysis', {})
                if leak_analysis.get('leak_detected', False):
                    severity = leak_analysis.get('leak_severity', 'low')
                    if severity in ['critical', 'high']:
                        critical_issues.append(f"Memory leak detected: {severity} severity")
                    key_findings.append(f"Memory leak status: {severity}")
            
            # Database analysis
            db_result = processing_results.get('database_performance')
            if db_result:
                db_analysis = db_result.get('database_analysis', {})
                overall_summary = db_analysis.get('overall_summary', {})
                if overall_summary:
                    performance_grade = overall_summary.get('performance_grade', 'F')
                    if performance_grade in ['D', 'F']:
                        critical_issues.append(f"Database performance grade: {performance_grade}")
                    key_findings.append(f"Database performance grade: {performance_grade}")
            
            # Prometheus metrics analysis
            prometheus_result = processing_results.get('prometheus_metrics')
            if prometheus_result:
                variance_analysis = prometheus_result.get('variance_analysis', {})
                overall_assessment = variance_analysis.get('overall_assessment', {})
                if overall_assessment:
                    overall_compliant = overall_assessment.get('overall_compliant', True)
                    compliance_statuses.append(overall_compliant)
                    
                    compliance_rate = overall_assessment.get('compliance_rate_percent', 100)
                    key_findings.append(f"Prometheus metrics compliance: {compliance_rate:.1f}%")
            
            # Overall status determination
            if compliance_statuses:
                overall_compliance_rate = sum(compliance_statuses) / len(compliance_statuses)
                
                if overall_compliance_rate >= 0.9:
                    summary['overall_performance_status'] = 'excellent'
                    summary['compliance_status'] = 'compliant'
                elif overall_compliance_rate >= 0.7:
                    summary['overall_performance_status'] = 'good'
                    summary['compliance_status'] = 'mostly_compliant'
                elif overall_compliance_rate >= 0.5:
                    summary['overall_performance_status'] = 'needs_improvement'
                    summary['compliance_status'] = 'partially_compliant'
                else:
                    summary['overall_performance_status'] = 'critical'
                    summary['compliance_status'] = 'non_compliant'
            
            # Recommendation summary
            if critical_issues:
                summary['recommendation_summary'] = 'Immediate action required - critical performance issues detected'
            elif len(key_findings) > 0 and summary['overall_performance_status'] in ['needs_improvement', 'good']:
                summary['recommendation_summary'] = 'Performance optimization recommended'
            else:
                summary['recommendation_summary'] = 'Performance within acceptable limits - continue monitoring'
            
            summary['key_findings'] = key_findings[:10]  # Limit to top 10 findings
            summary['critical_issues'] = critical_issues
            
            return summary
            
        except Exception as e:
            logger.error(f"Executive summary generation failed: {str(e)}")
            return {
                'error': f'Executive summary generation failed: {str(e)}',
                'overall_performance_status': 'unknown',
                'compliance_status': 'unknown'
            }
    
    def _assess_overall_compliance(self, processing_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess overall compliance with ≤10% variance threshold across all metrics.
        
        Args:
            processing_results: All processing results
            
        Returns:
            Overall compliance assessment
        """
        try:
            compliance_assessment = {
                'overall_compliant': True,
                'component_compliance': {},
                'variance_summary': {},
                'risk_assessment': {},
                'compliance_score': 0.0
            }
            
            component_scores = []
            variance_violations = []
            
            # Assess each component
            for component_key, result in processing_results.items():
                component_compliance = {
                    'compliant': True,
                    'variance_percent': 0.0,
                    'risk_level': 'low'
                }
                
                # Response time compliance
                if component_key.startswith('response_time_'):
                    compliance_validation = result.get('compliance_validation', {})
                    if compliance_validation:
                        component_compliance['compliant'] = compliance_validation.get('overall_compliant', True)
                        component_compliance['risk_level'] = compliance_validation.get('risk_level', 'low')
                        
                        variance_details = compliance_validation.get('compliance_details', {})
                        component_compliance['variance_percent'] = variance_details.get('mean_variance_percent', 0)
                
                # Memory compliance
                elif component_key == 'memory_usage':
                    memory_analysis = result.get('memory_analysis', {})
                    variance_analysis = memory_analysis.get('variance_analysis', {})
                    if variance_analysis:
                        compliance_status = variance_analysis.get('compliance_status', {})
                        component_compliance['compliant'] = compliance_status.get('overall_compliant', True)
                        component_compliance['variance_percent'] = variance_analysis.get('variance_analysis', {}).get('mean_variance_percent', 0)
                        
                        risk_assessment = variance_analysis.get('risk_assessment', {})
                        component_compliance['risk_level'] = risk_assessment.get('risk_level', 'low')
                
                # Database compliance
                elif component_key == 'database_performance':
                    db_analysis = result.get('database_analysis', {})
                    overall_summary = db_analysis.get('overall_summary', {})
                    if overall_summary:
                        compliance_assessment_db = overall_summary.get('compliance_assessment', {})
                        compliance_rate = compliance_assessment_db.get('compliance_rate_percent', 100)
                        component_compliance['compliant'] = compliance_rate >= 90
                        component_compliance['variance_percent'] = 100 - compliance_rate
                        component_compliance['risk_level'] = 'high' if compliance_rate < 80 else 'moderate' if compliance_rate < 90 else 'low'
                
                # Prometheus metrics compliance
                elif component_key == 'prometheus_metrics':
                    variance_analysis = result.get('variance_analysis', {})
                    overall_assessment = variance_analysis.get('overall_assessment', {})
                    if overall_assessment:
                        component_compliance['compliant'] = overall_assessment.get('overall_compliant', True)
                        component_compliance['variance_percent'] = 100 - overall_assessment.get('compliance_rate_percent', 100)
                
                compliance_assessment['component_compliance'][component_key] = component_compliance
                
                # Track component scores
                component_score = 1.0 if component_compliance['compliant'] else 0.0
                component_scores.append(component_score)
                
                if not component_compliance['compliant']:
                    variance_violations.append({
                        'component': component_key,
                        'variance_percent': component_compliance['variance_percent'],
                        'risk_level': component_compliance['risk_level']
                    })
            
            # Calculate overall compliance score
            if component_scores:
                compliance_assessment['compliance_score'] = sum(component_scores) / len(component_scores)
                compliance_assessment['overall_compliant'] = compliance_assessment['compliance_score'] >= 0.8
            
            # Variance summary
            compliance_assessment['variance_summary'] = {
                'total_components': len(processing_results),
                'compliant_components': sum(component_scores),
                'variance_violations': len(variance_violations),
                'violation_details': variance_violations
            }
            
            # Risk assessment
            high_risk_count = sum(1 for v in variance_violations if v['risk_level'] in ['critical', 'high'])
            moderate_risk_count = sum(1 for v in variance_violations if v['risk_level'] == 'moderate')
            
            overall_risk = 'low'
            if high_risk_count > 0:
                overall_risk = 'critical' if high_risk_count > 1 else 'high'
            elif moderate_risk_count > 0:
                overall_risk = 'moderate'
            
            compliance_assessment['risk_assessment'] = {
                'overall_risk_level': overall_risk,
                'high_risk_components': high_risk_count,
                'moderate_risk_components': moderate_risk_count,
                'immediate_action_required': overall_risk in ['critical', 'high']
            }
            
            return compliance_assessment
            
        except Exception as e:
            logger.error(f"Overall compliance assessment failed: {str(e)}")
            return {
                'error': f'Compliance assessment failed: {str(e)}',
                'overall_compliant': False,
                'compliance_score': 0.0
            }
    
    def _generate_comprehensive_recommendations(self, processing_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive actionable recommendations across all analysis components.
        
        Args:
            processing_results: All processing results
            
        Returns:
            Comprehensive recommendations organized by priority and category
        """
        try:
            recommendations = {
                'immediate_actions': [],
                'short_term_optimizations': [],
                'long_term_improvements': [],
                'monitoring_enhancements': [],
                'category_specific': {
                    'response_time': [],
                    'memory_usage': [],
                    'database_performance': [],
                    'system_monitoring': []
                }
            }
            
            # Collect recommendations from each component
            for component_key, result in processing_results.items():
                
                # Response time recommendations
                if component_key.startswith('response_time_'):
                    compliance_validation = result.get('compliance_validation', {})
                    if compliance_validation:
                        component_recommendations = compliance_validation.get('recommendations', [])
                        
                        risk_level = compliance_validation.get('risk_level', 'low')
                        if risk_level in ['critical', 'high']:
                            recommendations['immediate_actions'].extend(component_recommendations)
                        else:
                            recommendations['short_term_optimizations'].extend(component_recommendations)
                        
                        recommendations['category_specific']['response_time'].extend(component_recommendations)
                
                # Memory usage recommendations
                elif component_key == 'memory_usage':
                    memory_analysis = result.get('memory_analysis', {})
                    memory_recommendations = memory_analysis.get('recommendations', [])
                    
                    # Check for memory leaks
                    leak_analysis = memory_analysis.get('leak_analysis', {})
                    if leak_analysis.get('leak_detected', False):
                        severity = leak_analysis.get('leak_severity', 'low')
                        if severity in ['critical', 'high']:
                            recommendations['immediate_actions'].extend(memory_recommendations)
                        else:
                            recommendations['short_term_optimizations'].extend(memory_recommendations)
                    else:
                        recommendations['long_term_improvements'].extend(memory_recommendations)
                    
                    recommendations['category_specific']['memory_usage'].extend(memory_recommendations)
                
                # Database performance recommendations
                elif component_key == 'database_performance':
                    db_optimization_recommendations = result.get('optimization_recommendations', [])
                    
                    db_analysis = result.get('database_analysis', {})
                    overall_summary = db_analysis.get('overall_summary', {})
                    if overall_summary:
                        performance_grade = overall_summary.get('performance_grade', 'A')
                        if performance_grade in ['D', 'F']:
                            recommendations['immediate_actions'].extend(db_optimization_recommendations)
                        elif performance_grade == 'C':
                            recommendations['short_term_optimizations'].extend(db_optimization_recommendations)
                        else:
                            recommendations['long_term_improvements'].extend(db_optimization_recommendations)
                    
                    recommendations['category_specific']['database_performance'].extend(db_optimization_recommendations)
                
                # Prometheus metrics recommendations
                elif component_key == 'prometheus_metrics':
                    # Add system monitoring recommendations
                    variance_analysis = result.get('variance_analysis', {})
                    overall_assessment = variance_analysis.get('overall_assessment', {})
                    if overall_assessment and not overall_assessment.get('overall_compliant', True):
                        recommendations['monitoring_enhancements'].append("Enhance Prometheus metrics collection for better visibility")
                        recommendations['short_term_optimizations'].append("Investigate Prometheus metrics variance causes")
                    
                    recommendations['category_specific']['system_monitoring'].append("Continue Prometheus metrics monitoring")
            
            # Add general recommendations based on overall analysis
            recommendations['monitoring_enhancements'].extend([
                "Implement automated performance regression detection",
                "Set up real-time alerting for performance threshold violations",
                "Establish performance baseline tracking and trending"
            ])
            
            # Long-term improvements
            recommendations['long_term_improvements'].extend([
                "Implement continuous performance optimization processes",
                "Establish performance testing as part of CI/CD pipeline",
                "Develop performance optimization playbooks for common issues"
            ])
            
            # Remove duplicates while preserving order
            for category in recommendations:
                if isinstance(recommendations[category], list):
                    recommendations[category] = list(dict.fromkeys(recommendations[category]))
                elif isinstance(recommendations[category], dict):
                    for subcategory in recommendations[category]:
                        recommendations[category][subcategory] = list(dict.fromkeys(recommendations[category][subcategory]))
            
            # Add priority scoring
            recommendations['priority_summary'] = {
                'immediate_actions_count': len(recommendations['immediate_actions']),
                'short_term_optimizations_count': len(recommendations['short_term_optimizations']),
                'long_term_improvements_count': len(recommendations['long_term_improvements']),
                'total_recommendations': sum([
                    len(recommendations['immediate_actions']),
                    len(recommendations['short_term_optimizations']),
                    len(recommendations['long_term_improvements']),
                    len(recommendations['monitoring_enhancements'])
                ])
            }
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Comprehensive recommendations generation failed: {str(e)}")
            return {
                'error': f'Recommendations generation failed: {str(e)}',
                'immediate_actions': ['Manual analysis required due to processing error'],
                'short_term_optimizations': [],
                'long_term_improvements': [],
                'monitoring_enhancements': []
            }
    
    def _analyze_comprehensive_trends(self, processing_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze performance trends across all components for pattern identification.
        
        Args:
            processing_results: All processing results
            
        Returns:
            Comprehensive trend analysis results
        """
        try:
            trends_analysis = {
                'overall_trend': 'stable',
                'component_trends': {},
                'correlation_analysis': {},
                'future_projections': {},
                'trend_summary': {}
            }
            
            component_trend_scores = []
            
            # Analyze trends for each component
            for component_key, result in processing_results.items():
                
                component_trend = {
                    'trend_direction': 'stable',
                    'trend_strength': 'weak',
                    'confidence': 'low'
                }
                
                # Response time trends
                if component_key.startswith('response_time_'):
                    statistical_analysis = result.get('statistical_analysis', {})
                    trend_analysis = statistical_analysis.get('trend_analysis', {})
                    if trend_analysis:
                        trend_summary = trend_analysis.get('trend_summary', {})
                        component_trend['trend_direction'] = trend_summary.get('overall_trend', 'stable')
                        component_trend['trend_strength'] = trend_summary.get('trend_strength', 'weak')
                        component_trend['confidence'] = 'high' if trend_analysis.get('linear_trend', {}).get('trend_significant', False) else 'low'
                
                # Memory trends
                elif component_key == 'memory_usage':
                    memory_trends = result.get('memory_trends', {})
                    if memory_trends:
                        trend_summary = memory_trends.get('trend_summary', {})
                        component_trend['trend_direction'] = trend_summary.get('overall_trend', 'stable')
                        component_trend['confidence'] = 'high' if trend_summary.get('requires_attention', False) else 'medium'
                
                # Database trends
                elif component_key == 'database_performance':
                    db_trends = result.get('database_trends', {})
                    if db_trends:
                        trend_assessment = db_trends.get('trend_assessment', {})
                        component_trend['trend_direction'] = trend_assessment.get('performance_trend', 'stable')
                        component_trend['confidence'] = 'medium'
                
                trends_analysis['component_trends'][component_key] = component_trend
                
                # Calculate trend score for overall assessment
                trend_score = 1.0  # Neutral score for stable
                if component_trend['trend_direction'] == 'improving':
                    trend_score = 1.2
                elif component_trend['trend_direction'] in ['degrading', 'concerning']:
                    trend_score = 0.8
                
                component_trend_scores.append(trend_score)
            
            # Overall trend assessment
            if component_trend_scores:
                avg_trend_score = sum(component_trend_scores) / len(component_trend_scores)
                
                if avg_trend_score > 1.1:
                    trends_analysis['overall_trend'] = 'improving'
                elif avg_trend_score < 0.9:
                    trends_analysis['overall_trend'] = 'degrading'
                else:
                    trends_analysis['overall_trend'] = 'stable'
            
            # Future projections
            degrading_components = [
                key for key, trend in trends_analysis['component_trends'].items()
                if trend['trend_direction'] in ['degrading', 'concerning']
            ]
            
            improving_components = [
                key for key, trend in trends_analysis['component_trends'].items()
                if trend['trend_direction'] == 'improving'
            ]
            
            trends_analysis['future_projections'] = {
                'short_term_outlook': 'positive' if len(improving_components) > len(degrading_components) else 'negative' if len(degrading_components) > len(improving_components) else 'neutral',
                'components_at_risk': degrading_components,
                'components_improving': improving_components,
                'monitoring_priority': 'high' if len(degrading_components) > 2 else 'medium' if len(degrading_components) > 0 else 'low'
            }
            
            # Trend summary
            trends_analysis['trend_summary'] = {
                'total_components_analyzed': len(trends_analysis['component_trends']),
                'stable_components': len([t for t in trends_analysis['component_trends'].values() if t['trend_direction'] == 'stable']),
                'improving_components': len(improving_components),
                'degrading_components': len(degrading_components),
                'overall_health': 'excellent' if trends_analysis['overall_trend'] == 'improving' else 'good' if trends_analysis['overall_trend'] == 'stable' else 'needs_attention'
            }
            
            return trends_analysis
            
        except Exception as e:
            logger.error(f"Comprehensive trends analysis failed: {str(e)}")
            return {
                'error': f'Trends analysis failed: {str(e)}',
                'overall_trend': 'unknown',
                'component_trends': {}
            }
    
    def _generate_performance_visualizations(self, processing_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate performance trend visualizations using matplotlib.
        
        Args:
            processing_results: All processing results
            
        Returns:
            Visualization metadata and file paths
        """
        try:
            if not SCIENTIFIC_LIBRARIES_AVAILABLE:
                return {'note': 'Visualizations require scientific libraries (matplotlib, seaborn)'}
            
            import matplotlib
            matplotlib.use('Agg')  # Use non-interactive backend
            
            visualizations = {
                'generated_plots': [],
                'plot_metadata': {},
                'generation_timestamp': datetime.utcnow().isoformat()
            }
            
            # Create visualizations directory
            viz_dir = Path('performance_visualizations')
            viz_dir.mkdir(exist_ok=True)
            
            # Response time trend plots
            response_time_data = {}
            for key, result in processing_results.items():
                if key.startswith('response_time_'):
                    statistical_analysis = result.get('statistical_analysis', {})
                    sample_stats = statistical_analysis.get('sample_statistics', {})
                    if sample_stats:
                        response_time_data[key] = {
                            'mean': sample_stats.get('mean', 0),
                            'median': sample_stats.get('median', 0),
                            'p95': sample_stats.get('max', 0)  # Approximation if percentiles not available
                        }
            
            if response_time_data:
                # Create response time comparison plot
                plt.figure(figsize=(12, 6))
                
                endpoints = list(response_time_data.keys())
                means = [response_time_data[ep]['mean'] for ep in endpoints]
                medians = [response_time_data[ep]['median'] for ep in endpoints]
                
                x = range(len(endpoints))
                width = 0.35
                
                plt.bar([i - width/2 for i in x], means, width, label='Mean Response Time', alpha=0.8)
                plt.bar([i + width/2 for i in x], medians, width, label='Median Response Time', alpha=0.8)
                
                plt.xlabel('API Endpoints')
                plt.ylabel('Response Time (ms)')
                plt.title('API Response Time Performance Comparison')
                plt.xticks(x, [ep.replace('response_time_', '') for ep in endpoints], rotation=45, ha='right')
                plt.legend()
                plt.grid(True, alpha=0.3)
                plt.tight_layout()
                
                plot_path = viz_dir / 'response_time_comparison.png'
                plt.savefig(plot_path, dpi=300, bbox_inches='tight')
                plt.close()
                
                visualizations['generated_plots'].append(str(plot_path))
                visualizations['plot_metadata']['response_time_comparison'] = {
                    'file_path': str(plot_path),
                    'plot_type': 'bar_chart',
                    'data_points': len(endpoints),
                    'description': 'API endpoint response time comparison'
                }
            
            # Memory usage trend plot
            memory_result = processing_results.get('memory_usage')
            if memory_result:
                memory_analysis = memory_result.get('memory_analysis', {})
                if 'memory_snapshots' in self.memory_profiler.__dict__:
                    with self.memory_profiler.lock:
                        snapshots = self.memory_profiler.memory_snapshots.copy()
                    
                    if len(snapshots) > 5:
                        timestamps = []
                        memory_values = []
                        
                        for snapshot in snapshots[-100:]:  # Last 100 snapshots
                            if 'process_memory' in snapshot and 'rss_mb' in snapshot['process_memory']:
                                timestamps.append(datetime.fromisoformat(snapshot['timestamp']))
                                memory_values.append(snapshot['process_memory']['rss_mb'])
                        
                        if timestamps and memory_values:
                            plt.figure(figsize=(12, 6))
                            plt.plot(timestamps, memory_values, linewidth=2, color='blue', alpha=0.7)
                            
                            # Add trend line
                            if len(memory_values) > 2:
                                z = np.polyfit(range(len(memory_values)), memory_values, 1)
                                p = np.poly1d(z)
                                trend_line = p(range(len(memory_values)))
                                plt.plot(timestamps, trend_line, '--', color='red', alpha=0.8, label='Trend')
                            
                            plt.xlabel('Time')
                            plt.ylabel('Memory Usage (MB)')
                            plt.title('Memory Usage Over Time')
                            plt.xticks(rotation=45)
                            plt.grid(True, alpha=0.3)
                            plt.legend()
                            plt.tight_layout()
                            
                            plot_path = viz_dir / 'memory_usage_trend.png'
                            plt.savefig(plot_path, dpi=300, bbox_inches='tight')
                            plt.close()
                            
                            visualizations['generated_plots'].append(str(plot_path))
                            visualizations['plot_metadata']['memory_usage_trend'] = {
                                'file_path': str(plot_path),
                                'plot_type': 'time_series',
                                'data_points': len(memory_values),
                                'description': 'Memory usage trend over time'
                            }
            
            # Performance variance summary plot
            variance_data = []
            component_names = []
            
            for key, result in processing_results.items():
                variance_percent = None
                
                if key.startswith('response_time_'):
                    statistical_analysis = result.get('statistical_analysis', {})
                    variance_analysis = statistical_analysis.get('variance_analysis', {})
                    variance_percent = variance_analysis.get('mean_variance_percent', 0)
                    component_names.append(key.replace('response_time_', ''))
                
                elif key == 'memory_usage':
                    memory_analysis = result.get('memory_analysis', {})
                    variance_analysis = memory_analysis.get('variance_analysis', {})
                    if variance_analysis:
                        variance_analysis_inner = variance_analysis.get('variance_analysis', {})
                        variance_percent = variance_analysis_inner.get('mean_variance_percent', 0)
                        component_names.append('Memory Usage')
                
                if variance_percent is not None:
                    variance_data.append(variance_percent)
            
            if variance_data and component_names:
                plt.figure(figsize=(10, 6))
                
                colors = ['green' if abs(v) <= WARNING_VARIANCE_THRESHOLD else 'orange' if abs(v) <= PERFORMANCE_VARIANCE_THRESHOLD else 'red' for v in variance_data]
                
                bars = plt.bar(component_names, variance_data, color=colors, alpha=0.7)
                
                # Add threshold lines
                plt.axhline(y=PERFORMANCE_VARIANCE_THRESHOLD, color='red', linestyle='--', alpha=0.7, label='±10% Threshold')
                plt.axhline(y=-PERFORMANCE_VARIANCE_THRESHOLD, color='red', linestyle='--', alpha=0.7)
                plt.axhline(y=WARNING_VARIANCE_THRESHOLD, color='orange', linestyle='--', alpha=0.7, label='±5% Warning')
                plt.axhline(y=-WARNING_VARIANCE_THRESHOLD, color='orange', linestyle='--', alpha=0.7)
                
                plt.xlabel('Performance Components')
                plt.ylabel('Variance from Baseline (%)')
                plt.title('Performance Variance Analysis')
                plt.xticks(rotation=45, ha='right')
                plt.legend()
                plt.grid(True, alpha=0.3)
                plt.tight_layout()
                
                plot_path = viz_dir / 'performance_variance_summary.png'
                plt.savefig(plot_path, dpi=300, bbox_inches='tight')
                plt.close()
                
                visualizations['generated_plots'].append(str(plot_path))
                visualizations['plot_metadata']['performance_variance_summary'] = {
                    'file_path': str(plot_path),
                    'plot_type': 'bar_chart',
                    'data_points': len(variance_data),
                    'description': 'Performance variance from baseline across components'
                }
            
            logger.info(f"Generated {len(visualizations['generated_plots'])} performance visualizations")
            return visualizations
            
        except Exception as e:
            logger.error(f"Performance visualizations generation failed: {str(e)}")
            return {
                'error': f'Visualizations generation failed: {str(e)}',
                'generated_plots': [],
                'note': 'Manual visualization creation may be required'
            }
    
    def _generate_overall_assessment(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate overall assessment and final recommendations.
        
        Args:
            report: Complete performance analysis report
            
        Returns:
            Overall assessment with final recommendations and migration status
        """
        try:
            executive_summary = report.get('executive_summary', {})
            compliance_assessment = report.get('compliance_assessment', {})
            recommendations = report.get('recommendations', {})
            
            overall_assessment = {
                'migration_readiness': 'unknown',
                'performance_grade': 'F',
                'risk_level': 'high',
                'deployment_recommendation': 'hold',
                'key_metrics_summary': {},
                'action_plan': {},
                'confidence_level': 'low'
            }
            
            # Migration readiness assessment
            overall_performance_status = executive_summary.get('overall_performance_status', 'unknown')
            compliance_status = executive_summary.get('compliance_status', 'unknown')
            overall_compliant = compliance_assessment.get('overall_compliant', False)
            compliance_score = compliance_assessment.get('compliance_score', 0.0)
            
            # Determine migration readiness
            if overall_compliant and compliance_score >= 0.9 and overall_performance_status == 'excellent':
                overall_assessment['migration_readiness'] = 'ready'
                overall_assessment['deployment_recommendation'] = 'proceed'
                overall_assessment['confidence_level'] = 'high'
            elif overall_compliant and compliance_score >= 0.8 and overall_performance_status in ['excellent', 'good']:
                overall_assessment['migration_readiness'] = 'ready_with_monitoring'
                overall_assessment['deployment_recommendation'] = 'proceed_with_caution'
                overall_assessment['confidence_level'] = 'medium'
            elif compliance_score >= 0.6:
                overall_assessment['migration_readiness'] = 'needs_optimization'
                overall_assessment['deployment_recommendation'] = 'optimize_first'
                overall_assessment['confidence_level'] = 'medium'
            else:
                overall_assessment['migration_readiness'] = 'not_ready'
                overall_assessment['deployment_recommendation'] = 'hold'
                overall_assessment['confidence_level'] = 'low'
            
            # Performance grade
            if compliance_score >= 0.9:
                overall_assessment['performance_grade'] = 'A'
            elif compliance_score >= 0.8:
                overall_assessment['performance_grade'] = 'B'
            elif compliance_score >= 0.7:
                overall_assessment['performance_grade'] = 'C'
            elif compliance_score >= 0.6:
                overall_assessment['performance_grade'] = 'D'
            else:
                overall_assessment['performance_grade'] = 'F'
            
            # Risk level assessment
            risk_assessment = compliance_assessment.get('risk_assessment', {})
            overall_risk_level = risk_assessment.get('overall_risk_level', 'high')
            overall_assessment['risk_level'] = overall_risk_level
            
            # Key metrics summary
            critical_issues = executive_summary.get('critical_issues', [])
            overall_assessment['key_metrics_summary'] = {
                'compliance_score': compliance_score,
                'performance_status': overall_performance_status,
                'critical_issues_count': len(critical_issues),
                'immediate_actions_required': len(recommendations.get('immediate_actions', [])),
                'overall_health': 'healthy' if overall_assessment['performance_grade'] in ['A', 'B'] else 'at_risk'
            }
            
            # Action plan
            immediate_actions = recommendations.get('immediate_actions', [])
            short_term_optimizations = recommendations.get('short_term_optimizations', [])
            
            if immediate_actions:
                overall_assessment['action_plan']['immediate'] = 'Address critical performance issues before deployment'
                overall_assessment['action_plan']['timeline'] = '1-2 days'
            elif short_term_optimizations:
                overall_assessment['action_plan']['immediate'] = 'Implement performance optimizations'
                overall_assessment['action_plan']['timeline'] = '1-2 weeks'
            else:
                overall_assessment['action_plan']['immediate'] = 'Continue monitoring and maintain current performance'
                overall_assessment['action_plan']['timeline'] = 'Ongoing'
            
            # Final recommendation
            if overall_assessment['deployment_recommendation'] == 'proceed':
                overall_assessment['final_recommendation'] = 'Flask migration demonstrates excellent performance compliance. Deployment approved.'
            elif overall_assessment['deployment_recommendation'] == 'proceed_with_caution':
                overall_assessment['final_recommendation'] = 'Flask migration shows good performance. Deploy with enhanced monitoring.'
            elif overall_assessment['deployment_recommendation'] == 'optimize_first':
                overall_assessment['final_recommendation'] = 'Performance optimization required before deployment. Address identified issues.'
            else:
                overall_assessment['final_recommendation'] = 'Migration not ready for production. Significant performance issues require resolution.'
            
            return overall_assessment
            
        except Exception as e:
            logger.error(f"Overall assessment generation failed: {str(e)}")
            return {
                'error': f'Overall assessment generation failed: {str(e)}',
                'migration_readiness': 'unknown',
                'deployment_recommendation': 'hold',
                'final_recommendation': 'Manual assessment required due to processing error'
            }


def main():
    """
    Main execution function for performance data processing script.
    
    Supports command-line execution with arguments for different analysis modes
    and data sources. Provides comprehensive performance analysis workflow.
    """
    parser = argparse.ArgumentParser(
        description='Performance Data Processing and Analysis Script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --mode response_time --data response_times.json --endpoint "/api/users" --method GET
  %(prog)s --mode memory --baseline-memory 256
  %(prog)s --mode database --time-window 24
  %(prog)s --mode prometheus --metrics-file metrics.txt
  %(prog)s --mode comprehensive --output-format json --include-visualizations
        """
    )
    
    parser.add_argument(
        '--mode',
        choices=['response_time', 'memory', 'database', 'prometheus', 'comprehensive'],
        default='comprehensive',
        help='Analysis mode to execute (default: comprehensive)'
    )
    
    parser.add_argument(
        '--environment',
        choices=['development', 'testing', 'staging', 'production', 'ci_cd'],
        default='development',
        help='Performance configuration environment (default: development)'
    )
    
    parser.add_argument(
        '--data',
        type=str,
        help='Input data file path (JSON format for response times)'
    )
    
    parser.add_argument(
        '--endpoint',
        type=str,
        help='API endpoint for response time analysis'
    )
    
    parser.add_argument(
        '--method',
        type=str,
        default='GET',
        help='HTTP method for response time analysis (default: GET)'
    )
    
    parser.add_argument(
        '--baseline-memory',
        type=float,
        help='Baseline memory usage in MB for memory analysis'
    )
    
    parser.add_argument(
        '--time-window',
        type=int,
        help='Time window in hours for database analysis'
    )
    
    parser.add_argument(
        '--metrics-file',
        type=str,
        help='Prometheus metrics file path for metrics analysis'
    )
    
    parser.add_argument(
        '--output-format',
        choices=['json', 'markdown', 'html'],
        default='json',
        help='Output format for comprehensive report (default: json)'
    )
    
    parser.add_argument(
        '--include-visualizations',
        action='store_true',
        help='Include performance visualizations in comprehensive report'
    )
    
    parser.add_argument(
        '--output-file',
        type=str,
        help='Output file path for results (default: stdout)'
    )
    
    parser.add_argument(
        '--start-monitoring',
        action='store_true',
        help='Start continuous performance monitoring'
    )
    
    parser.add_argument(
        '--monitoring-duration',
        type=int,
        default=300,
        help='Monitoring duration in seconds (default: 300)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Initialize performance data processor
        processor = PerformanceDataProcessor(config_environment=args.environment)
        
        logger.info(f"Starting performance analysis - Mode: {args.mode}, Environment: {args.environment}")
        
        results = {}
        
        # Execute based on mode
        if args.mode == 'response_time':
            if not args.data or not args.endpoint:
                logger.error("Response time mode requires --data and --endpoint arguments")
                sys.exit(1)
            
            # Load response time data
            with open(args.data, 'r') as f:
                response_times = json.load(f)
            
            if not isinstance(response_times, list):
                logger.error("Response time data must be a list of numbers")
                sys.exit(1)
            
            results = processor.process_response_time_data(
                response_times, args.endpoint, args.method
            )
        
        elif args.mode == 'memory':
            if args.start_monitoring:
                processor.start_monitoring()
                logger.info(f"Starting memory monitoring for {args.monitoring_duration} seconds...")
                time.sleep(args.monitoring_duration)
                processor.stop_monitoring()
            
            results = processor.process_memory_usage_data(args.baseline_memory)
        
        elif args.mode == 'database':
            results = processor.process_database_performance_data(args.time_window)
        
        elif args.mode == 'prometheus':
            if not args.metrics_file:
                logger.error("Prometheus mode requires --metrics-file argument")
                sys.exit(1)
            
            with open(args.metrics_file, 'r') as f:
                metrics_text = f.read()
            
            results = processor.process_prometheus_metrics_data(metrics_text)
        
        elif args.mode == 'comprehensive':
            if args.start_monitoring:
                processor.start_monitoring()
                logger.info(f"Starting comprehensive monitoring for {args.monitoring_duration} seconds...")
                time.sleep(args.monitoring_duration)
                processor.stop_monitoring()
            
            # Process any provided data
            if args.data and args.endpoint:
                with open(args.data, 'r') as f:
                    response_times = json.load(f)
                processor.process_response_time_data(response_times, args.endpoint, args.method)
            
            if args.metrics_file:
                with open(args.metrics_file, 'r') as f:
                    metrics_text = f.read()
                processor.process_prometheus_metrics_data(metrics_text)
            
            # Process memory and database data if monitoring was started
            if args.start_monitoring:
                processor.process_memory_usage_data(args.baseline_memory)
                processor.process_database_performance_data(args.time_window)
            
            # Generate comprehensive report
            results = processor.generate_comprehensive_report(args.include_visualizations)
        
        # Output results
        if args.output_format == 'json':
            output_content = json.dumps(results, indent=2, default=str)
        elif args.output_format == 'markdown':
            output_content = _format_results_as_markdown(results)
        elif args.output_format == 'html':
            output_content = _format_results_as_html(results)
        else:
            output_content = json.dumps(results, indent=2, default=str)
        
        # Write output
        if args.output_file:
            with open(args.output_file, 'w') as f:
                f.write(output_content)
            logger.info(f"Results written to {args.output_file}")
        else:
            print(output_content)
        
        # Check for critical issues
        if args.mode == 'comprehensive':
            overall_assessment = results.get('overall_assessment', {})
            deployment_recommendation = overall_assessment.get('deployment_recommendation', 'hold')
            
            if deployment_recommendation == 'hold':
                logger.warning("CRITICAL: Performance analysis indicates deployment should be held")
                sys.exit(2)
            elif deployment_recommendation == 'optimize_first':
                logger.warning("WARNING: Performance optimization required before deployment")
                sys.exit(1)
        
        logger.info("Performance analysis completed successfully")
        
    except KeyboardInterrupt:
        logger.info("Performance analysis interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Performance analysis failed: {str(e)}")
        sys.exit(1)


def _format_results_as_markdown(results: Dict[str, Any]) -> str:
    """
    Format analysis results as Markdown report.
    
    Args:
        results: Analysis results dictionary
        
    Returns:
        Formatted Markdown string
    """
    md_content = "# Performance Analysis Report\n\n"
    
    # Add timestamp
    timestamp = results.get('report_metadata', {}).get('generated_at', datetime.utcnow().isoformat())
    md_content += f"**Generated:** {timestamp}\n\n"
    
    # Executive summary
    if 'executive_summary' in results:
        executive_summary = results['executive_summary']
        md_content += "## Executive Summary\n\n"
        md_content += f"**Overall Status:** {executive_summary.get('overall_performance_status', 'Unknown')}\n"
        md_content += f"**Compliance:** {executive_summary.get('compliance_status', 'Unknown')}\n\n"
        
        critical_issues = executive_summary.get('critical_issues', [])
        if critical_issues:
            md_content += "### Critical Issues\n\n"
            for issue in critical_issues:
                md_content += f"- {issue}\n"
            md_content += "\n"
        
        key_findings = executive_summary.get('key_findings', [])
        if key_findings:
            md_content += "### Key Findings\n\n"
            for finding in key_findings[:5]:  # Top 5 findings
                md_content += f"- {finding}\n"
            md_content += "\n"
    
    # Overall assessment
    if 'overall_assessment' in results:
        overall_assessment = results['overall_assessment']
        md_content += "## Overall Assessment\n\n"
        md_content += f"**Migration Readiness:** {overall_assessment.get('migration_readiness', 'Unknown')}\n"
        md_content += f"**Performance Grade:** {overall_assessment.get('performance_grade', 'F')}\n"
        md_content += f"**Risk Level:** {overall_assessment.get('risk_level', 'High')}\n"
        md_content += f"**Deployment Recommendation:** {overall_assessment.get('deployment_recommendation', 'Hold')}\n\n"
        
        final_recommendation = overall_assessment.get('final_recommendation', '')
        if final_recommendation:
            md_content += f"**Final Recommendation:** {final_recommendation}\n\n"
    
    # Recommendations
    if 'recommendations' in results:
        recommendations = results['recommendations']
        md_content += "## Recommendations\n\n"
        
        immediate_actions = recommendations.get('immediate_actions', [])
        if immediate_actions:
            md_content += "### Immediate Actions Required\n\n"
            for action in immediate_actions:
                md_content += f"- {action}\n"
            md_content += "\n"
        
        short_term = recommendations.get('short_term_optimizations', [])
        if short_term:
            md_content += "### Short-term Optimizations\n\n"
            for optimization in short_term[:5]:  # Top 5 optimizations
                md_content += f"- {optimization}\n"
            md_content += "\n"
    
    return md_content


def _format_results_as_html(results: Dict[str, Any]) -> str:
    """
    Format analysis results as HTML report.
    
    Args:
        results: Analysis results dictionary
        
    Returns:
        Formatted HTML string
    """
    html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>Performance Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        .header { background: #f4f4f4; padding: 20px; border-radius: 5px; }
        .summary { background: #e9f7ef; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .critical { background: #fdf2e9; padding: 15px; margin: 20px 0; border-radius: 5px; border-left: 5px solid #e74c3c; }
        .assessment { background: #eaf2f8; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .recommendations { background: #f8f9fa; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .grade-a { color: #27ae60; font-weight: bold; }
        .grade-b { color: #2980b9; font-weight: bold; }
        .grade-c { color: #f39c12; font-weight: bold; }
        .grade-d { color: #e67e22; font-weight: bold; }
        .grade-f { color: #e74c3c; font-weight: bold; }
        ul { margin: 10px 0; }
        li { margin: 5px 0; }
    </style>
</head>
<body>
"""
    
    # Header
    timestamp = results.get('report_metadata', {}).get('generated_at', datetime.utcnow().isoformat())
    html_content += f"""
    <div class="header">
        <h1>Performance Analysis Report</h1>
        <p><strong>Generated:</strong> {timestamp}</p>
    </div>
"""
    
    # Executive summary
    if 'executive_summary' in results:
        executive_summary = results['executive_summary']
        html_content += """
    <div class="summary">
        <h2>Executive Summary</h2>
"""
        html_content += f"        <p><strong>Overall Status:</strong> {executive_summary.get('overall_performance_status', 'Unknown')}</p>\n"
        html_content += f"        <p><strong>Compliance:</strong> {executive_summary.get('compliance_status', 'Unknown')}</p>\n"
        
        critical_issues = executive_summary.get('critical_issues', [])
        if critical_issues:
            html_content += """
        <h3>Critical Issues</h3>
        <ul>
"""
            for issue in critical_issues:
                html_content += f"            <li>{issue}</li>\n"
            html_content += "        </ul>\n"
        
        html_content += "    </div>\n"
    
    # Overall assessment
    if 'overall_assessment' in results:
        overall_assessment = results['overall_assessment']
        performance_grade = overall_assessment.get('performance_grade', 'F')
        grade_class = f"grade-{performance_grade.lower()}"
        
        html_content += f"""
    <div class="assessment">
        <h2>Overall Assessment</h2>
        <p><strong>Migration Readiness:</strong> {overall_assessment.get('migration_readiness', 'Unknown')}</p>
        <p><strong>Performance Grade:</strong> <span class="{grade_class}">{performance_grade}</span></p>
        <p><strong>Risk Level:</strong> {overall_assessment.get('risk_level', 'High')}</p>
        <p><strong>Deployment Recommendation:</strong> {overall_assessment.get('deployment_recommendation', 'Hold')}</p>
"""
        
        final_recommendation = overall_assessment.get('final_recommendation', '')
        if final_recommendation:
            html_content += f"        <p><strong>Final Recommendation:</strong> {final_recommendation}</p>\n"
        
        html_content += "    </div>\n"
    
    # Recommendations
    if 'recommendations' in results:
        recommendations = results['recommendations']
        html_content += """
    <div class="recommendations">
        <h2>Recommendations</h2>
"""
        
        immediate_actions = recommendations.get('immediate_actions', [])
        if immediate_actions:
            html_content += """
        <h3>Immediate Actions Required</h3>
        <ul>
"""
            for action in immediate_actions:
                html_content += f"            <li>{action}</li>\n"
            html_content += "        </ul>\n"
        
        short_term = recommendations.get('short_term_optimizations', [])
        if short_term:
            html_content += """
        <h3>Short-term Optimizations</h3>
        <ul>
"""
            for optimization in short_term[:5]:  # Top 5 optimizations
                html_content += f"            <li>{optimization}</li>\n"
            html_content += "        </ul>\n"
        
        html_content += "    </div>\n"
    
    html_content += """
</body>
</html>
"""
    
    return html_content


if __name__ == '__main__':
    main()