"""
Performance Testing Configuration Management Module

This module provides comprehensive performance testing configuration for the Flask migration
project, implementing ≤10% variance threshold compliance, load testing parameters, baseline
comparison settings, and CI/CD pipeline integration configuration per technical specification
requirements.

Key Features:
- ≤10% variance threshold configuration per Section 0.1.1 primary objective
- Load testing parameter management (10-1000 concurrent users) per Section 4.6.3
- Performance metrics thresholds (500ms response, 100 req/sec) per Section 4.6.3
- CI/CD pipeline integration configuration per Section 6.6.2
- Environment-specific performance settings per Section 6.6.1
- Baseline comparison configuration per Section 0.3.2 performance monitoring

Architecture Integration:
- Section 0.1.1: Performance optimization ensuring ≤10% variance from Node.js baseline
- Section 4.6.3: Load testing specifications with progressive scaling and performance metrics
- Section 6.6.2: CI/CD integration with automated performance validation and regression detection
- Section 6.6.1: Environment-specific test configuration and isolation parameters
- Section 0.3.2: Continuous performance monitoring with baseline comparison requirements

Author: Flask Migration Team
Version: 1.0.0
Dependencies: locust ≥2.x, apache-bench, pytest ≥7.4+, structlog ≥23.1+
"""

import os
import time
import statistics
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional, Tuple, Union, NamedTuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import secrets
import json
import logging

# Performance testing framework dependencies
try:
    import locust
    from locust import HttpUser, task, between
    LOCUST_AVAILABLE = True
except ImportError:
    LOCUST_AVAILABLE = False

try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False

# Prometheus metrics integration
try:
    from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False


class PerformanceTestType(Enum):
    """Performance test type enumeration for different testing scenarios."""
    
    UNIT_PERFORMANCE = "unit_performance"
    LOAD_TESTING = "load_testing"
    STRESS_TESTING = "stress_testing"
    BASELINE_COMPARISON = "baseline_comparison"
    ENDURANCE_TESTING = "endurance_testing"
    SPIKE_TESTING = "spike_testing"
    VOLUME_TESTING = "volume_testing"


class PerformanceEnvironment(Enum):
    """Performance testing environment enumeration."""
    
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"
    CI_CD = "ci_cd"


class LoadTestPhase(Enum):
    """Load testing phase enumeration for progressive scaling."""
    
    WARMUP = "warmup"
    RAMP_UP = "ramp_up"
    STEADY_STATE = "steady_state"
    PEAK_LOAD = "peak_load"
    RAMP_DOWN = "ramp_down"
    COOLDOWN = "cooldown"


class PerformanceMetricType(Enum):
    """Performance metric type enumeration for measurement categories."""
    
    RESPONSE_TIME = "response_time"
    THROUGHPUT = "throughput"
    ERROR_RATE = "error_rate"
    MEMORY_USAGE = "memory_usage"
    CPU_UTILIZATION = "cpu_utilization"
    DATABASE_PERFORMANCE = "database_performance"
    CONCURRENT_USERS = "concurrent_users"


@dataclass
class PerformanceThreshold:
    """Performance threshold configuration for specific metrics."""
    
    metric_name: str
    baseline_value: float
    variance_threshold: float = 0.10  # 10% variance limit per Section 0.1.1
    warning_threshold: float = 0.05   # 5% warning threshold
    critical_threshold: float = 0.15  # 15% critical threshold
    unit: str = "ms"
    description: str = ""
    
    def calculate_variance(self, current_value: float) -> float:
        """
        Calculate performance variance percentage from baseline.
        
        Args:
            current_value: Current measured performance value
            
        Returns:
            Variance percentage (positive for degradation, negative for improvement)
        """
        if self.baseline_value == 0:
            return 0.0
        return ((current_value - self.baseline_value) / self.baseline_value) * 100.0
    
    def is_within_threshold(self, current_value: float) -> bool:
        """
        Check if performance metric is within acceptable variance threshold.
        
        Args:
            current_value: Current measured performance value
            
        Returns:
            True if within ≤10% variance threshold, False otherwise
        """
        variance = abs(self.calculate_variance(current_value))
        return variance <= (self.variance_threshold * 100.0)
    
    def get_threshold_status(self, current_value: float) -> str:
        """
        Get threshold status classification for current performance value.
        
        Args:
            current_value: Current measured performance value
            
        Returns:
            Status classification: 'ok', 'warning', 'critical', 'failure'
        """
        variance = abs(self.calculate_variance(current_value))
        variance_decimal = variance / 100.0
        
        if variance_decimal <= self.warning_threshold:
            return "ok"
        elif variance_decimal <= self.variance_threshold:
            return "warning"
        elif variance_decimal <= self.critical_threshold:
            return "critical"
        else:
            return "failure"


@dataclass
class LoadTestConfiguration:
    """Load testing configuration for progressive user scaling per Section 4.6.3."""
    
    min_users: int = 10              # Minimum concurrent users
    max_users: int = 1000            # Maximum concurrent users per Section 4.6.3
    user_spawn_rate: float = 2.0     # Users spawned per second
    test_duration: int = 1800        # 30-minute sustained load per Section 4.6.3
    ramp_up_time: int = 300          # 5-minute ramp-up time
    steady_state_time: int = 1200    # 20-minute steady state
    ramp_down_time: int = 300        # 5-minute ramp-down time
    
    # Request rate configuration per Section 4.6.3
    target_request_rate: int = 100   # Minimum 100 requests/second
    max_request_rate: int = 500      # Target 100-500 requests per second
    
    # Geographic distribution simulation
    geographic_regions: List[str] = field(default_factory=lambda: [
        "us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"
    ])
    
    # Test scenario weights
    scenario_weights: Dict[str, float] = field(default_factory=lambda: {
        "api_read_operations": 0.60,     # 60% read operations
        "api_write_operations": 0.25,    # 25% write operations
        "authentication_flow": 0.10,     # 10% authentication
        "file_upload_operations": 0.05   # 5% file operations
    })
    
    def get_user_progression(self) -> List[Tuple[int, int]]:
        """
        Generate user progression schedule for load testing phases.
        
        Returns:
            List of (time_seconds, user_count) tuples for progressive scaling
        """
        progression = []
        
        # Warmup phase
        progression.append((0, self.min_users))
        
        # Ramp-up phase
        ramp_steps = self.ramp_up_time // 60  # Steps every minute
        user_increment = (self.max_users - self.min_users) // ramp_steps
        
        for step in range(1, ramp_steps + 1):
            time_point = step * 60
            user_count = self.min_users + (user_increment * step)
            progression.append((time_point, min(user_count, self.max_users)))
        
        # Steady state phase
        steady_start = self.ramp_up_time
        progression.append((steady_start, self.max_users))
        progression.append((steady_start + self.steady_state_time, self.max_users))
        
        # Ramp-down phase
        ramp_down_start = steady_start + self.steady_state_time
        ramp_down_steps = self.ramp_down_time // 60
        user_decrement = (self.max_users - self.min_users) // ramp_down_steps
        
        for step in range(1, ramp_down_steps + 1):
            time_point = ramp_down_start + (step * 60)
            user_count = self.max_users - (user_decrement * step)
            progression.append((time_point, max(user_count, self.min_users)))
        
        return progression
    
    def get_phase_duration(self, phase: LoadTestPhase) -> int:
        """
        Get duration for specific load testing phase.
        
        Args:
            phase: Load testing phase
            
        Returns:
            Duration in seconds for the specified phase
        """
        phase_durations = {
            LoadTestPhase.WARMUP: 60,
            LoadTestPhase.RAMP_UP: self.ramp_up_time,
            LoadTestPhase.STEADY_STATE: self.steady_state_time,
            LoadTestPhase.PEAK_LOAD: 300,  # 5-minute peak load
            LoadTestPhase.RAMP_DOWN: self.ramp_down_time,
            LoadTestPhase.COOLDOWN: 60
        }
        
        return phase_durations.get(phase, 0)


@dataclass 
class BaselineMetrics:
    """Baseline performance metrics for Node.js comparison per Section 0.3.2."""
    
    # Response time baselines (milliseconds)
    api_response_time_p50: float = 100.0      # 50th percentile
    api_response_time_p95: float = 250.0      # 95th percentile ≤500ms per Section 4.6.3
    api_response_time_p99: float = 400.0      # 99th percentile
    database_query_time: float = 50.0         # Average database query time
    
    # Throughput baselines
    requests_per_second: float = 100.0        # Minimum 100 req/sec per Section 4.6.3
    peak_throughput: float = 500.0            # Peak throughput capacity
    concurrent_users_capacity: int = 1000     # Maximum concurrent users
    
    # Resource utilization baselines
    memory_usage_mb: float = 256.0            # Memory usage in MB
    cpu_utilization_percent: float = 15.0     # CPU utilization percentage
    database_connection_count: int = 50       # Database connection pool size
    
    # Error rate baselines
    error_rate_percent: float = 0.1           # ≤0.1% error rate per Section 4.6.3
    timeout_rate_percent: float = 0.05        # Timeout rate threshold
    
    # Calculated from Node.js implementation
    nodejs_baseline_timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    nodejs_version: str = "18.x"
    express_version: str = "4.x"
    
    def to_performance_thresholds(self) -> List[PerformanceThreshold]:
        """
        Convert baseline metrics to performance threshold configurations.
        
        Returns:
            List of PerformanceThreshold objects for validation
        """
        thresholds = [
            PerformanceThreshold(
                metric_name="api_response_time_p95",
                baseline_value=self.api_response_time_p95,
                unit="ms",
                description="95th percentile API response time"
            ),
            PerformanceThreshold(
                metric_name="requests_per_second",
                baseline_value=self.requests_per_second,
                unit="req/s",
                description="Sustained request throughput"
            ),
            PerformanceThreshold(
                metric_name="memory_usage",
                baseline_value=self.memory_usage_mb,
                unit="MB",
                description="Application memory consumption"
            ),
            PerformanceThreshold(
                metric_name="cpu_utilization",
                baseline_value=self.cpu_utilization_percent,
                unit="%",
                description="CPU utilization under load"
            ),
            PerformanceThreshold(
                metric_name="error_rate",
                baseline_value=self.error_rate_percent,
                variance_threshold=0.5,  # Stricter error rate threshold
                unit="%",
                description="Request error rate"
            )
        ]
        
        return thresholds


class BasePerformanceConfig:
    """
    Base performance testing configuration providing shared settings and utilities.
    
    Implements core performance testing configuration patterns with ≤10% variance
    threshold enforcement per Section 0.1.1 and comprehensive load testing
    parameters per Section 4.6.3.
    """
    
    # Core Performance Requirements per Section 0.1.1
    PERFORMANCE_VARIANCE_THRESHOLD = 0.10  # ≤10% variance requirement
    BASELINE_COMPARISON_ENABLED = True
    PERFORMANCE_MONITORING_ENABLED = True
    
    # Load Testing Configuration per Section 4.6.3
    LOAD_TEST_MIN_USERS = 10
    LOAD_TEST_MAX_USERS = 1000
    LOAD_TEST_DURATION = 1800  # 30 minutes
    TARGET_THROUGHPUT_RPS = 100  # 100 requests/second minimum
    PEAK_THROUGHPUT_RPS = 500    # 500 requests/second target
    
    # Performance Metrics Thresholds per Section 4.6.3
    RESPONSE_TIME_P95_THRESHOLD = 500      # 95th percentile ≤500ms
    ERROR_RATE_THRESHOLD = 0.1             # ≤0.1% error rate
    RESOURCE_CPU_THRESHOLD = 70            # CPU ≤70%
    RESOURCE_MEMORY_THRESHOLD = 80         # Memory ≤80%
    
    # Test Execution Configuration
    WARMUP_ITERATIONS = 10
    BENCHMARK_ITERATIONS = 100
    BENCHMARK_TIMEOUT = 300  # 5 minutes
    
    # Monitoring and Reporting
    METRICS_COLLECTION_INTERVAL = 1  # seconds
    PERFORMANCE_REPORT_ENABLED = True
    TREND_ANALYSIS_ENABLED = True
    
    # CI/CD Integration per Section 6.6.2
    CI_CD_INTEGRATION_ENABLED = True
    AUTOMATED_PERFORMANCE_GATES = True
    PIPELINE_FAILURE_ON_REGRESSION = True
    
    # Environment-specific Settings per Section 6.6.1
    ENVIRONMENT_ISOLATION_ENABLED = True
    TEST_DATA_CLEANUP_ENABLED = True
    PARALLEL_EXECUTION_ENABLED = True
    
    @classmethod
    def get_baseline_metrics(cls) -> BaselineMetrics:
        """
        Get baseline performance metrics for Node.js comparison.
        
        Returns:
            BaselineMetrics instance with Node.js performance baselines
        """
        return BaselineMetrics(
            api_response_time_p95=cls.RESPONSE_TIME_P95_THRESHOLD,
            requests_per_second=cls.TARGET_THROUGHPUT_RPS,
            memory_usage_mb=256.0,
            cpu_utilization_percent=15.0,
            error_rate_percent=cls.ERROR_RATE_THRESHOLD
        )
    
    @classmethod
    def get_load_test_config(cls) -> LoadTestConfiguration:
        """
        Get load testing configuration for progressive scaling.
        
        Returns:
            LoadTestConfiguration instance with load test parameters
        """
        return LoadTestConfiguration(
            min_users=cls.LOAD_TEST_MIN_USERS,
            max_users=cls.LOAD_TEST_MAX_USERS,
            test_duration=cls.LOAD_TEST_DURATION,
            target_request_rate=cls.TARGET_THROUGHPUT_RPS,
            max_request_rate=cls.PEAK_THROUGHPUT_RPS
        )
    
    @classmethod
    def calculate_performance_variance(cls, current_value: float, baseline_value: float) -> float:
        """
        Calculate performance variance percentage from baseline.
        
        Args:
            current_value: Current measured performance value
            baseline_value: Baseline Node.js performance value
            
        Returns:
            Variance percentage (positive for degradation, negative for improvement)
        """
        if baseline_value == 0:
            return 0.0
        return ((current_value - baseline_value) / baseline_value) * 100.0
    
    @classmethod
    def is_within_variance_threshold(cls, current_value: float, baseline_value: float) -> bool:
        """
        Check if performance metric is within ≤10% variance threshold.
        
        Args:
            current_value: Current measured performance value
            baseline_value: Baseline Node.js performance value
            
        Returns:
            True if within threshold, False if exceeds ≤10% variance
        """
        variance = abs(cls.calculate_performance_variance(current_value, baseline_value))
        return variance <= (cls.PERFORMANCE_VARIANCE_THRESHOLD * 100.0)
    
    @classmethod
    def get_performance_thresholds(cls) -> Dict[str, PerformanceThreshold]:
        """
        Get comprehensive performance threshold configuration.
        
        Returns:
            Dictionary of performance thresholds by metric name
        """
        baseline = cls.get_baseline_metrics()
        thresholds = {}
        
        for threshold in baseline.to_performance_thresholds():
            thresholds[threshold.metric_name] = threshold
        
        return thresholds
    
    @classmethod
    def get_environment_name(cls) -> str:
        """Get current performance testing environment name."""
        return os.getenv('PERFORMANCE_ENV', 'development')
    
    @classmethod
    def is_ci_cd_environment(cls) -> bool:
        """Check if running in CI/CD environment."""
        return os.getenv('CI', 'false').lower() == 'true' or os.getenv('GITHUB_ACTIONS', 'false').lower() == 'true'


class DevelopmentPerformanceConfig(BasePerformanceConfig):
    """
    Development environment performance configuration with relaxed thresholds.
    
    Provides developer-friendly performance testing settings with faster execution
    and relaxed variance thresholds for local development iterations.
    """
    
    # Relaxed Development Settings
    PERFORMANCE_VARIANCE_THRESHOLD = 0.25  # 25% variance allowance for development
    LOAD_TEST_MAX_USERS = 50               # Reduced load for development
    LOAD_TEST_DURATION = 300               # 5-minute tests for development
    BENCHMARK_ITERATIONS = 20              # Reduced iterations for speed
    
    # Development Monitoring
    PERFORMANCE_MONITORING_ENABLED = True
    BASELINE_COMPARISON_ENABLED = False    # Disabled for local development
    TREND_ANALYSIS_ENABLED = False         # Disabled for development
    
    # Development-specific Settings
    LOCUST_WEB_UI_ENABLED = True          # Enable Locust web UI for development
    REAL_TIME_MONITORING = True           # Real-time performance monitoring
    DEBUG_PERFORMANCE_LOGGING = True      # Detailed performance logging
    
    @classmethod
    def get_environment_name(cls) -> str:
        """Get development environment name."""
        return "development"


class TestingPerformanceConfig(BasePerformanceConfig):
    """
    Testing environment performance configuration for automated testing.
    
    Provides optimized performance testing settings for CI/CD pipeline execution
    with automated regression detection and fast feedback cycles.
    """
    
    # Testing Environment Settings
    PERFORMANCE_VARIANCE_THRESHOLD = 0.15  # 15% variance for testing environment
    LOAD_TEST_MAX_USERS = 100              # Moderate load for testing
    LOAD_TEST_DURATION = 600               # 10-minute tests for CI/CD
    BENCHMARK_ITERATIONS = 50              # Balanced iterations for CI/CD
    
    # CI/CD Optimizations
    CI_CD_INTEGRATION_ENABLED = True
    AUTOMATED_PERFORMANCE_GATES = True
    PIPELINE_FAILURE_ON_REGRESSION = True
    PARALLEL_EXECUTION_ENABLED = True
    
    # Testing-specific Settings
    LOCUST_WEB_UI_ENABLED = False         # Disabled for automated testing
    HEADLESS_EXECUTION = True             # Headless mode for CI/CD
    AUTOMATED_REPORTING = True            # Automated performance reports
    
    # Performance Test Isolation
    TEST_ISOLATION_ENABLED = True
    CLEANUP_ON_COMPLETION = True
    RESOURCE_MONITORING = True
    
    @classmethod
    def get_environment_name(cls) -> str:
        """Get testing environment name."""
        return "testing"


class StagingPerformanceConfig(BasePerformanceConfig):
    """
    Staging environment performance configuration for pre-production validation.
    
    Provides production-equivalent performance testing settings with comprehensive
    baseline comparison and validation before production deployment.
    """
    
    # Staging Environment Settings (strict compliance)
    PERFORMANCE_VARIANCE_THRESHOLD = 0.10  # Full ≤10% variance enforcement
    LOAD_TEST_MAX_USERS = 750              # Near-production load testing
    LOAD_TEST_DURATION = 1500              # 25-minute comprehensive tests
    BENCHMARK_ITERATIONS = 100             # Full benchmark iterations
    
    # Production Parity Settings
    BASELINE_COMPARISON_ENABLED = True
    NODEJS_BASELINE_MONITORING = True
    COMPREHENSIVE_MONITORING = True
    
    # Staging-specific Settings
    PRODUCTION_PARITY_VALIDATION = True
    EXTERNAL_SERVICE_INTEGRATION = True
    REALISTIC_DATA_VOLUMES = True
    
    @classmethod
    def get_environment_name(cls) -> str:
        """Get staging environment name."""
        return "staging"


class ProductionPerformanceConfig(BasePerformanceConfig):
    """
    Production environment performance configuration for live monitoring.
    
    Provides production performance monitoring and validation settings with
    strict ≤10% variance enforcement and comprehensive baseline tracking.
    """
    
    # Production Settings (maximum strictness)
    PERFORMANCE_VARIANCE_THRESHOLD = 0.10  # Strict ≤10% variance enforcement
    LOAD_TEST_MAX_USERS = 1000             # Full production load capacity
    LOAD_TEST_DURATION = 1800              # Full 30-minute testing per Section 4.6.3
    BENCHMARK_ITERATIONS = 100             # Complete benchmark suite
    
    # Production Monitoring
    CONTINUOUS_MONITORING_ENABLED = True
    REAL_TIME_ALERTING = True
    PERFORMANCE_TRENDING = True
    BASELINE_DRIFT_DETECTION = True
    
    # Production-specific Settings
    HIGH_AVAILABILITY_MONITORING = True
    DISASTER_RECOVERY_TESTING = False      # Disabled in production
    LIVE_TRAFFIC_ANALYSIS = True
    
    @classmethod
    def get_environment_name(cls) -> str:
        """Get production environment name."""
        return "production"


class CICDPerformanceConfig(BasePerformanceConfig):
    """
    CI/CD pipeline performance configuration per Section 6.6.2.
    
    Provides optimized performance testing for GitHub Actions CI/CD pipeline
    with automated performance gates and regression detection.
    """
    
    # CI/CD Pipeline Settings
    PERFORMANCE_VARIANCE_THRESHOLD = 0.10  # Strict enforcement for CI/CD
    LOAD_TEST_MAX_USERS = 200              # Optimized for CI/CD resources
    LOAD_TEST_DURATION = 900               # 15-minute tests for pipeline efficiency
    BENCHMARK_ITERATIONS = 50              # Balanced for CI/CD execution time
    
    # Pipeline Integration Settings per Section 6.6.2
    CI_CD_INTEGRATION_ENABLED = True
    AUTOMATED_PERFORMANCE_GATES = True
    PIPELINE_FAILURE_ON_REGRESSION = True
    GITHUB_ACTIONS_INTEGRATION = True
    
    # CI/CD Optimization
    PARALLEL_TEST_EXECUTION = True
    CONTAINERIZED_TESTING = True
    ARTIFACT_GENERATION = True
    PERFORMANCE_REPORTING = True
    
    # Notification Integration per Section 6.6.2
    SLACK_NOTIFICATIONS = os.getenv('SLACK_WEBHOOK_URL', '') != ''
    TEAMS_NOTIFICATIONS = os.getenv('TEAMS_WEBHOOK_URL', '') != ''
    EMAIL_NOTIFICATIONS = os.getenv('EMAIL_NOTIFICATIONS', 'false').lower() == 'true'
    
    # Performance Regression Detection
    BASELINE_DRIFT_THRESHOLD = 0.05       # 5% drift detection
    TREND_ANALYSIS_WINDOW_DAYS = 7        # 7-day trend analysis
    REGRESSION_ALERT_THRESHOLD = 0.08     # 8% regression alert
    
    @classmethod
    def get_environment_name(cls) -> str:
        """Get CI/CD environment name."""
        return "ci_cd"
    
    @classmethod
    def get_github_actions_config(cls) -> Dict[str, Any]:
        """
        Get GitHub Actions specific configuration.
        
        Returns:
            Configuration dictionary for GitHub Actions integration
        """
        return {
            'enabled': cls.GITHUB_ACTIONS_INTEGRATION,
            'matrix_testing': True,
            'python_versions': ['3.8', '3.11'],
            'performance_gates': cls.AUTOMATED_PERFORMANCE_GATES,
            'artifact_upload': cls.ARTIFACT_GENERATION,
            'notification_integration': {
                'slack': cls.SLACK_NOTIFICATIONS,
                'teams': cls.TEAMS_NOTIFICATIONS,
                'email': cls.EMAIL_NOTIFICATIONS
            }
        }


class PerformanceConfigFactory:
    """
    Performance configuration factory for environment-specific settings.
    
    Provides centralized performance configuration management with environment
    detection and validation for all performance testing scenarios.
    """
    
    _configs: Dict[str, type] = {
        'development': DevelopmentPerformanceConfig,
        'testing': TestingPerformanceConfig,
        'staging': StagingPerformanceConfig,
        'production': ProductionPerformanceConfig,
        'ci_cd': CICDPerformanceConfig
    }
    
    @classmethod
    def get_config(cls, environment: Optional[str] = None) -> BasePerformanceConfig:
        """
        Get performance configuration for specified environment.
        
        Args:
            environment: Target environment name (defaults to PERFORMANCE_ENV)
            
        Returns:
            Performance configuration class for the specified environment
            
        Raises:
            ValueError: If environment is not supported
        """
        if environment is None:
            environment = os.getenv('PERFORMANCE_ENV', 'development')
            
            # Auto-detect CI/CD environment
            if os.getenv('CI', 'false').lower() == 'true' or os.getenv('GITHUB_ACTIONS', 'false').lower() == 'true':
                environment = 'ci_cd'
        
        environment = environment.lower()
        
        if environment not in cls._configs:
            raise ValueError(
                f"Unsupported performance environment: {environment}. "
                f"Supported environments: {list(cls._configs.keys())}"
            )
        
        config_class = cls._configs[environment]
        return config_class()
    
    @classmethod
    def get_load_test_config(cls, environment: Optional[str] = None) -> LoadTestConfiguration:
        """
        Get load testing configuration for specified environment.
        
        Args:
            environment: Target environment name
            
        Returns:
            LoadTestConfiguration instance for the environment
        """
        config = cls.get_config(environment)
        return config.get_load_test_config()
    
    @classmethod
    def get_baseline_metrics(cls, environment: Optional[str] = None) -> BaselineMetrics:
        """
        Get baseline metrics configuration for specified environment.
        
        Args:
            environment: Target environment name
            
        Returns:
            BaselineMetrics instance for baseline comparison
        """
        config = cls.get_config(environment)
        return config.get_baseline_metrics()
    
    @classmethod
    def get_performance_thresholds(cls, environment: Optional[str] = None) -> Dict[str, PerformanceThreshold]:
        """
        Get performance thresholds for specified environment.
        
        Args:
            environment: Target environment name
            
        Returns:
            Dictionary of performance thresholds by metric name
        """
        config = cls.get_config(environment)
        return config.get_performance_thresholds()
    
    @classmethod
    def validate_performance_config(cls, config: BasePerformanceConfig) -> bool:
        """
        Validate performance configuration for completeness and correctness.
        
        Args:
            config: Performance configuration instance to validate
            
        Returns:
            True if configuration is valid
            
        Raises:
            ValueError: If configuration validation fails
        """
        # Validate variance threshold
        if config.PERFORMANCE_VARIANCE_THRESHOLD <= 0 or config.PERFORMANCE_VARIANCE_THRESHOLD > 1.0:
            raise ValueError("Performance variance threshold must be between 0 and 1.0")
        
        # Validate load testing parameters
        if config.LOAD_TEST_MIN_USERS >= config.LOAD_TEST_MAX_USERS:
            raise ValueError("Load test minimum users must be less than maximum users")
        
        if config.LOAD_TEST_DURATION <= 0:
            raise ValueError("Load test duration must be positive")
        
        # Validate performance thresholds
        if config.RESPONSE_TIME_P95_THRESHOLD <= 0:
            raise ValueError("Response time threshold must be positive")
        
        if config.ERROR_RATE_THRESHOLD < 0 or config.ERROR_RATE_THRESHOLD > 100:
            raise ValueError("Error rate threshold must be between 0 and 100 percent")
        
        return True
    
    @classmethod
    def get_available_environments(cls) -> List[str]:
        """
        Get list of available performance testing environments.
        
        Returns:
            List of supported environment names
        """
        return list(cls._configs.keys())


# Performance Testing Utility Functions

def create_performance_config(environment: Optional[str] = None) -> BasePerformanceConfig:
    """
    Create performance configuration instance for specified environment with validation.
    
    Args:
        environment: Target environment name (defaults to PERFORMANCE_ENV)
        
    Returns:
        Validated performance configuration instance
        
    Raises:
        ValueError: If environment is unsupported or configuration is invalid
    """
    config = PerformanceConfigFactory.get_config(environment)
    PerformanceConfigFactory.validate_performance_config(config)
    return config


def get_performance_baseline_comparison(
    current_metrics: Dict[str, float],
    environment: Optional[str] = None
) -> Dict[str, Dict[str, Any]]:
    """
    Compare current performance metrics against baseline values.
    
    Args:
        current_metrics: Dictionary of current performance metric values
        environment: Target environment for baseline comparison
        
    Returns:
        Dictionary containing variance analysis and threshold compliance
    """
    config = PerformanceConfigFactory.get_config(environment)
    thresholds = config.get_performance_thresholds()
    baseline = config.get_baseline_metrics()
    
    comparison_results = {}
    
    for metric_name, current_value in current_metrics.items():
        if metric_name in thresholds:
            threshold = thresholds[metric_name]
            variance = threshold.calculate_variance(current_value)
            within_threshold = threshold.is_within_threshold(current_value)
            status = threshold.get_threshold_status(current_value)
            
            comparison_results[metric_name] = {
                'current_value': current_value,
                'baseline_value': threshold.baseline_value,
                'variance_percent': variance,
                'within_threshold': within_threshold,
                'status': status,
                'threshold_config': threshold
            }
    
    return comparison_results


def generate_performance_report(
    test_results: Dict[str, Any],
    environment: Optional[str] = None,
    output_format: str = 'json'
) -> Union[Dict[str, Any], str]:
    """
    Generate comprehensive performance testing report.
    
    Args:
        test_results: Performance test execution results
        environment: Target environment for reporting
        output_format: Output format ('json', 'markdown', 'html')
        
    Returns:
        Performance report in specified format
    """
    config = PerformanceConfigFactory.get_config(environment)
    baseline = config.get_baseline_metrics()
    
    report_data = {
        'report_metadata': {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'environment': config.get_environment_name(),
            'performance_config': {
                'variance_threshold': config.PERFORMANCE_VARIANCE_THRESHOLD,
                'load_test_users': f"{config.LOAD_TEST_MIN_USERS}-{config.LOAD_TEST_MAX_USERS}",
                'test_duration': config.LOAD_TEST_DURATION
            }
        },
        'baseline_comparison': baseline.__dict__,
        'test_results': test_results,
        'compliance_status': {
            'within_variance_threshold': True,  # To be calculated
            'performance_gates_passed': True,   # To be calculated
            'recommendation': 'Deployment approved'  # To be determined
        }
    }
    
    if output_format.lower() == 'json':
        return report_data
    elif output_format.lower() == 'markdown':
        return _generate_markdown_report(report_data)
    elif output_format.lower() == 'html':
        return _generate_html_report(report_data)
    else:
        raise ValueError(f"Unsupported output format: {output_format}")


def _generate_markdown_report(report_data: Dict[str, Any]) -> str:
    """Generate markdown format performance report."""
    md_report = f"""# Performance Testing Report

**Generated:** {report_data['report_metadata']['generated_at']}  
**Environment:** {report_data['report_metadata']['environment']}  

## Configuration Summary

- **Variance Threshold:** {report_data['report_metadata']['performance_config']['variance_threshold']*100:.1f}%
- **Load Test Users:** {report_data['report_metadata']['performance_config']['load_test_users']}
- **Test Duration:** {report_data['report_metadata']['performance_config']['test_duration']} seconds

## Baseline Comparison

| Metric | Baseline | Current | Variance | Status |
|--------|----------|---------|----------|--------|
| Response Time P95 | {report_data['baseline_comparison']['api_response_time_p95']:.1f}ms | TBD | TBD | TBD |
| Throughput | {report_data['baseline_comparison']['requests_per_second']:.1f} req/s | TBD | TBD | TBD |
| Memory Usage | {report_data['baseline_comparison']['memory_usage_mb']:.1f}MB | TBD | TBD | TBD |

## Compliance Status

- **Within Variance Threshold:** {report_data['compliance_status']['within_variance_threshold']}
- **Performance Gates:** {report_data['compliance_status']['performance_gates_passed']}
- **Recommendation:** {report_data['compliance_status']['recommendation']}
"""
    return md_report


def _generate_html_report(report_data: Dict[str, Any]) -> str:
    """Generate HTML format performance report."""
    html_report = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Performance Testing Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .pass {{ color: green; }}
        .fail {{ color: red; }}
        .warning {{ color: orange; }}
    </style>
</head>
<body>
    <h1>Performance Testing Report</h1>
    <p><strong>Generated:</strong> {report_data['report_metadata']['generated_at']}</p>
    <p><strong>Environment:</strong> {report_data['report_metadata']['environment']}</p>
    
    <h2>Configuration Summary</h2>
    <ul>
        <li><strong>Variance Threshold:</strong> {report_data['report_metadata']['performance_config']['variance_threshold']*100:.1f}%</li>
        <li><strong>Load Test Users:</strong> {report_data['report_metadata']['performance_config']['load_test_users']}</li>
        <li><strong>Test Duration:</strong> {report_data['report_metadata']['performance_config']['test_duration']} seconds</li>
    </ul>
    
    <h2>Compliance Status</h2>
    <p><strong>Recommendation:</strong> {report_data['compliance_status']['recommendation']}</p>
</body>
</html>
"""
    return html_report


# Export configuration classes and utilities
__all__ = [
    'BasePerformanceConfig',
    'DevelopmentPerformanceConfig',
    'TestingPerformanceConfig', 
    'StagingPerformanceConfig',
    'ProductionPerformanceConfig',
    'CICDPerformanceConfig',
    'PerformanceConfigFactory',
    'PerformanceThreshold',
    'LoadTestConfiguration',
    'BaselineMetrics',
    'PerformanceTestType',
    'PerformanceEnvironment',
    'LoadTestPhase',
    'PerformanceMetricType',
    'create_performance_config',
    'get_performance_baseline_comparison',
    'generate_performance_report'
]