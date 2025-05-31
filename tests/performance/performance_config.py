"""
Performance Testing Configuration Management Module

This module provides comprehensive performance testing configuration management for the Flask migration project,
including load test parameters, baseline thresholds, monitoring settings, and CI/CD integration configuration.
Centralizes all performance testing settings and environment-specific parameters to ensure compliance with the
≤10% variance requirement from the Node.js baseline.

Key Features:
- ≤10% variance threshold configuration per Section 0.1.1 primary objective
- Load testing parameters (10-1000 concurrent users) per Section 4.6.3
- Performance metrics thresholds (500ms response, 100 req/sec) per Section 4.6.3
- CI/CD pipeline integration configuration per Section 6.6.2
- Environment-specific performance parameters per Section 6.6.1
- Baseline comparison configuration per Section 0.3.2 performance monitoring

Architecture Integration:
- Section 4.6.3: Load testing specifications with locust and apache-bench integration
- Section 6.6.2: CI/CD pipeline performance validation and automated rollback triggers
- Section 6.5.1: Performance metrics collection and Prometheus integration
- Section 6.5.2: Performance monitoring patterns and SLA compliance

Performance Requirements:
- Maintains ≤10% performance variance from Node.js baseline per Section 0.1.1
- 95th percentile response time ≤500ms per Section 4.6.3
- Minimum 100 requests/second sustained throughput per Section 4.6.3
- CPU ≤70%, Memory ≤80% during peak load per Section 4.6.3

Author: Flask Migration Team
Version: 1.0.0
Dependencies: locust ≥2.x, apache-bench, prometheus-client 0.17+, psutil 5.9+
"""

import os
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum

# Performance testing framework imports
import psutil

# Configuration imports
from tests.test_config import TestBaseConfig
from src.config.settings import BaseConfig


# Configure module logger
logger = logging.getLogger(__name__)


class LoadTestScenario(Enum):
    """Load testing scenario types with predefined configurations."""
    
    LIGHT_LOAD = "light_load"
    NORMAL_LOAD = "normal_load"
    HEAVY_LOAD = "heavy_load"
    STRESS_TEST = "stress_test"
    BASELINE_COMPARISON = "baseline_comparison"
    SPIKE_TEST = "spike_test"
    ENDURANCE_TEST = "endurance_test"


class PerformanceMetricType(Enum):
    """Performance metric types for monitoring and alerting."""
    
    RESPONSE_TIME = "response_time"
    THROUGHPUT = "throughput"
    ERROR_RATE = "error_rate"
    CPU_UTILIZATION = "cpu_utilization"
    MEMORY_USAGE = "memory_usage"
    GC_PAUSE_TIME = "gc_pause_time"
    DATABASE_RESPONSE = "database_response"
    CACHE_HIT_RATE = "cache_hit_rate"


@dataclass
class NodeJSBaselineMetrics:
    """Node.js baseline performance metrics for comparison validation."""
    
    # Response time baselines (milliseconds)
    response_times: Dict[str, float] = field(default_factory=lambda: {
        'api_get_users': 150.0,
        'api_create_user': 200.0,
        'api_update_user': 180.0,
        'api_delete_user': 120.0,
        'api_list_users': 100.0,
        'api_user_search': 175.0,
        'api_user_profile': 130.0,
        'health_check': 50.0,
        'auth_login': 180.0,
        'auth_logout': 80.0,
        'auth_token_refresh': 160.0,
        'file_upload': 300.0,
        'file_download': 250.0,
        'database_query': 75.0,
        'cache_operations': 25.0,
        'external_api_calls': 400.0
    })
    
    # Memory usage baselines (megabytes)
    memory_usage: Dict[str, float] = field(default_factory=lambda: {
        'baseline_mb': 256.0,
        'peak_mb': 512.0,
        'average_mb': 320.0,
        'startup_mb': 180.0,
        'steady_state_mb': 280.0,
        'memory_growth_rate': 2.0  # MB per hour
    })
    
    # Throughput baselines (requests per second)
    throughput: Dict[str, float] = field(default_factory=lambda: {
        'requests_per_second': 1000.0,
        'concurrent_users': 100.0,
        'database_ops_per_second': 500.0,
        'cache_ops_per_second': 2000.0,
        'peak_throughput': 1500.0,
        'sustained_throughput': 800.0
    })
    
    # Database performance baselines (milliseconds)
    database_performance: Dict[str, float] = field(default_factory=lambda: {
        'user_lookup': 45.0,
        'user_create': 85.0,
        'user_update': 70.0,
        'user_delete': 40.0,
        'bulk_operations': 200.0,
        'index_queries': 25.0,
        'aggregation_queries': 150.0,
        'connection_setup': 30.0
    })
    
    # Cache performance baselines (milliseconds)
    cache_performance: Dict[str, float] = field(default_factory=lambda: {
        'get_hit': 5.0,
        'get_miss': 15.0,
        'set': 10.0,
        'delete': 8.0,
        'bulk_get': 20.0,
        'pipeline_operations': 30.0,
        'cache_invalidation': 12.0
    })
    
    # CPU and system resource baselines
    system_resources: Dict[str, float] = field(default_factory=lambda: {
        'cpu_utilization_average': 45.0,  # percentage
        'cpu_utilization_peak': 70.0,
        'memory_utilization_average': 60.0,
        'disk_io_average': 50.0,  # operations per second
        'network_io_average': 100.0,  # MB per second
        'context_switches_per_second': 1000.0,
        'thread_count_average': 50.0
    })


@dataclass
class LoadTestConfiguration:
    """Load test scenario configuration with scaling parameters."""
    
    scenario_name: str
    users: int
    spawn_rate: float
    duration: int  # seconds
    host: str = "http://localhost:5000"
    
    # Advanced load testing parameters
    ramp_up_time: int = field(default=60)  # seconds
    steady_state_time: int = field(default=300)  # seconds
    ramp_down_time: int = field(default=30)  # seconds
    
    # Request distribution weights
    endpoint_weights: Dict[str, float] = field(default_factory=lambda: {
        'GET /api/users': 0.3,
        'POST /api/users': 0.15,
        'PUT /api/users/{id}': 0.1,
        'DELETE /api/users/{id}': 0.05,
        'GET /api/users/{id}': 0.2,
        'GET /health': 0.1,
        'POST /auth/login': 0.05,
        'POST /auth/logout': 0.05
    })
    
    # Performance thresholds for this scenario
    response_time_p95: float = field(default=500.0)  # milliseconds
    error_rate_threshold: float = field(default=0.1)  # percentage
    throughput_threshold: float = field(default=100.0)  # requests per second


class PerformanceTestConfig(TestBaseConfig):
    """
    Performance testing configuration class providing comprehensive load test parameters,
    baseline thresholds, monitoring settings, and CI/CD integration configuration.
    
    Implements the ≤10% variance requirement and ensures compatibility with Node.js baseline
    performance metrics across all testing scenarios and deployment environments.
    """
    
    # Performance Testing Configuration
    PERFORMANCE_TESTING_ENABLED = True
    PERFORMANCE_BASELINE_ENABLED = True
    PERFORMANCE_VARIANCE_THRESHOLD = 10.0  # ≤10% variance requirement per Section 0.1.1
    PERFORMANCE_COMPARISON_ENABLED = True
    
    # Node.js Baseline Metrics
    NODEJS_BASELINE_METRICS = NodeJSBaselineMetrics()
    
    # Performance Test Environment Configuration
    PERFORMANCE_TEST_HOST = os.getenv('PERFORMANCE_TEST_HOST', 'http://localhost:5000')
    PERFORMANCE_TEST_DURATION = int(os.getenv('PERFORMANCE_TEST_DURATION', '300'))  # 5 minutes default
    PERFORMANCE_TEST_USERS = int(os.getenv('PERFORMANCE_TEST_USERS', '100'))
    PERFORMANCE_TEST_SPAWN_RATE = float(os.getenv('PERFORMANCE_TEST_SPAWN_RATE', '10.0'))
    
    # Load Testing Framework Configuration
    LOCUST_CONFIG = {
        'master_bind_host': '0.0.0.0',
        'master_bind_port': 8089,
        'master_web_port': 8090,
        'worker_count': int(os.getenv('LOCUST_WORKER_COUNT', '4')),
        'headless': os.getenv('LOCUST_HEADLESS', 'true').lower() == 'true',
        'autostart': True,
        'autoquit': 10,  # seconds after test completion
        'csv_output': '/tmp/performance_results',
        'html_output': '/tmp/performance_report.html',
        'logfile': '/tmp/locust.log',
        'loglevel': 'INFO'
    }
    
    # Apache Bench Configuration
    APACHE_BENCH_CONFIG = {
        'requests_total': int(os.getenv('AB_REQUESTS_TOTAL', '10000')),
        'concurrency': int(os.getenv('AB_CONCURRENCY', '100')),
        'timeout': int(os.getenv('AB_TIMEOUT', '30')),
        'keep_alive': True,
        'post_file': None,  # For POST request testing
        'content_type': 'application/json',
        'output_format': 'csv',
        'confidence_interval': 95
    }
    
    # Performance Metrics Thresholds per Section 4.6.3
    PERFORMANCE_THRESHOLDS = {
        # Response time thresholds (milliseconds)
        'response_time_p95': 500.0,  # 95th percentile ≤500ms
        'response_time_p99': 800.0,  # 99th percentile ≤800ms
        'response_time_average': 200.0,  # Average ≤200ms
        'response_time_max': 2000.0,  # Maximum ≤2 seconds
        
        # Throughput thresholds (requests per second)
        'throughput_minimum': 100.0,  # Minimum 100 req/sec sustained
        'throughput_target': 500.0,  # Target 500 req/sec
        'throughput_peak': 1000.0,  # Peak 1000 req/sec
        
        # Error rate thresholds (percentage)
        'error_rate_warning': 0.1,  # 0.1% warning threshold
        'error_rate_critical': 1.0,  # 1% critical threshold
        'error_rate_maximum': 5.0,  # 5% maximum acceptable
        
        # Resource utilization thresholds (percentage)
        'cpu_utilization_warning': 70.0,  # 70% warning per Section 4.6.3
        'cpu_utilization_critical': 90.0,  # 90% critical
        'memory_utilization_warning': 80.0,  # 80% warning per Section 4.6.3
        'memory_utilization_critical': 95.0,  # 95% critical
        
        # Database performance thresholds (milliseconds)
        'database_response_warning': 100.0,  # 100ms warning
        'database_response_critical': 500.0,  # 500ms critical
        'database_connection_timeout': 5000.0,  # 5 seconds
        
        # Cache performance thresholds (milliseconds)
        'cache_response_warning': 50.0,  # 50ms warning
        'cache_response_critical': 200.0,  # 200ms critical
        'cache_hit_rate_minimum': 90.0,  # 90% minimum hit rate
        
        # GC performance thresholds (milliseconds)
        'gc_pause_warning': 100.0,  # 100ms warning
        'gc_pause_critical': 300.0,  # 300ms critical
        'gc_frequency_maximum': 10.0  # Maximum 10 GC cycles per minute
    }
    
    # Load Testing Scenarios per Section 4.6.3
    LOAD_TEST_SCENARIOS = {
        LoadTestScenario.LIGHT_LOAD: LoadTestConfiguration(
            scenario_name="Light Load",
            users=10,
            spawn_rate=2.0,
            duration=300,  # 5 minutes
            response_time_p95=300.0,
            error_rate_threshold=0.05,
            throughput_threshold=50.0
        ),
        LoadTestScenario.NORMAL_LOAD: LoadTestConfiguration(
            scenario_name="Normal Load",
            users=100,
            spawn_rate=10.0,
            duration=600,  # 10 minutes
            response_time_p95=500.0,
            error_rate_threshold=0.1,
            throughput_threshold=100.0
        ),
        LoadTestScenario.HEAVY_LOAD: LoadTestConfiguration(
            scenario_name="Heavy Load",
            users=500,
            spawn_rate=25.0,
            duration=1200,  # 20 minutes
            response_time_p95=800.0,
            error_rate_threshold=0.5,
            throughput_threshold=300.0
        ),
        LoadTestScenario.STRESS_TEST: LoadTestConfiguration(
            scenario_name="Stress Test",
            users=1000,
            spawn_rate=50.0,
            duration=1800,  # 30 minutes
            response_time_p95=1500.0,
            error_rate_threshold=2.0,
            throughput_threshold=500.0
        ),
        LoadTestScenario.BASELINE_COMPARISON: LoadTestConfiguration(
            scenario_name="Baseline Comparison",
            users=100,
            spawn_rate=10.0,
            duration=900,  # 15 minutes
            response_time_p95=500.0,
            error_rate_threshold=0.1,
            throughput_threshold=100.0
        ),
        LoadTestScenario.SPIKE_TEST: LoadTestConfiguration(
            scenario_name="Spike Test",
            users=200,
            spawn_rate=100.0,  # Rapid ramp-up
            duration=300,  # 5 minutes
            ramp_up_time=10,  # Very fast ramp-up
            response_time_p95=1000.0,
            error_rate_threshold=1.0,
            throughput_threshold=150.0
        ),
        LoadTestScenario.ENDURANCE_TEST: LoadTestConfiguration(
            scenario_name="Endurance Test",
            users=150,
            spawn_rate=5.0,
            duration=7200,  # 2 hours
            steady_state_time=6600,  # Most of the test
            response_time_p95=600.0,
            error_rate_threshold=0.2,
            throughput_threshold=120.0
        )
    }
    
    # Performance Monitoring Configuration
    PERFORMANCE_MONITORING = {
        'metrics_collection_enabled': True,
        'metrics_collection_interval': 15,  # seconds
        'metrics_retention_period': 86400,  # 24 hours in seconds
        'prometheus_integration': True,
        'prometheus_pushgateway_url': os.getenv('PROMETHEUS_PUSHGATEWAY_URL', 'http://localhost:9091'),
        'grafana_dashboard_enabled': True,
        'real_time_alerts': True,
        'alert_webhook_url': os.getenv('PERFORMANCE_ALERT_WEBHOOK_URL'),
        'alert_slack_channel': os.getenv('PERFORMANCE_ALERT_SLACK_CHANNEL', '#performance-alerts'),
        'baseline_drift_detection': True,
        'baseline_update_frequency': 'weekly',
        'performance_regression_detection': True
    }
    
    # CI/CD Pipeline Integration Configuration per Section 6.6.2
    CICD_INTEGRATION = {
        'github_actions_enabled': True,
        'performance_gate_enabled': True,
        'performance_gate_threshold': 10.0,  # ≤10% variance threshold
        'automated_rollback_enabled': True,
        'rollback_trigger_threshold': 15.0,  # >15% variance triggers rollback
        'pipeline_timeout': 3600,  # 1 hour maximum test duration
        'parallel_execution': True,
        'artifact_retention': 30,  # days
        'test_report_format': 'junit',
        'performance_report_format': 'html',
        'notification_enabled': True,
        'notification_channels': ['slack', 'email'],
        'approval_gate_enabled': True,  # Manual approval for production
        'performance_comparison_required': True,
        'baseline_validation_required': True
    }
    
    # Environment-Specific Performance Parameters per Section 6.6.1
    ENVIRONMENT_CONFIGS = {
        'development': {
            'performance_testing_enabled': True,
            'load_test_scenario': LoadTestScenario.LIGHT_LOAD,
            'baseline_comparison_enabled': False,
            'ci_integration_enabled': False,
            'resource_limits': {
                'cpu_cores': 2,
                'memory_gb': 4,
                'max_users': 50
            },
            'test_duration_multiplier': 0.5,  # Shorter tests in dev
            'alert_thresholds_relaxed': True
        },
        'testing': {
            'performance_testing_enabled': True,
            'load_test_scenario': LoadTestScenario.NORMAL_LOAD,
            'baseline_comparison_enabled': True,
            'ci_integration_enabled': True,
            'resource_limits': {
                'cpu_cores': 4,
                'memory_gb': 8,
                'max_users': 200
            },
            'test_duration_multiplier': 0.75,
            'alert_thresholds_relaxed': False
        },
        'staging': {
            'performance_testing_enabled': True,
            'load_test_scenario': LoadTestScenario.HEAVY_LOAD,
            'baseline_comparison_enabled': True,
            'ci_integration_enabled': True,
            'resource_limits': {
                'cpu_cores': 8,
                'memory_gb': 16,
                'max_users': 500
            },
            'test_duration_multiplier': 1.0,
            'alert_thresholds_relaxed': False
        },
        'production': {
            'performance_testing_enabled': True,
            'load_test_scenario': LoadTestScenario.BASELINE_COMPARISON,
            'baseline_comparison_enabled': True,
            'ci_integration_enabled': True,
            'resource_limits': {
                'cpu_cores': 16,
                'memory_gb': 32,
                'max_users': 1000
            },
            'test_duration_multiplier': 1.0,
            'alert_thresholds_relaxed': False,
            'production_traffic_sampling': 0.1  # 10% traffic for performance monitoring
        }
    }
    
    # Baseline Comparison Configuration per Section 0.3.2
    BASELINE_COMPARISON = {
        'comparison_enabled': True,
        'variance_threshold': 10.0,  # ≤10% variance requirement
        'variance_calculation_method': 'percentage',
        'comparison_metrics': [
            'response_time_average',
            'response_time_p95',
            'response_time_p99',
            'throughput',
            'error_rate',
            'cpu_utilization',
            'memory_usage',
            'database_response_time'
        ],
        'statistical_significance': 0.95,  # 95% confidence interval
        'sample_size_minimum': 1000,  # Minimum requests for valid comparison
        'outlier_detection_enabled': True,
        'outlier_threshold': 3.0,  # Standard deviations
        'trend_analysis_enabled': True,
        'trend_analysis_window': 7,  # days
        'regression_detection_sensitivity': 'medium',
        'baseline_update_criteria': {
            'improvement_threshold': 5.0,  # Update baseline if 5% improvement
            'stability_period': 7,  # days of stable performance
            'validation_tests_required': 3
        }
    }
    
    # Resource Monitoring Configuration
    RESOURCE_MONITORING = {
        'system_metrics_enabled': True,
        'container_metrics_enabled': True,
        'application_metrics_enabled': True,
        'database_metrics_enabled': True,
        'cache_metrics_enabled': True,
        'network_metrics_enabled': True,
        
        # System resource monitoring
        'cpu_monitoring': {
            'enabled': True,
            'collection_interval': 15,  # seconds
            'per_core_monitoring': True,
            'load_average_monitoring': True,
            'context_switch_monitoring': True
        },
        
        'memory_monitoring': {
            'enabled': True,
            'collection_interval': 30,  # seconds
            'heap_monitoring': True,
            'garbage_collection_monitoring': True,
            'memory_leak_detection': True,
            'swap_monitoring': True
        },
        
        'disk_monitoring': {
            'enabled': True,
            'collection_interval': 60,  # seconds
            'io_monitoring': True,
            'space_monitoring': True,
            'latency_monitoring': True
        },
        
        'network_monitoring': {
            'enabled': True,
            'collection_interval': 30,  # seconds
            'bandwidth_monitoring': True,
            'connection_monitoring': True,
            'packet_loss_monitoring': True
        }
    }
    
    # Test Data Configuration
    TEST_DATA_CONFIG = {
        'data_generation_enabled': True,
        'synthetic_data_size': 10000,  # Number of test records
        'data_variety_factor': 0.8,  # 80% variety in test data
        'realistic_data_patterns': True,
        'data_cleanup_enabled': True,
        'data_isolation_per_test': True,
        'performance_data_templates': {
            'user_profiles': 1000,
            'transaction_records': 5000,
            'session_data': 500,
            'cache_entries': 2000
        }
    }
    
    @classmethod
    def get_environment_config(cls, environment: str = None) -> Dict[str, Any]:
        """
        Get environment-specific performance configuration.
        
        Args:
            environment: Target environment name (defaults to FLASK_ENV)
            
        Returns:
            Dict containing environment-specific performance parameters
        """
        if environment is None:
            environment = os.getenv('FLASK_ENV', 'development')
        
        environment = environment.lower()
        
        if environment not in cls.ENVIRONMENT_CONFIGS:
            logger.warning(f"Unknown environment '{environment}', using development config")
            environment = 'development'
        
        env_config = cls.ENVIRONMENT_CONFIGS[environment].copy()
        
        # Apply environment-specific modifications
        if env_config.get('alert_thresholds_relaxed'):
            # Relax thresholds for development environments
            env_config['performance_thresholds'] = cls._get_relaxed_thresholds()
        else:
            env_config['performance_thresholds'] = cls.PERFORMANCE_THRESHOLDS.copy()
        
        # Apply test duration multiplier
        multiplier = env_config.get('test_duration_multiplier', 1.0)
        for scenario in cls.LOAD_TEST_SCENARIOS.values():
            env_config[f'{scenario.scenario_name.lower().replace(" ", "_")}_duration'] = int(
                scenario.duration * multiplier
            )
        
        logger.info(
            f"Performance configuration loaded for environment: {environment}",
            extra={
                'environment': environment,
                'load_test_scenario': env_config['load_test_scenario'].value,
                'baseline_comparison_enabled': env_config['baseline_comparison_enabled'],
                'ci_integration_enabled': env_config['ci_integration_enabled']
            }
        )
        
        return env_config
    
    @classmethod
    def _get_relaxed_thresholds(cls) -> Dict[str, float]:
        """Get relaxed performance thresholds for development environments."""
        relaxed_thresholds = cls.PERFORMANCE_THRESHOLDS.copy()
        
        # Increase thresholds by 50% for development
        multiplier = 1.5
        
        threshold_keys = [
            'response_time_p95', 'response_time_p99', 'response_time_average',
            'database_response_warning', 'database_response_critical',
            'cache_response_warning', 'cache_response_critical',
            'gc_pause_warning', 'gc_pause_critical'
        ]
        
        for key in threshold_keys:
            if key in relaxed_thresholds:
                relaxed_thresholds[key] *= multiplier
        
        # Reduce throughput requirements for development
        throughput_keys = ['throughput_minimum', 'throughput_target']
        for key in throughput_keys:
            if key in relaxed_thresholds:
                relaxed_thresholds[key] *= 0.5
        
        return relaxed_thresholds
    
    @classmethod
    def calculate_variance_percentage(cls, baseline: float, measured: float) -> float:
        """
        Calculate performance variance percentage against Node.js baseline.
        
        Args:
            baseline: Node.js baseline metric value
            measured: Flask implementation measured value
            
        Returns:
            Variance percentage (positive = slower, negative = faster)
        """
        if baseline == 0:
            return 0.0
        return ((measured - baseline) / baseline) * 100
    
    @classmethod
    def is_within_variance_threshold(cls, baseline: float, measured: float, 
                                   threshold: float = None) -> bool:
        """
        Check if measured performance is within acceptable variance threshold.
        
        Args:
            baseline: Node.js baseline metric value
            measured: Flask implementation measured value
            threshold: Custom variance threshold (defaults to class threshold)
            
        Returns:
            True if within variance threshold
        """
        if threshold is None:
            threshold = cls.PERFORMANCE_VARIANCE_THRESHOLD
        
        variance = cls.calculate_variance_percentage(baseline, measured)
        return abs(variance) <= threshold
    
    @classmethod
    def get_performance_thresholds(cls, metric_category: str, 
                                 environment: str = None) -> Dict[str, float]:
        """
        Get performance thresholds for specific metric category and environment.
        
        Args:
            metric_category: Category of metrics (response_times, memory_usage, etc.)
            environment: Target environment (defaults to current environment)
            
        Returns:
            Dictionary of performance thresholds with variance applied
        """
        env_config = cls.get_environment_config(environment)
        thresholds = {}
        
        if metric_category == 'response_times':
            baseline_metrics = cls.NODEJS_BASELINE_METRICS.response_times
        elif metric_category == 'memory_usage':
            baseline_metrics = cls.NODEJS_BASELINE_METRICS.memory_usage
        elif metric_category == 'throughput':
            baseline_metrics = cls.NODEJS_BASELINE_METRICS.throughput
        elif metric_category == 'database_performance':
            baseline_metrics = cls.NODEJS_BASELINE_METRICS.database_performance
        elif metric_category == 'cache_performance':
            baseline_metrics = cls.NODEJS_BASELINE_METRICS.cache_performance
        elif metric_category == 'system_resources':
            baseline_metrics = cls.NODEJS_BASELINE_METRICS.system_resources
        else:
            logger.warning(f"Unknown metric category: {metric_category}")
            return {}
        
        variance_threshold = cls.PERFORMANCE_VARIANCE_THRESHOLD
        
        for metric_name, baseline_value in baseline_metrics.items():
            # Calculate acceptable maximum (baseline + variance threshold)
            max_threshold = baseline_value * (1 + variance_threshold / 100)
            thresholds[f"{metric_name}_max"] = max_threshold
            
            # Calculate warning threshold (baseline + half variance threshold)
            warning_threshold = baseline_value * (1 + (variance_threshold / 2) / 100)
            thresholds[f"{metric_name}_warning"] = warning_threshold
            
            # Store baseline for comparison
            thresholds[f"{metric_name}_baseline"] = baseline_value
            
            # Calculate acceptable minimum (for throughput metrics)
            if metric_category in ['throughput', 'cache_performance']:
                min_threshold = baseline_value * (1 - variance_threshold / 100)
                thresholds[f"{metric_name}_min"] = max(0, min_threshold)
        
        return thresholds
    
    @classmethod
    def get_load_test_config(cls, scenario: LoadTestScenario, 
                           environment: str = None) -> LoadTestConfiguration:
        """
        Get load test configuration for specific scenario and environment.
        
        Args:
            scenario: Load test scenario type
            environment: Target environment
            
        Returns:
            LoadTestConfiguration instance for the scenario
        """
        if scenario not in cls.LOAD_TEST_SCENARIOS:
            raise ValueError(f"Unknown load test scenario: {scenario}")
        
        base_config = cls.LOAD_TEST_SCENARIOS[scenario]
        env_config = cls.get_environment_config(environment)
        
        # Apply environment-specific modifications
        config = LoadTestConfiguration(
            scenario_name=base_config.scenario_name,
            users=min(base_config.users, env_config['resource_limits']['max_users']),
            spawn_rate=base_config.spawn_rate,
            duration=int(base_config.duration * env_config.get('test_duration_multiplier', 1.0)),
            host=cls.PERFORMANCE_TEST_HOST,
            ramp_up_time=base_config.ramp_up_time,
            steady_state_time=base_config.steady_state_time,
            ramp_down_time=base_config.ramp_down_time,
            endpoint_weights=base_config.endpoint_weights.copy(),
            response_time_p95=base_config.response_time_p95,
            error_rate_threshold=base_config.error_rate_threshold,
            throughput_threshold=base_config.throughput_threshold
        )
        
        # Adjust thresholds based on environment
        if env_config.get('alert_thresholds_relaxed'):
            config.response_time_p95 *= 1.5
            config.error_rate_threshold *= 2.0
            config.throughput_threshold *= 0.7
        
        return config
    
    @classmethod
    def get_monitoring_config(cls, environment: str = None) -> Dict[str, Any]:
        """
        Get monitoring configuration for specific environment.
        
        Args:
            environment: Target environment
            
        Returns:
            Monitoring configuration dictionary
        """
        env_config = cls.get_environment_config(environment)
        monitoring_config = cls.PERFORMANCE_MONITORING.copy()
        
        # Environment-specific monitoring adjustments
        if environment == 'development':
            monitoring_config['metrics_collection_interval'] = 30  # Less frequent
            monitoring_config['real_time_alerts'] = False
        elif environment == 'production':
            monitoring_config['metrics_collection_interval'] = 10  # More frequent
            monitoring_config['real_time_alerts'] = True
            monitoring_config['baseline_drift_detection'] = True
        
        return monitoring_config
    
    @classmethod
    def get_system_resources(cls) -> Dict[str, float]:
        """
        Get current system resource utilization for comparison.
        
        Returns:
            Dictionary containing current system resource metrics
        """
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return {
                'cpu_utilization': cpu_percent,
                'memory_utilization': memory.percent,
                'memory_available_mb': memory.available / (1024 * 1024),
                'memory_total_mb': memory.total / (1024 * 1024),
                'disk_utilization': (disk.used / disk.total) * 100,
                'disk_available_gb': disk.free / (1024 * 1024 * 1024),
                'load_average': os.getloadavg()[0] if hasattr(os, 'getloadavg') else 0.0,
                'timestamp': datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Error getting system resources: {e}")
            return {}
    
    @classmethod
    def validate_performance_requirements(cls, test_results: Dict[str, Any], 
                                        environment: str = None) -> Dict[str, Any]:
        """
        Validate test results against performance requirements.
        
        Args:
            test_results: Performance test results
            environment: Target environment
            
        Returns:
            Validation results with pass/fail status and details
        """
        validation_results = {
            'overall_status': 'PASS',
            'variance_within_threshold': True,
            'threshold_violations': [],
            'baseline_comparisons': {},
            'recommendations': []
        }
        
        env_config = cls.get_environment_config(environment)
        thresholds = env_config.get('performance_thresholds', cls.PERFORMANCE_THRESHOLDS)
        
        # Validate response time metrics
        if 'response_time_p95' in test_results:
            measured_p95 = test_results['response_time_p95']
            threshold_p95 = thresholds['response_time_p95']
            
            if measured_p95 > threshold_p95:
                validation_results['overall_status'] = 'FAIL'
                validation_results['threshold_violations'].append({
                    'metric': 'response_time_p95',
                    'measured': measured_p95,
                    'threshold': threshold_p95,
                    'variance': ((measured_p95 - threshold_p95) / threshold_p95) * 100
                })
        
        # Validate throughput metrics
        if 'throughput' in test_results:
            measured_throughput = test_results['throughput']
            threshold_throughput = thresholds['throughput_minimum']
            
            if measured_throughput < threshold_throughput:
                validation_results['overall_status'] = 'FAIL'
                validation_results['threshold_violations'].append({
                    'metric': 'throughput',
                    'measured': measured_throughput,
                    'threshold': threshold_throughput,
                    'variance': ((threshold_throughput - measured_throughput) / threshold_throughput) * 100
                })
        
        # Validate baseline comparisons
        baseline_metrics = cls.NODEJS_BASELINE_METRICS.response_times
        for endpoint, baseline_time in baseline_metrics.items():
            if endpoint in test_results:
                measured_time = test_results[endpoint]
                variance = cls.calculate_variance_percentage(baseline_time, measured_time)
                
                validation_results['baseline_comparisons'][endpoint] = {
                    'baseline': baseline_time,
                    'measured': measured_time,
                    'variance_percentage': variance,
                    'within_threshold': abs(variance) <= cls.PERFORMANCE_VARIANCE_THRESHOLD
                }
                
                if abs(variance) > cls.PERFORMANCE_VARIANCE_THRESHOLD:
                    validation_results['overall_status'] = 'FAIL'
                    validation_results['variance_within_threshold'] = False
        
        # Generate recommendations
        if validation_results['threshold_violations']:
            validation_results['recommendations'].append(
                "Performance optimization required for threshold violations"
            )
        
        if not validation_results['variance_within_threshold']:
            validation_results['recommendations'].append(
                f"Performance variance exceeds ±{cls.PERFORMANCE_VARIANCE_THRESHOLD}% threshold"
            )
        
        if validation_results['overall_status'] == 'PASS':
            validation_results['recommendations'].append(
                "All performance requirements met successfully"
            )
        
        return validation_results


class PerformanceConfigFactory:
    """
    Factory class for creating environment-specific performance configurations.
    """
    
    _configs: Dict[str, PerformanceTestConfig] = {}
    
    @classmethod
    def get_config(cls, environment: str = None) -> PerformanceTestConfig:
        """
        Get or create performance configuration for environment.
        
        Args:
            environment: Target environment name
            
        Returns:
            PerformanceTestConfig instance
        """
        if environment is None:
            environment = os.getenv('FLASK_ENV', 'development')
        
        environment = environment.lower()
        
        if environment not in cls._configs:
            cls._configs[environment] = PerformanceTestConfig()
        
        return cls._configs[environment]
    
    @classmethod
    def create_load_test_config(cls, scenario: LoadTestScenario, 
                              environment: str = None) -> LoadTestConfiguration:
        """
        Create load test configuration for specific scenario.
        
        Args:
            scenario: Load test scenario
            environment: Target environment
            
        Returns:
            LoadTestConfiguration instance
        """
        config = cls.get_config(environment)
        return config.get_load_test_config(scenario, environment)
    
    @classmethod
    def validate_test_results(cls, test_results: Dict[str, Any], 
                            environment: str = None) -> Dict[str, Any]:
        """
        Validate performance test results.
        
        Args:
            test_results: Test results to validate
            environment: Target environment
            
        Returns:
            Validation results
        """
        config = cls.get_config(environment)
        return config.validate_performance_requirements(test_results, environment)


# Convenience functions for common use cases
def create_performance_config(environment: str = None) -> PerformanceTestConfig:
    """
    Create performance configuration for specific environment.
    
    Args:
        environment: Target environment
        
    Returns:
        PerformanceTestConfig instance
    """
    return PerformanceConfigFactory.get_config(environment)


def get_load_test_config(scenario: LoadTestScenario, 
                        environment: str = None) -> LoadTestConfiguration:
    """
    Get load test configuration for scenario and environment.
    
    Args:
        scenario: Load test scenario
        environment: Target environment
        
    Returns:
        LoadTestConfiguration instance
    """
    return PerformanceConfigFactory.create_load_test_config(scenario, environment)


def validate_performance_results(test_results: Dict[str, Any], 
                                environment: str = None) -> Dict[str, Any]:
    """
    Validate performance test results against requirements.
    
    Args:
        test_results: Performance test results
        environment: Target environment
        
    Returns:
        Validation results with pass/fail status
    """
    return PerformanceConfigFactory.validate_test_results(test_results, environment)


def get_baseline_metrics(category: str = None) -> Dict[str, float]:
    """
    Get Node.js baseline metrics for comparison.
    
    Args:
        category: Specific metric category (optional)
        
    Returns:
        Baseline metrics dictionary
    """
    baseline = NodeJSBaselineMetrics()
    
    if category == 'response_times':
        return baseline.response_times
    elif category == 'memory_usage':
        return baseline.memory_usage
    elif category == 'throughput':
        return baseline.throughput
    elif category == 'database_performance':
        return baseline.database_performance
    elif category == 'cache_performance':
        return baseline.cache_performance
    elif category == 'system_resources':
        return baseline.system_resources
    else:
        # Return all categories
        return {
            'response_times': baseline.response_times,
            'memory_usage': baseline.memory_usage,
            'throughput': baseline.throughput,
            'database_performance': baseline.database_performance,
            'cache_performance': baseline.cache_performance,
            'system_resources': baseline.system_resources
        }


# Export all configuration classes and functions
__all__ = [
    # Enums
    'LoadTestScenario',
    'PerformanceMetricType',
    
    # Data classes
    'NodeJSBaselineMetrics',
    'LoadTestConfiguration',
    
    # Configuration classes
    'PerformanceTestConfig',
    'PerformanceConfigFactory',
    
    # Convenience functions
    'create_performance_config',
    'get_load_test_config',
    'validate_performance_results',
    'get_baseline_metrics'
]