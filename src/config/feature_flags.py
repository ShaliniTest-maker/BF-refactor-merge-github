"""
Feature flag configuration for gradual traffic migration and deployment management.

This module implements comprehensive feature flag configuration enabling gradual
traffic migration from Node.js to Python Flask application. Provides support for
blue-green deployment patterns, percentage-based traffic routing (5% → 25% → 50% → 100%),
and automated rollback triggers based on performance metrics to ensure safe migration execution.

The feature flag system integrates with enterprise monitoring and deployment infrastructure
to provide real-time deployment control and automated failure response capabilities.

Author: Flask Migration Team
Version: 1.0.0
Dependencies: python-dotenv, structlog, prometheus-client
"""

import os
import json
import logging
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Union, Any
from enum import Enum, auto
from datetime import datetime, timedelta

# Third-party imports for configuration and monitoring
try:
    from prometheus_client import Counter, Gauge, Histogram
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False


class DeploymentStrategy(Enum):
    """Deployment strategy enumeration for traffic routing control."""
    BLUE_GREEN = "blue-green"
    CANARY = "canary"
    ROLLING = "rolling"
    MAINTENANCE = "maintenance"


class MigrationPhase(Enum):
    """Migration phase enumeration for gradual traffic migration."""
    INITIALIZATION = auto()
    PHASE_1_5_PERCENT = auto()
    PHASE_2_25_PERCENT = auto()
    PHASE_3_50_PERCENT = auto()
    PHASE_4_100_PERCENT = auto()
    COMPLETE = auto()
    ROLLBACK = auto()


class PerformanceMetric(Enum):
    """Performance metrics for rollback trigger evaluation."""
    RESPONSE_TIME_VARIANCE = "response_time_variance"
    ERROR_RATE = "error_rate"
    CPU_UTILIZATION = "cpu_utilization"
    MEMORY_USAGE = "memory_usage"
    DATABASE_RESPONSE_TIME = "database_response_time"
    THROUGHPUT_VARIANCE = "throughput_variance"


@dataclass
class RollbackTrigger:
    """Configuration for automated rollback triggers based on performance metrics."""
    metric: PerformanceMetric
    threshold: float
    duration_seconds: int
    evaluation_window_seconds: int
    enabled: bool = True
    
    def __post_init__(self):
        """Validate rollback trigger configuration."""
        if self.threshold <= 0:
            raise ValueError(f"Threshold must be positive for metric {self.metric.value}")
        if self.duration_seconds <= 0:
            raise ValueError(f"Duration must be positive for metric {self.metric.value}")
        if self.evaluation_window_seconds <= 0:
            raise ValueError(f"Evaluation window must be positive for metric {self.metric.value}")


@dataclass
class TrafficRoutingConfig:
    """Configuration for traffic routing percentages during migration phases."""
    phase: MigrationPhase
    percentage: int
    min_duration_minutes: int
    max_duration_minutes: int
    health_check_interval_seconds: int = 30
    stability_threshold_minutes: int = 5
    
    def __post_init__(self):
        """Validate traffic routing configuration."""
        if not 0 <= self.percentage <= 100:
            raise ValueError(f"Percentage must be between 0-100, got {self.percentage}")
        if self.min_duration_minutes > self.max_duration_minutes:
            raise ValueError("Min duration cannot exceed max duration")
        if self.health_check_interval_seconds <= 0:
            raise ValueError("Health check interval must be positive")


@dataclass
class BlueGreenConfig:
    """Configuration for blue-green deployment pattern."""
    enabled: bool
    blue_environment: str
    green_environment: str
    health_check_url: str
    warmup_duration_seconds: int
    cooldown_duration_seconds: int
    max_parallel_deployments: int = 1
    dns_switch_timeout_seconds: int = 300
    
    def __post_init__(self):
        """Validate blue-green configuration."""
        if self.enabled and not all([self.blue_environment, self.green_environment, self.health_check_url]):
            raise ValueError("Blue-green deployment requires all environment configurations")
        if self.warmup_duration_seconds < 0 or self.cooldown_duration_seconds < 0:
            raise ValueError("Duration values must be non-negative")


@dataclass
class PerformanceThresholds:
    """Performance thresholds for deployment validation and rollback decisions."""
    # Response time variance threshold (≤10% from Node.js baseline per Section 0.1.1)
    response_time_variance_percent: float = 10.0
    
    # Error rate thresholds
    error_rate_warning_percent: float = 1.0
    error_rate_critical_percent: float = 5.0
    
    # Resource utilization thresholds
    cpu_utilization_warning_percent: float = 70.0
    cpu_utilization_critical_percent: float = 85.0
    memory_usage_warning_percent: float = 80.0
    memory_usage_critical_percent: float = 90.0
    
    # Database performance thresholds
    database_response_time_warning_ms: float = 200.0
    database_response_time_critical_ms: float = 500.0
    
    # Throughput variance threshold
    throughput_variance_percent: float = 15.0
    
    def __post_init__(self):
        """Validate performance thresholds."""
        if self.response_time_variance_percent > 15.0:
            logging.warning(f"Response time variance {self.response_time_variance_percent}% exceeds recommended 10% threshold")


class FeatureFlagManager:
    """
    Comprehensive feature flag manager for gradual migration and deployment control.
    
    This class implements enterprise-grade feature flag management with support for:
    - Gradual traffic migration (5% → 25% → 50% → 100%)
    - Blue-green deployment patterns
    - Automated rollback based on performance metrics
    - Environment-specific configuration
    - Real-time monitoring and metrics collection
    """
    
    def __init__(self, environment: str = None):
        """
        Initialize feature flag manager with environment-specific configuration.
        
        Args:
            environment: Deployment environment (development, staging, production)
        """
        self.environment = environment or os.getenv('FLASK_ENV', 'development')
        self.logger = self._setup_logging()
        
        # Initialize Prometheus metrics if available
        self._init_metrics()
        
        # Load configuration from environment variables
        self._load_configuration()
        
        # Initialize deployment state
        self.current_phase = MigrationPhase.INITIALIZATION
        self.deployment_start_time: Optional[datetime] = None
        self.last_health_check: Optional[datetime] = None
        self.rollback_triggered = False
        
        self.logger.info(
            "Feature flag manager initialized",
            environment=self.environment,
            deployment_strategy=self.deployment_strategy.value,
            blue_green_enabled=self.blue_green_config.enabled
        )
    
    def _setup_logging(self) -> logging.Logger:
        """Set up structured logging for feature flag operations."""
        if STRUCTLOG_AVAILABLE:
            structlog.configure(
                processors=[
                    structlog.stdlib.filter_by_level,
                    structlog.stdlib.add_logger_name,
                    structlog.stdlib.add_log_level,
                    structlog.stdlib.PositionalArgumentsFormatter(),
                    structlog.processors.TimeStamper(fmt="iso"),
                    structlog.processors.StackInfoRenderer(),
                    structlog.processors.format_exc_info,
                    structlog.processors.JSONRenderer()
                ],
                context_class=dict,
                logger_factory=structlog.stdlib.LoggerFactory(),
                wrapper_class=structlog.stdlib.BoundLogger,
                cache_logger_on_first_use=True,
            )
            return structlog.get_logger("feature_flags")
        else:
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            return logging.getLogger("feature_flags")
    
    def _init_metrics(self) -> None:
        """Initialize Prometheus metrics for feature flag monitoring."""
        if not PROMETHEUS_AVAILABLE:
            self.logger.warning("Prometheus client not available, metrics collection disabled")
            return
        
        self.metrics = {
            'deployment_phase': Gauge(
                'feature_flag_deployment_phase',
                'Current deployment phase',
                ['environment', 'strategy']
            ),
            'traffic_percentage': Gauge(
                'feature_flag_traffic_percentage',
                'Current traffic percentage to new deployment',
                ['environment', 'phase']
            ),
            'rollback_counter': Counter(
                'feature_flag_rollback_total',
                'Total number of rollbacks triggered',
                ['environment', 'trigger_reason']
            ),
            'phase_duration': Histogram(
                'feature_flag_phase_duration_seconds',
                'Duration of deployment phases',
                ['environment', 'phase']
            ),
            'health_check_duration': Histogram(
                'feature_flag_health_check_duration_seconds',
                'Duration of health checks',
                ['environment', 'status']
            )
        }
    
    def _load_configuration(self) -> None:
        """Load feature flag configuration from environment variables."""
        # Deployment strategy configuration
        strategy_name = os.getenv('DEPLOYMENT_STRATEGY', 'blue-green')
        try:
            self.deployment_strategy = DeploymentStrategy(strategy_name)
        except ValueError:
            self.logger.warning(f"Invalid deployment strategy '{strategy_name}', defaulting to blue-green")
            self.deployment_strategy = DeploymentStrategy.BLUE_GREEN
        
        # Blue-green deployment configuration
        self.blue_green_config = BlueGreenConfig(
            enabled=os.getenv('FEATURE_FLAG_BLUE_GREEN_DEPLOYMENT', 'true').lower() == 'true',
            blue_environment=os.getenv('BLUE_ENVIRONMENT', 'blue'),
            green_environment=os.getenv('GREEN_ENVIRONMENT', 'green'),
            health_check_url=os.getenv('HEALTH_CHECK_URL', '/health'),
            warmup_duration_seconds=int(os.getenv('DEPLOYMENT_WARMUP_DURATION', '120')),
            cooldown_duration_seconds=int(os.getenv('DEPLOYMENT_COOLDOWN_DURATION', '300')),
            max_parallel_deployments=int(os.getenv('MAX_PARALLEL_DEPLOYMENTS', '1')),
            dns_switch_timeout_seconds=int(os.getenv('DNS_SWITCH_TIMEOUT', '300'))
        )
        
        # Performance thresholds configuration
        self.performance_thresholds = PerformanceThresholds(
            response_time_variance_percent=float(os.getenv('PERFORMANCE_BASELINE_VARIANCE_THRESHOLD', '10.0')),
            error_rate_warning_percent=float(os.getenv('ERROR_RATE_WARNING_THRESHOLD', '1.0')),
            error_rate_critical_percent=float(os.getenv('ERROR_RATE_CRITICAL_THRESHOLD', '5.0')),
            cpu_utilization_warning_percent=float(os.getenv('CPU_UTILIZATION_WARNING_THRESHOLD', '70.0')),
            cpu_utilization_critical_percent=float(os.getenv('CPU_UTILIZATION_CRITICAL_THRESHOLD', '85.0')),
            memory_usage_warning_percent=float(os.getenv('MEMORY_USAGE_WARNING_THRESHOLD', '80.0')),
            memory_usage_critical_percent=float(os.getenv('MEMORY_USAGE_CRITICAL_THRESHOLD', '90.0')),
            database_response_time_warning_ms=float(os.getenv('DB_RESPONSE_TIME_WARNING_MS', '200.0')),
            database_response_time_critical_ms=float(os.getenv('DB_RESPONSE_TIME_CRITICAL_MS', '500.0')),
            throughput_variance_percent=float(os.getenv('THROUGHPUT_VARIANCE_THRESHOLD', '15.0'))
        )
        
        # Traffic routing configurations for each phase
        self.traffic_configs = {
            MigrationPhase.PHASE_1_5_PERCENT: TrafficRoutingConfig(
                phase=MigrationPhase.PHASE_1_5_PERCENT,
                percentage=5,
                min_duration_minutes=int(os.getenv('PHASE_1_MIN_DURATION', '15')),
                max_duration_minutes=int(os.getenv('PHASE_1_MAX_DURATION', '60')),
                health_check_interval_seconds=int(os.getenv('PHASE_1_HEALTH_CHECK_INTERVAL', '30')),
                stability_threshold_minutes=int(os.getenv('PHASE_1_STABILITY_THRESHOLD', '5'))
            ),
            MigrationPhase.PHASE_2_25_PERCENT: TrafficRoutingConfig(
                phase=MigrationPhase.PHASE_2_25_PERCENT,
                percentage=25,
                min_duration_minutes=int(os.getenv('PHASE_2_MIN_DURATION', '30')),
                max_duration_minutes=int(os.getenv('PHASE_2_MAX_DURATION', '120')),
                health_check_interval_seconds=int(os.getenv('PHASE_2_HEALTH_CHECK_INTERVAL', '30')),
                stability_threshold_minutes=int(os.getenv('PHASE_2_STABILITY_THRESHOLD', '10'))
            ),
            MigrationPhase.PHASE_3_50_PERCENT: TrafficRoutingConfig(
                phase=MigrationPhase.PHASE_3_50_PERCENT,
                percentage=50,
                min_duration_minutes=int(os.getenv('PHASE_3_MIN_DURATION', '45')),
                max_duration_minutes=int(os.getenv('PHASE_3_MAX_DURATION', '180')),
                health_check_interval_seconds=int(os.getenv('PHASE_3_HEALTH_CHECK_INTERVAL', '30')),
                stability_threshold_minutes=int(os.getenv('PHASE_3_STABILITY_THRESHOLD', '15'))
            ),
            MigrationPhase.PHASE_4_100_PERCENT: TrafficRoutingConfig(
                phase=MigrationPhase.PHASE_4_100_PERCENT,
                percentage=100,
                min_duration_minutes=int(os.getenv('PHASE_4_MIN_DURATION', '60')),
                max_duration_minutes=int(os.getenv('PHASE_4_MAX_DURATION', '240')),
                health_check_interval_seconds=int(os.getenv('PHASE_4_HEALTH_CHECK_INTERVAL', '60')),
                stability_threshold_minutes=int(os.getenv('PHASE_4_STABILITY_THRESHOLD', '30'))
            )
        }
        
        # Rollback trigger configurations
        self.rollback_triggers = [
            RollbackTrigger(
                metric=PerformanceMetric.RESPONSE_TIME_VARIANCE,
                threshold=self.performance_thresholds.response_time_variance_percent,
                duration_seconds=int(os.getenv('RESPONSE_TIME_ROLLBACK_DURATION', '300')),
                evaluation_window_seconds=int(os.getenv('RESPONSE_TIME_EVALUATION_WINDOW', '600')),
                enabled=os.getenv('RESPONSE_TIME_ROLLBACK_ENABLED', 'true').lower() == 'true'
            ),
            RollbackTrigger(
                metric=PerformanceMetric.ERROR_RATE,
                threshold=self.performance_thresholds.error_rate_critical_percent,
                duration_seconds=int(os.getenv('ERROR_RATE_ROLLBACK_DURATION', '180')),
                evaluation_window_seconds=int(os.getenv('ERROR_RATE_EVALUATION_WINDOW', '300')),
                enabled=os.getenv('ERROR_RATE_ROLLBACK_ENABLED', 'true').lower() == 'true'
            ),
            RollbackTrigger(
                metric=PerformanceMetric.CPU_UTILIZATION,
                threshold=self.performance_thresholds.cpu_utilization_critical_percent,
                duration_seconds=int(os.getenv('CPU_ROLLBACK_DURATION', '600')),
                evaluation_window_seconds=int(os.getenv('CPU_EVALUATION_WINDOW', '900')),
                enabled=os.getenv('CPU_ROLLBACK_ENABLED', 'true').lower() == 'true'
            ),
            RollbackTrigger(
                metric=PerformanceMetric.DATABASE_RESPONSE_TIME,
                threshold=self.performance_thresholds.database_response_time_critical_ms,
                duration_seconds=int(os.getenv('DB_ROLLBACK_DURATION', '300')),
                evaluation_window_seconds=int(os.getenv('DB_EVALUATION_WINDOW', '600')),
                enabled=os.getenv('DB_ROLLBACK_ENABLED', 'true').lower() == 'true'
            )
        ]
        
        # Global rollback configuration
        self.rollback_enabled = os.getenv('ROLLBACK_ENABLED', 'true').lower() == 'true'
        self.auto_rollback_enabled = os.getenv('AUTO_ROLLBACK_ENABLED', 'true').lower() == 'true'
    
    def get_current_traffic_percentage(self) -> int:
        """
        Get the current traffic percentage for the new deployment.
        
        Returns:
            Current traffic percentage (0-100)
        """
        if self.current_phase in self.traffic_configs:
            return self.traffic_configs[self.current_phase].percentage
        return 0
    
    def should_route_to_new_deployment(self, user_id: Optional[str] = None) -> bool:
        """
        Determine if traffic should be routed to the new deployment.
        
        This method implements consistent routing based on user ID hashing
        to ensure users have a consistent experience during migration.
        
        Args:
            user_id: Optional user identifier for consistent routing
            
        Returns:
            True if traffic should be routed to new deployment, False for legacy
        """
        if self.rollback_triggered:
            self.logger.debug("Rollback triggered, routing to blue environment")
            return False
        
        traffic_percentage = self.get_current_traffic_percentage()
        
        if traffic_percentage == 0:
            return False
        elif traffic_percentage == 100:
            return True
        
        # Implement consistent hashing for user-based routing
        if user_id:
            hash_value = hash(user_id) % 100
            route_to_new = hash_value < traffic_percentage
        else:
            # Fallback to simple percentage for anonymous users
            import random
            route_to_new = random.randint(1, 100) <= traffic_percentage
        
        self.logger.debug(
            "Traffic routing decision",
            user_id=user_id,
            traffic_percentage=traffic_percentage,
            route_to_new=route_to_new,
            phase=self.current_phase.name
        )
        
        return route_to_new
    
    def advance_migration_phase(self) -> bool:
        """
        Advance to the next migration phase if conditions are met.
        
        Returns:
            True if phase was advanced, False otherwise
        """
        if self.rollback_triggered:
            self.logger.warning("Cannot advance phase while rollback is triggered")
            return False
        
        # Define phase progression
        phase_progression = {
            MigrationPhase.INITIALIZATION: MigrationPhase.PHASE_1_5_PERCENT,
            MigrationPhase.PHASE_1_5_PERCENT: MigrationPhase.PHASE_2_25_PERCENT,
            MigrationPhase.PHASE_2_25_PERCENT: MigrationPhase.PHASE_3_50_PERCENT,
            MigrationPhase.PHASE_3_50_PERCENT: MigrationPhase.PHASE_4_100_PERCENT,
            MigrationPhase.PHASE_4_100_PERCENT: MigrationPhase.COMPLETE
        }
        
        if self.current_phase not in phase_progression:
            self.logger.info(f"No next phase available from {self.current_phase.name}")
            return False
        
        # Check if minimum duration has been met
        if self.deployment_start_time and self.current_phase in self.traffic_configs:
            config = self.traffic_configs[self.current_phase]
            elapsed_minutes = (datetime.now() - self.deployment_start_time).total_seconds() / 60
            
            if elapsed_minutes < config.min_duration_minutes:
                self.logger.info(
                    "Minimum phase duration not met",
                    current_phase=self.current_phase.name,
                    elapsed_minutes=elapsed_minutes,
                    required_minutes=config.min_duration_minutes
                )
                return False
        
        # Advance to next phase
        next_phase = phase_progression[self.current_phase]
        previous_phase = self.current_phase
        self.current_phase = next_phase
        
        # Update metrics
        if PROMETHEUS_AVAILABLE and hasattr(self, 'metrics'):
            self.metrics['deployment_phase'].labels(
                environment=self.environment,
                strategy=self.deployment_strategy.value
            ).set(self.current_phase.value)
            
            if next_phase in self.traffic_configs:
                self.metrics['traffic_percentage'].labels(
                    environment=self.environment,
                    phase=next_phase.name
                ).set(self.traffic_configs[next_phase].percentage)
        
        self.logger.info(
            "Migration phase advanced",
            previous_phase=previous_phase.name,
            current_phase=self.current_phase.name,
            traffic_percentage=self.get_current_traffic_percentage()
        )
        
        return True
    
    def trigger_rollback(self, reason: str, metric: Optional[PerformanceMetric] = None) -> bool:
        """
        Trigger automated rollback to previous stable deployment.
        
        Args:
            reason: Human-readable reason for rollback
            metric: Performance metric that triggered rollback (if applicable)
            
        Returns:
            True if rollback was triggered, False if already in rollback state
        """
        if self.rollback_triggered:
            self.logger.warning("Rollback already triggered")
            return False
        
        if not self.rollback_enabled:
            self.logger.warning("Rollback disabled, ignoring trigger request")
            return False
        
        self.rollback_triggered = True
        self.current_phase = MigrationPhase.ROLLBACK
        
        # Update metrics
        if PROMETHEUS_AVAILABLE and hasattr(self, 'metrics'):
            metric_name = metric.value if metric else 'manual'
            self.metrics['rollback_counter'].labels(
                environment=self.environment,
                trigger_reason=metric_name
            ).inc()
        
        self.logger.critical(
            "Rollback triggered",
            reason=reason,
            trigger_metric=metric.value if metric else None,
            environment=self.environment,
            previous_phase=self.current_phase.name
        )
        
        return True
    
    def reset_rollback(self) -> None:
        """Reset rollback state and return to initialization phase."""
        self.rollback_triggered = False
        self.current_phase = MigrationPhase.INITIALIZATION
        self.deployment_start_time = None
        
        self.logger.info(
            "Rollback state reset",
            environment=self.environment,
            current_phase=self.current_phase.name
        )
    
    def evaluate_performance_metrics(self, metrics_data: Dict[str, float]) -> List[str]:
        """
        Evaluate performance metrics against rollback triggers.
        
        Args:
            metrics_data: Dictionary containing current performance metrics
            
        Returns:
            List of triggered rollback reasons (empty if no triggers)
        """
        triggered_reasons = []
        
        if not self.auto_rollback_enabled:
            return triggered_reasons
        
        for trigger in self.rollback_triggers:
            if not trigger.enabled:
                continue
            
            metric_key = trigger.metric.value
            if metric_key not in metrics_data:
                continue
            
            current_value = metrics_data[metric_key]
            
            # Check if metric exceeds threshold
            if current_value > trigger.threshold:
                reason = (
                    f"{trigger.metric.value} exceeded threshold: "
                    f"{current_value} > {trigger.threshold}"
                )
                triggered_reasons.append(reason)
                
                # Trigger rollback if auto-rollback is enabled
                if self.auto_rollback_enabled:
                    self.trigger_rollback(reason, trigger.metric)
        
        return triggered_reasons
    
    def start_deployment(self) -> None:
        """Start deployment process and initialize timing."""
        self.deployment_start_time = datetime.now()
        self.current_phase = MigrationPhase.PHASE_1_5_PERCENT
        self.rollback_triggered = False
        
        self.logger.info(
            "Deployment started",
            environment=self.environment,
            start_time=self.deployment_start_time.isoformat(),
            initial_phase=self.current_phase.name,
            strategy=self.deployment_strategy.value
        )
    
    def get_deployment_status(self) -> Dict[str, Any]:
        """
        Get comprehensive deployment status information.
        
        Returns:
            Dictionary containing current deployment status
        """
        status = {
            'environment': self.environment,
            'current_phase': self.current_phase.name,
            'traffic_percentage': self.get_current_traffic_percentage(),
            'deployment_strategy': self.deployment_strategy.value,
            'rollback_triggered': self.rollback_triggered,
            'rollback_enabled': self.rollback_enabled,
            'auto_rollback_enabled': self.auto_rollback_enabled,
            'blue_green_enabled': self.blue_green_config.enabled,
            'deployment_start_time': self.deployment_start_time.isoformat() if self.deployment_start_time else None,
            'last_health_check': self.last_health_check.isoformat() if self.last_health_check else None
        }
        
        # Add phase-specific information
        if self.current_phase in self.traffic_configs:
            config = self.traffic_configs[self.current_phase]
            status['phase_config'] = asdict(config)
            
            # Calculate elapsed time in current phase
            if self.deployment_start_time:
                elapsed_seconds = (datetime.now() - self.deployment_start_time).total_seconds()
                status['elapsed_seconds'] = elapsed_seconds
                status['elapsed_minutes'] = elapsed_seconds / 60
        
        # Add performance thresholds
        status['performance_thresholds'] = asdict(self.performance_thresholds)
        
        return status
    
    def export_configuration(self) -> Dict[str, Any]:
        """
        Export complete feature flag configuration for external systems.
        
        Returns:
            Dictionary containing complete configuration
        """
        return {
            'environment': self.environment,
            'deployment_strategy': self.deployment_strategy.value,
            'blue_green_config': asdict(self.blue_green_config),
            'performance_thresholds': asdict(self.performance_thresholds),
            'traffic_configs': {
                phase.name: asdict(config) for phase, config in self.traffic_configs.items()
            },
            'rollback_triggers': [asdict(trigger) for trigger in self.rollback_triggers],
            'rollback_enabled': self.rollback_enabled,
            'auto_rollback_enabled': self.auto_rollback_enabled
        }


# Global feature flag manager instance
_feature_flag_manager: Optional[FeatureFlagManager] = None


def get_feature_flag_manager() -> FeatureFlagManager:
    """
    Get or create global feature flag manager instance.
    
    Returns:
        Global FeatureFlagManager instance
    """
    global _feature_flag_manager
    if _feature_flag_manager is None:
        _feature_flag_manager = FeatureFlagManager()
    return _feature_flag_manager


def should_use_new_deployment(user_id: Optional[str] = None) -> bool:
    """
    Convenience function to check if traffic should use new deployment.
    
    Args:
        user_id: Optional user identifier for consistent routing
        
    Returns:
        True if should use new deployment, False for legacy
    """
    manager = get_feature_flag_manager()
    return manager.should_route_to_new_deployment(user_id)


def get_current_migration_phase() -> MigrationPhase:
    """
    Get current migration phase.
    
    Returns:
        Current MigrationPhase
    """
    manager = get_feature_flag_manager()
    return manager.current_phase


def advance_deployment_phase() -> bool:
    """
    Advance to next deployment phase.
    
    Returns:
        True if phase was advanced, False otherwise
    """
    manager = get_feature_flag_manager()
    return manager.advance_migration_phase()


def trigger_emergency_rollback(reason: str) -> bool:
    """
    Trigger emergency rollback with specified reason.
    
    Args:
        reason: Reason for emergency rollback
        
    Returns:
        True if rollback was triggered, False otherwise
    """
    manager = get_feature_flag_manager()
    return manager.trigger_rollback(reason)


# Environment-specific configurations
ENVIRONMENT_CONFIGS = {
    'development': {
        'auto_rollback_enabled': False,
        'phase_durations': {
            'phase_1_min_duration': 5,  # 5 minutes for faster development
            'phase_2_min_duration': 10,
            'phase_3_min_duration': 15,
            'phase_4_min_duration': 20
        }
    },
    'staging': {
        'auto_rollback_enabled': True,
        'phase_durations': {
            'phase_1_min_duration': 10,
            'phase_2_min_duration': 20,
            'phase_3_min_duration': 30,
            'phase_4_min_duration': 45
        }
    },
    'production': {
        'auto_rollback_enabled': True,
        'phase_durations': {
            'phase_1_min_duration': 15,
            'phase_2_min_duration': 30,
            'phase_3_min_duration': 45,
            'phase_4_min_duration': 60
        }
    }
}


def get_environment_config(environment: str) -> Dict[str, Any]:
    """
    Get environment-specific configuration.
    
    Args:
        environment: Environment name (development, staging, production)
        
    Returns:
        Environment-specific configuration dictionary
    """
    return ENVIRONMENT_CONFIGS.get(environment, ENVIRONMENT_CONFIGS['production'])


if __name__ == "__main__":
    # Example usage and testing
    import sys
    
    # Initialize feature flag manager
    manager = FeatureFlagManager('development')
    
    # Display current configuration
    print("Feature Flag Configuration:")
    print(json.dumps(manager.export_configuration(), indent=2, default=str))
    
    # Simulate deployment process
    print("\nStarting deployment simulation...")
    manager.start_deployment()
    
    # Test traffic routing
    for i in range(10):
        user_id = f"user_{i}"
        route_to_new = manager.should_route_to_new_deployment(user_id)
        print(f"User {user_id}: {'New' if route_to_new else 'Legacy'} deployment")
    
    # Test phase advancement
    print(f"\nCurrent phase: {manager.current_phase.name}")
    print(f"Traffic percentage: {manager.get_current_traffic_percentage()}%")
    
    if manager.advance_migration_phase():
        print(f"Advanced to phase: {manager.current_phase.name}")
        print(f"New traffic percentage: {manager.get_current_traffic_percentage()}%")
    
    # Test rollback functionality
    print("\nTesting rollback functionality...")
    test_metrics = {
        'response_time_variance': 15.0,  # Exceeds 10% threshold
        'error_rate': 2.0,  # Within acceptable range
        'cpu_utilization': 75.0  # Warning level
    }
    
    triggered_reasons = manager.evaluate_performance_metrics(test_metrics)
    if triggered_reasons:
        print(f"Rollback triggered due to: {triggered_reasons}")
    else:
        print("All metrics within acceptable ranges")
    
    # Display final status
    print("\nFinal deployment status:")
    print(json.dumps(manager.get_deployment_status(), indent=2, default=str))