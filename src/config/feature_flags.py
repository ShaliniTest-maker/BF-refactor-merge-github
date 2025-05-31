"""
Feature Flag Configuration Module for Flask Migration

This module implements comprehensive feature flag configuration for gradual traffic migration
from Node.js to Python Flask application, supporting blue-green deployment patterns,
percentage-based traffic routing, and automated rollback triggers based on performance
degradation detection.

Key Features:
- Blue-green deployment pattern support with zero-downtime migration capabilities
- Gradual traffic migration: 5% → 25% → 50% → 100% progression with automated validation
- Performance-based rollback triggers when variance exceeds ±10% threshold
- Environment-specific feature flag management (dev/staging/production)
- Redis-backed distributed feature flag storage for multi-instance deployments
- Real-time performance monitoring integration with Prometheus metrics
- Emergency rollback procedures with immediate traffic diversion to Node.js baseline
- Circuit breaker integration for service degradation detection

Architecture Integration:
- Section 0.2.3: Blue-green deployment with gradual traffic migration support
- Section 0.2.5: Feature flag integration for infrastructure updates and environment management
- Section 6.5: Integration with monitoring and observability infrastructure
- Section 4.4: Deployment and migration flows with automated rollback capabilities
- Section 8.1: Environment-specific configuration management across dev/staging/production

Performance Requirements:
- Automated rollback when response time variance >10% from Node.js baseline
- CPU utilization monitoring with rollback triggers >90% sustained utilization
- Health check integration for automated service state management
- Performance correlation analysis for proactive scaling decisions

Migration Phases:
1. INITIALIZATION: Initial setup and baseline establishment
2. CANARY_5_PERCENT: 5% traffic to Flask application with intensive monitoring
3. CANARY_25_PERCENT: 25% traffic progression after validation
4. CANARY_50_PERCENT: 50% traffic with load balancing optimization
5. FULL_MIGRATION: 100% traffic to Flask with Node.js baseline preservation
6. ROLLBACK: Emergency rollback to Node.js baseline with diagnostic preservation

References:
- Section 0.2.3: Deployment considerations with blue-green patterns
- Section 0.2.5: Infrastructure updates with feature flag configuration
- Section 6.5.3: Incident response and rollback procedures
- Section 4.4.5: Error handling and rollback procedures
"""

import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from enum import Enum, IntEnum
from typing import Dict, Any, Optional, List, Union, Callable, Tuple
from dataclasses import dataclass, asdict
from functools import wraps
from threading import Lock, RLock
import threading

import redis
import structlog
from dotenv import load_dotenv
from flask import Flask, request, g, current_app
from prometheus_client import Counter, Histogram, Gauge, Info
import psutil

# Load environment variables
load_dotenv()

# Configure structured logging for feature flag operations
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.LoggerFactory(),
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

# Initialize feature flag audit logger
feature_flag_logger = structlog.get_logger("feature_flags.migration")
performance_logger = structlog.get_logger("performance.monitoring")
rollback_logger = structlog.get_logger("rollback.procedures")


class MigrationPhase(Enum):
    """
    Migration phase enumeration representing the gradual traffic migration progression.
    
    Each phase represents a specific percentage of traffic routed to the Flask application
    with corresponding monitoring and validation requirements.
    """
    INITIALIZATION = "initialization"
    CANARY_5_PERCENT = "canary_5_percent"
    CANARY_25_PERCENT = "canary_25_percent"
    CANARY_50_PERCENT = "canary_50_percent"
    FULL_MIGRATION = "full_migration"
    ROLLBACK = "rollback"
    MAINTENANCE = "maintenance"


class DeploymentStrategy(Enum):
    """
    Deployment strategy enumeration for blue-green deployment pattern support.
    """
    BLUE_GREEN = "blue_green"
    ROLLING_UPDATE = "rolling_update"
    CANARY = "canary"
    FEATURE_FLAG = "feature_flag"


class PerformanceStatus(Enum):
    """
    Performance status enumeration for monitoring and rollback decisions.
    """
    OPTIMAL = "optimal"
    WARNING = "warning"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class RollbackTrigger(Enum):
    """
    Rollback trigger enumeration for automated rollback decision making.
    """
    PERFORMANCE_VARIANCE = "performance_variance"
    CPU_UTILIZATION = "cpu_utilization"
    MEMORY_PRESSURE = "memory_pressure"
    ERROR_RATE = "error_rate"
    HEALTH_CHECK_FAILURE = "health_check_failure"
    MANUAL = "manual"
    CIRCUIT_BREAKER = "circuit_breaker"


@dataclass
class PerformanceThresholds:
    """
    Performance threshold configuration for monitoring and rollback triggers.
    
    Implements the ≤10% variance requirement with appropriate warning and critical thresholds
    for proactive performance management and automated rollback decision making.
    """
    # Response time variance thresholds (percentage)
    response_time_warning_threshold: float = 5.0  # 5% variance warning
    response_time_critical_threshold: float = 10.0  # 10% variance critical (rollback trigger)
    
    # CPU utilization thresholds (percentage)
    cpu_warning_threshold: float = 70.0  # 70% CPU warning
    cpu_critical_threshold: float = 90.0  # 90% CPU critical (rollback trigger)
    
    # Memory utilization thresholds (percentage)
    memory_warning_threshold: float = 80.0  # 80% memory warning
    memory_critical_threshold: float = 95.0  # 95% memory critical (rollback trigger)
    
    # Error rate thresholds (percentage)
    error_rate_warning_threshold: float = 1.0  # 1% error rate warning
    error_rate_critical_threshold: float = 5.0  # 5% error rate critical (rollback trigger)
    
    # Health check failure thresholds (count)
    health_check_failure_warning: int = 3  # 3 consecutive failures warning
    health_check_failure_critical: int = 5  # 5 consecutive failures critical (rollback trigger)
    
    # Performance monitoring intervals (seconds)
    monitoring_interval: int = 30  # 30-second monitoring interval
    rollback_cooldown: int = 300  # 5-minute rollback cooldown period
    
    def to_dict(self) -> Dict[str, Union[float, int]]:
        """Convert thresholds to dictionary for JSON serialization."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Union[float, int]]) -> 'PerformanceThresholds':
        """Create PerformanceThresholds from dictionary."""
        return cls(**data)


@dataclass
class MigrationConfig:
    """
    Migration configuration dataclass containing all feature flag settings and state.
    
    Provides comprehensive configuration for gradual traffic migration with blue-green
    deployment support, performance monitoring integration, and automated rollback capabilities.
    """
    # Migration state
    current_phase: MigrationPhase = MigrationPhase.INITIALIZATION
    deployment_strategy: DeploymentStrategy = DeploymentStrategy.BLUE_GREEN
    traffic_percentage: float = 0.0  # Current percentage of traffic to Flask application
    target_percentage: float = 0.0  # Target percentage for current migration phase
    
    # Performance monitoring
    performance_status: PerformanceStatus = PerformanceStatus.UNKNOWN
    performance_thresholds: PerformanceThresholds = None
    nodejs_baseline_response_time: Optional[float] = None
    flask_average_response_time: Optional[float] = None
    current_variance_percentage: Optional[float] = None
    
    # Environment configuration
    environment: str = "development"
    blue_environment_url: str = ""  # Node.js baseline environment URL
    green_environment_url: str = ""  # Flask application environment URL
    
    # Feature flag settings
    feature_flags_enabled: bool = True
    rollback_enabled: bool = True
    automatic_rollback_enabled: bool = True
    manual_approval_required: bool = False
    
    # Monitoring integration
    prometheus_enabled: bool = True
    health_check_enabled: bool = True
    performance_monitoring_enabled: bool = True
    
    # Rollback configuration
    last_rollback_time: Optional[datetime] = None
    rollback_count: int = 0
    max_rollback_attempts: int = 3
    rollback_triggers: List[RollbackTrigger] = None
    
    # Timestamps
    created_at: datetime = None
    updated_at: datetime = None
    migration_started_at: Optional[datetime] = None
    migration_completed_at: Optional[datetime] = None
    
    def __post_init__(self):
        """Initialize default values and validate configuration."""
        if self.performance_thresholds is None:
            self.performance_thresholds = PerformanceThresholds()
        
        if self.rollback_triggers is None:
            self.rollback_triggers = []
        
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc)
        
        if self.updated_at is None:
            self.updated_at = datetime.now(timezone.utc)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert migration config to dictionary for JSON serialization."""
        data = asdict(self)
        
        # Convert enums to string values
        data['current_phase'] = self.current_phase.value
        data['deployment_strategy'] = self.deployment_strategy.value
        data['performance_status'] = self.performance_status.value
        data['rollback_triggers'] = [trigger.value for trigger in self.rollback_triggers]
        
        # Convert datetime objects to ISO format
        if self.created_at:
            data['created_at'] = self.created_at.isoformat()
        if self.updated_at:
            data['updated_at'] = self.updated_at.isoformat()
        if self.migration_started_at:
            data['migration_started_at'] = self.migration_started_at.isoformat()
        if self.migration_completed_at:
            data['migration_completed_at'] = self.migration_completed_at.isoformat()
        if self.last_rollback_time:
            data['last_rollback_time'] = self.last_rollback_time.isoformat()
        
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MigrationConfig':
        """Create MigrationConfig from dictionary."""
        # Convert string values to enums
        if 'current_phase' in data:
            data['current_phase'] = MigrationPhase(data['current_phase'])
        if 'deployment_strategy' in data:
            data['deployment_strategy'] = DeploymentStrategy(data['deployment_strategy'])
        if 'performance_status' in data:
            data['performance_status'] = PerformanceStatus(data['performance_status'])
        if 'rollback_triggers' in data:
            data['rollback_triggers'] = [RollbackTrigger(trigger) for trigger in data['rollback_triggers']]
        
        # Convert ISO format strings to datetime objects
        datetime_fields = ['created_at', 'updated_at', 'migration_started_at', 'migration_completed_at', 'last_rollback_time']
        for field in datetime_fields:
            if field in data and data[field]:
                data[field] = datetime.fromisoformat(data[field])
        
        # Handle nested PerformanceThresholds
        if 'performance_thresholds' in data and isinstance(data['performance_thresholds'], dict):
            data['performance_thresholds'] = PerformanceThresholds.from_dict(data['performance_thresholds'])
        
        return cls(**data)


class FeatureFlagMetrics:
    """
    Prometheus metrics for feature flag operations and performance monitoring.
    
    Provides comprehensive metrics collection for migration progress, performance variance,
    rollback operations, and system resource utilization monitoring.
    """
    
    def __init__(self):
        """Initialize Prometheus metrics for feature flag monitoring."""
        
        # Migration progress metrics
        self.migration_phase_info = Info(
            'migration_phase_info',
            'Current migration phase and configuration',
            ['environment', 'deployment_strategy']
        )
        
        self.traffic_percentage_gauge = Gauge(
            'migration_traffic_percentage',
            'Current percentage of traffic routed to Flask application',
            ['environment', 'phase']
        )
        
        # Performance monitoring metrics
        self.performance_variance_gauge = Gauge(
            'migration_performance_variance_percentage',
            'Current performance variance from Node.js baseline',
            ['environment', 'metric_type']
        )
        
        self.nodejs_baseline_response_time = Histogram(
            'nodejs_baseline_response_time_seconds',
            'Node.js baseline response time distribution',
            ['endpoint', 'method']
        )
        
        self.flask_response_time = Histogram(
            'flask_response_time_seconds',
            'Flask application response time distribution',
            ['endpoint', 'method']
        )
        
        # System resource metrics
        self.cpu_utilization_gauge = Gauge(
            'migration_cpu_utilization_percentage',
            'Current CPU utilization for migration monitoring',
            ['environment', 'process_type']
        )
        
        self.memory_utilization_gauge = Gauge(
            'migration_memory_utilization_percentage',
            'Current memory utilization for migration monitoring',
            ['environment', 'process_type']
        )
        
        # Rollback operation metrics
        self.rollback_operations_counter = Counter(
            'migration_rollback_operations_total',
            'Total number of rollback operations by trigger',
            ['environment', 'trigger', 'result']
        )
        
        self.rollback_duration_histogram = Histogram(
            'migration_rollback_duration_seconds',
            'Duration of rollback operations',
            ['environment', 'trigger']
        )
        
        # Feature flag operation metrics
        self.feature_flag_operations_counter = Counter(
            'feature_flag_operations_total',
            'Total feature flag operations by type',
            ['operation', 'result', 'environment']
        )
        
        self.feature_flag_evaluation_duration = Histogram(
            'feature_flag_evaluation_duration_seconds',
            'Feature flag evaluation duration',
            ['flag_name', 'environment']
        )
        
        # Health check metrics
        self.health_check_status_gauge = Gauge(
            'migration_health_check_status',
            'Health check status (1=healthy, 0=unhealthy)',
            ['environment', 'check_type']
        )
        
        self.health_check_failure_counter = Counter(
            'migration_health_check_failures_total',
            'Total health check failures by type',
            ['environment', 'check_type', 'failure_reason']
        )


class FeatureFlagConfig:
    """
    Comprehensive feature flag configuration manager for Flask migration.
    
    Implements distributed feature flag management with Redis backend, performance
    monitoring integration, automated rollback capabilities, and enterprise-grade
    observability for gradual traffic migration from Node.js to Flask application.
    """
    
    def __init__(self, environment: str = None):
        """
        Initialize feature flag configuration with environment-specific settings.
        
        Args:
            environment: Deployment environment (development, staging, production)
        """
        self.environment = environment or os.getenv('FLASK_ENV', 'development')
        self._lock = RLock()  # Thread-safe operations
        self._redis_client: Optional[redis.Redis] = None
        self._metrics: Optional[FeatureFlagMetrics] = None
        self._config: Optional[MigrationConfig] = None
        self._performance_monitor_thread: Optional[threading.Thread] = None
        self._monitoring_active = False
        
        # Configuration keys
        self.config_key = f"feature_flags:migration:{self.environment}"
        self.performance_key = f"performance:migration:{self.environment}"
        self.rollback_key = f"rollback:migration:{self.environment}"
        
        # Initialize configuration
        self._initialize_configuration()
        
        # Initialize metrics if Prometheus is enabled
        if self.prometheus_enabled:
            self._metrics = FeatureFlagMetrics()
        
        feature_flag_logger.info(
            "Feature flag configuration initialized",
            environment=self.environment,
            config_key=self.config_key,
            prometheus_enabled=self.prometheus_enabled
        )
    
    def _initialize_configuration(self):
        """Initialize configuration from environment variables with defaults."""
        
        # Redis configuration
        self.redis_host = os.getenv('FEATURE_FLAGS_REDIS_HOST', os.getenv('REDIS_HOST', 'localhost'))
        self.redis_port = int(os.getenv('FEATURE_FLAGS_REDIS_PORT', os.getenv('REDIS_PORT', '6379')))
        self.redis_db = int(os.getenv('FEATURE_FLAGS_REDIS_DB', '2'))  # Separate DB for feature flags
        self.redis_password = os.getenv('FEATURE_FLAGS_REDIS_PASSWORD', os.getenv('REDIS_PASSWORD', None))
        self.redis_ssl = os.getenv('FEATURE_FLAGS_REDIS_SSL', 'false').lower() == 'true'
        
        # Feature flag configuration
        self.feature_flags_enabled = os.getenv('FEATURE_FLAGS_ENABLED', 'true').lower() == 'true'
        self.prometheus_enabled = os.getenv('PROMETHEUS_ENABLED', 'true').lower() == 'true'
        self.automatic_rollback_enabled = os.getenv('AUTOMATIC_ROLLBACK_ENABLED', 'true').lower() == 'true'
        
        # Environment-specific configuration
        if self.environment == 'production':
            self.manual_approval_required = os.getenv('MANUAL_APPROVAL_REQUIRED', 'true').lower() == 'true'
            self.rollback_enabled = True
            self.performance_monitoring_enabled = True
            self.max_rollback_attempts = int(os.getenv('MAX_ROLLBACK_ATTEMPTS', '3'))
        elif self.environment == 'staging':
            self.manual_approval_required = os.getenv('MANUAL_APPROVAL_REQUIRED', 'false').lower() == 'true'
            self.rollback_enabled = True
            self.performance_monitoring_enabled = True
            self.max_rollback_attempts = int(os.getenv('MAX_ROLLBACK_ATTEMPTS', '5'))
        else:  # development
            self.manual_approval_required = False
            self.rollback_enabled = os.getenv('ROLLBACK_ENABLED', 'true').lower() == 'true'
            self.performance_monitoring_enabled = os.getenv('PERFORMANCE_MONITORING_ENABLED', 'false').lower() == 'true'
            self.max_rollback_attempts = int(os.getenv('MAX_ROLLBACK_ATTEMPTS', '10'))
        
        # Environment URLs
        self.blue_environment_url = os.getenv('BLUE_ENVIRONMENT_URL', 'http://localhost:3000')  # Node.js baseline
        self.green_environment_url = os.getenv('GREEN_ENVIRONMENT_URL', 'http://localhost:5000')  # Flask application
        
        # Performance thresholds with environment-specific defaults
        thresholds_config = {}
        if self.environment == 'production':
            thresholds_config = {
                'response_time_warning_threshold': float(os.getenv('RESPONSE_TIME_WARNING_THRESHOLD', '3.0')),
                'response_time_critical_threshold': float(os.getenv('RESPONSE_TIME_CRITICAL_THRESHOLD', '10.0')),
                'cpu_warning_threshold': float(os.getenv('CPU_WARNING_THRESHOLD', '60.0')),
                'cpu_critical_threshold': float(os.getenv('CPU_CRITICAL_THRESHOLD', '80.0')),
                'monitoring_interval': int(os.getenv('MONITORING_INTERVAL', '15')),
            }
        elif self.environment == 'staging':
            thresholds_config = {
                'response_time_warning_threshold': float(os.getenv('RESPONSE_TIME_WARNING_THRESHOLD', '5.0')),
                'response_time_critical_threshold': float(os.getenv('RESPONSE_TIME_CRITICAL_THRESHOLD', '15.0')),
                'cpu_warning_threshold': float(os.getenv('CPU_WARNING_THRESHOLD', '70.0')),
                'cpu_critical_threshold': float(os.getenv('CPU_CRITICAL_THRESHOLD', '90.0')),
                'monitoring_interval': int(os.getenv('MONITORING_INTERVAL', '30')),
            }
        else:  # development
            thresholds_config = {
                'response_time_warning_threshold': float(os.getenv('RESPONSE_TIME_WARNING_THRESHOLD', '10.0')),
                'response_time_critical_threshold': float(os.getenv('RESPONSE_TIME_CRITICAL_THRESHOLD', '25.0')),
                'cpu_warning_threshold': float(os.getenv('CPU_WARNING_THRESHOLD', '80.0')),
                'cpu_critical_threshold': float(os.getenv('CPU_CRITICAL_THRESHOLD', '95.0')),
                'monitoring_interval': int(os.getenv('MONITORING_INTERVAL', '60')),
            }
        
        self.performance_thresholds = PerformanceThresholds(**thresholds_config)
    
    @property
    def redis_client(self) -> redis.Redis:
        """Get Redis client with connection pooling and error handling."""
        if self._redis_client is None:
            try:
                self._redis_client = redis.Redis(
                    host=self.redis_host,
                    port=self.redis_port,
                    db=self.redis_db,
                    password=self.redis_password,
                    ssl=self.redis_ssl,
                    decode_responses=True,
                    socket_timeout=5,
                    socket_connect_timeout=5,
                    retry_on_timeout=True,
                    max_connections=10,
                    health_check_interval=30
                )
                
                # Test connection
                self._redis_client.ping()
                
                feature_flag_logger.info(
                    "Redis connection established",
                    host=self.redis_host,
                    port=self.redis_port,
                    db=self.redis_db,
                    environment=self.environment
                )
                
            except (redis.ConnectionError, redis.TimeoutError) as e:
                feature_flag_logger.error(
                    "Failed to connect to Redis",
                    error=str(e),
                    host=self.redis_host,
                    port=self.redis_port,
                    environment=self.environment
                )
                raise ConnectionError(f"Failed to connect to Redis: {e}")
        
        return self._redis_client
    
    def get_migration_config(self) -> MigrationConfig:
        """
        Get current migration configuration from Redis with fallback to defaults.
        
        Returns:
            Current migration configuration
        """
        with self._lock:
            try:
                if not self.feature_flags_enabled:
                    # Return default configuration when feature flags are disabled
                    return MigrationConfig(
                        environment=self.environment,
                        feature_flags_enabled=False,
                        performance_thresholds=self.performance_thresholds
                    )
                
                # Attempt to load configuration from Redis
                config_data = self.redis_client.get(self.config_key)
                
                if config_data:
                    config_dict = json.loads(config_data)
                    self._config = MigrationConfig.from_dict(config_dict)
                    
                    feature_flag_logger.debug(
                        "Migration configuration loaded from Redis",
                        phase=self._config.current_phase.value,
                        traffic_percentage=self._config.traffic_percentage,
                        environment=self.environment
                    )
                else:
                    # Initialize default configuration
                    self._config = MigrationConfig(
                        environment=self.environment,
                        blue_environment_url=self.blue_environment_url,
                        green_environment_url=self.green_environment_url,
                        feature_flags_enabled=self.feature_flags_enabled,
                        rollback_enabled=self.rollback_enabled,
                        automatic_rollback_enabled=self.automatic_rollback_enabled,
                        manual_approval_required=self.manual_approval_required,
                        prometheus_enabled=self.prometheus_enabled,
                        performance_monitoring_enabled=self.performance_monitoring_enabled,
                        performance_thresholds=self.performance_thresholds,
                        max_rollback_attempts=self.max_rollback_attempts
                    )
                    
                    # Save default configuration to Redis
                    self.save_migration_config(self._config)
                    
                    feature_flag_logger.info(
                        "Default migration configuration created",
                        environment=self.environment,
                        phase=self._config.current_phase.value
                    )
                
                # Update metrics if enabled
                if self._metrics:
                    self._update_metrics()
                
                return self._config
                
            except (redis.ConnectionError, json.JSONDecodeError) as e:
                feature_flag_logger.error(
                    "Failed to load migration configuration",
                    error=str(e),
                    environment=self.environment
                )
                
                # Return cached configuration or default
                if self._config:
                    return self._config
                
                return MigrationConfig(
                    environment=self.environment,
                    performance_thresholds=self.performance_thresholds
                )
    
    def save_migration_config(self, config: MigrationConfig) -> bool:
        """
        Save migration configuration to Redis with audit logging.
        
        Args:
            config: Migration configuration to save
            
        Returns:
            True if successful, False otherwise
        """
        with self._lock:
            try:
                if not self.feature_flags_enabled:
                    feature_flag_logger.warning(
                        "Attempted to save configuration with feature flags disabled",
                        environment=self.environment
                    )
                    return False
                
                # Update timestamp
                config.updated_at = datetime.now(timezone.utc)
                
                # Serialize configuration
                config_data = json.dumps(config.to_dict(), indent=2)
                
                # Save to Redis with expiration
                expiration_seconds = 86400 * 7  # 7 days
                success = self.redis_client.setex(
                    self.config_key,
                    expiration_seconds,
                    config_data
                )
                
                if success:
                    self._config = config
                    
                    feature_flag_logger.info(
                        "Migration configuration saved",
                        phase=config.current_phase.value,
                        traffic_percentage=config.traffic_percentage,
                        performance_status=config.performance_status.value,
                        environment=self.environment
                    )
                    
                    # Update metrics
                    if self._metrics:
                        self._update_metrics()
                    
                    # Record feature flag operation
                    if self._metrics:
                        self._metrics.feature_flag_operations_counter.labels(
                            operation='save_config',
                            result='success',
                            environment=self.environment
                        ).inc()
                    
                    return True
                else:
                    feature_flag_logger.error(
                        "Failed to save migration configuration to Redis",
                        environment=self.environment
                    )
                    return False
                
            except (redis.ConnectionError, json.JSONEncodeError) as e:
                feature_flag_logger.error(
                    "Error saving migration configuration",
                    error=str(e),
                    environment=self.environment
                )
                
                if self._metrics:
                    self._metrics.feature_flag_operations_counter.labels(
                        operation='save_config',
                        result='error',
                        environment=self.environment
                    ).inc()
                
                return False
    
    def advance_migration_phase(self, target_phase: MigrationPhase, manual_approval: bool = False) -> bool:
        """
        Advance migration to the next phase with validation and safety checks.
        
        Args:
            target_phase: Target migration phase
            manual_approval: Whether manual approval was provided
            
        Returns:
            True if phase advancement was successful, False otherwise
        """
        with self._lock:
            config = self.get_migration_config()
            
            # Validate phase transition
            if not self._validate_phase_transition(config.current_phase, target_phase):
                feature_flag_logger.warning(
                    "Invalid phase transition attempted",
                    current_phase=config.current_phase.value,
                    target_phase=target_phase.value,
                    environment=self.environment
                )
                return False
            
            # Check manual approval requirement
            if config.manual_approval_required and not manual_approval:
                feature_flag_logger.warning(
                    "Manual approval required for phase advancement",
                    current_phase=config.current_phase.value,
                    target_phase=target_phase.value,
                    environment=self.environment
                )
                return False
            
            # Check performance status
            if config.performance_status == PerformanceStatus.CRITICAL:
                feature_flag_logger.error(
                    "Cannot advance phase with critical performance status",
                    current_phase=config.current_phase.value,
                    target_phase=target_phase.value,
                    performance_status=config.performance_status.value,
                    environment=self.environment
                )
                return False
            
            # Update configuration
            previous_phase = config.current_phase
            config.current_phase = target_phase
            config.traffic_percentage = self._get_traffic_percentage_for_phase(target_phase)
            config.target_percentage = config.traffic_percentage
            
            if target_phase != MigrationPhase.ROLLBACK and config.migration_started_at is None:
                config.migration_started_at = datetime.now(timezone.utc)
            
            if target_phase == MigrationPhase.FULL_MIGRATION:
                config.migration_completed_at = datetime.now(timezone.utc)
            
            # Save updated configuration
            if self.save_migration_config(config):
                feature_flag_logger.info(
                    "Migration phase advanced successfully",
                    previous_phase=previous_phase.value,
                    new_phase=target_phase.value,
                    traffic_percentage=config.traffic_percentage,
                    manual_approval=manual_approval,
                    environment=self.environment
                )
                return True
            else:
                feature_flag_logger.error(
                    "Failed to save configuration after phase advancement",
                    target_phase=target_phase.value,
                    environment=self.environment
                )
                return False
    
    def trigger_rollback(self, trigger: RollbackTrigger, reason: str = None, manual: bool = False) -> bool:
        """
        Trigger immediate rollback to Node.js baseline with comprehensive logging.
        
        Args:
            trigger: Rollback trigger type
            reason: Optional reason for rollback
            manual: Whether rollback was manually initiated
            
        Returns:
            True if rollback was successful, False otherwise
        """
        rollback_start_time = time.time()
        
        with self._lock:
            config = self.get_migration_config()
            
            # Check rollback eligibility
            if not config.rollback_enabled:
                rollback_logger.warning(
                    "Rollback attempted but rollback is disabled",
                    trigger=trigger.value,
                    reason=reason,
                    environment=self.environment
                )
                return False
            
            # Check rollback cooldown
            if (config.last_rollback_time and 
                datetime.now(timezone.utc) - config.last_rollback_time < 
                timedelta(seconds=config.performance_thresholds.rollback_cooldown)):
                
                rollback_logger.warning(
                    "Rollback attempted during cooldown period",
                    trigger=trigger.value,
                    reason=reason,
                    last_rollback=config.last_rollback_time.isoformat(),
                    environment=self.environment
                )
                return False
            
            # Check maximum rollback attempts
            if config.rollback_count >= config.max_rollback_attempts:
                rollback_logger.error(
                    "Maximum rollback attempts exceeded",
                    trigger=trigger.value,
                    reason=reason,
                    rollback_count=config.rollback_count,
                    max_attempts=config.max_rollback_attempts,
                    environment=self.environment
                )
                return False
            
            # Check automatic rollback eligibility
            if not manual and not config.automatic_rollback_enabled:
                rollback_logger.warning(
                    "Automatic rollback attempted but automatic rollback is disabled",
                    trigger=trigger.value,
                    reason=reason,
                    environment=self.environment
                )
                return False
            
            # Record rollback trigger
            if trigger not in config.rollback_triggers:
                config.rollback_triggers.append(trigger)
            
            # Update configuration for rollback
            previous_phase = config.current_phase
            config.current_phase = MigrationPhase.ROLLBACK
            config.traffic_percentage = 0.0  # All traffic to Node.js baseline
            config.target_percentage = 0.0
            config.performance_status = PerformanceStatus.UNKNOWN
            config.last_rollback_time = datetime.now(timezone.utc)
            config.rollback_count += 1
            
            # Save rollback configuration
            if self.save_migration_config(config):
                rollback_duration = time.time() - rollback_start_time
                
                rollback_logger.critical(
                    "Rollback executed successfully",
                    trigger=trigger.value,
                    reason=reason,
                    previous_phase=previous_phase.value,
                    rollback_count=config.rollback_count,
                    rollback_duration=rollback_duration,
                    manual=manual,
                    environment=self.environment
                )
                
                # Update metrics
                if self._metrics:
                    self._metrics.rollback_operations_counter.labels(
                        environment=self.environment,
                        trigger=trigger.value,
                        result='success'
                    ).inc()
                    
                    self._metrics.rollback_duration_histogram.labels(
                        environment=self.environment,
                        trigger=trigger.value
                    ).observe(rollback_duration)
                
                # Store rollback details in Redis for audit
                self._store_rollback_audit(trigger, reason, manual, previous_phase, rollback_duration)
                
                return True
            else:
                rollback_logger.error(
                    "Failed to save rollback configuration",
                    trigger=trigger.value,
                    reason=reason,
                    environment=self.environment
                )
                
                if self._metrics:
                    self._metrics.rollback_operations_counter.labels(
                        environment=self.environment,
                        trigger=trigger.value,
                        result='failure'
                    ).inc()
                
                return False
    
    def update_performance_status(self, response_time: float = None, cpu_utilization: float = None, 
                                memory_utilization: float = None, error_rate: float = None) -> PerformanceStatus:
        """
        Update performance status based on current metrics and determine if rollback is needed.
        
        Args:
            response_time: Current response time in milliseconds
            cpu_utilization: Current CPU utilization percentage
            memory_utilization: Current memory utilization percentage
            error_rate: Current error rate percentage
            
        Returns:
            Updated performance status
        """
        with self._lock:
            config = self.get_migration_config()
            
            # Calculate performance variance if baseline is available
            variance_percentage = None
            if response_time and config.nodejs_baseline_response_time:
                variance_percentage = ((response_time - config.nodejs_baseline_response_time) / 
                                     config.nodejs_baseline_response_time) * 100.0
                config.current_variance_percentage = variance_percentage
                config.flask_average_response_time = response_time
            
            # Determine performance status
            status = PerformanceStatus.OPTIMAL
            rollback_triggers = []
            
            # Check response time variance
            if variance_percentage is not None:
                if variance_percentage > config.performance_thresholds.response_time_critical_threshold:
                    status = PerformanceStatus.CRITICAL
                    rollback_triggers.append(RollbackTrigger.PERFORMANCE_VARIANCE)
                elif variance_percentage > config.performance_thresholds.response_time_warning_threshold:
                    if status == PerformanceStatus.OPTIMAL:
                        status = PerformanceStatus.WARNING
            
            # Check CPU utilization
            if cpu_utilization is not None:
                if cpu_utilization > config.performance_thresholds.cpu_critical_threshold:
                    status = PerformanceStatus.CRITICAL
                    rollback_triggers.append(RollbackTrigger.CPU_UTILIZATION)
                elif cpu_utilization > config.performance_thresholds.cpu_warning_threshold:
                    if status == PerformanceStatus.OPTIMAL:
                        status = PerformanceStatus.WARNING
            
            # Check memory utilization
            if memory_utilization is not None:
                if memory_utilization > config.performance_thresholds.memory_critical_threshold:
                    status = PerformanceStatus.CRITICAL
                    rollback_triggers.append(RollbackTrigger.MEMORY_PRESSURE)
                elif memory_utilization > config.performance_thresholds.memory_warning_threshold:
                    if status == PerformanceStatus.OPTIMAL:
                        status = PerformanceStatus.WARNING
            
            # Check error rate
            if error_rate is not None:
                if error_rate > config.performance_thresholds.error_rate_critical_threshold:
                    status = PerformanceStatus.CRITICAL
                    rollback_triggers.append(RollbackTrigger.ERROR_RATE)
                elif error_rate > config.performance_thresholds.error_rate_warning_threshold:
                    if status == PerformanceStatus.OPTIMAL:
                        status = PerformanceStatus.WARNING
            
            # Update configuration
            config.performance_status = status
            
            # Log performance update
            performance_logger.info(
                "Performance status updated",
                status=status.value,
                response_time=response_time,
                variance_percentage=variance_percentage,
                cpu_utilization=cpu_utilization,
                memory_utilization=memory_utilization,
                error_rate=error_rate,
                environment=self.environment
            )
            
            # Update metrics
            if self._metrics:
                if variance_percentage is not None:
                    self._metrics.performance_variance_gauge.labels(
                        environment=self.environment,
                        metric_type='response_time'
                    ).set(variance_percentage)
                
                if cpu_utilization is not None:
                    self._metrics.cpu_utilization_gauge.labels(
                        environment=self.environment,
                        process_type='flask'
                    ).set(cpu_utilization)
                
                if memory_utilization is not None:
                    self._metrics.memory_utilization_gauge.labels(
                        environment=self.environment,
                        process_type='flask'
                    ).set(memory_utilization)
            
            # Trigger automatic rollback if status is critical
            if (status == PerformanceStatus.CRITICAL and 
                config.automatic_rollback_enabled and 
                rollback_triggers):
                
                # Select primary rollback trigger
                primary_trigger = rollback_triggers[0]
                
                rollback_reason = f"Automatic rollback triggered by {primary_trigger.value}"
                if variance_percentage:
                    rollback_reason += f" (variance: {variance_percentage:.2f}%)"
                if cpu_utilization:
                    rollback_reason += f" (CPU: {cpu_utilization:.1f}%)"
                if memory_utilization:
                    rollback_reason += f" (Memory: {memory_utilization:.1f}%)"
                if error_rate:
                    rollback_reason += f" (Error rate: {error_rate:.2f}%)"
                
                performance_logger.critical(
                    "Critical performance status detected, triggering automatic rollback",
                    triggers=rollback_triggers,
                    reason=rollback_reason,
                    environment=self.environment
                )
                
                # Execute rollback
                self.trigger_rollback(primary_trigger, rollback_reason, manual=False)
            
            # Save updated configuration
            self.save_migration_config(config)
            
            return status
    
    def get_traffic_routing_config(self) -> Dict[str, Any]:
        """
        Get current traffic routing configuration for load balancer integration.
        
        Returns:
            Traffic routing configuration dictionary
        """
        config = self.get_migration_config()
        
        return {
            'environment': self.environment,
            'phase': config.current_phase.value,
            'traffic_percentage': config.traffic_percentage,
            'flask_weight': config.traffic_percentage,
            'nodejs_weight': 100.0 - config.traffic_percentage,
            'blue_environment_url': config.blue_environment_url,
            'green_environment_url': config.green_environment_url,
            'deployment_strategy': config.deployment_strategy.value,
            'performance_status': config.performance_status.value,
            'rollback_enabled': config.rollback_enabled,
            'health_check_enabled': config.health_check_enabled,
            'updated_at': config.updated_at.isoformat() if config.updated_at else None
        }
    
    def start_performance_monitoring(self):
        """Start background performance monitoring thread."""
        if not self.performance_monitoring_enabled or self._monitoring_active:
            return
        
        self._monitoring_active = True
        self._performance_monitor_thread = threading.Thread(
            target=self._performance_monitoring_loop,
            daemon=True,
            name=f"performance-monitor-{self.environment}"
        )
        self._performance_monitor_thread.start()
        
        feature_flag_logger.info(
            "Performance monitoring started",
            environment=self.environment,
            monitoring_interval=self.performance_thresholds.monitoring_interval
        )
    
    def stop_performance_monitoring(self):
        """Stop background performance monitoring thread."""
        self._monitoring_active = False
        if self._performance_monitor_thread and self._performance_monitor_thread.is_alive():
            self._performance_monitor_thread.join(timeout=5)
        
        feature_flag_logger.info(
            "Performance monitoring stopped",
            environment=self.environment
        )
    
    def _performance_monitoring_loop(self):
        """Background performance monitoring loop."""
        while self._monitoring_active:
            try:
                # Collect system metrics
                cpu_utilization = psutil.cpu_percent(interval=1)
                memory_info = psutil.virtual_memory()
                memory_utilization = memory_info.percent
                
                # Update performance status
                self.update_performance_status(
                    cpu_utilization=cpu_utilization,
                    memory_utilization=memory_utilization
                )
                
                # Sleep until next monitoring interval
                time.sleep(self.performance_thresholds.monitoring_interval)
                
            except Exception as e:
                performance_logger.error(
                    "Error in performance monitoring loop",
                    error=str(e),
                    environment=self.environment
                )
                time.sleep(self.performance_thresholds.monitoring_interval)
    
    def _validate_phase_transition(self, current_phase: MigrationPhase, target_phase: MigrationPhase) -> bool:
        """
        Validate that the phase transition is allowed.
        
        Args:
            current_phase: Current migration phase
            target_phase: Target migration phase
            
        Returns:
            True if transition is valid, False otherwise
        """
        valid_transitions = {
            MigrationPhase.INITIALIZATION: [
                MigrationPhase.CANARY_5_PERCENT,
                MigrationPhase.MAINTENANCE
            ],
            MigrationPhase.CANARY_5_PERCENT: [
                MigrationPhase.CANARY_25_PERCENT,
                MigrationPhase.ROLLBACK,
                MigrationPhase.MAINTENANCE
            ],
            MigrationPhase.CANARY_25_PERCENT: [
                MigrationPhase.CANARY_50_PERCENT,
                MigrationPhase.ROLLBACK,
                MigrationPhase.MAINTENANCE
            ],
            MigrationPhase.CANARY_50_PERCENT: [
                MigrationPhase.FULL_MIGRATION,
                MigrationPhase.ROLLBACK,
                MigrationPhase.MAINTENANCE
            ],
            MigrationPhase.FULL_MIGRATION: [
                MigrationPhase.ROLLBACK,
                MigrationPhase.MAINTENANCE
            ],
            MigrationPhase.ROLLBACK: [
                MigrationPhase.INITIALIZATION,
                MigrationPhase.CANARY_5_PERCENT,
                MigrationPhase.MAINTENANCE
            ],
            MigrationPhase.MAINTENANCE: [
                MigrationPhase.INITIALIZATION,
                MigrationPhase.CANARY_5_PERCENT,
                MigrationPhase.CANARY_25_PERCENT,
                MigrationPhase.CANARY_50_PERCENT,
                MigrationPhase.FULL_MIGRATION,
                MigrationPhase.ROLLBACK
            ]
        }
        
        return target_phase in valid_transitions.get(current_phase, [])
    
    def _get_traffic_percentage_for_phase(self, phase: MigrationPhase) -> float:
        """
        Get traffic percentage for a given migration phase.
        
        Args:
            phase: Migration phase
            
        Returns:
            Traffic percentage for the phase
        """
        phase_percentages = {
            MigrationPhase.INITIALIZATION: 0.0,
            MigrationPhase.CANARY_5_PERCENT: 5.0,
            MigrationPhase.CANARY_25_PERCENT: 25.0,
            MigrationPhase.CANARY_50_PERCENT: 50.0,
            MigrationPhase.FULL_MIGRATION: 100.0,
            MigrationPhase.ROLLBACK: 0.0,
            MigrationPhase.MAINTENANCE: 0.0
        }
        
        return phase_percentages.get(phase, 0.0)
    
    def _update_metrics(self):
        """Update Prometheus metrics with current configuration."""
        if not self._metrics or not self._config:
            return
        
        try:
            # Update migration phase info
            self._metrics.migration_phase_info.labels(
                environment=self.environment,
                deployment_strategy=self._config.deployment_strategy.value
            ).info({
                'phase': self._config.current_phase.value,
                'traffic_percentage': str(self._config.traffic_percentage),
                'performance_status': self._config.performance_status.value,
                'rollback_count': str(self._config.rollback_count)
            })
            
            # Update traffic percentage gauge
            self._metrics.traffic_percentage_gauge.labels(
                environment=self.environment,
                phase=self._config.current_phase.value
            ).set(self._config.traffic_percentage)
            
            # Update health check status
            health_status = 1 if self._config.performance_status != PerformanceStatus.CRITICAL else 0
            self._metrics.health_check_status_gauge.labels(
                environment=self.environment,
                check_type='performance'
            ).set(health_status)
            
        except Exception as e:
            feature_flag_logger.error(
                "Error updating metrics",
                error=str(e),
                environment=self.environment
            )
    
    def _store_rollback_audit(self, trigger: RollbackTrigger, reason: str, manual: bool, 
                             previous_phase: MigrationPhase, duration: float):
        """
        Store rollback audit information in Redis for compliance and analysis.
        
        Args:
            trigger: Rollback trigger type
            reason: Rollback reason
            manual: Whether rollback was manual
            previous_phase: Previous migration phase
            duration: Rollback duration in seconds
        """
        try:
            audit_data = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'environment': self.environment,
                'trigger': trigger.value,
                'reason': reason,
                'manual': manual,
                'previous_phase': previous_phase.value,
                'duration_seconds': duration,
                'config_key': self.config_key
            }
            
            # Store with timestamp-based key for historical tracking
            audit_key = f"{self.rollback_key}:{int(time.time())}"
            
            self.redis_client.setex(
                audit_key,
                86400 * 30,  # 30 days retention
                json.dumps(audit_data)
            )
            
        except Exception as e:
            rollback_logger.error(
                "Failed to store rollback audit data",
                error=str(e),
                environment=self.environment
            )
    
    def get_rollback_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get rollback history for audit and analysis.
        
        Args:
            limit: Maximum number of rollback records to return
            
        Returns:
            List of rollback audit records
        """
        try:
            pattern = f"{self.rollback_key}:*"
            keys = self.redis_client.keys(pattern)
            
            # Sort keys by timestamp (newest first)
            keys.sort(reverse=True)
            
            rollback_history = []
            for key in keys[:limit]:
                try:
                    data = self.redis_client.get(key)
                    if data:
                        rollback_history.append(json.loads(data))
                except (json.JSONDecodeError, redis.ConnectionError):
                    continue
            
            return rollback_history
            
        except Exception as e:
            feature_flag_logger.error(
                "Error retrieving rollback history",
                error=str(e),
                environment=self.environment
            )
            return []
    
    def cleanup_expired_data(self):
        """Clean up expired feature flag data and audit records."""
        try:
            # Clean up old rollback audit records (older than 30 days)
            pattern = f"{self.rollback_key}:*"
            keys = self.redis_client.keys(pattern)
            
            cutoff_timestamp = int(time.time()) - (86400 * 30)  # 30 days ago
            
            for key in keys:
                try:
                    # Extract timestamp from key
                    timestamp_str = key.split(':')[-1]
                    if timestamp_str.isdigit():
                        timestamp = int(timestamp_str)
                        if timestamp < cutoff_timestamp:
                            self.redis_client.delete(key)
                except (ValueError, IndexError):
                    continue
            
            feature_flag_logger.info(
                "Feature flag data cleanup completed",
                environment=self.environment,
                cleaned_keys=len([k for k in keys if k.split(':')[-1].isdigit() and 
                                int(k.split(':')[-1]) < cutoff_timestamp])
            )
            
        except Exception as e:
            feature_flag_logger.error(
                "Error during feature flag data cleanup",
                error=str(e),
                environment=self.environment
            )


# Global feature flag configuration instance
_feature_flag_config: Optional[FeatureFlagConfig] = None
_config_lock = Lock()


def get_feature_flag_config(environment: str = None) -> FeatureFlagConfig:
    """
    Get global feature flag configuration instance with thread-safe initialization.
    
    Args:
        environment: Optional environment override
        
    Returns:
        Feature flag configuration instance
    """
    global _feature_flag_config
    
    with _config_lock:
        if _feature_flag_config is None:
            _feature_flag_config = FeatureFlagConfig(environment)
        
        return _feature_flag_config


def init_feature_flags(app: Flask):
    """
    Initialize feature flags with Flask application integration.
    
    Args:
        app: Flask application instance
    """
    environment = app.config.get('FLASK_ENV', 'development')
    
    # Initialize feature flag configuration
    feature_config = get_feature_flag_config(environment)
    
    # Store in app config for access throughout application
    app.config['FEATURE_FLAG_CONFIG'] = feature_config
    
    # Start performance monitoring if enabled
    if feature_config.performance_monitoring_enabled:
        feature_config.start_performance_monitoring()
    
    feature_flag_logger.info(
        "Feature flags initialized with Flask application",
        environment=environment,
        feature_flags_enabled=feature_config.feature_flags_enabled,
        performance_monitoring=feature_config.performance_monitoring_enabled
    )
    
    # Register cleanup function
    @app.teardown_appcontext
    def cleanup_feature_flags(error):
        """Clean up feature flag resources on application context teardown."""
        if error:
            feature_flag_logger.error(
                "Application context teardown with error",
                error=str(error),
                environment=environment
            )


def feature_flag_required(flag_name: str):
    """
    Decorator to require specific feature flag for endpoint access.
    
    Args:
        flag_name: Name of the feature flag to check
        
    Returns:
        Decorator function
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            feature_config = get_feature_flag_config()
            
            if not feature_config.feature_flags_enabled:
                return jsonify({
                    'error': 'Feature flags are disabled',
                    'status': 'feature_disabled'
                }), 503
            
            config = feature_config.get_migration_config()
            
            # Check if we're in rollback mode
            if config.current_phase == MigrationPhase.ROLLBACK:
                return jsonify({
                    'error': 'System is in rollback mode',
                    'status': 'rollback_active',
                    'message': 'Please try again later'
                }), 503
            
            # Check performance status
            if config.performance_status == PerformanceStatus.CRITICAL:
                return jsonify({
                    'error': 'System performance is critical',
                    'status': 'performance_critical',
                    'message': 'Service temporarily unavailable'
                }), 503
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


# Export key classes and functions for external use
__all__ = [
    'FeatureFlagConfig',
    'MigrationPhase',
    'DeploymentStrategy', 
    'PerformanceStatus',
    'RollbackTrigger',
    'PerformanceThresholds',
    'MigrationConfig',
    'FeatureFlagMetrics',
    'get_feature_flag_config',
    'init_feature_flags',
    'feature_flag_required'
]