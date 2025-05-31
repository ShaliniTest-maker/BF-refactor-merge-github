"""
Historical Performance Data Management Module

This module provides comprehensive historical performance data storage, retrieval, archival,
and analysis capabilities for the Flask migration project. Maintains comprehensive performance
history for trend analysis, long-term optimization, and compliance with enterprise data retention
policies per Section 8.6.5 and historical trend analysis per Section 6.6.3.

Key Features:
- Historical performance data storage and management per Section 6.6.3
- Data retention and archival policies per Section 8.6.5 (90-day active retention)
- Performance data aggregation and analysis per Section 6.5.5 improvement tracking
- Data compression and optimization per Section 6.5.5 continuous optimization
- Data integrity validation and backup procedures per Section 8.6.5 audit framework
- Automated data cleanup and maintenance per Section 8.6.5 compliance data classification

Architecture Integration:
- Section 6.6.3: Historical trend analysis reporting with quarterly assessment reviews
- Section 8.6.5: Log retention and archival policies with AWS S3 long-term storage
- Section 6.5.5: APM sampling optimization and performance impact reduction tracking
- Section 6.5.5: Continuous optimization tracking with metrics collection efficiency

Performance Requirements:
- Maintains ≤10% variance tracking history per Section 0.1.1 primary objective
- Supports quarterly trend analysis and assessment reviews per Section 6.6.3
- Implements automated archival to AWS S3 per Section 8.6.5
- Provides compliance data classification per Section 8.6.5

Author: Flask Migration Team
Version: 1.0.0
Dependencies: tests/performance/baseline_data.py, tests/performance/performance_config.py
"""

import asyncio
import gzip
import hashlib
import json
import logging
import statistics
import threading
import warnings
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union, NamedTuple, Callable
from dataclasses import dataclass, field, asdict
import concurrent.futures
import sqlite3
import uuid
import pickle
import zlib

# Performance testing framework integration
from tests.performance.baseline_data import (
    NodeJSPerformanceBaseline,
    BaselineDataManager,
    BaselineDataSource,
    BaselineValidationStatus,
    get_baseline_manager,
    get_nodejs_baseline
)
from tests.performance.performance_config import (
    PerformanceTestConfig,
    PerformanceConfigFactory,
    LoadTestScenario,
    PerformanceMetricType,
    NodeJSBaselineMetrics,
    create_performance_config
)

# Structured logging for historical data tracking
try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False
    warnings.warn("structlog not available - falling back to standard logging")

# Prometheus metrics integration for historical tracking
try:
    from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge, Info
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    warnings.warn("prometheus_client not available - metrics collection disabled")

# AWS S3 integration for archival storage
try:
    import boto3
    from botocore.exceptions import ClientError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False
    warnings.warn("boto3 not available - AWS S3 archival disabled")

# Data compression and serialization
try:
    import lz4.frame
    LZ4_AVAILABLE = True
except ImportError:
    LZ4_AVAILABLE = False
    warnings.warn("lz4 not available - using gzip compression")


class DataRetentionLevel(Enum):
    """Data retention levels with associated retention periods per Section 8.6.5."""
    
    DEBUG = "debug"           # 7 days retention
    INFO = "info"             # 30 days retention  
    WARNING = "warning"       # 60 days retention
    ERROR = "error"           # 90 days retention
    CRITICAL = "critical"     # 365 days retention
    COMPLIANCE = "compliance" # 7 years retention
    AUDIT = "audit"          # 10 years retention


class DataCompressionType(Enum):
    """Data compression algorithms for historical data optimization."""
    
    NONE = "none"
    GZIP = "gzip"
    LZ4 = "lz4"
    ZLIB = "zlib"


class ArchivalStatus(Enum):
    """Data archival status tracking."""
    
    ACTIVE = "active"           # Data in primary storage
    ARCHIVED = "archived"       # Data archived to S3
    COMPRESSED = "compressed"   # Data compressed but not archived
    FAILED = "failed"          # Archival failed
    SCHEDULED = "scheduled"     # Scheduled for archival


class TrendAnalysisType(Enum):
    """Types of trend analysis for historical data."""
    
    PERFORMANCE_VARIANCE = "performance_variance"
    RESPONSE_TIME_TREND = "response_time_trend"
    THROUGHPUT_TREND = "throughput_trend"
    ERROR_RATE_TREND = "error_rate_trend"
    RESOURCE_UTILIZATION = "resource_utilization"
    BASELINE_DRIFT = "baseline_drift"
    REGRESSION_DETECTION = "regression_detection"
    SEASONAL_PATTERNS = "seasonal_patterns"


@dataclass
class RetentionPolicy:
    """Data retention policy configuration per Section 8.6.5."""
    
    level: DataRetentionLevel
    retention_days: int
    compression_enabled: bool = True
    compression_type: DataCompressionType = DataCompressionType.LZ4
    archival_enabled: bool = True
    archival_threshold_days: int = field(init=False)
    compliance_classification: Optional[str] = None
    
    def __post_init__(self):
        """Calculate archival threshold based on retention level."""
        # Archive data after 50% of retention period
        self.archival_threshold_days = max(1, self.retention_days // 2)


@dataclass
class HistoricalDataPoint:
    """Single historical performance data point with metadata."""
    
    # Core identification
    data_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Performance metrics
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    baseline_comparison: Dict[str, Any] = field(default_factory=dict)
    variance_percentage: Optional[float] = None
    
    # Test configuration context
    test_scenario: Optional[str] = None
    environment: str = "production"
    flask_version: str = "2.3.0"
    python_version: str = "3.11"
    
    # Data classification and retention
    retention_level: DataRetentionLevel = DataRetentionLevel.INFO
    compliance_tags: List[str] = field(default_factory=list)
    
    # Storage and archival metadata
    compression_type: DataCompressionType = DataCompressionType.NONE
    archival_status: ArchivalStatus = ArchivalStatus.ACTIVE
    s3_key: Optional[str] = None
    data_size_bytes: int = 0
    compressed_size_bytes: int = 0
    
    # Data integrity
    data_hash: str = field(default="", init=False)
    validation_status: str = "valid"
    
    def __post_init__(self):
        """Post-initialization processing and validation."""
        self._calculate_data_hash()
        self._validate_data_integrity()
        self._apply_compliance_classification()
    
    def _calculate_data_hash(self) -> None:
        """Calculate SHA-256 hash for data integrity validation."""
        hash_data = {
            "timestamp": self.timestamp.isoformat(),
            "performance_metrics": self.performance_metrics,
            "baseline_comparison": self.baseline_comparison,
            "test_scenario": self.test_scenario,
            "environment": self.environment
        }
        
        hash_string = json.dumps(hash_data, sort_keys=True, separators=(',', ':'))
        self.data_hash = hashlib.sha256(hash_string.encode('utf-8')).hexdigest()
    
    def _validate_data_integrity(self) -> None:
        """Validate data integrity and consistency."""
        try:
            # Validate timestamp
            if not isinstance(self.timestamp, datetime):
                self.validation_status = "invalid_timestamp"
                return
            
            # Validate performance metrics
            if not self.performance_metrics:
                self.validation_status = "missing_metrics"
                return
            
            # Validate numeric values
            for key, value in self.performance_metrics.items():
                if not isinstance(value, (int, float)) or value < 0:
                    self.validation_status = f"invalid_metric_{key}"
                    return
            
            # Validate variance percentage if present
            if self.variance_percentage is not None:
                if not isinstance(self.variance_percentage, (int, float)):
                    self.validation_status = "invalid_variance"
                    return
            
            self.validation_status = "valid"
            
        except Exception as e:
            self.validation_status = f"validation_error: {str(e)}"
    
    def _apply_compliance_classification(self) -> None:
        """Apply compliance classification per Section 8.6.5."""
        # Clear existing tags
        self.compliance_tags = []
        
        # Performance metrics classification
        if self.performance_metrics:
            self.compliance_tags.append("performance_data")
        
        # Environment classification
        if self.environment == "production":
            self.compliance_tags.append("production_data")
            self.compliance_tags.append("audit_required")
        
        # Error data classification
        if "error_rate" in self.performance_metrics:
            if self.performance_metrics["error_rate"] > 1.0:
                self.compliance_tags.append("high_error_rate")
                self.retention_level = DataRetentionLevel.ERROR
        
        # Performance variance classification
        if self.variance_percentage is not None:
            if abs(self.variance_percentage) > 10.0:  # Exceeds ≤10% threshold
                self.compliance_tags.append("variance_violation")
                self.retention_level = DataRetentionLevel.WARNING
        
        # Baseline comparison classification
        if self.baseline_comparison:
            self.compliance_tags.append("baseline_comparison")
            if not self.baseline_comparison.get("overall_compliant", True):
                self.compliance_tags.append("compliance_violation")
                self.retention_level = DataRetentionLevel.ERROR
        
        # GDPR compliance (if applicable)
        if any("user" in key.lower() for key in self.performance_metrics.keys()):
            self.compliance_tags.append("gdpr_relevant")
        
        # SOX compliance for financial data
        if self.environment == "production" and "transaction" in str(self.performance_metrics):
            self.compliance_tags.append("sox_compliance")
            self.retention_level = DataRetentionLevel.COMPLIANCE
    
    def get_size_estimate(self) -> int:
        """Estimate data size in bytes for storage planning."""
        if self.data_size_bytes > 0:
            return self.data_size_bytes
        
        # Estimate based on serialized data
        serialized = json.dumps(asdict(self), default=str)
        self.data_size_bytes = len(serialized.encode('utf-8'))
        return self.data_size_bytes
    
    def compress_data(self, compression_type: DataCompressionType = None) -> bytes:
        """Compress historical data point for storage optimization."""
        if compression_type is None:
            compression_type = self.compression_type or DataCompressionType.LZ4
        
        # Serialize data
        data_dict = asdict(self)
        serialized_data = json.dumps(data_dict, default=str).encode('utf-8')
        
        # Apply compression
        if compression_type == DataCompressionType.LZ4 and LZ4_AVAILABLE:
            compressed_data = lz4.frame.compress(serialized_data)
            self.compression_type = DataCompressionType.LZ4
        elif compression_type == DataCompressionType.GZIP:
            compressed_data = gzip.compress(serialized_data)
            self.compression_type = DataCompressionType.GZIP
        elif compression_type == DataCompressionType.ZLIB:
            compressed_data = zlib.compress(serialized_data)
            self.compression_type = DataCompressionType.ZLIB
        else:
            compressed_data = serialized_data
            self.compression_type = DataCompressionType.NONE
        
        self.compressed_size_bytes = len(compressed_data)
        return compressed_data
    
    @classmethod
    def decompress_data(cls, compressed_data: bytes, compression_type: DataCompressionType) -> 'HistoricalDataPoint':
        """Decompress historical data point from storage."""
        # Decompress data
        if compression_type == DataCompressionType.LZ4 and LZ4_AVAILABLE:
            decompressed_data = lz4.frame.decompress(compressed_data)
        elif compression_type == DataCompressionType.GZIP:
            decompressed_data = gzip.decompress(compressed_data)
        elif compression_type == DataCompressionType.ZLIB:
            decompressed_data = zlib.decompress(compressed_data)
        else:
            decompressed_data = compressed_data
        
        # Deserialize data
        data_dict = json.loads(decompressed_data.decode('utf-8'))
        
        # Convert timestamp back to datetime
        if isinstance(data_dict["timestamp"], str):
            data_dict["timestamp"] = datetime.fromisoformat(data_dict["timestamp"])
        
        # Convert enums back
        data_dict["retention_level"] = DataRetentionLevel(data_dict["retention_level"])
        data_dict["compression_type"] = DataCompressionType(data_dict["compression_type"])
        data_dict["archival_status"] = ArchivalStatus(data_dict["archival_status"])
        
        return cls(**data_dict)


@dataclass
class TrendAnalysisResult:
    """Results from historical trend analysis."""
    
    analysis_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    analysis_type: TrendAnalysisType = TrendAnalysisType.PERFORMANCE_VARIANCE
    analysis_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Time range analyzed
    start_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc) - timedelta(days=30))
    end_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Analysis results
    trend_direction: str = "stable"  # "improving", "degrading", "stable"
    trend_magnitude: float = 0.0     # Percentage change
    confidence_level: float = 0.95   # Statistical confidence
    data_points_count: int = 0
    
    # Statistical analysis
    mean_value: float = 0.0
    median_value: float = 0.0
    std_deviation: float = 0.0
    min_value: float = 0.0
    max_value: float = 0.0
    
    # Trend-specific metrics
    trend_metrics: Dict[str, Any] = field(default_factory=dict)
    seasonal_patterns: Dict[str, Any] = field(default_factory=dict)
    anomalies_detected: List[Dict[str, Any]] = field(default_factory=list)
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    action_required: bool = False
    priority_level: str = "low"  # "low", "medium", "high", "critical"
    
    def add_recommendation(self, recommendation: str, priority: str = "medium"):
        """Add analysis recommendation with priority."""
        self.recommendations.append(recommendation)
        if priority in ["high", "critical"] and not self.action_required:
            self.action_required = True
            self.priority_level = priority


class HistoricalDataManager:
    """
    Comprehensive historical performance data management system providing data storage,
    retrieval, archival, and analysis capabilities per Section 6.6.3 and Section 8.6.5.
    
    Features:
    - Historical data storage with SQLite backend
    - Automated retention and archival policies
    - Data compression and optimization
    - AWS S3 integration for long-term storage
    - Trend analysis and pattern detection
    - Compliance data classification
    - Data integrity validation and backup procedures
    """
    
    def __init__(
        self,
        data_directory: Optional[Path] = None,
        database_path: Optional[Path] = None,
        s3_bucket: Optional[str] = None,
        enable_compression: bool = True,
        compression_type: DataCompressionType = DataCompressionType.LZ4
    ):
        """
        Initialize historical data manager with storage and archival configuration.
        
        Args:
            data_directory: Directory for local data storage
            database_path: Path to SQLite database file
            s3_bucket: AWS S3 bucket name for archival storage
            enable_compression: Enable data compression for optimization
            compression_type: Default compression algorithm
        """
        # Storage configuration
        self.data_directory = data_directory or Path(__file__).parent / "historical_data"
        self.data_directory.mkdir(parents=True, exist_ok=True)
        
        self.database_path = database_path or self.data_directory / "historical_performance.db"
        self.s3_bucket = s3_bucket or "performance-data-archive"
        self.enable_compression = enable_compression
        self.compression_type = compression_type
        
        # Initialize logging
        if STRUCTLOG_AVAILABLE:
            self.logger = structlog.get_logger(__name__)
        else:
            self.logger = logging.getLogger(__name__)
        
        # Initialize database
        self._init_database()
        
        # Initialize AWS S3 client
        self._init_s3_client()
        
        # Initialize Prometheus metrics
        self._init_prometheus_metrics()
        
        # Configure retention policies per Section 8.6.5
        self._init_retention_policies()
        
        # Initialize background tasks
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)
        self._background_tasks_enabled = True
        self._last_cleanup_run = datetime.now(timezone.utc)
        self._last_archival_run = datetime.now(timezone.utc)
        
        # Data cache for performance
        self._data_cache: Dict[str, HistoricalDataPoint] = {}
        self._cache_max_size = 1000
        self._cache_lock = threading.RLock()
        
        # Integration with baseline and config managers
        self.baseline_manager = get_baseline_manager()
        self.performance_config = create_performance_config()
        
        # Start background maintenance tasks
        self._start_background_tasks()
    
    def _init_database(self) -> None:
        """Initialize SQLite database for historical data storage."""
        try:
            with sqlite3.connect(self.database_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS historical_data (
                        data_id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        performance_metrics TEXT NOT NULL,
                        baseline_comparison TEXT,
                        variance_percentage REAL,
                        test_scenario TEXT,
                        environment TEXT NOT NULL,
                        flask_version TEXT,
                        python_version TEXT,
                        retention_level TEXT NOT NULL,
                        compliance_tags TEXT,
                        compression_type TEXT NOT NULL,
                        archival_status TEXT NOT NULL,
                        s3_key TEXT,
                        data_size_bytes INTEGER,
                        compressed_size_bytes INTEGER,
                        data_hash TEXT NOT NULL,
                        validation_status TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        archived_at TEXT,
                        compressed_data BLOB
                    )
                """)
                
                # Create indexes for performance
                conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON historical_data(timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_environment ON historical_data(environment)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_retention_level ON historical_data(retention_level)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_archival_status ON historical_data(archival_status)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_variance_percentage ON historical_data(variance_percentage)")
                
                # Create trend analysis results table
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS trend_analysis (
                        analysis_id TEXT PRIMARY KEY,
                        analysis_type TEXT NOT NULL,
                        analysis_timestamp TEXT NOT NULL,
                        start_date TEXT NOT NULL,
                        end_date TEXT NOT NULL,
                        trend_direction TEXT NOT NULL,
                        trend_magnitude REAL NOT NULL,
                        confidence_level REAL NOT NULL,
                        data_points_count INTEGER NOT NULL,
                        mean_value REAL,
                        median_value REAL,
                        std_deviation REAL,
                        min_value REAL,
                        max_value REAL,
                        trend_metrics TEXT,
                        seasonal_patterns TEXT,
                        anomalies_detected TEXT,
                        recommendations TEXT,
                        action_required INTEGER NOT NULL,
                        priority_level TEXT NOT NULL
                    )
                """)
                
                conn.execute("CREATE INDEX IF NOT EXISTS idx_analysis_timestamp ON trend_analysis(analysis_timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_analysis_type ON trend_analysis(analysis_type)")
                
                conn.commit()
                
            if STRUCTLOG_AVAILABLE:
                self.logger.info("Historical data database initialized", database_path=str(self.database_path))
                
        except Exception as e:
            error_msg = f"Failed to initialize database: {e}"
            if STRUCTLOG_AVAILABLE:
                self.logger.error("Database initialization failed", error=str(e))
            raise RuntimeError(error_msg)
    
    def _init_s3_client(self) -> None:
        """Initialize AWS S3 client for archival storage."""
        self.s3_client = None
        if not AWS_AVAILABLE:
            if STRUCTLOG_AVAILABLE:
                self.logger.warning("AWS S3 integration disabled - boto3 not available")
            return
        
        try:
            self.s3_client = boto3.client('s3')
            
            # Verify bucket exists or create it
            try:
                self.s3_client.head_bucket(Bucket=self.s3_bucket)
            except ClientError as e:
                if e.response['Error']['Code'] == '404':
                    # Bucket doesn't exist, create it
                    self.s3_client.create_bucket(Bucket=self.s3_bucket)
                    if STRUCTLOG_AVAILABLE:
                        self.logger.info("Created S3 bucket for archival", bucket=self.s3_bucket)
                else:
                    raise
            
            if STRUCTLOG_AVAILABLE:
                self.logger.info("AWS S3 archival storage initialized", bucket=self.s3_bucket)
                
        except Exception as e:
            if STRUCTLOG_AVAILABLE:
                self.logger.warning("AWS S3 initialization failed", error=str(e))
            self.s3_client = None
    
    def _init_prometheus_metrics(self) -> None:
        """Initialize Prometheus metrics for historical data tracking."""
        if not PROMETHEUS_AVAILABLE:
            return
        
        self.metrics_registry = CollectorRegistry()
        
        # Data storage metrics
        self.data_points_total = Counter(
            'historical_data_points_total',
            'Total historical data points stored',
            ['environment', 'retention_level'],
            registry=self.metrics_registry
        )
        
        self.data_storage_bytes = Gauge(
            'historical_data_storage_bytes',
            'Total storage space used by historical data',
            ['compression_type'],
            registry=self.metrics_registry
        )
        
        # Archival metrics
        self.archival_operations_total = Counter(
            'historical_data_archival_total',
            'Total archival operations performed',
            ['status', 'destination'],
            registry=self.metrics_registry
        )
        
        self.archival_duration_seconds = Histogram(
            'historical_data_archival_duration_seconds',
            'Time spent on archival operations',
            ['operation_type'],
            registry=self.metrics_registry
        )
        
        # Trend analysis metrics
        self.trend_analysis_total = Counter(
            'historical_trend_analysis_total',
            'Total trend analysis operations',
            ['analysis_type', 'trend_direction'],
            registry=self.metrics_registry
        )
        
        # Data integrity metrics
        self.data_integrity_checks_total = Counter(
            'historical_data_integrity_checks_total',
            'Total data integrity validation checks',
            ['status'],
            registry=self.metrics_registry
        )
        
        # Compression efficiency metrics
        self.compression_ratio_gauge = Gauge(
            'historical_data_compression_ratio',
            'Data compression ratio achieved',
            ['compression_type'],
            registry=self.metrics_registry
        )
    
    def _init_retention_policies(self) -> None:
        """Initialize data retention policies per Section 8.6.5."""
        self.retention_policies = {
            DataRetentionLevel.DEBUG: RetentionPolicy(
                level=DataRetentionLevel.DEBUG,
                retention_days=7,
                compression_enabled=True,
                compression_type=DataCompressionType.GZIP,
                archival_enabled=False  # Short retention, no archival needed
            ),
            DataRetentionLevel.INFO: RetentionPolicy(
                level=DataRetentionLevel.INFO,
                retention_days=30,
                compression_enabled=True,
                compression_type=DataCompressionType.LZ4,
                archival_enabled=True
            ),
            DataRetentionLevel.WARNING: RetentionPolicy(
                level=DataRetentionLevel.WARNING,
                retention_days=60,
                compression_enabled=True,
                compression_type=DataCompressionType.LZ4,
                archival_enabled=True
            ),
            DataRetentionLevel.ERROR: RetentionPolicy(
                level=DataRetentionLevel.ERROR,
                retention_days=90,
                compression_enabled=True,
                compression_type=DataCompressionType.LZ4,
                archival_enabled=True
            ),
            DataRetentionLevel.CRITICAL: RetentionPolicy(
                level=DataRetentionLevel.CRITICAL,
                retention_days=365,
                compression_enabled=True,
                compression_type=DataCompressionType.LZ4,
                archival_enabled=True
            ),
            DataRetentionLevel.COMPLIANCE: RetentionPolicy(
                level=DataRetentionLevel.COMPLIANCE,
                retention_days=365 * 7,  # 7 years
                compression_enabled=True,
                compression_type=DataCompressionType.LZ4,
                archival_enabled=True,
                compliance_classification="regulatory"
            ),
            DataRetentionLevel.AUDIT: RetentionPolicy(
                level=DataRetentionLevel.AUDIT,
                retention_days=365 * 10,  # 10 years
                compression_enabled=True,
                compression_type=DataCompressionType.LZ4,
                archival_enabled=True,
                compliance_classification="audit_trail"
            )
        }
    
    def _start_background_tasks(self) -> None:
        """Start background maintenance tasks."""
        if not self._background_tasks_enabled:
            return
        
        # Schedule cleanup and archival tasks
        self._executor.submit(self._background_maintenance_loop)
    
    def _background_maintenance_loop(self) -> None:
        """Background maintenance loop for cleanup and archival."""
        while self._background_tasks_enabled:
            try:
                current_time = datetime.now(timezone.utc)
                
                # Run cleanup every 6 hours
                if (current_time - self._last_cleanup_run).total_seconds() > 21600:
                    self._run_automated_cleanup()
                    self._last_cleanup_run = current_time
                
                # Run archival every 12 hours
                if (current_time - self._last_archival_run).total_seconds() > 43200:
                    self._run_automated_archival()
                    self._last_archival_run = current_time
                
                # Sleep for 1 hour before next check
                import time
                time.sleep(3600)
                
            except Exception as e:
                if STRUCTLOG_AVAILABLE:
                    self.logger.error("Background maintenance error", error=str(e))
                import time
                time.sleep(3600)  # Continue after errors
    
    def store_historical_data(
        self,
        performance_metrics: Dict[str, float],
        test_scenario: Optional[str] = None,
        environment: str = "production",
        baseline_comparison: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Store historical performance data point with compliance classification.
        
        Args:
            performance_metrics: Performance metrics dictionary
            test_scenario: Optional test scenario identifier
            environment: Environment name (production, staging, etc.)
            baseline_comparison: Optional baseline comparison results
            
        Returns:
            Data point ID for the stored record
            
        Raises:
            ValueError: If performance metrics are invalid
            RuntimeError: If storage operation fails
        """
        if not performance_metrics:
            raise ValueError("Performance metrics cannot be empty")
        
        # Calculate variance if baseline comparison available
        variance_percentage = None
        if baseline_comparison and "summary" in baseline_comparison:
            summary = baseline_comparison["summary"]
            if "compliance_percentage" in summary:
                # Convert compliance to variance (100% compliance = 0% variance)
                compliance_pct = summary["compliance_percentage"]
                variance_percentage = max(0, 100 - compliance_pct)
        
        # Create historical data point
        data_point = HistoricalDataPoint(
            performance_metrics=performance_metrics,
            baseline_comparison=baseline_comparison or {},
            variance_percentage=variance_percentage,
            test_scenario=test_scenario,
            environment=environment,
            flask_version=self.performance_config.get("flask_version", "2.3.0"),
            python_version=self.performance_config.get("python_version", "3.11")
        )
        
        # Apply compression if enabled
        compressed_data = None
        if self.enable_compression:
            policy = self.retention_policies.get(data_point.retention_level)
            if policy and policy.compression_enabled:
                compressed_data = data_point.compress_data(policy.compression_type)
        
        # Store in database
        try:
            with sqlite3.connect(self.database_path) as conn:
                conn.execute("""
                    INSERT INTO historical_data (
                        data_id, timestamp, performance_metrics, baseline_comparison,
                        variance_percentage, test_scenario, environment, flask_version,
                        python_version, retention_level, compliance_tags, compression_type,
                        archival_status, s3_key, data_size_bytes, compressed_size_bytes,
                        data_hash, validation_status, created_at, compressed_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    data_point.data_id,
                    data_point.timestamp.isoformat(),
                    json.dumps(data_point.performance_metrics),
                    json.dumps(data_point.baseline_comparison) if data_point.baseline_comparison else None,
                    data_point.variance_percentage,
                    data_point.test_scenario,
                    data_point.environment,
                    data_point.flask_version,
                    data_point.python_version,
                    data_point.retention_level.value,
                    json.dumps(data_point.compliance_tags),
                    data_point.compression_type.value,
                    data_point.archival_status.value,
                    data_point.s3_key,
                    data_point.get_size_estimate(),
                    data_point.compressed_size_bytes,
                    data_point.data_hash,
                    data_point.validation_status,
                    data_point.timestamp.isoformat(),
                    compressed_data
                ))
                conn.commit()
            
            # Update cache
            with self._cache_lock:
                if len(self._data_cache) >= self._cache_max_size:
                    # Remove oldest entry
                    oldest_key = min(self._data_cache.keys())
                    del self._data_cache[oldest_key]
                
                self._data_cache[data_point.data_id] = data_point
            
            # Update Prometheus metrics
            if PROMETHEUS_AVAILABLE:
                self.data_points_total.labels(
                    environment=data_point.environment,
                    retention_level=data_point.retention_level.value
                ).inc()
                
                self.data_storage_bytes.labels(
                    compression_type=data_point.compression_type.value
                ).inc(data_point.get_size_estimate())
                
                if compressed_data:
                    compression_ratio = len(compressed_data) / data_point.get_size_estimate()
                    self.compression_ratio_gauge.labels(
                        compression_type=data_point.compression_type.value
                    ).set(compression_ratio)
            
            if STRUCTLOG_AVAILABLE:
                self.logger.info(
                    "Stored historical performance data",
                    data_id=data_point.data_id,
                    environment=data_point.environment,
                    retention_level=data_point.retention_level.value,
                    variance_percentage=data_point.variance_percentage,
                    compression_enabled=compressed_data is not None
                )
            
            return data_point.data_id
            
        except Exception as e:
            error_msg = f"Failed to store historical data: {e}"
            if STRUCTLOG_AVAILABLE:
                self.logger.error("Historical data storage failed", error=str(e))
            raise RuntimeError(error_msg)
    
    def retrieve_historical_data(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        environment: Optional[str] = None,
        retention_level: Optional[DataRetentionLevel] = None,
        limit: int = 1000,
        include_archived: bool = False
    ) -> List[HistoricalDataPoint]:
        """
        Retrieve historical performance data with filtering and pagination.
        
        Args:
            start_date: Start date for data retrieval
            end_date: End date for data retrieval
            environment: Filter by environment
            retention_level: Filter by retention level
            limit: Maximum number of records to retrieve
            include_archived: Include archived data in results
            
        Returns:
            List of HistoricalDataPoint instances
        """
        # Build SQL query with filters
        query = "SELECT * FROM historical_data WHERE 1=1"
        params = []
        
        if start_date:
            query += " AND timestamp >= ?"
            params.append(start_date.isoformat())
        
        if end_date:
            query += " AND timestamp <= ?"
            params.append(end_date.isoformat())
        
        if environment:
            query += " AND environment = ?"
            params.append(environment)
        
        if retention_level:
            query += " AND retention_level = ?"
            params.append(retention_level.value)
        
        if not include_archived:
            query += " AND archival_status != 'archived'"
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        try:
            with sqlite3.connect(self.database_path) as conn:
                conn.row_factory = sqlite3.Row  # Enable column access by name
                cursor = conn.execute(query, params)
                rows = cursor.fetchall()
            
            # Convert rows to HistoricalDataPoint instances
            data_points = []
            for row in rows:
                # Handle compressed data if present
                if row['compressed_data'] and row['compression_type'] != 'none':
                    compression_type = DataCompressionType(row['compression_type'])
                    data_point = HistoricalDataPoint.decompress_data(
                        row['compressed_data'], compression_type
                    )
                else:
                    # Reconstruct from individual columns
                    data_point = HistoricalDataPoint(
                        data_id=row['data_id'],
                        timestamp=datetime.fromisoformat(row['timestamp']),
                        performance_metrics=json.loads(row['performance_metrics']),
                        baseline_comparison=json.loads(row['baseline_comparison']) if row['baseline_comparison'] else {},
                        variance_percentage=row['variance_percentage'],
                        test_scenario=row['test_scenario'],
                        environment=row['environment'],
                        flask_version=row['flask_version'],
                        python_version=row['python_version'],
                        retention_level=DataRetentionLevel(row['retention_level']),
                        compliance_tags=json.loads(row['compliance_tags']),
                        compression_type=DataCompressionType(row['compression_type']),
                        archival_status=ArchivalStatus(row['archival_status']),
                        s3_key=row['s3_key'],
                        data_size_bytes=row['data_size_bytes'],
                        compressed_size_bytes=row['compressed_size_bytes'],
                        validation_status=row['validation_status']
                    )
                    data_point.data_hash = row['data_hash']
                
                data_points.append(data_point)
            
            if STRUCTLOG_AVAILABLE:
                self.logger.info(
                    "Retrieved historical performance data",
                    records_count=len(data_points),
                    start_date=start_date.isoformat() if start_date else None,
                    end_date=end_date.isoformat() if end_date else None,
                    environment=environment,
                    include_archived=include_archived
                )
            
            return data_points
            
        except Exception as e:
            if STRUCTLOG_AVAILABLE:
                self.logger.error("Historical data retrieval failed", error=str(e))
            raise RuntimeError(f"Failed to retrieve historical data: {e}")
    
    def analyze_performance_trend(
        self,
        analysis_type: TrendAnalysisType,
        metric_name: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        environment: str = "production"
    ) -> TrendAnalysisResult:
        """
        Perform trend analysis on historical performance data.
        
        Args:
            analysis_type: Type of trend analysis to perform
            metric_name: Name of the performance metric to analyze
            start_date: Start date for analysis (defaults to 30 days ago)
            end_date: End date for analysis (defaults to now)
            environment: Environment to analyze
            
        Returns:
            TrendAnalysisResult with comprehensive analysis
        """
        # Set default date range
        if end_date is None:
            end_date = datetime.now(timezone.utc)
        if start_date is None:
            start_date = end_date - timedelta(days=30)
        
        # Retrieve historical data for analysis
        data_points = self.retrieve_historical_data(
            start_date=start_date,
            end_date=end_date,
            environment=environment,
            limit=10000  # Large limit for comprehensive analysis
        )
        
        # Extract metric values
        metric_values = []
        timestamps = []
        
        for data_point in data_points:
            if metric_name in data_point.performance_metrics:
                metric_values.append(data_point.performance_metrics[metric_name])
                timestamps.append(data_point.timestamp)
        
        if len(metric_values) < 2:
            raise ValueError(f"Insufficient data points for trend analysis: {len(metric_values)}")
        
        # Perform statistical analysis
        mean_value = statistics.mean(metric_values)
        median_value = statistics.median(metric_values)
        std_deviation = statistics.stdev(metric_values) if len(metric_values) > 1 else 0.0
        min_value = min(metric_values)
        max_value = max(metric_values)
        
        # Calculate trend direction and magnitude
        trend_direction, trend_magnitude = self._calculate_trend(metric_values, timestamps)
        
        # Create analysis result
        result = TrendAnalysisResult(
            analysis_type=analysis_type,
            start_date=start_date,
            end_date=end_date,
            trend_direction=trend_direction,
            trend_magnitude=trend_magnitude,
            confidence_level=0.95,  # TODO: Calculate actual confidence interval
            data_points_count=len(metric_values),
            mean_value=mean_value,
            median_value=median_value,
            std_deviation=std_deviation,
            min_value=min_value,
            max_value=max_value
        )
        
        # Analyze specific trend patterns
        if analysis_type == TrendAnalysisType.PERFORMANCE_VARIANCE:
            self._analyze_variance_trend(result, data_points)
        elif analysis_type == TrendAnalysisType.RESPONSE_TIME_TREND:
            self._analyze_response_time_trend(result, metric_values, timestamps)
        elif analysis_type == TrendAnalysisType.BASELINE_DRIFT:
            self._analyze_baseline_drift(result, data_points, metric_name)
        elif analysis_type == TrendAnalysisType.SEASONAL_PATTERNS:
            self._analyze_seasonal_patterns(result, metric_values, timestamps)
        elif analysis_type == TrendAnalysisType.REGRESSION_DETECTION:
            self._analyze_performance_regression(result, metric_values, timestamps)
        
        # Generate recommendations
        self._generate_trend_recommendations(result, analysis_type, metric_name)
        
        # Store analysis result
        self._store_trend_analysis(result)
        
        # Update Prometheus metrics
        if PROMETHEUS_AVAILABLE:
            self.trend_analysis_total.labels(
                analysis_type=analysis_type.value,
                trend_direction=trend_direction
            ).inc()
        
        if STRUCTLOG_AVAILABLE:
            self.logger.info(
                "Completed trend analysis",
                analysis_type=analysis_type.value,
                metric_name=metric_name,
                trend_direction=trend_direction,
                trend_magnitude=trend_magnitude,
                data_points_count=len(metric_values),
                action_required=result.action_required
            )
        
        return result
    
    def _calculate_trend(self, values: List[float], timestamps: List[datetime]) -> Tuple[str, float]:
        """Calculate trend direction and magnitude using linear regression."""
        if len(values) < 2:
            return "stable", 0.0
        
        # Convert timestamps to numeric values (seconds since first timestamp)
        base_time = timestamps[0]
        x_values = [(ts - base_time).total_seconds() for ts in timestamps]
        
        # Calculate linear regression
        n = len(values)
        sum_x = sum(x_values)
        sum_y = sum(values)
        sum_xy = sum(x * y for x, y in zip(x_values, values))
        sum_x2 = sum(x * x for x in x_values)
        
        # Calculate slope
        denominator = n * sum_x2 - sum_x * sum_x
        if denominator == 0:
            return "stable", 0.0
        
        slope = (n * sum_xy - sum_x * sum_y) / denominator
        
        # Calculate magnitude as percentage change over time period
        time_span_seconds = x_values[-1] - x_values[0]
        if time_span_seconds == 0:
            return "stable", 0.0
        
        total_change = slope * time_span_seconds
        base_value = statistics.mean(values)
        
        if base_value == 0:
            magnitude = 0.0
        else:
            magnitude = abs(total_change / base_value) * 100
        
        # Determine trend direction
        if slope > 0.01:  # Threshold for detecting improvement/degradation
            if metric_name in ["error_rate", "response_time"]:
                direction = "degrading"  # Higher is worse for these metrics
            else:
                direction = "improving"  # Higher is better for throughput, etc.
        elif slope < -0.01:
            if metric_name in ["error_rate", "response_time"]:
                direction = "improving"  # Lower is better for these metrics
            else:
                direction = "degrading"  # Lower is worse for throughput, etc.
        else:
            direction = "stable"
        
        return direction, magnitude
    
    def _analyze_variance_trend(self, result: TrendAnalysisResult, data_points: List[HistoricalDataPoint]) -> None:
        """Analyze performance variance trend against ≤10% threshold."""
        variance_violations = []
        recent_violations = 0
        
        # Count variance violations over time
        for data_point in data_points:
            if data_point.variance_percentage is not None:
                if abs(data_point.variance_percentage) > 10.0:
                    variance_violations.append({
                        "timestamp": data_point.timestamp.isoformat(),
                        "variance": data_point.variance_percentage,
                        "environment": data_point.environment
                    })
                    
                    # Count recent violations (last 7 days)
                    if data_point.timestamp > datetime.now(timezone.utc) - timedelta(days=7):
                        recent_violations += 1
        
        result.trend_metrics["variance_violations_total"] = len(variance_violations)
        result.trend_metrics["recent_violations"] = recent_violations
        result.trend_metrics["violation_rate"] = len(variance_violations) / len(data_points) if data_points else 0
        
        # Set action required if recent violations exceed threshold
        if recent_violations > 2:
            result.action_required = True
            result.priority_level = "high"
            result.add_recommendation(
                f"Performance variance violations detected: {recent_violations} in last 7 days", 
                "high"
            )
        
        result.anomalies_detected = variance_violations
    
    def _analyze_response_time_trend(self, result: TrendAnalysisResult, values: List[float], timestamps: List[datetime]) -> None:
        """Analyze response time trend patterns."""
        # Calculate percentiles
        sorted_values = sorted(values)
        n = len(sorted_values)
        
        p50 = sorted_values[n // 2]
        p95 = sorted_values[int(n * 0.95)]
        p99 = sorted_values[int(n * 0.99)]
        
        result.trend_metrics["response_time_p50"] = p50
        result.trend_metrics["response_time_p95"] = p95
        result.trend_metrics["response_time_p99"] = p99
        
        # Check against thresholds
        if p95 > 500.0:  # Section 4.6.3 threshold
            result.action_required = True
            result.priority_level = "high"
            result.add_recommendation(
                f"95th percentile response time ({p95:.1f}ms) exceeds 500ms threshold",
                "high"
            )
        
        # Detect spikes
        mean_val = result.mean_value
        std_val = result.std_deviation
        threshold = mean_val + (3 * std_val)
        
        spikes = []
        for i, (value, timestamp) in enumerate(zip(values, timestamps)):
            if value > threshold:
                spikes.append({
                    "timestamp": timestamp.isoformat(),
                    "value": value,
                    "deviation": (value - mean_val) / std_val
                })
        
        result.trend_metrics["response_time_spikes"] = len(spikes)
        if spikes:
            result.anomalies_detected.extend(spikes[:10])  # Limit to top 10 spikes
    
    def _analyze_baseline_drift(self, result: TrendAnalysisResult, data_points: List[HistoricalDataPoint], metric_name: str) -> None:
        """Analyze drift from Node.js baseline over time."""
        baseline = get_nodejs_baseline()
        
        try:
            baseline_threshold = baseline.get_performance_threshold(metric_name)
            baseline_value = baseline_threshold.baseline_value
        except KeyError:
            result.add_recommendation(f"No baseline available for metric: {metric_name}", "low")
            return
        
        # Calculate drift over time
        drift_values = []
        for data_point in data_points:
            if metric_name in data_point.performance_metrics:
                current_value = data_point.performance_metrics[metric_name]
                drift = ((current_value - baseline_value) / baseline_value) * 100
                drift_values.append(drift)
        
        if drift_values:
            avg_drift = statistics.mean(drift_values)
            max_drift = max(drift_values)
            min_drift = min(drift_values)
            
            result.trend_metrics["baseline_drift_average"] = avg_drift
            result.trend_metrics["baseline_drift_max"] = max_drift
            result.trend_metrics["baseline_drift_min"] = min_drift
            result.trend_metrics["baseline_value"] = baseline_value
            
            # Check for significant drift
            if abs(avg_drift) > 5.0:  # 5% drift threshold
                result.action_required = True
                result.priority_level = "medium"
                result.add_recommendation(
                    f"Baseline drift detected: {avg_drift:.1f}% average drift from Node.js baseline",
                    "medium"
                )
    
    def _analyze_seasonal_patterns(self, result: TrendAnalysisResult, values: List[float], timestamps: List[datetime]) -> None:
        """Analyze seasonal patterns in performance data."""
        if len(values) < 24:  # Need at least 24 data points for pattern analysis
            return
        
        # Group by hour of day
        hourly_patterns = defaultdict(list)
        for value, timestamp in zip(values, timestamps):
            hour = timestamp.hour
            hourly_patterns[hour].append(value)
        
        # Calculate average by hour
        hourly_averages = {}
        for hour, values_for_hour in hourly_patterns.items():
            if values_for_hour:
                hourly_averages[hour] = statistics.mean(values_for_hour)
        
        if hourly_averages:
            peak_hour = max(hourly_averages, key=hourly_averages.get)
            peak_value = hourly_averages[peak_hour]
            low_hour = min(hourly_averages, key=hourly_averages.get)
            low_value = hourly_averages[low_hour]
            
            result.seasonal_patterns["hourly_patterns"] = hourly_averages
            result.seasonal_patterns["peak_hour"] = peak_hour
            result.seasonal_patterns["peak_value"] = peak_value
            result.seasonal_patterns["low_hour"] = low_hour
            result.seasonal_patterns["low_value"] = low_value
            result.seasonal_patterns["daily_variation"] = ((peak_value - low_value) / low_value) * 100
    
    def _analyze_performance_regression(self, result: TrendAnalysisResult, values: List[float], timestamps: List[datetime]) -> None:
        """Analyze for performance regressions."""
        if len(values) < 10:
            return
        
        # Split data into two halves for comparison
        mid_point = len(values) // 2
        first_half = values[:mid_point]
        second_half = values[mid_point:]
        
        first_avg = statistics.mean(first_half)
        second_avg = statistics.mean(second_half)
        
        # Calculate regression percentage
        if first_avg != 0:
            regression_pct = ((second_avg - first_avg) / first_avg) * 100
            
            result.trend_metrics["regression_percentage"] = regression_pct
            result.trend_metrics["first_period_average"] = first_avg
            result.trend_metrics["second_period_average"] = second_avg
            
            # Determine if regression is significant
            threshold = 5.0  # 5% regression threshold
            if abs(regression_pct) > threshold:
                if regression_pct > 0 and metric_name in ["error_rate", "response_time"]:
                    # Performance degraded
                    result.action_required = True
                    result.priority_level = "high"
                    result.add_recommendation(
                        f"Performance regression detected: {regression_pct:.1f}% degradation",
                        "high"
                    )
                elif regression_pct < 0 and metric_name in ["throughput"]:
                    # Throughput decreased
                    result.action_required = True
                    result.priority_level = "medium"
                    result.add_recommendation(
                        f"Throughput regression detected: {abs(regression_pct):.1f}% decrease",
                        "medium"
                    )
    
    def _generate_trend_recommendations(self, result: TrendAnalysisResult, analysis_type: TrendAnalysisType, metric_name: str) -> None:
        """Generate actionable recommendations based on trend analysis."""
        # General recommendations based on trend direction
        if result.trend_direction == "degrading":
            if analysis_type == TrendAnalysisType.RESPONSE_TIME_TREND:
                result.add_recommendation("Consider optimizing database queries and caching strategies", "medium")
                result.add_recommendation("Review recent deployments for performance regressions", "medium")
            elif analysis_type == TrendAnalysisType.THROUGHPUT_TREND:
                result.add_recommendation("Investigate resource constraints and scaling requirements", "medium")
                result.add_recommendation("Analyze bottlenecks in request processing pipeline", "medium")
        
        elif result.trend_direction == "improving":
            result.add_recommendation("Document recent optimizations for knowledge sharing", "low")
            result.add_recommendation("Consider updating baseline metrics if improvement is sustained", "low")
        
        # Specific recommendations based on variance
        if result.trend_metrics.get("variance_violations_total", 0) > 0:
            result.add_recommendation("Review ≤10% variance compliance and optimization opportunities", "high")
        
        # Recommendations based on statistical analysis
        if result.std_deviation > result.mean_value * 0.5:  # High variability
            result.add_recommendation("High performance variability detected - investigate consistency issues", "medium")
        
        # Seasonal pattern recommendations
        if result.seasonal_patterns:
            daily_variation = result.seasonal_patterns.get("daily_variation", 0)
            if daily_variation > 20:  # >20% variation throughout the day
                result.add_recommendation("Consider implementing time-based auto-scaling for daily patterns", "low")
    
    def _store_trend_analysis(self, result: TrendAnalysisResult) -> None:
        """Store trend analysis result in database."""
        try:
            with sqlite3.connect(self.database_path) as conn:
                conn.execute("""
                    INSERT INTO trend_analysis (
                        analysis_id, analysis_type, analysis_timestamp, start_date, end_date,
                        trend_direction, trend_magnitude, confidence_level, data_points_count,
                        mean_value, median_value, std_deviation, min_value, max_value,
                        trend_metrics, seasonal_patterns, anomalies_detected, recommendations,
                        action_required, priority_level
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    result.analysis_id,
                    result.analysis_type.value,
                    result.analysis_timestamp.isoformat(),
                    result.start_date.isoformat(),
                    result.end_date.isoformat(),
                    result.trend_direction,
                    result.trend_magnitude,
                    result.confidence_level,
                    result.data_points_count,
                    result.mean_value,
                    result.median_value,
                    result.std_deviation,
                    result.min_value,
                    result.max_value,
                    json.dumps(result.trend_metrics),
                    json.dumps(result.seasonal_patterns),
                    json.dumps(result.anomalies_detected),
                    json.dumps(result.recommendations),
                    1 if result.action_required else 0,
                    result.priority_level
                ))
                conn.commit()
        except Exception as e:
            if STRUCTLOG_AVAILABLE:
                self.logger.error("Failed to store trend analysis", error=str(e))
    
    def archive_historical_data(self, data_point_ids: List[str]) -> Dict[str, str]:
        """
        Archive historical data points to AWS S3 per Section 8.6.5.
        
        Args:
            data_point_ids: List of data point IDs to archive
            
        Returns:
            Dictionary mapping data point IDs to archival status
        """
        if not self.s3_client:
            raise RuntimeError("AWS S3 client not available for archival")
        
        archival_results = {}
        
        for data_id in data_point_ids:
            try:
                start_time = datetime.now()
                
                # Retrieve data point
                with sqlite3.connect(self.database_path) as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.execute(
                        "SELECT * FROM historical_data WHERE data_id = ?",
                        (data_id,)
                    )
                    row = cursor.fetchone()
                
                if not row:
                    archival_results[data_id] = "not_found"
                    continue
                
                # Generate S3 key
                timestamp = datetime.fromisoformat(row['timestamp'])
                s3_key = f"performance-data/{timestamp.year}/{timestamp.month:02d}/{timestamp.day:02d}/{data_id}.json.gz"
                
                # Prepare data for archival
                if row['compressed_data']:
                    # Use already compressed data
                    compressed_data = row['compressed_data']
                else:
                    # Compress data for archival
                    data_dict = {
                        col: row[col] for col in row.keys()
                    }
                    data_dict.pop('compressed_data', None)  # Remove blob field
                    json_data = json.dumps(data_dict, default=str)
                    compressed_data = gzip.compress(json_data.encode('utf-8'))
                
                # Upload to S3
                self.s3_client.put_object(
                    Bucket=self.s3_bucket,
                    Key=s3_key,
                    Body=compressed_data,
                    ContentType='application/gzip',
                    Metadata={
                        'data_id': data_id,
                        'environment': row['environment'],
                        'retention_level': row['retention_level'],
                        'archived_at': datetime.now(timezone.utc).isoformat()
                    }
                )
                
                # Update database record
                with sqlite3.connect(self.database_path) as conn:
                    conn.execute("""
                        UPDATE historical_data 
                        SET archival_status = ?, s3_key = ?, archived_at = ?
                        WHERE data_id = ?
                    """, (
                        ArchivalStatus.ARCHIVED.value,
                        s3_key,
                        datetime.now(timezone.utc).isoformat(),
                        data_id
                    ))
                    conn.commit()
                
                archival_results[data_id] = "archived"
                
                # Update Prometheus metrics
                if PROMETHEUS_AVAILABLE:
                    duration = (datetime.now() - start_time).total_seconds()
                    self.archival_duration_seconds.labels(operation_type="s3_upload").observe(duration)
                    self.archival_operations_total.labels(status="success", destination="s3").inc()
                
                if STRUCTLOG_AVAILABLE:
                    self.logger.info(
                        "Archived historical data to S3",
                        data_id=data_id,
                        s3_key=s3_key,
                        bucket=self.s3_bucket
                    )
                
            except Exception as e:
                archival_results[data_id] = f"failed: {str(e)}"
                
                if PROMETHEUS_AVAILABLE:
                    self.archival_operations_total.labels(status="failed", destination="s3").inc()
                
                if STRUCTLOG_AVAILABLE:
                    self.logger.error("Failed to archive historical data", data_id=data_id, error=str(e))
        
        return archival_results
    
    def _run_automated_cleanup(self) -> None:
        """Run automated data cleanup based on retention policies."""
        try:
            cleanup_summary = {
                "records_processed": 0,
                "records_deleted": 0,
                "records_archived": 0,
                "storage_freed_bytes": 0
            }
            
            current_time = datetime.now(timezone.utc)
            
            for retention_level, policy in self.retention_policies.items():
                # Find expired records
                cutoff_date = current_time - timedelta(days=policy.retention_days)
                
                with sqlite3.connect(self.database_path) as conn:
                    # Get expired records
                    cursor = conn.execute("""
                        SELECT data_id, data_size_bytes, archival_status
                        FROM historical_data 
                        WHERE retention_level = ? AND timestamp < ?
                    """, (retention_level.value, cutoff_date.isoformat()))
                    
                    expired_records = cursor.fetchall()
                    cleanup_summary["records_processed"] += len(expired_records)
                
                # Process expired records
                for data_id, size_bytes, archival_status in expired_records:
                    if archival_status == ArchivalStatus.ACTIVE.value and policy.archival_enabled:
                        # Archive before deletion
                        try:
                            result = self.archive_historical_data([data_id])
                            if result.get(data_id) == "archived":
                                cleanup_summary["records_archived"] += 1
                        except Exception as e:
                            if STRUCTLOG_AVAILABLE:
                                self.logger.warning("Failed to archive before cleanup", data_id=data_id, error=str(e))
                    
                    # Delete expired record
                    with sqlite3.connect(self.database_path) as conn:
                        conn.execute("DELETE FROM historical_data WHERE data_id = ?", (data_id,))
                        conn.commit()
                    
                    cleanup_summary["records_deleted"] += 1
                    cleanup_summary["storage_freed_bytes"] += size_bytes or 0
            
            if STRUCTLOG_AVAILABLE:
                self.logger.info("Automated cleanup completed", **cleanup_summary)
                
        except Exception as e:
            if STRUCTLOG_AVAILABLE:
                self.logger.error("Automated cleanup failed", error=str(e))
    
    def _run_automated_archival(self) -> None:
        """Run automated archival for eligible records."""
        try:
            archival_summary = {
                "candidates_found": 0,
                "successfully_archived": 0,
                "archival_failed": 0
            }
            
            current_time = datetime.now(timezone.utc)
            
            # Find records eligible for archival
            archival_candidates = []
            
            for retention_level, policy in self.retention_policies.items():
                if not policy.archival_enabled:
                    continue
                
                archival_threshold_date = current_time - timedelta(days=policy.archival_threshold_days)
                
                with sqlite3.connect(self.database_path) as conn:
                    cursor = conn.execute("""
                        SELECT data_id FROM historical_data 
                        WHERE retention_level = ? AND timestamp < ? AND archival_status = ?
                        LIMIT 100
                    """, (
                        retention_level.value,
                        archival_threshold_date.isoformat(),
                        ArchivalStatus.ACTIVE.value
                    ))
                    
                    candidates = [row[0] for row in cursor.fetchall()]
                    archival_candidates.extend(candidates)
            
            archival_summary["candidates_found"] = len(archival_candidates)
            
            # Perform archival in batches
            batch_size = 10
            for i in range(0, len(archival_candidates), batch_size):
                batch = archival_candidates[i:i + batch_size]
                results = self.archive_historical_data(batch)
                
                for data_id, status in results.items():
                    if status == "archived":
                        archival_summary["successfully_archived"] += 1
                    else:
                        archival_summary["archival_failed"] += 1
            
            if STRUCTLOG_AVAILABLE:
                self.logger.info("Automated archival completed", **archival_summary)
                
        except Exception as e:
            if STRUCTLOG_AVAILABLE:
                self.logger.error("Automated archival failed", error=str(e))
    
    def validate_data_integrity(self, data_point_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Validate data integrity for specified or all historical data points.
        
        Args:
            data_point_ids: Optional list of specific data point IDs to validate
            
        Returns:
            Dictionary containing validation results and statistics
        """
        validation_results = {
            "total_records": 0,
            "valid_records": 0,
            "invalid_records": 0,
            "corrupted_records": 0,
            "integrity_issues": [],
            "validation_timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        try:
            # Build query
            if data_point_ids:
                placeholders = ','.join(['?' for _ in data_point_ids])
                query = f"SELECT * FROM historical_data WHERE data_id IN ({placeholders})"
                params = data_point_ids
            else:
                query = "SELECT * FROM historical_data ORDER BY timestamp DESC LIMIT 1000"
                params = []
            
            with sqlite3.connect(self.database_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(query, params)
                
                for row in cursor:
                    validation_results["total_records"] += 1
                    data_id = row['data_id']
                    
                    try:
                        # Validate data hash if available
                        if row['data_hash']:
                            # Reconstruct data for hash validation
                            hash_data = {
                                "timestamp": row['timestamp'],
                                "performance_metrics": json.loads(row['performance_metrics']),
                                "baseline_comparison": json.loads(row['baseline_comparison']) if row['baseline_comparison'] else {},
                                "test_scenario": row['test_scenario'],
                                "environment": row['environment']
                            }
                            
                            expected_hash = hashlib.sha256(
                                json.dumps(hash_data, sort_keys=True, separators=(',', ':')).encode('utf-8')
                            ).hexdigest()
                            
                            if expected_hash != row['data_hash']:
                                validation_results["corrupted_records"] += 1
                                validation_results["integrity_issues"].append({
                                    "data_id": data_id,
                                    "issue": "hash_mismatch",
                                    "expected_hash": expected_hash,
                                    "actual_hash": row['data_hash']
                                })
                                continue
                        
                        # Validate JSON fields
                        json.loads(row['performance_metrics'])
                        if row['baseline_comparison']:
                            json.loads(row['baseline_comparison'])
                        if row['compliance_tags']:
                            json.loads(row['compliance_tags'])
                        
                        # Validate timestamp format
                        datetime.fromisoformat(row['timestamp'])
                        
                        # Validate enum values
                        DataRetentionLevel(row['retention_level'])
                        DataCompressionType(row['compression_type'])
                        ArchivalStatus(row['archival_status'])
                        
                        validation_results["valid_records"] += 1
                        
                    except (json.JSONDecodeError, ValueError, KeyError) as e:
                        validation_results["invalid_records"] += 1
                        validation_results["integrity_issues"].append({
                            "data_id": data_id,
                            "issue": "validation_error",
                            "error": str(e)
                        })
                    
                    # Update Prometheus metrics
                    if PROMETHEUS_AVAILABLE:
                        status = "valid" if data_id not in [issue["data_id"] for issue in validation_results["integrity_issues"]] else "invalid"
                        self.data_integrity_checks_total.labels(status=status).inc()
            
            # Calculate integrity percentage
            if validation_results["total_records"] > 0:
                integrity_percentage = (validation_results["valid_records"] / validation_results["total_records"]) * 100
                validation_results["integrity_percentage"] = integrity_percentage
            else:
                validation_results["integrity_percentage"] = 100.0
            
            if STRUCTLOG_AVAILABLE:
                self.logger.info(
                    "Data integrity validation completed",
                    total_records=validation_results["total_records"],
                    valid_records=validation_results["valid_records"],
                    integrity_percentage=validation_results["integrity_percentage"],
                    issues_found=len(validation_results["integrity_issues"])
                )
            
            return validation_results
            
        except Exception as e:
            if STRUCTLOG_AVAILABLE:
                self.logger.error("Data integrity validation failed", error=str(e))
            raise RuntimeError(f"Data integrity validation failed: {e}")
    
    def generate_historical_report(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        environment: str = "production"
    ) -> Dict[str, Any]:
        """
        Generate comprehensive historical performance report for quarterly assessments.
        
        Args:
            start_date: Start date for report (defaults to 90 days ago)
            end_date: End date for report (defaults to now)
            environment: Environment to analyze
            
        Returns:
            Dictionary containing comprehensive historical analysis
        """
        # Set default date range (quarterly report)
        if end_date is None:
            end_date = datetime.now(timezone.utc)
        if start_date is None:
            start_date = end_date - timedelta(days=90)  # Quarterly assessment
        
        report = {
            "report_id": str(uuid.uuid4()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "report_period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "duration_days": (end_date - start_date).days
            },
            "environment": environment,
            "summary": {},
            "trend_analysis": {},
            "compliance_analysis": {},
            "recommendations": [],
            "data_quality": {}
        }
        
        try:
            # Retrieve historical data for report period
            data_points = self.retrieve_historical_data(
                start_date=start_date,
                end_date=end_date,
                environment=environment,
                limit=10000
            )
            
            report["summary"]["total_data_points"] = len(data_points)
            
            if not data_points:
                report["summary"]["status"] = "no_data"
                return report
            
            # Performance trend analysis
            key_metrics = ["api_response_time_p95", "throughput", "error_rate", "memory_usage", "cpu_utilization"]
            
            for metric in key_metrics:
                try:
                    trend_result = self.analyze_performance_trend(
                        TrendAnalysisType.PERFORMANCE_VARIANCE,
                        metric,
                        start_date,
                        end_date,
                        environment
                    )
                    
                    report["trend_analysis"][metric] = {
                        "trend_direction": trend_result.trend_direction,
                        "trend_magnitude": trend_result.trend_magnitude,
                        "mean_value": trend_result.mean_value,
                        "std_deviation": trend_result.std_deviation,
                        "action_required": trend_result.action_required,
                        "recommendations": trend_result.recommendations
                    }
                    
                except Exception as e:
                    report["trend_analysis"][metric] = {"error": str(e)}
            
            # Compliance analysis per Section 8.6.5
            variance_violations = 0
            compliance_violations = 0
            
            for data_point in data_points:
                if data_point.variance_percentage is not None:
                    if abs(data_point.variance_percentage) > 10.0:
                        variance_violations += 1
                
                if "compliance_violation" in data_point.compliance_tags:
                    compliance_violations += 1
            
            report["compliance_analysis"] = {
                "variance_violations": variance_violations,
                "variance_compliance_rate": ((len(data_points) - variance_violations) / len(data_points)) * 100 if data_points else 100,
                "compliance_violations": compliance_violations,
                "overall_compliance_rate": ((len(data_points) - compliance_violations) / len(data_points)) * 100 if data_points else 100
            }
            
            # Data quality assessment
            integrity_results = self.validate_data_integrity([dp.data_id for dp in data_points[:100]])  # Sample validation
            
            report["data_quality"] = {
                "integrity_percentage": integrity_results["integrity_percentage"],
                "validation_issues": len(integrity_results["integrity_issues"]),
                "data_freshness": "current",  # TODO: Calculate actual freshness
                "compression_efficiency": self._calculate_compression_efficiency(data_points)
            }
            
            # Generate recommendations based on analysis
            self._generate_report_recommendations(report)
            
            # Store report for future reference
            report_file = self.data_directory / f"historical_report_{report['report_id']}.json"
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            if STRUCTLOG_AVAILABLE:
                self.logger.info(
                    "Generated historical performance report",
                    report_id=report["report_id"],
                    data_points=len(data_points),
                    variance_compliance_rate=report["compliance_analysis"]["variance_compliance_rate"],
                    report_file=str(report_file)
                )
            
            return report
            
        except Exception as e:
            if STRUCTLOG_AVAILABLE:
                self.logger.error("Historical report generation failed", error=str(e))
            raise RuntimeError(f"Failed to generate historical report: {e}")
    
    def _calculate_compression_efficiency(self, data_points: List[HistoricalDataPoint]) -> float:
        """Calculate compression efficiency across data points."""
        total_original_size = 0
        total_compressed_size = 0
        
        for data_point in data_points:
            if data_point.compressed_size_bytes > 0:
                total_original_size += data_point.data_size_bytes or data_point.get_size_estimate()
                total_compressed_size += data_point.compressed_size_bytes
        
        if total_original_size == 0:
            return 0.0
        
        efficiency = (1 - (total_compressed_size / total_original_size)) * 100
        return max(0.0, efficiency)
    
    def _generate_report_recommendations(self, report: Dict[str, Any]) -> None:
        """Generate actionable recommendations based on historical report analysis."""
        recommendations = []
        
        # Variance compliance recommendations
        variance_compliance = report["compliance_analysis"]["variance_compliance_rate"]
        if variance_compliance < 95:
            recommendations.append({
                "category": "compliance",
                "priority": "high",
                "recommendation": f"Variance compliance rate ({variance_compliance:.1f}%) below 95% target - implement performance optimization measures"
            })
        
        # Trend-based recommendations
        degrading_metrics = []
        for metric, analysis in report["trend_analysis"].items():
            if isinstance(analysis, dict) and analysis.get("trend_direction") == "degrading":
                degrading_metrics.append(metric)
        
        if degrading_metrics:
            recommendations.append({
                "category": "performance",
                "priority": "medium",
                "recommendation": f"Degrading performance trends detected in: {', '.join(degrading_metrics)} - investigate root causes"
            })
        
        # Data quality recommendations
        integrity_pct = report["data_quality"]["integrity_percentage"]
        if integrity_pct < 99:
            recommendations.append({
                "category": "data_quality",
                "priority": "medium",
                "recommendation": f"Data integrity issues detected ({integrity_pct:.1f}%) - review data collection processes"
            })
        
        # Compression efficiency recommendations
        compression_efficiency = report["data_quality"]["compression_efficiency"]
        if compression_efficiency < 50:
            recommendations.append({
                "category": "optimization",
                "priority": "low",
                "recommendation": f"Low compression efficiency ({compression_efficiency:.1f}%) - consider optimizing data structure"
            })
        
        report["recommendations"] = recommendations
    
    def cleanup_and_optimize(self) -> Dict[str, Any]:
        """
        Perform comprehensive cleanup and optimization of historical data storage.
        
        Returns:
            Dictionary containing cleanup and optimization results
        """
        optimization_results = {
            "started_at": datetime.now(timezone.utc).isoformat(),
            "operations_performed": [],
            "storage_optimization": {},
            "performance_improvements": {},
            "errors": []
        }
        
        try:
            # Run data cleanup
            self._run_automated_cleanup()
            optimization_results["operations_performed"].append("automated_cleanup")
            
            # Run archival
            self._run_automated_archival()
            optimization_results["operations_performed"].append("automated_archival")
            
            # Optimize database
            with sqlite3.connect(self.database_path) as conn:
                # Vacuum database to reclaim space
                conn.execute("VACUUM")
                
                # Reindex for performance
                conn.execute("REINDEX")
                
                # Analyze for query optimization
                conn.execute("ANALYZE")
                
                optimization_results["operations_performed"].append("database_optimization")
            
            # Validate data integrity
            integrity_results = self.validate_data_integrity()
            optimization_results["data_integrity"] = integrity_results
            optimization_results["operations_performed"].append("integrity_validation")
            
            # Calculate storage statistics
            database_size = self.database_path.stat().st_size if self.database_path.exists() else 0
            optimization_results["storage_optimization"]["database_size_bytes"] = database_size
            
            # Update cache efficiency
            with self._cache_lock:
                cache_hit_rate = len(self._data_cache) / max(1, self._cache_max_size) * 100
                optimization_results["performance_improvements"]["cache_utilization"] = cache_hit_rate
            
            optimization_results["completed_at"] = datetime.now(timezone.utc).isoformat()
            optimization_results["status"] = "success"
            
            if STRUCTLOG_AVAILABLE:
                self.logger.info(
                    "Cleanup and optimization completed",
                    operations=len(optimization_results["operations_performed"]),
                    database_size_mb=database_size / (1024 * 1024),
                    integrity_percentage=integrity_results["integrity_percentage"]
                )
            
            return optimization_results
            
        except Exception as e:
            optimization_results["errors"].append(str(e))
            optimization_results["status"] = "failed"
            optimization_results["completed_at"] = datetime.now(timezone.utc).isoformat()
            
            if STRUCTLOG_AVAILABLE:
                self.logger.error("Cleanup and optimization failed", error=str(e))
            
            return optimization_results
    
    def close(self) -> None:
        """Clean shutdown of historical data manager."""
        self._background_tasks_enabled = False
        
        if hasattr(self, '_executor'):
            self._executor.shutdown(wait=True)
        
        if STRUCTLOG_AVAILABLE:
            self.logger.info("Historical data manager shutdown completed")


# Global historical data manager instance
_historical_manager: Optional[HistoricalDataManager] = None


def get_historical_data_manager() -> HistoricalDataManager:
    """
    Get global historical data manager instance (singleton pattern).
    
    Returns:
        HistoricalDataManager instance for historical data operations
    """
    global _historical_manager
    if _historical_manager is None:
        _historical_manager = HistoricalDataManager()
    return _historical_manager


def store_performance_data(
    performance_metrics: Dict[str, float],
    test_scenario: Optional[str] = None,
    environment: str = "production",
    baseline_comparison: Optional[Dict[str, Any]] = None
) -> str:
    """
    Store historical performance data with automatic compliance classification.
    
    Convenience function for storing performance data with full historical tracking,
    retention policy application, and compliance data classification per Section 8.6.5.
    
    Args:
        performance_metrics: Performance metrics dictionary
        test_scenario: Optional test scenario identifier
        environment: Environment name
        baseline_comparison: Optional baseline comparison results
        
    Returns:
        Data point ID for the stored record
    """
    manager = get_historical_data_manager()
    return manager.store_historical_data(
        performance_metrics=performance_metrics,
        test_scenario=test_scenario,
        environment=environment,
        baseline_comparison=baseline_comparison
    )


def analyze_historical_trend(
    metric_name: str,
    analysis_type: TrendAnalysisType = TrendAnalysisType.PERFORMANCE_VARIANCE,
    days_back: int = 30,
    environment: str = "production"
) -> TrendAnalysisResult:
    """
    Perform trend analysis on historical performance data.
    
    Convenience function for comprehensive trend analysis with pattern detection,
    baseline drift analysis, and automated recommendation generation.
    
    Args:
        metric_name: Name of the performance metric to analyze
        analysis_type: Type of trend analysis to perform
        days_back: Number of days to analyze (default 30)
        environment: Environment to analyze
        
    Returns:
        TrendAnalysisResult with comprehensive analysis and recommendations
    """
    manager = get_historical_data_manager()
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days_back)
    
    return manager.analyze_performance_trend(
        analysis_type=analysis_type,
        metric_name=metric_name,
        start_date=start_date,
        end_date=end_date,
        environment=environment
    )


def generate_quarterly_report(environment: str = "production") -> Dict[str, Any]:
    """
    Generate quarterly historical performance report per Section 6.6.3.
    
    Convenience function for comprehensive quarterly assessment reporting with
    trend analysis, compliance evaluation, and actionable recommendations.
    
    Args:
        environment: Environment to analyze
        
    Returns:
        Dictionary containing comprehensive quarterly analysis
    """
    manager = get_historical_data_manager()
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=90)  # Quarterly assessment
    
    return manager.generate_historical_report(
        start_date=start_date,
        end_date=end_date,
        environment=environment
    )


def validate_historical_integrity() -> Dict[str, Any]:
    """
    Validate historical data integrity across all stored records.
    
    Convenience function for comprehensive data integrity validation with
    hash verification, format validation, and corruption detection.
    
    Returns:
        Dictionary containing validation results and integrity statistics
    """
    manager = get_historical_data_manager()
    return manager.validate_data_integrity()


def optimize_historical_storage() -> Dict[str, Any]:
    """
    Perform comprehensive optimization of historical data storage.
    
    Convenience function for automated cleanup, archival, compression optimization,
    and database maintenance per Section 8.6.5 archival policies.
    
    Returns:
        Dictionary containing optimization results and performance improvements
    """
    manager = get_historical_data_manager()
    return manager.cleanup_and_optimize()


# Export public interface
__all__ = [
    # Core classes
    'HistoricalDataManager',
    'HistoricalDataPoint',
    'TrendAnalysisResult',
    'RetentionPolicy',
    
    # Enumerations
    'DataRetentionLevel',
    'DataCompressionType',
    'ArchivalStatus',
    'TrendAnalysisType',
    
    # Convenience functions
    'get_historical_data_manager',
    'store_performance_data',
    'analyze_historical_trend',
    'generate_quarterly_report',
    'validate_historical_integrity',
    'optimize_historical_storage'
]