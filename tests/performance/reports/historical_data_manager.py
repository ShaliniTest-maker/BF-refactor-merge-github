"""
Historical Performance Data Management Module

This module provides comprehensive historical performance data management for the Flask migration
project, implementing data storage, retrieval, archival, and analysis capabilities. Maintains
comprehensive performance history for trend analysis and long-term optimization per technical
specification requirements.

Key Features:
- Historical performance data storage and management per Section 6.6.3
- Data retention and archival policies per Section 8.6.5 (90-day active retention)
- Performance data aggregation and analysis per Section 6.5.5
- Data integrity validation and backup procedures per Section 8.6.5
- Data compression and optimization for long-term storage
- Automated data cleanup and maintenance per Section 8.6.5
- Compliance data classification and audit trail support

Architecture Integration:
- Section 6.6.3: Historical trend analysis for performance optimization
- Section 8.6.5: Log retention and archival policies with AWS S3 integration
- Section 6.5.5: Improvement tracking and continuous optimization
- Section 8.6.5: Audit framework and compliance data classification

Author: Flask Migration Team
Version: 1.0.0
Dependencies: boto3 ≥1.28+, structlog ≥23.1+, python-dateutil ≥2.8+
"""

import gzip
import json
import logging
import os
import shutil
import statistics
import tempfile
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union, NamedTuple
from dataclasses import dataclass, field, asdict
from enum import Enum
import hashlib
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

# Core dependencies
try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False
    import logging as structlog

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False
    boto3 = None
    ClientError = Exception
    NoCredentialsError = Exception

try:
    from dateutil.parser import parse as parse_datetime
    from dateutil.relativedelta import relativedelta
    DATEUTIL_AVAILABLE = True
except ImportError:
    DATEUTIL_AVAILABLE = False
    relativedelta = None

# Internal dependencies
from tests.performance.baseline_data import (
    BaselineDataManager, ResponseTimeBaseline, ResourceUtilizationBaseline,
    DatabasePerformanceBaseline, ThroughputBaseline, NetworkIOBaseline,
    PERFORMANCE_VARIANCE_THRESHOLD, MEMORY_VARIANCE_THRESHOLD,
    default_baseline_manager
)
from tests.performance.performance_config import (
    PerformanceConfigFactory, BasePerformanceConfig, PerformanceThreshold,
    BaselineMetrics, LoadTestConfiguration
)


# Historical data management constants per Section 8.6.5
ACTIVE_RETENTION_DAYS = 90                    # 90-day active retention
ARCHIVE_RETENTION_YEARS = 7                   # 7-year archive retention
COMPRESSION_THRESHOLD_MB = 50                 # Compress files >50MB
CLEANUP_BATCH_SIZE = 1000                     # Cleanup operations batch size
DATA_INTEGRITY_CHECK_INTERVAL = 24           # Hours between integrity checks
BACKUP_VERIFICATION_INTERVAL = 168           # Hours (7 days) between backup verification

# Performance data classification per Section 8.6.5
DATA_CLASSIFICATION_LEVELS = {
    'PUBLIC': 0,
    'INTERNAL': 1,
    'CONFIDENTIAL': 2,
    'RESTRICTED': 3
}

RETENTION_POLICIES_BY_LEVEL = {
    'DEBUG': timedelta(days=7),                # Debug data: 7 days
    'INFO': timedelta(days=30),                # Info data: 30 days  
    'WARNING': timedelta(days=60),             # Warning data: 60 days
    'ERROR': timedelta(days=90),               # Error data: 90 days
    'CRITICAL': timedelta(days=365),           # Critical data: 365 days
    'PERFORMANCE': timedelta(days=90),         # Performance data: 90 days
    'COMPLIANCE': timedelta(days=2555)         # Compliance data: 7 years
}


class DataClassification(Enum):
    """Data classification levels per Section 8.6.5 compliance framework."""
    
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class RetentionPolicy(Enum):
    """Data retention policy enumeration per Section 8.6.5."""
    
    DEBUG = "debug"           # 7 days
    INFO = "info"             # 30 days
    WARNING = "warning"       # 60 days
    ERROR = "error"           # 90 days
    CRITICAL = "critical"     # 365 days
    PERFORMANCE = "performance"  # 90 days
    COMPLIANCE = "compliance"    # 7 years


class ArchiveStatus(Enum):
    """Archive status enumeration for data lifecycle management."""
    
    ACTIVE = "active"
    ARCHIVED = "archived"
    COMPRESSED = "compressed"
    VERIFIED = "verified"
    CORRUPTED = "corrupted"
    EXPIRED = "expired"


@dataclass
class HistoricalDataRecord:
    """
    Historical performance data record with metadata for comprehensive tracking.
    
    Supports Section 6.6.3 historical trend analysis and Section 8.6.5 audit framework.
    """
    
    record_id: str
    timestamp: datetime
    data_type: str  # 'response_time', 'resource_usage', 'throughput', etc.
    performance_data: Dict[str, Any]
    baseline_comparison: Optional[Dict[str, Any]] = None
    variance_analysis: Optional[Dict[str, Any]] = None
    test_environment: str = "unknown"
    test_configuration: Optional[Dict[str, Any]] = None
    data_classification: DataClassification = DataClassification.INTERNAL
    retention_policy: RetentionPolicy = RetentionPolicy.PERFORMANCE
    archive_status: ArchiveStatus = ArchiveStatus.ACTIVE
    checksum: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Calculate checksum for data integrity validation."""
        if self.checksum is None:
            self.checksum = self._calculate_checksum()
    
    def _calculate_checksum(self) -> str:
        """Calculate SHA-256 checksum for data integrity validation."""
        data_for_checksum = {
            'record_id': self.record_id,
            'timestamp': self.timestamp.isoformat(),
            'data_type': self.data_type,
            'performance_data': self.performance_data
        }
        data_json = json.dumps(data_for_checksum, sort_keys=True)
        return hashlib.sha256(data_json.encode()).hexdigest()
    
    def validate_integrity(self) -> bool:
        """
        Validate data integrity using checksum verification.
        
        Returns:
            True if data integrity is valid, False if corrupted
        """
        current_checksum = self._calculate_checksum()
        return current_checksum == self.checksum
    
    def is_expired(self) -> bool:
        """
        Check if record has exceeded retention policy.
        
        Returns:
            True if record should be archived or deleted
        """
        retention_period = RETENTION_POLICIES_BY_LEVEL.get(
            self.retention_policy.value.upper(),
            timedelta(days=90)
        )
        expiry_date = self.timestamp + retention_period
        return datetime.now(timezone.utc) > expiry_date
    
    def should_compress(self) -> bool:
        """
        Check if record should be compressed based on age and size.
        
        Returns:
            True if record should be compressed for storage optimization
        """
        # Compress records older than 30 days
        compression_age = timedelta(days=30)
        age_threshold = datetime.now(timezone.utc) - compression_age
        return self.timestamp < age_threshold
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert record to dictionary for serialization."""
        return {
            'record_id': self.record_id,
            'timestamp': self.timestamp.isoformat(),
            'data_type': self.data_type,
            'performance_data': self.performance_data,
            'baseline_comparison': self.baseline_comparison,
            'variance_analysis': self.variance_analysis,
            'test_environment': self.test_environment,
            'test_configuration': self.test_configuration,
            'data_classification': self.data_classification.value,
            'retention_policy': self.retention_policy.value,
            'archive_status': self.archive_status.value,
            'checksum': self.checksum,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HistoricalDataRecord':
        """Create record from dictionary."""
        # Parse timestamp
        timestamp = data['timestamp']
        if isinstance(timestamp, str):
            if DATEUTIL_AVAILABLE:
                timestamp = parse_datetime(timestamp)
            else:
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        
        return cls(
            record_id=data['record_id'],
            timestamp=timestamp,
            data_type=data['data_type'],
            performance_data=data['performance_data'],
            baseline_comparison=data.get('baseline_comparison'),
            variance_analysis=data.get('variance_analysis'),
            test_environment=data.get('test_environment', 'unknown'),
            test_configuration=data.get('test_configuration'),
            data_classification=DataClassification(data.get('data_classification', 'internal')),
            retention_policy=RetentionPolicy(data.get('retention_policy', 'performance')),
            archive_status=ArchiveStatus(data.get('archive_status', 'active')),
            checksum=data.get('checksum'),
            metadata=data.get('metadata', {})
        )


@dataclass
class TrendAnalysisResult:
    """
    Performance trend analysis result for improvement tracking.
    
    Supports Section 6.5.5 improvement tracking and continuous optimization.
    """
    
    metric_name: str
    analysis_period: Tuple[datetime, datetime]
    trend_direction: str  # 'improving', 'degrading', 'stable'
    trend_percentage: float
    confidence_level: float
    data_points: int
    statistical_summary: Dict[str, float]
    variance_from_baseline: Optional[float] = None
    recommendations: List[str] = field(default_factory=list)
    compliance_status: bool = True
    
    def __post_init__(self):
        """Validate trend analysis result."""
        if not 0 <= self.confidence_level <= 1.0:
            raise ValueError("Confidence level must be between 0 and 1")
        if self.data_points < 2:
            raise ValueError("Trend analysis requires at least 2 data points")


@dataclass
class ArchiveMetadata:
    """
    Archive metadata for AWS S3 storage tracking per Section 8.6.5.
    """
    
    archive_id: str
    original_path: str
    s3_bucket: str
    s3_key: str
    archive_timestamp: datetime
    compressed_size: int
    original_size: int
    compression_ratio: float
    record_count: int
    checksum: str
    retention_until: datetime
    access_tier: str = "STANDARD"  # S3 storage class
    
    def __post_init__(self):
        """Calculate compression ratio."""
        if self.original_size > 0:
            self.compression_ratio = (1 - self.compressed_size / self.original_size) * 100
        else:
            self.compression_ratio = 0.0


class HistoricalDataManager:
    """
    Comprehensive historical performance data management system.
    
    Provides storage, retrieval, archival, and analysis capabilities for historical
    performance data supporting Section 6.6.3 trend analysis, Section 8.6.5 
    retention policies, and Section 6.5.5 improvement tracking.
    """
    
    def __init__(
        self,
        storage_path: str = "data/performance/historical",
        archive_path: str = "data/performance/archive",
        aws_s3_bucket: Optional[str] = None,
        aws_region: str = "us-east-1",
        enable_compression: bool = True,
        enable_archival: bool = True,
        max_workers: int = 4
    ):
        """
        Initialize historical data manager with storage and archival configuration.
        
        Args:
            storage_path: Local storage path for active historical data
            archive_path: Local path for compressed archives
            aws_s3_bucket: AWS S3 bucket name for long-term archival
            aws_region: AWS region for S3 operations
            enable_compression: Enable data compression for storage optimization
            enable_archival: Enable automatic archival to AWS S3
            max_workers: Maximum worker threads for concurrent operations
        """
        self.storage_path = Path(storage_path)
        self.archive_path = Path(archive_path)
        self.aws_s3_bucket = aws_s3_bucket
        self.aws_region = aws_region
        self.enable_compression = enable_compression
        self.enable_archival = enable_archival
        self.max_workers = max_workers
        
        # Create storage directories
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.archive_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize AWS S3 client if available and configured
        self.s3_client = None
        if AWS_AVAILABLE and self.aws_s3_bucket:
            try:
                self.s3_client = boto3.client('s3', region_name=aws_region)
                self._verify_s3_bucket()
            except (NoCredentialsError, ClientError) as e:
                logging.warning(f"AWS S3 initialization failed: {e}")
                self.enable_archival = False
        
        # Initialize logging
        if STRUCTLOG_AVAILABLE:
            self.logger = structlog.get_logger(__name__)
        else:
            self.logger = logging.getLogger(__name__)
        
        # Initialize baseline data manager integration
        self.baseline_manager = default_baseline_manager
        
        # Initialize performance configuration
        self.performance_config = PerformanceConfigFactory.get_config()
        
        # Internal state management
        self._records_cache: Dict[str, HistoricalDataRecord] = {}
        self._cache_lock = threading.Lock()
        self._last_cleanup = datetime.now(timezone.utc)
        self._last_integrity_check = datetime.now(timezone.utc)
        
        # Archive metadata tracking
        self.archive_metadata: Dict[str, ArchiveMetadata] = {}
        self._load_archive_metadata()
    
    def _verify_s3_bucket(self) -> None:
        """Verify AWS S3 bucket accessibility."""
        if not self.s3_client:
            return
        
        try:
            self.s3_client.head_bucket(Bucket=self.aws_s3_bucket)
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == '404':
                raise ValueError(f"S3 bucket '{self.aws_s3_bucket}' not found")
            else:
                raise ValueError(f"S3 bucket access error: {e}")
    
    def _load_archive_metadata(self) -> None:
        """Load archive metadata from persistent storage."""
        metadata_file = self.archive_path / "archive_metadata.json"
        if metadata_file.exists():
            try:
                with open(metadata_file, 'r') as f:
                    data = json.load(f)
                    for archive_id, metadata_dict in data.items():
                        # Parse timestamps
                        metadata_dict['archive_timestamp'] = datetime.fromisoformat(
                            metadata_dict['archive_timestamp']
                        )
                        metadata_dict['retention_until'] = datetime.fromisoformat(
                            metadata_dict['retention_until']
                        )
                        self.archive_metadata[archive_id] = ArchiveMetadata(**metadata_dict)
            except Exception as e:
                self.logger.warning(f"Failed to load archive metadata: {e}")
    
    def _save_archive_metadata(self) -> None:
        """Save archive metadata to persistent storage."""
        metadata_file = self.archive_path / "archive_metadata.json"
        try:
            data = {}
            for archive_id, metadata in self.archive_metadata.items():
                metadata_dict = asdict(metadata)
                # Convert timestamps to ISO format
                metadata_dict['archive_timestamp'] = metadata.archive_timestamp.isoformat()
                metadata_dict['retention_until'] = metadata.retention_until.isoformat()
                data[archive_id] = metadata_dict
            
            with open(metadata_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save archive metadata: {e}")
    
    def store_performance_data(
        self,
        data_type: str,
        performance_data: Dict[str, Any],
        test_environment: str = "unknown",
        test_configuration: Optional[Dict[str, Any]] = None,
        classification: DataClassification = DataClassification.INTERNAL,
        retention_policy: RetentionPolicy = RetentionPolicy.PERFORMANCE
    ) -> str:
        """
        Store historical performance data with baseline comparison and variance analysis.
        
        Args:
            data_type: Type of performance data ('response_time', 'resource_usage', etc.)
            performance_data: Performance metrics dictionary
            test_environment: Test environment name
            test_configuration: Test configuration parameters
            classification: Data classification level per Section 8.6.5
            retention_policy: Data retention policy per Section 8.6.5
            
        Returns:
            Record ID for the stored performance data
        """
        # Generate unique record ID
        record_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc)
        
        # Perform baseline comparison and variance analysis
        baseline_comparison = self._perform_baseline_comparison(data_type, performance_data)
        variance_analysis = self._calculate_variance_analysis(performance_data, baseline_comparison)
        
        # Create historical data record
        record = HistoricalDataRecord(
            record_id=record_id,
            timestamp=timestamp,
            data_type=data_type,
            performance_data=performance_data,
            baseline_comparison=baseline_comparison,
            variance_analysis=variance_analysis,
            test_environment=test_environment,
            test_configuration=test_configuration,
            data_classification=classification,
            retention_policy=retention_policy
        )
        
        # Store record to disk
        self._persist_record(record)
        
        # Update cache
        with self._cache_lock:
            self._records_cache[record_id] = record
        
        # Log storage event
        self.logger.info(
            "Historical performance data stored",
            record_id=record_id,
            data_type=data_type,
            environment=test_environment,
            classification=classification.value,
            retention_policy=retention_policy.value
        )
        
        return record_id
    
    def _perform_baseline_comparison(
        self,
        data_type: str,
        performance_data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Perform baseline comparison against Node.js performance metrics.
        
        Args:
            data_type: Type of performance data
            performance_data: Current performance metrics
            
        Returns:
            Baseline comparison results or None if no baseline available
        """
        try:
            if data_type == "response_time" and "endpoint" in performance_data:
                baseline = self.baseline_manager.get_response_time_baseline(
                    performance_data["endpoint"],
                    performance_data.get("method", "GET")
                )
                if baseline:
                    return {
                        "baseline_mean_ms": baseline.mean_response_time_ms,
                        "baseline_p95_ms": baseline.p95_response_time_ms,
                        "baseline_sample_count": baseline.sample_count,
                        "comparison_timestamp": datetime.now(timezone.utc).isoformat()
                    }
            
            elif data_type == "resource_usage":
                avg_baseline = self.baseline_manager.get_average_resource_utilization()
                if avg_baseline:
                    return {
                        "baseline_cpu_percent": avg_baseline.cpu_utilization_percent,
                        "baseline_memory_mb": avg_baseline.memory_usage_mb,
                        "baseline_memory_percent": avg_baseline.memory_utilization_percent,
                        "comparison_timestamp": datetime.now(timezone.utc).isoformat()
                    }
            
            elif data_type == "throughput":
                peak_baseline = self.baseline_manager.get_peak_throughput_baseline()
                if peak_baseline:
                    return {
                        "baseline_rps": peak_baseline.requests_per_second,
                        "baseline_concurrent_users": peak_baseline.concurrent_users,
                        "baseline_error_rate": peak_baseline.error_rate_percent,
                        "comparison_timestamp": datetime.now(timezone.utc).isoformat()
                    }
            
            return None
            
        except Exception as e:
            self.logger.warning(f"Baseline comparison failed: {e}")
            return None
    
    def _calculate_variance_analysis(
        self,
        performance_data: Dict[str, Any],
        baseline_comparison: Optional[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """
        Calculate performance variance analysis against baseline.
        
        Args:
            performance_data: Current performance metrics
            baseline_comparison: Baseline comparison data
            
        Returns:
            Variance analysis results or None if no baseline available
        """
        if not baseline_comparison:
            return None
        
        try:
            variance_analysis = {
                "compliance_status": True,
                "variances": {},
                "overall_variance": 0.0,
                "critical_issues": [],
                "warnings": []
            }
            
            variances = []
            
            # Response time variance analysis
            if "response_time_ms" in performance_data and "baseline_mean_ms" in baseline_comparison:
                variance = self.baseline_manager.calculate_variance_percentage(
                    baseline_comparison["baseline_mean_ms"],
                    performance_data["response_time_ms"]
                )
                variances.append(abs(variance))
                variance_analysis["variances"]["response_time"] = variance
                
                if abs(variance) > PERFORMANCE_VARIANCE_THRESHOLD:
                    variance_analysis["compliance_status"] = False
                    variance_analysis["critical_issues"].append(
                        f"Response time variance {variance:.2f}% exceeds {PERFORMANCE_VARIANCE_THRESHOLD}% threshold"
                    )
                elif abs(variance) > 5.0:  # Warning threshold
                    variance_analysis["warnings"].append(
                        f"Response time variance {variance:.2f}% approaching threshold"
                    )
            
            # CPU utilization variance analysis
            if "cpu_utilization_percent" in performance_data and "baseline_cpu_percent" in baseline_comparison:
                variance = self.baseline_manager.calculate_variance_percentage(
                    baseline_comparison["baseline_cpu_percent"],
                    performance_data["cpu_utilization_percent"]
                )
                variances.append(abs(variance))
                variance_analysis["variances"]["cpu_utilization"] = variance
                
                if abs(variance) > PERFORMANCE_VARIANCE_THRESHOLD:
                    variance_analysis["compliance_status"] = False
                    variance_analysis["critical_issues"].append(
                        f"CPU utilization variance {variance:.2f}% exceeds threshold"
                    )
            
            # Memory usage variance analysis (±15% threshold per specification)
            if "memory_usage_mb" in performance_data and "baseline_memory_mb" in baseline_comparison:
                variance = self.baseline_manager.calculate_variance_percentage(
                    baseline_comparison["baseline_memory_mb"],
                    performance_data["memory_usage_mb"]
                )
                variances.append(abs(variance))
                variance_analysis["variances"]["memory_usage"] = variance
                
                if abs(variance) > MEMORY_VARIANCE_THRESHOLD:
                    variance_analysis["compliance_status"] = False
                    variance_analysis["critical_issues"].append(
                        f"Memory usage variance {variance:.2f}% exceeds {MEMORY_VARIANCE_THRESHOLD}% threshold"
                    )
            
            # Throughput variance analysis
            if "requests_per_second" in performance_data and "baseline_rps" in baseline_comparison:
                variance = self.baseline_manager.calculate_variance_percentage(
                    baseline_comparison["baseline_rps"],
                    performance_data["requests_per_second"]
                )
                variances.append(abs(variance))
                variance_analysis["variances"]["throughput"] = variance
                
                if abs(variance) > PERFORMANCE_VARIANCE_THRESHOLD:
                    variance_analysis["compliance_status"] = False
                    variance_analysis["critical_issues"].append(
                        f"Throughput variance {variance:.2f}% exceeds threshold"
                    )
            
            # Calculate overall variance (average of all variances)
            if variances:
                variance_analysis["overall_variance"] = statistics.mean(variances)
            
            return variance_analysis
            
        except Exception as e:
            self.logger.warning(f"Variance analysis failed: {e}")
            return None
    
    def _persist_record(self, record: HistoricalDataRecord) -> None:
        """
        Persist historical data record to disk storage.
        
        Args:
            record: Historical data record to persist
        """
        # Organize by date and data type for efficient retrieval
        date_str = record.timestamp.strftime("%Y/%m/%d")
        record_dir = self.storage_path / record.data_type / date_str
        record_dir.mkdir(parents=True, exist_ok=True)
        
        # Save record as JSON file
        record_file = record_dir / f"{record.record_id}.json"
        
        try:
            with open(record_file, 'w') as f:
                json.dump(record.to_dict(), f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to persist record {record.record_id}: {e}")
            raise
    
    def retrieve_records(
        self,
        data_type: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        environment: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List[HistoricalDataRecord]:
        """
        Retrieve historical performance data records with filtering.
        
        Args:
            data_type: Filter by data type
            start_date: Start date for time range filtering
            end_date: End date for time range filtering
            environment: Filter by test environment
            limit: Maximum number of records to return
            
        Returns:
            List of historical data records matching criteria
        """
        records = []
        
        # Search through storage directory structure
        for data_type_path in self.storage_path.iterdir():
            if data_type and data_type_path.name != data_type:
                continue
            
            if not data_type_path.is_dir():
                continue
            
            # Traverse date hierarchy
            for year_path in data_type_path.iterdir():
                if not year_path.is_dir():
                    continue
                
                for month_path in year_path.iterdir():
                    if not month_path.is_dir():
                        continue
                    
                    for day_path in month_path.iterdir():
                        if not day_path.is_dir():
                            continue
                        
                        # Check if date is within range
                        try:
                            date_str = f"{year_path.name}/{month_path.name}/{day_path.name}"
                            record_date = datetime.strptime(date_str, "%Y/%m/%d").replace(tzinfo=timezone.utc)
                            
                            if start_date and record_date < start_date:
                                continue
                            if end_date and record_date > end_date:
                                continue
                        except ValueError:
                            continue
                        
                        # Load records from day directory
                        for record_file in day_path.glob("*.json"):
                            try:
                                with open(record_file, 'r') as f:
                                    record_data = json.load(f)
                                    record = HistoricalDataRecord.from_dict(record_data)
                                    
                                    # Apply environment filter
                                    if environment and record.test_environment != environment:
                                        continue
                                    
                                    records.append(record)
                                    
                                    # Apply limit
                                    if limit and len(records) >= limit:
                                        return sorted(records, key=lambda r: r.timestamp, reverse=True)[:limit]
                                        
                            except Exception as e:
                                self.logger.warning(f"Failed to load record from {record_file}: {e}")
        
        # Sort by timestamp (newest first) and apply limit
        records.sort(key=lambda r: r.timestamp, reverse=True)
        if limit:
            records = records[:limit]
        
        return records
    
    def analyze_performance_trends(
        self,
        metric_name: str,
        data_type: str,
        analysis_days: int = 30,
        environment: Optional[str] = None
    ) -> TrendAnalysisResult:
        """
        Analyze performance trends for continuous optimization per Section 6.5.5.
        
        Args:
            metric_name: Name of the performance metric to analyze
            data_type: Type of performance data to analyze
            analysis_days: Number of days to include in trend analysis
            environment: Optional environment filter
            
        Returns:
            Trend analysis result with recommendations
        """
        # Calculate analysis period
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=analysis_days)
        
        # Retrieve relevant records
        records = self.retrieve_records(
            data_type=data_type,
            start_date=start_date,
            end_date=end_date,
            environment=environment
        )
        
        if len(records) < 2:
            raise ValueError(f"Insufficient data points for trend analysis: {len(records)}")
        
        # Extract metric values and timestamps
        metric_values = []
        timestamps = []
        
        for record in records:
            if metric_name in record.performance_data:
                metric_values.append(record.performance_data[metric_name])
                timestamps.append(record.timestamp)
        
        if len(metric_values) < 2:
            raise ValueError(f"Insufficient metric data points for {metric_name}: {len(metric_values)}")
        
        # Sort by timestamp for trend analysis
        sorted_data = sorted(zip(timestamps, metric_values), key=lambda x: x[0])
        timestamps, metric_values = zip(*sorted_data)
        
        # Calculate statistical summary
        statistical_summary = {
            'count': len(metric_values),
            'mean': statistics.mean(metric_values),
            'median': statistics.median(metric_values),
            'std_dev': statistics.stdev(metric_values) if len(metric_values) > 1 else 0.0,
            'min': min(metric_values),
            'max': max(metric_values),
            'range': max(metric_values) - min(metric_values)
        }
        
        # Calculate trend direction and percentage
        first_value = metric_values[0]
        last_value = metric_values[-1]
        trend_percentage = ((last_value - first_value) / first_value) * 100 if first_value != 0 else 0.0
        
        # Determine trend direction
        if abs(trend_percentage) < 2.0:  # Within 2% considered stable
            trend_direction = "stable"
        elif trend_percentage > 0:
            # For response time, CPU, memory: positive = degrading
            # For throughput: positive = improving
            if metric_name in ['response_time_ms', 'cpu_utilization_percent', 'memory_usage_mb']:
                trend_direction = "degrading"
            else:
                trend_direction = "improving"
        else:
            # For response time, CPU, memory: negative = improving
            # For throughput: negative = degrading
            if metric_name in ['response_time_ms', 'cpu_utilization_percent', 'memory_usage_mb']:
                trend_direction = "improving"
            else:
                trend_direction = "degrading"
        
        # Calculate confidence level based on data consistency
        if len(metric_values) >= 10:
            cv = statistical_summary['std_dev'] / statistical_summary['mean'] if statistical_summary['mean'] != 0 else 0
            confidence_level = max(0.5, 1.0 - cv)  # Higher confidence with lower coefficient of variation
        else:
            confidence_level = 0.6  # Lower confidence with limited data
        
        # Calculate variance from baseline if available
        variance_from_baseline = None
        latest_record = records[0]  # Records are sorted newest first
        if latest_record.variance_analysis and metric_name in latest_record.variance_analysis.get('variances', {}):
            variance_from_baseline = latest_record.variance_analysis['variances'][metric_name]
        
        # Generate recommendations
        recommendations = self._generate_trend_recommendations(
            metric_name, trend_direction, trend_percentage, variance_from_baseline
        )
        
        # Check compliance status
        compliance_status = True
        if variance_from_baseline is not None:
            threshold = MEMORY_VARIANCE_THRESHOLD if 'memory' in metric_name.lower() else PERFORMANCE_VARIANCE_THRESHOLD
            compliance_status = abs(variance_from_baseline) <= threshold
        
        return TrendAnalysisResult(
            metric_name=metric_name,
            analysis_period=(start_date, end_date),
            trend_direction=trend_direction,
            trend_percentage=trend_percentage,
            confidence_level=confidence_level,
            data_points=len(metric_values),
            statistical_summary=statistical_summary,
            variance_from_baseline=variance_from_baseline,
            recommendations=recommendations,
            compliance_status=compliance_status
        )
    
    def _generate_trend_recommendations(
        self,
        metric_name: str,
        trend_direction: str,
        trend_percentage: float,
        variance_from_baseline: Optional[float]
    ) -> List[str]:
        """
        Generate optimization recommendations based on trend analysis.
        
        Args:
            metric_name: Name of the performance metric
            trend_direction: Trend direction ('improving', 'degrading', 'stable')
            trend_percentage: Trend percentage change
            variance_from_baseline: Variance from Node.js baseline
            
        Returns:
            List of optimization recommendations
        """
        recommendations = []
        
        # Response time recommendations
        if metric_name == 'response_time_ms':
            if trend_direction == 'degrading':
                recommendations.extend([
                    "Response time is degrading - investigate performance bottlenecks",
                    "Consider optimizing database queries and connection pooling",
                    "Review Flask middleware stack for performance overhead",
                    "Analyze memory usage patterns and garbage collection impact"
                ])
            elif trend_direction == 'stable' and variance_from_baseline and abs(variance_from_baseline) > 5:
                recommendations.append("Response time stable but variance exceeds 5% - monitor closely")
            elif trend_direction == 'improving':
                recommendations.append("Response time improving - continue current optimization strategy")
        
        # CPU utilization recommendations
        elif metric_name == 'cpu_utilization_percent':
            if trend_direction == 'degrading':
                recommendations.extend([
                    "CPU utilization increasing - investigate computational bottlenecks",
                    "Consider horizontal scaling or worker pool optimization",
                    "Review business logic efficiency and algorithmic complexity",
                    "Analyze concurrency patterns and thread contention"
                ])
            elif trend_percentage > 50:  # High CPU usage
                recommendations.extend([
                    "High CPU utilization detected - immediate optimization required",
                    "Consider load balancing and horizontal scaling",
                    "Profile CPU-intensive operations for optimization opportunities"
                ])
        
        # Memory usage recommendations
        elif metric_name == 'memory_usage_mb':
            if trend_direction == 'degrading':
                recommendations.extend([
                    "Memory usage increasing - investigate memory leaks",
                    "Review object lifecycle management and garbage collection",
                    "Optimize data structures and caching strategies",
                    "Consider memory profiling and heap analysis"
                ])
            elif variance_from_baseline and abs(variance_from_baseline) > MEMORY_VARIANCE_THRESHOLD:
                recommendations.append("Memory usage variance exceeds ±15% threshold - immediate investigation required")
        
        # Throughput recommendations
        elif metric_name == 'requests_per_second':
            if trend_direction == 'degrading':
                recommendations.extend([
                    "Throughput decreasing - investigate performance degradation",
                    "Review connection pooling and resource utilization",
                    "Consider scaling strategies and load balancing optimization",
                    "Analyze request processing pipeline for bottlenecks"
                ])
            elif trend_direction == 'improving':
                recommendations.append("Throughput improving - continue optimization efforts")
        
        # Compliance and variance recommendations
        if variance_from_baseline is not None:
            threshold = MEMORY_VARIANCE_THRESHOLD if 'memory' in metric_name.lower() else PERFORMANCE_VARIANCE_THRESHOLD
            if abs(variance_from_baseline) > threshold:
                recommendations.insert(0, f"CRITICAL: {metric_name} variance {variance_from_baseline:.2f}% exceeds {threshold}% threshold")
                recommendations.append("Consider reverting to Node.js baseline until performance issues resolved")
            elif abs(variance_from_baseline) > 5:
                recommendations.append("Performance variance approaching critical threshold - proactive optimization recommended")
        
        # General recommendations if no specific ones generated
        if not recommendations:
            recommendations.append(f"{metric_name} performance is {trend_direction} - continue monitoring")
        
        return recommendations
    
    def compress_historical_data(
        self,
        days_old: int = 30,
        batch_size: int = 100
    ) -> Dict[str, Any]:
        """
        Compress historical data for storage optimization per Section 6.5.5.
        
        Args:
            days_old: Compress data older than specified days
            batch_size: Number of records to process in each batch
            
        Returns:
            Compression summary with statistics
        """
        compression_summary = {
            'files_processed': 0,
            'files_compressed': 0,
            'original_size_mb': 0.0,
            'compressed_size_mb': 0.0,
            'compression_ratio': 0.0,
            'errors': []
        }
        
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_old)
        
        # Find files eligible for compression
        files_to_compress = []
        for data_type_path in self.storage_path.iterdir():
            if not data_type_path.is_dir():
                continue
            
            for root, dirs, files in os.walk(data_type_path):
                root_path = Path(root)
                for file in files:
                    if file.endswith('.json'):
                        file_path = root_path / file
                        
                        # Check file modification time
                        try:
                            mtime = datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc)
                            if mtime < cutoff_date:
                                files_to_compress.append(file_path)
                        except Exception as e:
                            compression_summary['errors'].append(f"Error checking {file_path}: {e}")
        
        # Process files in batches
        processed_files = 0
        for i in range(0, len(files_to_compress), batch_size):
            batch = files_to_compress[i:i + batch_size]
            
            for file_path in batch:
                try:
                    original_size = file_path.stat().st_size
                    compression_summary['original_size_mb'] += original_size / (1024 * 1024)
                    
                    # Compress file
                    compressed_path = file_path.with_suffix('.json.gz')
                    
                    with open(file_path, 'rb') as f_in:
                        with gzip.open(compressed_path, 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    
                    compressed_size = compressed_path.stat().st_size
                    compression_summary['compressed_size_mb'] += compressed_size / (1024 * 1024)
                    
                    # Remove original file
                    file_path.unlink()
                    
                    compression_summary['files_compressed'] += 1
                    
                except Exception as e:
                    compression_summary['errors'].append(f"Error compressing {file_path}: {e}")
                
                compression_summary['files_processed'] += 1
            
            processed_files += len(batch)
            
            # Log progress
            if processed_files % (batch_size * 10) == 0:
                self.logger.info(f"Compression progress: {processed_files}/{len(files_to_compress)} files processed")
        
        # Calculate compression ratio
        if compression_summary['original_size_mb'] > 0:
            compression_summary['compression_ratio'] = (
                1 - compression_summary['compressed_size_mb'] / compression_summary['original_size_mb']
            ) * 100
        
        self.logger.info(
            "Data compression completed",
            files_processed=compression_summary['files_processed'],
            files_compressed=compression_summary['files_compressed'],
            compression_ratio=f"{compression_summary['compression_ratio']:.2f}%",
            errors=len(compression_summary['errors'])
        )
        
        return compression_summary
    
    def archive_to_s3(
        self,
        retention_days: int = ACTIVE_RETENTION_DAYS,
        storage_class: str = "STANDARD_IA"
    ) -> Dict[str, Any]:
        """
        Archive historical data to AWS S3 per Section 8.6.5 archival policies.
        
        Args:
            retention_days: Archive data older than specified days
            storage_class: S3 storage class for archived data
            
        Returns:
            Archive operation summary
        """
        if not self.enable_archival or not self.s3_client:
            raise ValueError("S3 archival not enabled or configured")
        
        archive_summary = {
            'archives_created': 0,
            'files_archived': 0,
            'total_size_mb': 0.0,
            'errors': []
        }
        
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
        
        # Group files by data type and month for efficient archiving
        archive_groups = defaultdict(list)
        
        for data_type_path in self.storage_path.iterdir():
            if not data_type_path.is_dir():
                continue
            
            for year_path in data_type_path.iterdir():
                if not year_path.is_dir():
                    continue
                
                for month_path in year_path.iterdir():
                    if not month_path.is_dir():
                        continue
                    
                    # Check if month is older than retention period
                    try:
                        month_date = datetime.strptime(f"{year_path.name}/{month_path.name}/01", "%Y/%m/%d")
                        month_date = month_date.replace(tzinfo=timezone.utc)
                        
                        if month_date < cutoff_date:
                            archive_key = f"{data_type_path.name}/{year_path.name}/{month_path.name}"
                            archive_groups[archive_key].append(month_path)
                    except ValueError:
                        continue
        
        # Create archives for each group
        for archive_key, paths in archive_groups.items():
            try:
                archive_id = str(uuid.uuid4())
                s3_key = f"performance-archives/{archive_key}/{archive_id}.tar.gz"
                
                # Create compressed archive
                temp_archive = tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False)
                temp_archive.close()
                
                total_files = 0
                total_size = 0
                
                # Create tar.gz archive
                import tarfile
                with tarfile.open(temp_archive.name, 'w:gz') as tar:
                    for path in paths:
                        for file_path in path.rglob('*'):
                            if file_path.is_file():
                                tar.add(file_path, arcname=file_path.relative_to(self.storage_path))
                                total_files += 1
                                total_size += file_path.stat().st_size
                
                # Upload to S3
                compressed_size = Path(temp_archive.name).stat().st_size
                
                with open(temp_archive.name, 'rb') as f:
                    self.s3_client.upload_fileobj(
                        f,
                        self.aws_s3_bucket,
                        s3_key,
                        ExtraArgs={'StorageClass': storage_class}
                    )
                
                # Create archive metadata
                archive_metadata = ArchiveMetadata(
                    archive_id=archive_id,
                    original_path=archive_key,
                    s3_bucket=self.aws_s3_bucket,
                    s3_key=s3_key,
                    archive_timestamp=datetime.now(timezone.utc),
                    compressed_size=compressed_size,
                    original_size=total_size,
                    compression_ratio=0.0,  # Will be calculated in __post_init__
                    record_count=total_files,
                    checksum=self._calculate_archive_checksum(temp_archive.name),
                    retention_until=datetime.now(timezone.utc) + timedelta(days=365 * 7),  # 7 years
                    access_tier=storage_class
                )
                
                self.archive_metadata[archive_id] = archive_metadata
                
                # Remove local files after successful upload
                for path in paths:
                    shutil.rmtree(path)
                
                # Cleanup temporary file
                Path(temp_archive.name).unlink()
                
                archive_summary['archives_created'] += 1
                archive_summary['files_archived'] += total_files
                archive_summary['total_size_mb'] += total_size / (1024 * 1024)
                
                self.logger.info(
                    "Archive created and uploaded to S3",
                    archive_id=archive_id,
                    s3_key=s3_key,
                    files_archived=total_files,
                    size_mb=total_size / (1024 * 1024)
                )
                
            except Exception as e:
                error_msg = f"Failed to archive {archive_key}: {e}"
                archive_summary['errors'].append(error_msg)
                self.logger.error(error_msg)
        
        # Save updated archive metadata
        self._save_archive_metadata()
        
        return archive_summary
    
    def _calculate_archive_checksum(self, archive_path: str) -> str:
        """Calculate SHA-256 checksum for archive file."""
        hash_sha256 = hashlib.sha256()
        with open(archive_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def cleanup_expired_data(self) -> Dict[str, Any]:
        """
        Clean up expired historical data per Section 8.6.5 retention policies.
        
        Returns:
            Cleanup operation summary
        """
        cleanup_summary = {
            'records_processed': 0,
            'records_deleted': 0,
            'archives_expired': 0,
            'disk_space_freed_mb': 0.0,
            'errors': []
        }
        
        current_time = datetime.now(timezone.utc)
        
        # Cleanup expired local records
        for data_type_path in self.storage_path.iterdir():
            if not data_type_path.is_dir():
                continue
            
            for file_path in data_type_path.rglob('*.json*'):
                try:
                    cleanup_summary['records_processed'] += 1
                    
                    # Load record to check retention policy
                    if file_path.suffix == '.json':
                        with open(file_path, 'r') as f:
                            record_data = json.load(f)
                    elif file_path.suffix == '.gz':
                        with gzip.open(file_path, 'rt') as f:
                            record_data = json.load(f)
                    else:
                        continue
                    
                    record = HistoricalDataRecord.from_dict(record_data)
                    
                    if record.is_expired():
                        file_size = file_path.stat().st_size
                        file_path.unlink()
                        cleanup_summary['records_deleted'] += 1
                        cleanup_summary['disk_space_freed_mb'] += file_size / (1024 * 1024)
                        
                except Exception as e:
                    error_msg = f"Error processing {file_path}: {e}"
                    cleanup_summary['errors'].append(error_msg)
        
        # Cleanup expired S3 archives
        expired_archives = []
        for archive_id, metadata in self.archive_metadata.items():
            if current_time > metadata.retention_until:
                try:
                    # Delete from S3
                    if self.s3_client:
                        self.s3_client.delete_object(
                            Bucket=metadata.s3_bucket,
                            Key=metadata.s3_key
                        )
                    
                    expired_archives.append(archive_id)
                    cleanup_summary['archives_expired'] += 1
                    
                except Exception as e:
                    error_msg = f"Error deleting archive {archive_id}: {e}"
                    cleanup_summary['errors'].append(error_msg)
        
        # Remove expired archive metadata
        for archive_id in expired_archives:
            del self.archive_metadata[archive_id]
        
        if expired_archives:
            self._save_archive_metadata()
        
        # Update cleanup timestamp
        self._last_cleanup = current_time
        
        self.logger.info(
            "Data cleanup completed",
            records_processed=cleanup_summary['records_processed'],
            records_deleted=cleanup_summary['records_deleted'],
            archives_expired=cleanup_summary['archives_expired'],
            disk_space_freed_mb=cleanup_summary['disk_space_freed_mb'],
            errors=len(cleanup_summary['errors'])
        )
        
        return cleanup_summary
    
    def validate_data_integrity(
        self,
        sample_percentage: float = 10.0
    ) -> Dict[str, Any]:
        """
        Validate data integrity using checksum verification per Section 8.6.5.
        
        Args:
            sample_percentage: Percentage of records to validate (1-100)
            
        Returns:
            Data integrity validation summary
        """
        validation_summary = {
            'records_checked': 0,
            'records_valid': 0,
            'records_corrupted': 0,
            'corruption_rate': 0.0,
            'corrupted_files': [],
            'errors': []
        }
        
        if not 1 <= sample_percentage <= 100:
            raise ValueError("Sample percentage must be between 1 and 100")
        
        # Collect all record files
        all_files = []
        for file_path in self.storage_path.rglob('*.json*'):
            all_files.append(file_path)
        
        # Calculate sample size
        sample_size = max(1, int(len(all_files) * sample_percentage / 100))
        
        # Randomly sample files for validation
        import random
        random.seed(42)  # Reproducible sampling
        sample_files = random.sample(all_files, min(sample_size, len(all_files)))
        
        for file_path in sample_files:
            try:
                validation_summary['records_checked'] += 1
                
                # Load record
                if file_path.suffix == '.json':
                    with open(file_path, 'r') as f:
                        record_data = json.load(f)
                elif file_path.suffix == '.gz':
                    with gzip.open(file_path, 'rt') as f:
                        record_data = json.load(f)
                else:
                    continue
                
                record = HistoricalDataRecord.from_dict(record_data)
                
                # Validate integrity
                if record.validate_integrity():
                    validation_summary['records_valid'] += 1
                else:
                    validation_summary['records_corrupted'] += 1
                    validation_summary['corrupted_files'].append(str(file_path))
                    
                    self.logger.warning(
                        "Data corruption detected",
                        file_path=str(file_path),
                        record_id=record.record_id
                    )
                
            except Exception as e:
                error_msg = f"Error validating {file_path}: {e}"
                validation_summary['errors'].append(error_msg)
        
        # Calculate corruption rate
        if validation_summary['records_checked'] > 0:
            validation_summary['corruption_rate'] = (
                validation_summary['records_corrupted'] / validation_summary['records_checked']
            ) * 100
        
        # Update last integrity check timestamp
        self._last_integrity_check = datetime.now(timezone.utc)
        
        self.logger.info(
            "Data integrity validation completed",
            records_checked=validation_summary['records_checked'],
            records_valid=validation_summary['records_valid'],
            records_corrupted=validation_summary['records_corrupted'],
            corruption_rate=f"{validation_summary['corruption_rate']:.2f}%"
        )
        
        return validation_summary
    
    def generate_historical_report(
        self,
        report_type: str = "comprehensive",
        analysis_days: int = 30,
        environment: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate comprehensive historical performance report.
        
        Args:
            report_type: Type of report ('summary', 'comprehensive', 'trend_analysis')
            analysis_days: Number of days to include in analysis
            environment: Optional environment filter
            
        Returns:
            Comprehensive historical performance report
        """
        report = {
            'report_metadata': {
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'report_type': report_type,
                'analysis_period_days': analysis_days,
                'environment_filter': environment,
                'data_sources': []
            },
            'data_summary': {},
            'trend_analysis': {},
            'compliance_status': {},
            'recommendations': [],
            'archive_status': {}
        }
        
        # Get data summary
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=analysis_days)
        
        records = self.retrieve_records(
            start_date=start_date,
            end_date=end_date,
            environment=environment
        )
        
        # Data summary by type
        data_by_type = defaultdict(list)
        for record in records:
            data_by_type[record.data_type].append(record)
        
        report['data_summary'] = {
            'total_records': len(records),
            'records_by_type': {k: len(v) for k, v in data_by_type.items()},
            'date_range': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            },
            'environments': list(set(r.test_environment for r in records))
        }
        
        # Trend analysis for key metrics
        key_metrics = [
            ('response_time_ms', 'response_time'),
            ('cpu_utilization_percent', 'resource_usage'),
            ('memory_usage_mb', 'resource_usage'),
            ('requests_per_second', 'throughput')
        ]
        
        for metric_name, data_type in key_metrics:
            try:
                trend_result = self.analyze_performance_trends(
                    metric_name=metric_name,
                    data_type=data_type,
                    analysis_days=analysis_days,
                    environment=environment
                )
                
                report['trend_analysis'][metric_name] = {
                    'trend_direction': trend_result.trend_direction,
                    'trend_percentage': trend_result.trend_percentage,
                    'confidence_level': trend_result.confidence_level,
                    'data_points': trend_result.data_points,
                    'variance_from_baseline': trend_result.variance_from_baseline,
                    'compliance_status': trend_result.compliance_status,
                    'recommendations': trend_result.recommendations
                }
                
            except Exception as e:
                self.logger.warning(f"Trend analysis failed for {metric_name}: {e}")
        
        # Overall compliance status
        compliance_issues = []
        for metric_analysis in report['trend_analysis'].values():
            if not metric_analysis['compliance_status']:
                compliance_issues.append(f"Non-compliant: {metric_analysis}")
        
        report['compliance_status'] = {
            'overall_compliant': len(compliance_issues) == 0,
            'issues_count': len(compliance_issues),
            'critical_issues': compliance_issues
        }
        
        # Archive status summary
        report['archive_status'] = {
            'total_archives': len(self.archive_metadata),
            'archive_size_mb': sum(m.compressed_size for m in self.archive_metadata.values()) / (1024 * 1024),
            'compression_ratio': sum(m.compression_ratio for m in self.archive_metadata.values()) / len(self.archive_metadata) if self.archive_metadata else 0,
            'oldest_archive': min((m.archive_timestamp for m in self.archive_metadata.values()), default=None),
            'newest_archive': max((m.archive_timestamp for m in self.archive_metadata.values()), default=None)
        }
        
        # Convert datetime objects to ISO strings for JSON serialization
        if report['archive_status']['oldest_archive']:
            report['archive_status']['oldest_archive'] = report['archive_status']['oldest_archive'].isoformat()
        if report['archive_status']['newest_archive']:
            report['archive_status']['newest_archive'] = report['archive_status']['newest_archive'].isoformat()
        
        # Generate recommendations based on analysis
        recommendations = []
        
        # Performance recommendations
        for metric_name, analysis in report['trend_analysis'].items():
            if analysis['trend_direction'] == 'degrading':
                recommendations.append(f"Performance degradation detected in {metric_name} - immediate investigation required")
            elif analysis['variance_from_baseline'] and abs(analysis['variance_from_baseline']) > 8:
                recommendations.append(f"{metric_name} variance approaching critical threshold - proactive optimization recommended")
        
        # Data management recommendations
        if report['data_summary']['total_records'] > 10000:
            recommendations.append("Large volume of historical data - consider implementing automated archival")
        
        if not report['compliance_status']['overall_compliant']:
            recommendations.append("Performance compliance issues detected - review migration strategy")
        
        # Archive recommendations
        if report['archive_status']['total_archives'] == 0:
            recommendations.append("No archives found - consider implementing data archival for storage optimization")
        
        report['recommendations'] = recommendations
        
        return report
    
    def perform_maintenance(self) -> Dict[str, Any]:
        """
        Perform comprehensive maintenance operations per Section 8.6.5.
        
        Returns:
            Maintenance operation summary
        """
        maintenance_summary = {
            'started_at': datetime.now(timezone.utc).isoformat(),
            'operations_completed': [],
            'operations_failed': [],
            'total_duration_seconds': 0,
            'recommendations': []
        }
        
        start_time = time.time()
        
        try:
            # 1. Data integrity validation
            self.logger.info("Starting data integrity validation")
            integrity_result = self.validate_data_integrity(sample_percentage=5.0)
            maintenance_summary['operations_completed'].append({
                'operation': 'data_integrity_validation',
                'result': integrity_result
            })
            
            if integrity_result['corruption_rate'] > 1.0:
                maintenance_summary['recommendations'].append(
                    f"High corruption rate ({integrity_result['corruption_rate']:.2f}%) detected - investigate data storage issues"
                )
            
        except Exception as e:
            maintenance_summary['operations_failed'].append({
                'operation': 'data_integrity_validation',
                'error': str(e)
            })
        
        try:
            # 2. Data compression
            self.logger.info("Starting data compression")
            compression_result = self.compress_historical_data(days_old=30)
            maintenance_summary['operations_completed'].append({
                'operation': 'data_compression',
                'result': compression_result
            })
            
            if compression_result['compression_ratio'] > 50:
                maintenance_summary['recommendations'].append(
                    f"High compression ratio ({compression_result['compression_ratio']:.2f}%) achieved - consider more frequent compression"
                )
            
        except Exception as e:
            maintenance_summary['operations_failed'].append({
                'operation': 'data_compression',
                'error': str(e)
            })
        
        try:
            # 3. Data archival (if enabled)
            if self.enable_archival and self.s3_client:
                self.logger.info("Starting data archival to S3")
                archive_result = self.archive_to_s3(retention_days=ACTIVE_RETENTION_DAYS)
                maintenance_summary['operations_completed'].append({
                    'operation': 'data_archival',
                    'result': archive_result
                })
                
                if archive_result['archives_created'] > 0:
                    maintenance_summary['recommendations'].append(
                        f"Successfully archived {archive_result['archives_created']} data sets to S3"
                    )
            
        except Exception as e:
            maintenance_summary['operations_failed'].append({
                'operation': 'data_archival',
                'error': str(e)
            })
        
        try:
            # 4. Cleanup expired data
            self.logger.info("Starting cleanup of expired data")
            cleanup_result = self.cleanup_expired_data()
            maintenance_summary['operations_completed'].append({
                'operation': 'data_cleanup',
                'result': cleanup_result
            })
            
            if cleanup_result['disk_space_freed_mb'] > 100:
                maintenance_summary['recommendations'].append(
                    f"Freed {cleanup_result['disk_space_freed_mb']:.2f}MB of disk space - storage optimization successful"
                )
            
        except Exception as e:
            maintenance_summary['operations_failed'].append({
                'operation': 'data_cleanup',
                'error': str(e)
            })
        
        # Calculate total duration
        end_time = time.time()
        maintenance_summary['total_duration_seconds'] = end_time - start_time
        maintenance_summary['completed_at'] = datetime.now(timezone.utc).isoformat()
        
        # Log maintenance summary
        self.logger.info(
            "Maintenance operations completed",
            operations_completed=len(maintenance_summary['operations_completed']),
            operations_failed=len(maintenance_summary['operations_failed']),
            duration_seconds=maintenance_summary['total_duration_seconds']
        )
        
        return maintenance_summary


# Utility functions for external integration

def create_historical_data_manager(
    storage_path: Optional[str] = None,
    aws_s3_bucket: Optional[str] = None,
    enable_archival: bool = True
) -> HistoricalDataManager:
    """
    Create historical data manager instance with default configuration.
    
    Args:
        storage_path: Optional custom storage path
        aws_s3_bucket: Optional AWS S3 bucket for archival
        enable_archival: Enable automatic archival capabilities
        
    Returns:
        Configured historical data manager instance
    """
    if storage_path is None:
        storage_path = os.getenv('PERFORMANCE_DATA_PATH', 'data/performance/historical')
    
    if aws_s3_bucket is None:
        aws_s3_bucket = os.getenv('AWS_S3_PERFORMANCE_BUCKET')
    
    return HistoricalDataManager(
        storage_path=storage_path,
        aws_s3_bucket=aws_s3_bucket,
        enable_archival=enable_archival and AWS_AVAILABLE
    )


def analyze_performance_regression(
    manager: HistoricalDataManager,
    metric_name: str,
    data_type: str,
    comparison_days: int = 7
) -> Dict[str, Any]:
    """
    Analyze performance regression for specific metric.
    
    Args:
        manager: Historical data manager instance
        metric_name: Performance metric to analyze
        data_type: Type of performance data
        comparison_days: Number of days for regression analysis
        
    Returns:
        Regression analysis results
    """
    try:
        trend_result = manager.analyze_performance_trends(
            metric_name=metric_name,
            data_type=data_type,
            analysis_days=comparison_days
        )
        
        regression_analysis = {
            'metric_name': metric_name,
            'regression_detected': trend_result.trend_direction == 'degrading',
            'trend_percentage': trend_result.trend_percentage,
            'confidence_level': trend_result.confidence_level,
            'variance_from_baseline': trend_result.variance_from_baseline,
            'compliance_status': trend_result.compliance_status,
            'recommendations': trend_result.recommendations,
            'analysis_period_days': comparison_days
        }
        
        # Add severity assessment
        if regression_analysis['regression_detected']:
            if abs(trend_result.trend_percentage) > 20:
                regression_analysis['severity'] = 'critical'
            elif abs(trend_result.trend_percentage) > 10:
                regression_analysis['severity'] = 'high'
            elif abs(trend_result.trend_percentage) > 5:
                regression_analysis['severity'] = 'medium'
            else:
                regression_analysis['severity'] = 'low'
        else:
            regression_analysis['severity'] = 'none'
        
        return regression_analysis
        
    except Exception as e:
        return {
            'metric_name': metric_name,
            'error': str(e),
            'regression_detected': False,
            'severity': 'unknown'
        }


# Export public interface
__all__ = [
    'HistoricalDataManager',
    'HistoricalDataRecord',
    'TrendAnalysisResult',
    'ArchiveMetadata',
    'DataClassification',
    'RetentionPolicy',
    'ArchiveStatus',
    'create_historical_data_manager',
    'analyze_performance_regression',
    'ACTIVE_RETENTION_DAYS',
    'ARCHIVE_RETENTION_YEARS',
    'DATA_CLASSIFICATION_LEVELS',
    'RETENTION_POLICIES_BY_LEVEL'
]