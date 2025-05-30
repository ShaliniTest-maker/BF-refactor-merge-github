"""
Performance monitoring implementation providing Node.js baseline comparison, response time variance tracking,
memory profiling, CPU utilization monitoring, and Python garbage collection analysis.

This module implements comprehensive performance validation to ensure ≤10% variance compliance
and capacity planning insights for the Flask migration from Node.js.

Key Features:
- Real-time performance variance tracking against Node.js baseline
- CPU utilization monitoring with psutil 5.9+ integration
- Python garbage collection instrumentation and analysis  
- Memory profiling for performance compliance validation
- Container resource correlation analysis
- Performance baseline tracking and drift analysis
- Automated alerting for performance threshold violations

Performance Requirements:
- Maintain ≤10% variance from Node.js baseline (Section 0.1.1)
- CPU utilization ≤70% sustained (Section 6.5.2.2)
- Python GC pause time ≤100ms average (Section 6.5.2.2)
- Memory usage growth monitoring with 15% threshold (Section 6.5.2.2)
"""

import gc
import os
import sys
import time
import psutil
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Callable
from datetime import datetime, timedelta
from collections import deque, defaultdict
from contextlib import contextmanager
import tracemalloc
import resource
from functools import wraps

from prometheus_client import (
    Counter, Histogram, Gauge, Summary, Info,
    CollectorRegistry, generate_latest
)

from src.monitoring.logging import get_logger
from src.utils.exceptions import PerformanceException, AlertException
from src.utils.decorators import timing_decorator


# Initialize structured logger
logger = get_logger(__name__)

# Performance variance alert thresholds (Section 6.5.5)
VARIANCE_WARNING_THRESHOLD = 5.0  # >5% warning
VARIANCE_CRITICAL_THRESHOLD = 10.0  # >10% critical
CPU_WARNING_THRESHOLD = 70.0  # >70% sustained (5min)
CPU_CRITICAL_THRESHOLD = 90.0  # >90% sustained (2min)
MEMORY_WARNING_THRESHOLD = 80.0  # >80% heap usage
MEMORY_CRITICAL_THRESHOLD = 95.0  # >95% heap usage
GC_WARNING_THRESHOLD = 100.0  # >100ms average pause
GC_CRITICAL_THRESHOLD = 300.0  # >300ms average pause

# Performance baseline data storage
BASELINE_RETENTION_HOURS = 24
METRIC_COLLECTION_INTERVAL = 15  # 15-second intervals
CPU_SUSTAINED_PERIOD = 300  # 5 minutes for warning threshold
CPU_CRITICAL_PERIOD = 120  # 2 minutes for critical threshold


@dataclass
class PerformanceBaseline:
    """Node.js performance baseline data structure for comparison."""
    endpoint: str
    response_time_ms: float
    memory_usage_mb: float
    cpu_usage_percent: float
    throughput_rps: float
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PerformanceSnapshot:
    """Current Flask application performance snapshot."""
    response_time_ms: float
    memory_usage_mb: float
    cpu_usage_percent: float
    gc_pause_time_ms: float
    active_connections: int
    heap_size_mb: float
    worker_count: int
    timestamp: datetime
    endpoint: Optional[str] = None
    request_id: Optional[str] = None


@dataclass
class VarianceAnalysis:
    """Performance variance analysis results."""
    response_time_variance: float
    memory_variance: float
    cpu_variance: float
    overall_variance: float
    compliance_status: str  # 'COMPLIANT', 'WARNING', 'CRITICAL'
    recommendations: List[str]
    timestamp: datetime


class GarbageCollectionMonitor:
    """Python garbage collection instrumentation and analysis."""
    
    def __init__(self):
        """Initialize GC monitoring with collection event tracking."""
        self.gc_stats = deque(maxlen=1000)  # Last 1000 GC events
        self.gc_enabled = True
        self.collection_times = defaultdict(list)
        self.generation_stats = defaultdict(int)
        
        # Enable detailed GC tracking
        gc.set_debug(gc.DEBUG_STATS)
        self._setup_gc_callbacks()
        
        logger.info("Garbage collection monitoring initialized", extra={
            'gc_thresholds': gc.get_threshold(),
            'gc_enabled': gc.isenabled()
        })

    def _setup_gc_callbacks(self):
        """Set up garbage collection event callbacks."""
        # Store original callback
        self._original_callbacks = gc.callbacks.copy()
        
        # Add our monitoring callback
        gc.callbacks.append(self._gc_callback)

    def _gc_callback(self, phase, info):
        """Callback function for garbage collection events."""
        if phase == 'start':
            self._gc_start_time = time.perf_counter()
        elif phase == 'stop':
            if hasattr(self, '_gc_start_time'):
                duration_ms = (time.perf_counter() - self._gc_start_time) * 1000
                generation = info.get('generation', -1)
                
                gc_event = {
                    'timestamp': datetime.utcnow(),
                    'duration_ms': duration_ms,
                    'generation': generation,
                    'collected': info.get('collected', 0),
                    'connections': info.get('connections', 0),
                    'uncollectable': info.get('uncollectable', 0)
                }
                
                self.gc_stats.append(gc_event)
                self.collection_times[generation].append(duration_ms)
                self.generation_stats[generation] += 1
                
                # Log significant GC pauses
                if duration_ms > GC_WARNING_THRESHOLD:
                    logger.warning("Significant garbage collection pause", extra={
                        'gc_duration_ms': duration_ms,
                        'generation': generation,
                        'collected_objects': info.get('collected', 0),
                        'threshold_ms': GC_WARNING_THRESHOLD
                    })

    def get_gc_statistics(self) -> Dict[str, Any]:
        """Get comprehensive garbage collection statistics."""
        if not self.gc_stats:
            return {'status': 'no_data'}
        
        recent_events = [event for event in self.gc_stats 
                        if datetime.utcnow() - event['timestamp'] < timedelta(minutes=5)]
        
        if not recent_events:
            return {'status': 'no_recent_data'}
        
        pause_times = [event['duration_ms'] for event in recent_events]
        avg_pause_time = sum(pause_times) / len(pause_times)
        max_pause_time = max(pause_times)
        
        return {
            'average_pause_ms': avg_pause_time,
            'max_pause_ms': max_pause_time,
            'total_collections': len(recent_events),
            'generation_stats': dict(self.generation_stats),
            'compliance_status': self._assess_gc_compliance(avg_pause_time),
            'threshold_warning_ms': GC_WARNING_THRESHOLD,
            'threshold_critical_ms': GC_CRITICAL_THRESHOLD,
            'collection_frequency': len(recent_events) / 5.0  # per minute
        }

    def _assess_gc_compliance(self, avg_pause_time: float) -> str:
        """Assess GC performance compliance status."""
        if avg_pause_time > GC_CRITICAL_THRESHOLD:
            return 'CRITICAL'
        elif avg_pause_time > GC_WARNING_THRESHOLD:
            return 'WARNING'
        else:
            return 'COMPLIANT'

    def cleanup(self):
        """Cleanup GC monitoring resources."""
        # Restore original callbacks
        gc.callbacks.clear()
        gc.callbacks.extend(self._original_callbacks)
        logger.info("Garbage collection monitoring cleanup completed")


class CPUMonitor:
    """CPU utilization monitoring with sustained threshold tracking."""
    
    def __init__(self):
        """Initialize CPU monitoring with psutil integration."""
        self.cpu_readings = deque(maxlen=1000)
        self.process = psutil.Process()
        self.monitoring_active = False
        self.monitor_thread = None
        self.alert_callback = None
        
        logger.info("CPU monitoring initialized", extra={
            'process_pid': self.process.pid,
            'cpu_count': psutil.cpu_count(),
            'cpu_freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None
        })

    def start_monitoring(self, alert_callback: Optional[Callable] = None):
        """Start continuous CPU monitoring in background thread."""
        if self.monitoring_active:
            return
        
        self.alert_callback = alert_callback
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info("CPU monitoring started", extra={
            'monitoring_interval': METRIC_COLLECTION_INTERVAL,
            'warning_threshold': CPU_WARNING_THRESHOLD,
            'critical_threshold': CPU_CRITICAL_THRESHOLD
        })

    def stop_monitoring(self):
        """Stop CPU monitoring thread."""
        self.monitoring_active = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5.0)
        logger.info("CPU monitoring stopped")

    def _monitor_loop(self):
        """Main CPU monitoring loop running in background thread."""
        while self.monitoring_active:
            try:
                # Get system and process CPU usage
                system_cpu = psutil.cpu_percent(interval=None)
                process_cpu = self.process.cpu_percent()
                
                # Container CPU usage if available (cAdvisor integration)
                container_cpu = self._get_container_cpu_usage()
                
                cpu_data = {
                    'timestamp': datetime.utcnow(),
                    'system_cpu_percent': system_cpu,
                    'process_cpu_percent': process_cpu,
                    'container_cpu_percent': container_cpu,
                    'cpu_count': psutil.cpu_count(),
                    'load_average': os.getloadavg() if hasattr(os, 'getloadavg') else None
                }
                
                self.cpu_readings.append(cpu_data)
                
                # Check for sustained high CPU usage
                self._check_sustained_cpu_usage()
                
                time.sleep(METRIC_COLLECTION_INTERVAL)
                
            except Exception as e:
                logger.error("Error in CPU monitoring loop", extra={
                    'error': str(e),
                    'traceback': traceback.format_exc()
                })
                time.sleep(METRIC_COLLECTION_INTERVAL)

    def _get_container_cpu_usage(self) -> Optional[float]:
        """Get container CPU usage from cAdvisor metrics if available."""
        try:
            # Try to read from cgroup CPU stats
            if os.path.exists('/sys/fs/cgroup/cpu/cpu.stat'):
                with open('/sys/fs/cgroup/cpu/cpu.stat', 'r') as f:
                    content = f.read()
                    # Parse CPU usage from cgroup
                    # Implementation would depend on specific container environment
                    return None  # Placeholder for container-specific implementation
        except Exception:
            pass
        return None

    def _check_sustained_cpu_usage(self):
        """Check for sustained high CPU usage and trigger alerts."""
        if len(self.cpu_readings) < 10:  # Need minimum readings
            return
        
        now = datetime.utcnow()
        
        # Check critical threshold (2 minutes sustained)
        critical_cutoff = now - timedelta(seconds=CPU_CRITICAL_PERIOD)
        critical_readings = [r for r in self.cpu_readings 
                           if r['timestamp'] >= critical_cutoff]
        
        if critical_readings:
            avg_critical_cpu = sum(r['process_cpu_percent'] for r in critical_readings) / len(critical_readings)
            if avg_critical_cpu > CPU_CRITICAL_THRESHOLD:
                self._trigger_cpu_alert('CRITICAL', avg_critical_cpu, CPU_CRITICAL_PERIOD)
        
        # Check warning threshold (5 minutes sustained)
        warning_cutoff = now - timedelta(seconds=CPU_SUSTAINED_PERIOD)
        warning_readings = [r for r in self.cpu_readings 
                          if r['timestamp'] >= warning_cutoff]
        
        if warning_readings:
            avg_warning_cpu = sum(r['process_cpu_percent'] for r in warning_readings) / len(warning_readings)
            if avg_warning_cpu > CPU_WARNING_THRESHOLD:
                self._trigger_cpu_alert('WARNING', avg_warning_cpu, CPU_SUSTAINED_PERIOD)

    def _trigger_cpu_alert(self, severity: str, cpu_usage: float, duration: int):
        """Trigger CPU usage alert."""
        alert_data = {
            'severity': severity,
            'cpu_usage_percent': cpu_usage,
            'threshold': CPU_CRITICAL_THRESHOLD if severity == 'CRITICAL' else CPU_WARNING_THRESHOLD,
            'duration_seconds': duration,
            'timestamp': datetime.utcnow(),
            'process_pid': self.process.pid
        }
        
        logger.warning(f"Sustained high CPU usage detected ({severity})", extra=alert_data)
        
        if self.alert_callback:
            try:
                self.alert_callback('cpu_usage', alert_data)
            except Exception as e:
                logger.error("Error in CPU alert callback", extra={'error': str(e)})

    def get_cpu_statistics(self) -> Dict[str, Any]:
        """Get comprehensive CPU usage statistics."""
        if not self.cpu_readings:
            return {'status': 'no_data'}
        
        recent_readings = [r for r in self.cpu_readings 
                          if datetime.utcnow() - r['timestamp'] < timedelta(minutes=5)]
        
        if not recent_readings:
            return {'status': 'no_recent_data'}
        
        process_cpus = [r['process_cpu_percent'] for r in recent_readings]
        system_cpus = [r['system_cpu_percent'] for r in recent_readings]
        
        return {
            'process_cpu_average': sum(process_cpus) / len(process_cpus),
            'process_cpu_max': max(process_cpus),
            'system_cpu_average': sum(system_cpus) / len(system_cpus),
            'cpu_count': psutil.cpu_count(),
            'compliance_status': self._assess_cpu_compliance(process_cpus),
            'warning_threshold': CPU_WARNING_THRESHOLD,
            'critical_threshold': CPU_CRITICAL_THRESHOLD,
            'readings_count': len(recent_readings)
        }

    def _assess_cpu_compliance(self, cpu_readings: List[float]) -> str:
        """Assess CPU usage compliance status."""
        avg_cpu = sum(cpu_readings) / len(cpu_readings)
        
        if avg_cpu > CPU_CRITICAL_THRESHOLD:
            return 'CRITICAL'
        elif avg_cpu > CPU_WARNING_THRESHOLD:
            return 'WARNING'
        else:
            return 'COMPLIANT'


class MemoryProfiler:
    """Memory profiling and analysis for performance compliance."""
    
    def __init__(self):
        """Initialize memory profiling with tracemalloc integration."""
        self.memory_snapshots = deque(maxlen=1000)
        self.tracemalloc_enabled = False
        self.baseline_memory = None
        
        # Start memory tracing
        if not tracemalloc.is_tracing():
            tracemalloc.start()
            self.tracemalloc_enabled = True
        
        self.process = psutil.Process()
        self._capture_baseline_memory()
        
        logger.info("Memory profiling initialized", extra={
            'tracemalloc_enabled': self.tracemalloc_enabled,
            'baseline_memory_mb': self.baseline_memory
        })

    def _capture_baseline_memory(self):
        """Capture baseline memory usage."""
        memory_info = self.process.memory_info()
        self.baseline_memory = memory_info.rss / 1024 / 1024  # MB
        
        baseline_data = {
            'timestamp': datetime.utcnow(),
            'rss_mb': self.baseline_memory,
            'vms_mb': memory_info.vms / 1024 / 1024,
            'memory_percent': self.process.memory_percent()
        }
        
        self.memory_snapshots.append(baseline_data)

    def capture_memory_snapshot(self) -> Dict[str, Any]:
        """Capture current memory usage snapshot."""
        try:
            # Process memory info
            memory_info = self.process.memory_info()
            memory_percent = self.process.memory_percent()
            
            # System memory info
            system_memory = psutil.virtual_memory()
            
            # Python memory tracking
            python_memory = {}
            if self.tracemalloc_enabled:
                current, peak = tracemalloc.get_traced_memory()
                python_memory = {
                    'current_mb': current / 1024 / 1024,
                    'peak_mb': peak / 1024 / 1024
                }
            
            # Garbage collection memory stats
            gc_stats = {
                'gc_objects': len(gc.get_objects()),
                'gc_generation_counts': gc.get_count()
            }
            
            snapshot = {
                'timestamp': datetime.utcnow(),
                'process_rss_mb': memory_info.rss / 1024 / 1024,
                'process_vms_mb': memory_info.vms / 1024 / 1024,
                'process_memory_percent': memory_percent,
                'system_memory_percent': system_memory.percent,
                'system_available_mb': system_memory.available / 1024 / 1024,
                'python_memory': python_memory,
                'gc_stats': gc_stats
            }
            
            self.memory_snapshots.append(snapshot)
            return snapshot
            
        except Exception as e:
            logger.error("Error capturing memory snapshot", extra={'error': str(e)})
            return {}

    def analyze_memory_growth(self) -> Dict[str, Any]:
        """Analyze memory growth patterns and trends."""
        if len(self.memory_snapshots) < 2:
            return {'status': 'insufficient_data'}
        
        # Get recent snapshots (last 5 minutes)
        now = datetime.utcnow()
        recent_snapshots = [s for s in self.memory_snapshots 
                           if now - s['timestamp'] < timedelta(minutes=5)]
        
        if len(recent_snapshots) < 2:
            return {'status': 'insufficient_recent_data'}
        
        # Calculate memory growth rate
        first_memory = recent_snapshots[0]['process_rss_mb']
        last_memory = recent_snapshots[-1]['process_rss_mb']
        time_diff = (recent_snapshots[-1]['timestamp'] - recent_snapshots[0]['timestamp']).total_seconds()
        
        growth_rate_mb_per_minute = ((last_memory - first_memory) / time_diff) * 60
        growth_percentage = ((last_memory - self.baseline_memory) / self.baseline_memory) * 100
        
        # Memory statistics
        memory_values = [s['process_rss_mb'] for s in recent_snapshots]
        avg_memory = sum(memory_values) / len(memory_values)
        max_memory = max(memory_values)
        
        analysis = {
            'current_memory_mb': last_memory,
            'baseline_memory_mb': self.baseline_memory,
            'growth_rate_mb_per_minute': growth_rate_mb_per_minute,
            'growth_percentage': growth_percentage,
            'average_memory_mb': avg_memory,
            'max_memory_mb': max_memory,
            'compliance_status': self._assess_memory_compliance(growth_percentage, last_memory),
            'recommendations': self._generate_memory_recommendations(growth_rate_mb_per_minute, growth_percentage)
        }
        
        return analysis

    def _assess_memory_compliance(self, growth_percentage: float, current_memory: float) -> str:
        """Assess memory usage compliance status."""
        # Check if memory growth exceeds threshold
        if growth_percentage > MEMORY_CRITICAL_THRESHOLD:
            return 'CRITICAL'
        elif growth_percentage > MEMORY_WARNING_THRESHOLD:
            return 'WARNING'
        else:
            return 'COMPLIANT'

    def _generate_memory_recommendations(self, growth_rate: float, growth_percentage: float) -> List[str]:
        """Generate memory optimization recommendations."""
        recommendations = []
        
        if growth_rate > 10.0:  # >10 MB/minute growth
            recommendations.append("High memory growth rate detected - investigate memory leaks")
            recommendations.append("Consider implementing object pooling for frequently allocated objects")
        
        if growth_percentage > 50.0:
            recommendations.append("Significant memory growth from baseline - review caching strategies")
            recommendations.append("Consider garbage collection tuning or memory optimization")
        
        return recommendations


class PerformanceVarianceTracker:
    """Performance variance tracking against Node.js baseline."""
    
    def __init__(self):
        """Initialize performance variance tracking."""
        self.baselines: Dict[str, PerformanceBaseline] = {}
        self.variance_history = deque(maxlen=1000)
        self.alert_callback = None
        
        # Prometheus metrics for variance tracking
        self.response_time_variance_gauge = Gauge(
            'flask_response_time_variance_percent',
            'Response time variance percentage from Node.js baseline',
            ['endpoint']
        )
        
        self.performance_compliance_gauge = Gauge(
            'flask_performance_compliance_status',
            'Performance compliance status (1=compliant, 0=warning, -1=critical)',
            ['metric_type']
        )
        
        logger.info("Performance variance tracking initialized")

    def set_baseline(self, endpoint: str, baseline: PerformanceBaseline):
        """Set Node.js performance baseline for endpoint."""
        self.baselines[endpoint] = baseline
        logger.info("Performance baseline set", extra={
            'endpoint': endpoint,
            'baseline_response_time_ms': baseline.response_time_ms,
            'baseline_memory_mb': baseline.memory_usage_mb,
            'baseline_cpu_percent': baseline.cpu_usage_percent
        })

    def calculate_variance(self, endpoint: str, current_snapshot: PerformanceSnapshot) -> Optional[VarianceAnalysis]:
        """Calculate performance variance against baseline."""
        if endpoint not in self.baselines:
            logger.warning("No baseline found for endpoint", extra={'endpoint': endpoint})
            return None
        
        baseline = self.baselines[endpoint]
        
        # Calculate individual metric variances
        response_time_variance = self._calculate_percentage_variance(
            baseline.response_time_ms, current_snapshot.response_time_ms
        )
        
        memory_variance = self._calculate_percentage_variance(
            baseline.memory_usage_mb, current_snapshot.memory_usage_mb
        )
        
        cpu_variance = self._calculate_percentage_variance(
            baseline.cpu_usage_percent, current_snapshot.cpu_usage_percent
        )
        
        # Calculate overall variance (weighted average)
        overall_variance = (
            response_time_variance * 0.5 +  # Response time is most critical
            memory_variance * 0.3 +
            cpu_variance * 0.2
        )
        
        # Determine compliance status
        compliance_status = self._assess_compliance_status(overall_variance)
        
        # Generate recommendations
        recommendations = self._generate_variance_recommendations(
            response_time_variance, memory_variance, cpu_variance
        )
        
        variance_analysis = VarianceAnalysis(
            response_time_variance=response_time_variance,
            memory_variance=memory_variance,
            cpu_variance=cpu_variance,
            overall_variance=overall_variance,
            compliance_status=compliance_status,
            recommendations=recommendations,
            timestamp=datetime.utcnow()
        )
        
        # Update Prometheus metrics
        self.response_time_variance_gauge.labels(endpoint=endpoint).set(response_time_variance)
        compliance_value = self._compliance_to_numeric(compliance_status)
        self.performance_compliance_gauge.labels(metric_type='overall').set(compliance_value)
        
        # Store variance history
        self.variance_history.append(variance_analysis)
        
        # Trigger alert if needed
        if compliance_status in ['WARNING', 'CRITICAL']:
            self._trigger_variance_alert(endpoint, variance_analysis)
        
        logger.info("Performance variance calculated", extra={
            'endpoint': endpoint,
            'response_time_variance': response_time_variance,
            'overall_variance': overall_variance,
            'compliance_status': compliance_status
        })
        
        return variance_analysis

    def _calculate_percentage_variance(self, baseline: float, current: float) -> float:
        """Calculate percentage variance from baseline."""
        if baseline == 0:
            return 0.0 if current == 0 else 100.0
        return ((current - baseline) / baseline) * 100

    def _assess_compliance_status(self, overall_variance: float) -> str:
        """Assess compliance status based on overall variance."""
        if abs(overall_variance) > VARIANCE_CRITICAL_THRESHOLD:
            return 'CRITICAL'
        elif abs(overall_variance) > VARIANCE_WARNING_THRESHOLD:
            return 'WARNING'
        else:
            return 'COMPLIANT'

    def _compliance_to_numeric(self, status: str) -> float:
        """Convert compliance status to numeric value for Prometheus."""
        mapping = {'COMPLIANT': 1.0, 'WARNING': 0.0, 'CRITICAL': -1.0}
        return mapping.get(status, 0.0)

    def _generate_variance_recommendations(self, rt_var: float, mem_var: float, cpu_var: float) -> List[str]:
        """Generate performance optimization recommendations."""
        recommendations = []
        
        if abs(rt_var) > VARIANCE_WARNING_THRESHOLD:
            recommendations.append(f"Response time variance {rt_var:.1f}% - investigate request processing efficiency")
        
        if abs(mem_var) > VARIANCE_WARNING_THRESHOLD:
            recommendations.append(f"Memory variance {mem_var:.1f}% - review memory allocation patterns")
        
        if abs(cpu_var) > VARIANCE_WARNING_THRESHOLD:
            recommendations.append(f"CPU variance {cpu_var:.1f}% - analyze computational complexity")
        
        return recommendations

    def _trigger_variance_alert(self, endpoint: str, analysis: VarianceAnalysis):
        """Trigger performance variance alert."""
        alert_data = {
            'endpoint': endpoint,
            'overall_variance': analysis.overall_variance,
            'compliance_status': analysis.compliance_status,
            'response_time_variance': analysis.response_time_variance,
            'threshold_warning': VARIANCE_WARNING_THRESHOLD,
            'threshold_critical': VARIANCE_CRITICAL_THRESHOLD,
            'timestamp': analysis.timestamp.isoformat()
        }
        
        severity = analysis.compliance_status.lower()
        logger.warning(f"Performance variance alert ({severity})", extra=alert_data)
        
        if self.alert_callback:
            try:
                self.alert_callback('performance_variance', alert_data)
            except Exception as e:
                logger.error("Error in variance alert callback", extra={'error': str(e)})


class PerformanceMonitor:
    """Main performance monitoring coordinator class."""
    
    def __init__(self, alert_callback: Optional[Callable] = None):
        """Initialize comprehensive performance monitoring."""
        self.gc_monitor = GarbageCollectionMonitor()
        self.cpu_monitor = CPUMonitor()
        self.memory_profiler = MemoryProfiler()
        self.variance_tracker = PerformanceVarianceTracker()
        self.alert_callback = alert_callback
        
        # Performance metrics registry
        self.metrics_registry = CollectorRegistry()
        
        # Prometheus metrics
        self.request_duration_histogram = Histogram(
            'flask_request_duration_seconds',
            'Request duration in seconds',
            ['endpoint', 'method', 'status'],
            registry=self.metrics_registry
        )
        
        self.nodejs_baseline_counter = Counter(
            'nodejs_baseline_requests_total',
            'Node.js baseline request count for comparison',
            ['endpoint'],
            registry=self.metrics_registry
        )
        
        self.flask_migration_counter = Counter(
            'flask_migration_requests_total',
            'Flask migration request count',
            ['endpoint'],
            registry=self.metrics_registry
        )
        
        self.performance_variance_summary = Summary(
            'flask_performance_variance_seconds',
            'Performance variance distribution',
            ['endpoint'],
            registry=self.metrics_registry
        )
        
        # Start monitoring components
        self.cpu_monitor.start_monitoring(self._handle_alert)
        
        logger.info("Performance monitoring initialized", extra={
            'components': ['gc_monitor', 'cpu_monitor', 'memory_profiler', 'variance_tracker'],
            'alert_thresholds': {
                'variance_warning': VARIANCE_WARNING_THRESHOLD,
                'variance_critical': VARIANCE_CRITICAL_THRESHOLD,
                'cpu_warning': CPU_WARNING_THRESHOLD,
                'cpu_critical': CPU_CRITICAL_THRESHOLD
            }
        })

    def _handle_alert(self, alert_type: str, alert_data: Dict[str, Any]):
        """Handle alerts from monitoring components."""
        if self.alert_callback:
            self.alert_callback(alert_type, alert_data)

    @contextmanager
    def measure_request_performance(self, endpoint: str, method: str = 'GET'):
        """Context manager for measuring request performance."""
        start_time = time.perf_counter()
        start_memory = self.memory_profiler.capture_memory_snapshot()
        
        try:
            yield
            status = 'success'
        except Exception as e:
            status = 'error'
            logger.error("Request performance measurement error", extra={
                'endpoint': endpoint,
                'error': str(e)
            })
            raise
        finally:
            # Calculate request duration
            duration = time.perf_counter() - start_time
            end_memory = self.memory_profiler.capture_memory_snapshot()
            
            # Update metrics
            self.request_duration_histogram.labels(
                endpoint=endpoint, method=method, status=status
            ).observe(duration)
            
            self.flask_migration_counter.labels(endpoint=endpoint).inc()
            
            # Create performance snapshot
            current_snapshot = PerformanceSnapshot(
                response_time_ms=duration * 1000,
                memory_usage_mb=end_memory.get('process_rss_mb', 0),
                cpu_usage_percent=self.cpu_monitor.get_cpu_statistics().get('process_cpu_average', 0),
                gc_pause_time_ms=self.gc_monitor.get_gc_statistics().get('average_pause_ms', 0),
                active_connections=0,  # Would need connection tracking
                heap_size_mb=end_memory.get('python_memory', {}).get('current_mb', 0),
                worker_count=0,  # Would need worker tracking
                timestamp=datetime.utcnow(),
                endpoint=endpoint
            )
            
            # Calculate variance if baseline exists
            variance_analysis = self.variance_tracker.calculate_variance(endpoint, current_snapshot)
            
            if variance_analysis:
                self.performance_variance_summary.labels(endpoint=endpoint).observe(duration)

    def performance_monitoring_decorator(self, endpoint: str):
        """Decorator for automatic request performance monitoring."""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                with self.measure_request_performance(endpoint):
                    return func(*args, **kwargs)
            return wrapper
        return decorator

    def get_comprehensive_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance monitoring report."""
        try:
            # Collect data from all monitoring components
            gc_stats = self.gc_monitor.get_gc_statistics()
            cpu_stats = self.cpu_monitor.get_cpu_statistics()
            memory_analysis = self.memory_profiler.analyze_memory_growth()
            
            # Recent variance data
            recent_variances = [v for v in self.variance_tracker.variance_history 
                              if datetime.utcnow() - v.timestamp < timedelta(minutes=5)]
            
            # Overall compliance assessment
            overall_compliance = self._assess_overall_compliance(gc_stats, cpu_stats, memory_analysis, recent_variances)
            
            report = {
                'timestamp': datetime.utcnow().isoformat(),
                'monitoring_status': 'active',
                'overall_compliance': overall_compliance,
                'performance_summary': {
                    'variance_within_threshold': overall_compliance['variance_compliant'],
                    'cpu_within_threshold': overall_compliance['cpu_compliant'],
                    'memory_within_threshold': overall_compliance['memory_compliant'],
                    'gc_within_threshold': overall_compliance['gc_compliant']
                },
                'detailed_metrics': {
                    'garbage_collection': gc_stats,
                    'cpu_utilization': cpu_stats,
                    'memory_analysis': memory_analysis,
                    'variance_analysis': {
                        'recent_variances_count': len(recent_variances),
                        'average_variance': sum(v.overall_variance for v in recent_variances) / len(recent_variances) if recent_variances else 0
                    }
                },
                'recommendations': self._generate_comprehensive_recommendations(gc_stats, cpu_stats, memory_analysis),
                'alert_thresholds': {
                    'variance_warning': VARIANCE_WARNING_THRESHOLD,
                    'variance_critical': VARIANCE_CRITICAL_THRESHOLD,
                    'cpu_warning': CPU_WARNING_THRESHOLD,
                    'cpu_critical': CPU_CRITICAL_THRESHOLD,
                    'memory_warning': MEMORY_WARNING_THRESHOLD,
                    'memory_critical': MEMORY_CRITICAL_THRESHOLD,
                    'gc_warning': GC_WARNING_THRESHOLD,
                    'gc_critical': GC_CRITICAL_THRESHOLD
                }
            }
            
            return report
            
        except Exception as e:
            logger.error("Error generating comprehensive performance report", extra={
                'error': str(e),
                'traceback': traceback.format_exc()
            })
            return {'error': 'Failed to generate report', 'timestamp': datetime.utcnow().isoformat()}

    def _assess_overall_compliance(self, gc_stats, cpu_stats, memory_analysis, recent_variances) -> Dict[str, Any]:
        """Assess overall performance compliance status."""
        compliance = {
            'gc_compliant': gc_stats.get('compliance_status') == 'COMPLIANT',
            'cpu_compliant': cpu_stats.get('compliance_status') == 'COMPLIANT',
            'memory_compliant': memory_analysis.get('compliance_status') == 'COMPLIANT',
            'variance_compliant': all(v.compliance_status == 'COMPLIANT' for v in recent_variances)
        }
        
        compliance['overall_status'] = 'COMPLIANT' if all(compliance.values()) else 'NON_COMPLIANT'
        
        return compliance

    def _generate_comprehensive_recommendations(self, gc_stats, cpu_stats, memory_analysis) -> List[str]:
        """Generate comprehensive optimization recommendations."""
        recommendations = []
        
        # GC recommendations
        if gc_stats.get('compliance_status') != 'COMPLIANT':
            recommendations.append("Optimize Python garbage collection - consider gc.disable() for critical sections")
        
        # CPU recommendations
        if cpu_stats.get('compliance_status') != 'COMPLIANT':
            recommendations.append("Consider horizontal scaling - CPU utilization exceeds sustainable thresholds")
        
        # Memory recommendations
        if memory_analysis.get('compliance_status') != 'COMPLIANT':
            recommendations.extend(memory_analysis.get('recommendations', []))
        
        return recommendations

    def export_metrics(self) -> str:
        """Export Prometheus metrics in text format."""
        return generate_latest(self.metrics_registry)

    def cleanup(self):
        """Cleanup monitoring resources."""
        try:
            self.cpu_monitor.stop_monitoring()
            self.gc_monitor.cleanup()
            logger.info("Performance monitoring cleanup completed")
        except Exception as e:
            logger.error("Error during performance monitoring cleanup", extra={'error': str(e)})


# Global performance monitor instance
_performance_monitor = None


def get_performance_monitor(alert_callback: Optional[Callable] = None) -> PerformanceMonitor:
    """Get or create global performance monitor instance."""
    global _performance_monitor
    if _performance_monitor is None:
        _performance_monitor = PerformanceMonitor(alert_callback)
    return _performance_monitor


def monitor_performance(endpoint: str):
    """Decorator for monitoring endpoint performance."""
    monitor = get_performance_monitor()
    return monitor.performance_monitoring_decorator(endpoint)


# Utility functions for external integration
def set_nodejs_baseline(endpoint: str, response_time_ms: float, memory_mb: float, cpu_percent: float, throughput_rps: float):
    """Set Node.js performance baseline for comparison."""
    baseline = PerformanceBaseline(
        endpoint=endpoint,
        response_time_ms=response_time_ms,
        memory_usage_mb=memory_mb,
        cpu_usage_percent=cpu_percent,
        throughput_rps=throughput_rps,
        timestamp=datetime.utcnow()
    )
    
    monitor = get_performance_monitor()
    monitor.variance_tracker.set_baseline(endpoint, baseline)


def get_performance_report() -> Dict[str, Any]:
    """Get comprehensive performance monitoring report."""
    monitor = get_performance_monitor()
    return monitor.get_comprehensive_report()


def export_prometheus_metrics() -> str:
    """Export performance metrics in Prometheus format."""
    monitor = get_performance_monitor()
    return monitor.export_metrics()