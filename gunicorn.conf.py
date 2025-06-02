"""
Gunicorn WSGI Server Configuration

Production-ready Gunicorn configuration for Flask application deployment.
Optimized for enterprise-grade performance, security, and monitoring.
Replaces Node.js process management with Python WSGI server.

Configuration based on:
- Section 8.3.1 WSGI Server Integration
- Section 8.3.2 Production Runtime Configuration  
- Section 3.5.2 Docker Configuration
- Section 0.3.2 Performance Monitoring Requirements
"""

import multiprocessing
import os

# =============================================================================
# SERVER SOCKET CONFIGURATION
# =============================================================================

# Server binding configuration for containerized deployment
bind = "0.0.0.0:8000"

# Socket backlog for connection queuing
backlog = 2048

# =============================================================================
# WORKER PROCESS CONFIGURATION
# =============================================================================

# Dynamic worker count calculation based on CPU allocation
# Formula: (2 * CPU_COUNT) + 1 for optimal resource utilization
# Minimum of 2 workers for redundancy, maximum of 8 for resource constraints
workers = max(2, min(8, (2 * multiprocessing.cpu_count()) + 1))

# Worker class for synchronous request handling
# Using sync workers for optimal performance with Flask application
worker_class = "sync"

# Worker connections for handling concurrent requests per worker
worker_connections = 1000

# Maximum requests per worker before restart (memory leak prevention)
max_requests = 1000

# Random jitter for worker restart (0-50% of max_requests)
max_requests_jitter = 500

# =============================================================================
# TIMEOUT CONFIGURATION
# =============================================================================

# Worker timeout for request processing (seconds)
# Optimized for enterprise-grade response requirements
timeout = 120

# Keep-alive timeout for persistent connections
keepalive = 5

# Graceful timeout for worker shutdown
graceful_timeout = 30

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================

# User and group for worker processes (security hardening)
# Runs as non-root user for container security
user = os.getenv("GUNICORN_USER", "nobody")
group = os.getenv("GUNICORN_GROUP", "nogroup")

# Temporary directory for file uploads and processing
tmp_upload_dir = "/tmp"

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

# Access log format for enterprise log aggregation
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Log file configuration
accesslog = "-"  # stdout for container logging
errorlog = "-"   # stderr for container logging

# Log level for production monitoring
loglevel = os.getenv("GUNICORN_LOG_LEVEL", "info")

# Capture stdout/stderr to access logs
capture_output = True

# Enable access logging
disable_redirect_access_to_syslog = False

# =============================================================================
# PERFORMANCE OPTIMIZATION
# =============================================================================

# Preload application for improved memory usage
preload_app = True

# Enable sendfile for static file serving efficiency
sendfile = True

# Reuse port for improved load balancing
reuse_port = True

# =============================================================================
# MONITORING AND HEALTH CHECKS
# =============================================================================

# Enable stats for monitoring integration
enable_stdio_inheritance = True

# Prometheus metrics integration
def on_starting(server):
    """
    Called just before the master process is initialized.
    Sets up monitoring and metrics collection.
    """
    server.log.info("Gunicorn master process starting with %d workers", workers)
    
    # Initialize Prometheus metrics if available
    try:
        from prometheus_client import start_http_server, Counter, Histogram, Gauge
        
        # Start Prometheus metrics server on port 8001
        start_http_server(8001)
        server.log.info("Prometheus metrics server started on port 8001")
        
        # Store metrics in server for worker access
        server.prometheus_metrics = {
            'requests_total': Counter('gunicorn_requests_total', 'Total requests processed'),
            'request_duration': Histogram('gunicorn_request_duration_seconds', 'Request duration'),
            'workers': Gauge('gunicorn_workers', 'Number of workers'),
            'worker_memory': Gauge('gunicorn_worker_memory_bytes', 'Worker memory usage')
        }
        
        # Set initial worker count
        server.prometheus_metrics['workers'].set(workers)
        
    except ImportError:
        server.log.warning("prometheus_client not available, metrics disabled")

def on_reload(server):
    """
    Called to recycle workers during a reload via SIGHUP.
    """
    server.log.info("Gunicorn configuration reloaded")

def worker_int(worker):
    """
    Called just after a worker has been killed by a signal.
    Handles graceful worker shutdown.
    """
    worker.log.info("Worker %s shutting down gracefully", worker.pid)

def pre_fork(server, worker):
    """
    Called just before a worker is forked.
    """
    server.log.debug("Worker %s forked from master", worker.pid)

def post_fork(server, worker):
    """
    Called just after a worker has been forked.
    Sets up worker-specific monitoring.
    """
    worker.log.info("Worker %s ready to handle requests", worker.pid)
    
    # Initialize worker-specific metrics if available
    if hasattr(server, 'prometheus_metrics'):
        try:
            import psutil
            process = psutil.Process()
            server.prometheus_metrics['worker_memory'].set(process.memory_info().rss)
        except ImportError:
            pass

def pre_exec(server):
    """
    Called just before a new master process is forked.
    """
    server.log.info("Gunicorn master process forked")

def when_ready(server):
    """
    Called just after the server is started.
    """
    server.log.info("Gunicorn application ready to serve requests")

def worker_abort(worker):
    """
    Called when a worker receives the SIGABRT signal.
    Handles worker abort situations with proper logging.
    """
    worker.log.error("Worker %s aborted", worker.pid)

def pre_request(worker, req):
    """
    Called just before a worker processes the request.
    """
    # Update request metrics if available
    if hasattr(worker.app, 'prometheus_metrics'):
        worker.app.prometheus_metrics['requests_total'].inc()

def post_request(worker, req, environ, resp):
    """
    Called after a worker processes the request.
    """
    # Log request completion with timing
    worker.log.debug("Request processed: %s %s - %s", 
                     environ.get('REQUEST_METHOD'), 
                     environ.get('PATH_INFO'), 
                     resp.status)

# =============================================================================
# PROCESS MANAGEMENT
# =============================================================================

# Process name for system monitoring
proc_name = "gunicorn-flask-app"

# PID file for process management
pidfile = "/tmp/gunicorn.pid"

# Daemon mode (disabled for container deployment)
daemon = False

# Raw environment variables passthrough
raw_env = [
    "FLASK_ENV=production",
    "FLASK_APP=app:app"
]

# =============================================================================
# SSL/TLS CONFIGURATION (if required)
# =============================================================================

# SSL configuration for HTTPS termination at application level
# Note: Usually handled by load balancer/reverse proxy in production
keyfile = os.getenv("GUNICORN_KEYFILE")
certfile = os.getenv("GUNICORN_CERTFILE")

# SSL version and ciphers for security
ssl_version = os.getenv("GUNICORN_SSL_VERSION", 2)  # TLS
ciphers = os.getenv("GUNICORN_CIPHERS", "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA")

# =============================================================================
# DEVELOPMENT CONFIGURATION OVERRIDES
# =============================================================================

# Environment-specific configuration adjustments
if os.getenv("FLASK_ENV") == "development":
    # Development overrides
    workers = 1
    timeout = 0  # Disable timeout for debugging
    reload = True
    preload_app = False
    loglevel = "debug"
    
    # Enable code reloading for development
    reload_extra_files = [
        "app.py",
        "requirements.txt"
    ]

# Staging environment optimizations
elif os.getenv("FLASK_ENV") == "staging":
    workers = max(2, multiprocessing.cpu_count())
    timeout = 60
    loglevel = "debug"

# =============================================================================
# RESOURCE LIMITS
# =============================================================================

# Memory limits per worker (in bytes)
# Prevents memory leaks from affecting system stability
limit_request_line = 8192      # Maximum size of HTTP request line
limit_request_fields = 100     # Maximum number of header fields
limit_request_field_size = 8192  # Maximum size of header field

# File descriptor limits
worker_tmp_dir = "/dev/shm"    # Use shared memory for temporary files

# =============================================================================
# VALIDATION AND RUNTIME CHECKS
# =============================================================================

def validate_configuration():
    """
    Validates Gunicorn configuration for production readiness.
    """
    issues = []
    
    # Check worker count
    if workers < 2:
        issues.append("Worker count should be at least 2 for production")
    
    # Check timeout settings
    if timeout < 30:
        issues.append("Timeout should be at least 30 seconds for production")
    
    # Check security settings
    if user == "root":
        issues.append("Running as root user is not recommended for security")
    
    # Check log configuration
    if loglevel == "debug" and os.getenv("FLASK_ENV") == "production":
        issues.append("Debug logging should not be used in production")
    
    return issues

# Run validation if this file is executed directly
if __name__ == "__main__":
    validation_issues = validate_configuration()
    if validation_issues:
        print("Configuration validation issues:")
        for issue in validation_issues:
            print(f"  - {issue}")
    else:
        print("Configuration validation passed")
        print(f"Workers: {workers}")
        print(f"Timeout: {timeout}")
        print(f"Bind: {bind}")
        print(f"Log level: {loglevel}")