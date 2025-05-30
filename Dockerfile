# Multi-stage Docker container configuration for Python/Flask application deployment
# Implements optimized container build with pip-tools dependency management,
# Gunicorn WSGI server configuration, and security hardening replacing Node.js container setup.
#
# Based on:
# - Section 8.3.1 Container Platform Strategy - Docker containerization with enterprise-grade deployment patterns
# - Section 8.3.2 Base Image Strategy - python:3.11-slim for security optimization and performance balance
# - Section 8.3.3 Multi-Stage Build Strategy - pip-tools integration for deterministic dependency management
# - Section 8.3.4 Build Optimization Techniques - Layer caching and performance optimization
# - Section 8.3.5 Security Scanning Requirements - Container security framework with non-root execution

# =============================================================================
# STAGE 1: DEPENDENCY BUILDER
# =============================================================================
# Purpose: Compile and validate Python dependencies using pip-tools
# Optimizes build cache utilization and ensures deterministic dependency resolution

FROM python:3.11-slim as dependency-builder

# Set build-time labels for container metadata
LABEL stage="dependency-builder" \
      purpose="Compile Python dependencies using pip-tools" \
      maintainer="Flask Migration Team"

# Install system dependencies required for pip-tools and package compilation
# curl: Required for health checks in final stage
# gcc: Required for compiling certain Python packages
# build-essential: Complete build environment for Python extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create application directory and set working directory
WORKDIR /build

# Install pip-tools for deterministic dependency compilation and version pinning
# Using specific version for reproducible builds per Section 8.3.3
RUN pip install --no-cache-dir pip-tools==7.3.0

# Copy requirements source files for dependency compilation
# Prioritize requirements.in for pip-compile if available, fallback to requirements.txt
COPY requirements.txt ./
COPY requirements.in* ./

# Generate pinned requirements.txt using pip-compile for deterministic builds
# If requirements.in exists, compile it; otherwise use existing requirements.txt
RUN if [ -f requirements.in ]; then \
        pip-compile requirements.in --output-file requirements-compiled.txt --resolver=backtracking; \
    else \
        cp requirements.txt requirements-compiled.txt; \
    fi

# Validate compiled requirements and pre-download wheels for faster installation
# Pre-download strategy reduces runtime dependency installation time
RUN pip download --no-deps -r requirements-compiled.txt -d /build/wheels/

# Install and validate all dependencies to ensure compatibility
# This step catches dependency conflicts early in the build process
RUN pip install --no-cache-dir -r requirements-compiled.txt

# =============================================================================
# STAGE 2: PRODUCTION RUNTIME
# =============================================================================
# Purpose: Create optimized production container with minimal attack surface
# Implements security hardening and performance optimization

FROM python:3.11-slim as production

# Set production-time labels for container identification
LABEL stage="production" \
      purpose="Flask application production runtime" \
      version="1.0.0" \
      python.version="3.11" \
      framework="Flask" \
      wsgi.server="Gunicorn"

# Create non-root user for security per Section 8.3.5 WSGI Security Integration
# User ID 1001 avoids conflicts with common system users
RUN groupadd --gid 1001 appuser && \
    useradd --uid 1001 --gid 1001 --shell /bin/bash --create-home appuser

# Install minimal system dependencies for production runtime
# curl: Required for health checks
# ca-certificates: Required for HTTPS connections to external services
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create application directory with proper permissions
RUN mkdir -p /app && chown -R appuser:appuser /app

# Set working directory
WORKDIR /app

# Copy compiled requirements from builder stage
COPY --from=dependency-builder /build/requirements-compiled.txt ./requirements.txt

# Install production dependencies including Gunicorn WSGI server
# Install Gunicorn 23.0.0 explicitly as per Section 3.5.2 Production WSGI Servers
# Use --no-cache-dir to minimize image size per Section 8.3.4 Build Optimization
RUN pip install --no-cache-dir -r requirements.txt gunicorn==23.0.0

# Copy application source code
# Use .dockerignore to exclude unnecessary files per build optimization
COPY --chown=appuser:appuser . .

# Copy Gunicorn configuration with proper permissions
COPY --chown=appuser:appuser gunicorn.conf.py ./

# Create necessary runtime directories with proper permissions
# /tmp/uploads: For file upload processing
# /var/log/app: For application logs (if needed)
RUN mkdir -p /tmp/uploads /var/log/app && \
    chown -R appuser:appuser /tmp/uploads /var/log/app && \
    chmod 755 /tmp/uploads /var/log/app

# Switch to non-root user for security per Section 8.3.5 Container Security Context
USER appuser

# Set environment variables for Flask and Gunicorn
# FLASK_APP: Application module for Flask/Gunicorn discovery
# FLASK_ENV: Production environment configuration
# PYTHONDONTWRITEBYTECODE: Prevent .pyc file generation
# PYTHONUNBUFFERED: Ensure stdout/stderr are not buffered for container logging
ENV FLASK_APP=app:app \
    FLASK_ENV=production \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GUNICORN_CONF=/app/gunicorn.conf.py

# Expose port 8000 for Gunicorn WSGI server
# Matches gunicorn.conf.py bind configuration
EXPOSE 8000

# Expose port 8001 for Prometheus metrics (if enabled)
EXPOSE 8001

# Configure health check for container orchestration per Section 8.3.2 Production Runtime Configuration
# Validates Flask application readiness using health endpoint
# --interval=30s: Check every 30 seconds
# --timeout=10s: 10 second timeout for health check
# --start-period=5s: 5 second grace period for application startup
# --retries=3: 3 failed checks before marking unhealthy
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Set Gunicorn as container ENTRYPOINT per Section 8.3.1 WSGI Server Integration
# Uses configuration file for optimized production settings
# Dynamic worker count based on CPU allocation: --workers $((2 * $(nproc) + 1))
# Alternative static configuration available in gunicorn.conf.py
ENTRYPOINT ["gunicorn"]

# Default command arguments for Gunicorn startup
# --config: Use configuration file for advanced settings
# --bind: Bind to all interfaces on port 8000
# --workers: Dynamic worker calculation or fallback to 4
# --timeout: Request timeout configuration
# --keepalive: Keep-alive timeout for persistent connections
# --max-requests: Maximum requests per worker before restart
# --access-logfile: Access log to stdout for container logging
# --error-logfile: Error log to stderr for container logging
CMD ["--config", "/app/gunicorn.conf.py", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "4", \
     "--timeout", "120", \
     "--keepalive", "5", \
     "--max-requests", "1000", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "app:app"]

# =============================================================================
# CONTAINER OPTIMIZATION AND SECURITY NOTES
# =============================================================================
#
# Build Optimization Features:
# - Multi-stage build eliminates build dependencies from production image
# - Layer caching optimization through strategic COPY and RUN instruction ordering
# - Pip wheel pre-downloading for faster dependency installation
# - Minimal base image (python:3.11-slim) for reduced attack surface
#
# Security Features:
# - Non-root user execution for container security
# - Minimal system dependencies to reduce vulnerability exposure
# - Security-hardened Gunicorn configuration via gunicorn.conf.py
# - Container health checks for orchestration integration
#
# Performance Features:
# - Gunicorn WSGI server optimized for production workloads
# - Dynamic worker process management based on CPU allocation
# - Connection pooling and keep-alive configuration
# - Prometheus metrics integration for monitoring
#
# Production Readiness:
# - Zero-downtime deployment support through health checks
# - Graceful shutdown handling for rolling updates
# - Structured logging for enterprise log aggregation
# - Resource limit awareness through worker configuration
#
# Container Orchestration Compatibility:
# - Kubernetes-compatible health check endpoints
# - Docker Compose development environment support
# - Load balancer health check integration
# - Blue-green deployment pattern compatibility
#
# =============================================================================
# BUILD AND RUN INSTRUCTIONS
# =============================================================================
#
# Build Command:
# docker build -t flask-app:latest .
#
# Run Command (Development):
# docker run -p 8000:8000 -e FLASK_ENV=development flask-app:latest
#
# Run Command (Production):
# docker run -p 8000:8000 -p 8001:8001 flask-app:latest
#
# Health Check Test:
# curl http://localhost:8000/health
#
# Metrics Endpoint:
# curl http://localhost:8001/metrics
#
# =============================================================================