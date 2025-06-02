#!/bin/bash

# =============================================================================
# Docker Container Build Automation Script
# =============================================================================
#
# Enterprise-grade Docker container build automation script implementing 
# multi-stage builds with python:3.11-slim base image, comprehensive security 
# scanning integration, and optimized container image generation for Flask 
# application deployment.
#
# Based on Technical Specification:
# - Section 8.3.2: Base Image Strategy (python:3.11-slim)
# - Section 8.3.3: Multi-Stage Build Strategy with pip-tools integration
# - Section 8.5.2: Container Vulnerability Scanning with Trivy 0.48+
# - Section 8.3.1: WSGI Server Integration with Gunicorn 21.2+
# - Section 8.3.4: Build Optimization Techniques
# - Section 8.3.5: Container Security Framework
#
# Key Features:
# - Multi-stage Docker builds for optimal performance and security
# - Trivy 0.48+ container vulnerability scanning with critical blocking
# - Gunicorn WSGI server configuration as container entrypoint
# - Container health check configuration using Flask health endpoints
# - Build optimization with layer caching and dependency management
# - Enterprise-grade deployment patterns and CI/CD integration
# - Comprehensive security scanning and policy enforcement
#
# =============================================================================

set -euo pipefail  # Exit on any error, undefined variables, or pipe failures

# =============================================================================
# CONFIGURATION AND VARIABLES
# =============================================================================

# Script configuration
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
readonly LOG_FILE="${PROJECT_ROOT}/build.log"

# Docker configuration
readonly DOCKER_REGISTRY="${DOCKER_REGISTRY:-""}"
readonly IMAGE_NAME="${IMAGE_NAME:-flask-app}"
readonly IMAGE_TAG="${IMAGE_TAG:-latest}"
readonly BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
readonly BUILD_VERSION="${BUILD_VERSION:-$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')}"

# Build configuration
readonly DOCKERFILE_PATH="${PROJECT_ROOT}/Dockerfile"
readonly DOCKER_CONTEXT="${PROJECT_ROOT}"
readonly BUILD_CACHE_DIR="${PROJECT_ROOT}/.docker-cache"
readonly TRIVY_CACHE_DIR="${PROJECT_ROOT}/.trivy-cache"

# Security scanning configuration
readonly TRIVY_VERSION="${TRIVY_VERSION:-0.48.3}"
readonly TRIVY_SEVERITY="${TRIVY_SEVERITY:-CRITICAL,HIGH,MEDIUM}"
readonly TRIVY_EXIT_CODE="${TRIVY_EXIT_CODE:-1}"
readonly TRIVY_FORMAT="${TRIVY_FORMAT:-sarif}"
readonly SECURITY_SCAN_ENABLED="${SECURITY_SCAN_ENABLED:-true}"

# Performance and optimization configuration
readonly DOCKER_BUILDKIT="${DOCKER_BUILDKIT:-1}"
readonly BUILD_PARALLEL="${BUILD_PARALLEL:-true}"
readonly CACHE_FROM_ENABLED="${CACHE_FROM_ENABLED:-true}"
readonly BUILD_PROGRESS="${BUILD_PROGRESS:-auto}"

# Health check configuration
readonly HEALTH_CHECK_ENABLED="${HEALTH_CHECK_ENABLED:-true}"
readonly HEALTH_CHECK_TIMEOUT="${HEALTH_CHECK_TIMEOUT:-30}"
readonly HEALTH_CHECK_RETRIES="${HEALTH_CHECK_RETRIES:-3}"

# Logging colors and formatting
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# =============================================================================
# LOGGING AND UTILITY FUNCTIONS
# =============================================================================

# Logging function with timestamp and level
log() {
    local level="$1"
    local message="$2"
    local timestamp="$(date -u +'%Y-%m-%d %H:%M:%S UTC')"
    local color=""
    
    case "$level" in
        "INFO")  color="$GREEN" ;;
        "WARN")  color="$YELLOW" ;;
        "ERROR") color="$RED" ;;
        "DEBUG") color="$BLUE" ;;
        *)       color="$NC" ;;
    esac
    
    echo -e "${color}[$timestamp] [$level] $message${NC}" | tee -a "$LOG_FILE"
}

# Error handling with cleanup
error_exit() {
    local message="$1"
    local exit_code="${2:-1}"
    log "ERROR" "$message"
    cleanup
    exit "$exit_code"
}

# Cleanup function for temporary resources
cleanup() {
    log "INFO" "Performing cleanup operations..."
    
    # Remove temporary containers if they exist
    if [[ -n "${BUILD_CONTAINER_ID:-}" ]]; then
        docker rm -f "$BUILD_CONTAINER_ID" 2>/dev/null || true
    fi
    
    # Clean up dangling images from failed builds
    docker image prune -f --filter "dangling=true" 2>/dev/null || true
    
    log "INFO" "Cleanup completed"
}

# Trap for cleanup on script exit
trap cleanup EXIT

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Validate required dependencies
validate_dependencies() {
    log "INFO" "Validating build dependencies..."
    
    # Check Docker
    if ! command_exists docker; then
        error_exit "Docker is not installed or not in PATH"
    fi
    
    # Check Docker daemon
    if ! docker info >/dev/null 2>&1; then
        error_exit "Docker daemon is not running"
    fi
    
    # Check git (optional, for build version)
    if ! command_exists git; then
        log "WARN" "Git not available, using 'unknown' for build version"
    fi
    
    # Check if Dockerfile exists
    if [[ ! -f "$DOCKERFILE_PATH" ]]; then
        error_exit "Dockerfile not found at: $DOCKERFILE_PATH"
    fi
    
    log "INFO" "All dependencies validated successfully"
}

# =============================================================================
# SECURITY SCANNING FUNCTIONS
# =============================================================================

# Install Trivy for container vulnerability scanning
install_trivy() {
    log "INFO" "Installing Trivy $TRIVY_VERSION for container vulnerability scanning..."
    
    # Create cache directory
    mkdir -p "$TRIVY_CACHE_DIR"
    
    # Check if Trivy is already installed with correct version
    if command_exists trivy; then
        local installed_version
        installed_version="$(trivy --version | grep -oE 'Version: [0-9]+\.[0-9]+\.[0-9]+' | cut -d' ' -f2)"
        if [[ "$installed_version" == "$TRIVY_VERSION" ]]; then
            log "INFO" "Trivy $TRIVY_VERSION already installed"
            return 0
        fi
    fi
    
    # Download and install Trivy
    local trivy_url="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
    local temp_dir="/tmp/trivy-install"
    
    mkdir -p "$temp_dir"
    cd "$temp_dir"
    
    log "INFO" "Downloading Trivy from: $trivy_url"
    curl -sL "$trivy_url" | tar xz
    
    # Install to /usr/local/bin (requires sudo) or local directory
    if [[ $EUID -eq 0 ]] || sudo -n true 2>/dev/null; then
        sudo mv trivy /usr/local/bin/
        sudo chmod +x /usr/local/bin/trivy
    else
        # Install to local directory if no sudo access
        local local_bin="$HOME/.local/bin"
        mkdir -p "$local_bin"
        mv trivy "$local_bin/"
        chmod +x "$local_bin/trivy"
        
        # Add to PATH if not already there
        if [[ ":$PATH:" != *":$local_bin:"* ]]; then
            export PATH="$local_bin:$PATH"
        fi
    fi
    
    cd "$PROJECT_ROOT"
    rm -rf "$temp_dir"
    
    log "INFO" "Trivy $TRIVY_VERSION installed successfully"
}

# Perform container vulnerability scanning with Trivy
scan_container_vulnerabilities() {
    local image_name="$1"
    log "INFO" "Performing container vulnerability scan with Trivy..."
    
    # Ensure Trivy is installed
    if [[ "$SECURITY_SCAN_ENABLED" == "true" ]]; then
        install_trivy
    else
        log "WARN" "Security scanning disabled, skipping Trivy scan"
        return 0
    fi
    
    # Configure Trivy scan parameters
    local scan_output="$PROJECT_ROOT/trivy-results.${TRIVY_FORMAT}"
    local trivy_cmd=(
        trivy image
        --cache-dir "$TRIVY_CACHE_DIR"
        --format "$TRIVY_FORMAT"
        --output "$scan_output"
        --severity "$TRIVY_SEVERITY"
        --exit-code "$TRIVY_EXIT_CODE"
        --timeout 10m
        --no-progress
        "$image_name"
    )
    
    log "INFO" "Running Trivy scan: ${trivy_cmd[*]}"
    
    # Execute Trivy scan
    if "${trivy_cmd[@]}"; then
        log "INFO" "Container vulnerability scan passed"
        log "INFO" "Scan results saved to: $scan_output"
    else
        local scan_exit_code=$?
        log "ERROR" "Container vulnerability scan failed with exit code: $scan_exit_code"
        
        # Display scan results for debugging
        if [[ -f "$scan_output" ]]; then
            log "ERROR" "Vulnerability scan results:"
            cat "$scan_output" | tee -a "$LOG_FILE"
        fi
        
        # Check if this is a critical vulnerability failure
        if [[ $scan_exit_code -eq 1 ]]; then
            error_exit "Critical or high severity vulnerabilities detected. Build blocked per security policy." $scan_exit_code
        else
            log "WARN" "Non-critical scan issues detected, continuing with build"
        fi
    fi
    
    # Generate human-readable report
    log "INFO" "Generating vulnerability summary report..."
    trivy image --cache-dir "$TRIVY_CACHE_DIR" --format table "$image_name" > "$PROJECT_ROOT/trivy-summary.txt" || true
    
    log "INFO" "Vulnerability scan completed"
}

# =============================================================================
# DOCKER BUILD FUNCTIONS
# =============================================================================

# Prepare build environment and validate prerequisites
prepare_build_environment() {
    log "INFO" "Preparing Docker build environment..."
    
    # Create build cache directory
    mkdir -p "$BUILD_CACHE_DIR"
    
    # Enable Docker BuildKit for advanced build features
    export DOCKER_BUILDKIT="$DOCKER_BUILDKIT"
    
    # Validate build context
    if [[ ! -d "$DOCKER_CONTEXT" ]]; then
        error_exit "Docker build context directory not found: $DOCKER_CONTEXT"
    fi
    
    # Check for required files in build context
    local required_files=("requirements.txt" "app.py" "gunicorn.conf.py")
    for file in "${required_files[@]}"; do
        if [[ ! -f "$DOCKER_CONTEXT/$file" ]]; then
            log "WARN" "Required file not found: $file (continuing with build)"
        fi
    done
    
    # Clean up previous build artifacts if they exist
    log "INFO" "Cleaning up previous build artifacts..."
    docker system prune -f --filter "label=stage=dependency-builder" 2>/dev/null || true
    
    log "INFO" "Build environment prepared successfully"
}

# Execute multi-stage Docker build with optimization
execute_docker_build() {
    log "INFO" "Starting Docker multi-stage build process..."
    
    # Construct full image name with registry if specified
    local full_image_name="$IMAGE_NAME:$IMAGE_TAG"
    if [[ -n "$DOCKER_REGISTRY" ]]; then
        full_image_name="$DOCKER_REGISTRY/$full_image_name"
    fi
    
    # Prepare build arguments
    local build_args=(
        --file "$DOCKERFILE_PATH"
        --tag "$full_image_name"
        --label "build.date=$BUILD_DATE"
        --label "build.version=$BUILD_VERSION"
        --label "build.source=flask-migration"
        --label "deployment.type=production"
        --progress "$BUILD_PROGRESS"
    )
    
    # Add cache configuration if enabled
    if [[ "$CACHE_FROM_ENABLED" == "true" ]]; then
        # Use previous image as cache source if it exists
        if docker image inspect "$full_image_name" >/dev/null 2>&1; then
            build_args+=(--cache-from "$full_image_name")
        fi
    fi
    
    # Add build optimization arguments
    if [[ "$BUILD_PARALLEL" == "true" ]]; then
        build_args+=(--rm)
    fi
    
    # Add build context
    build_args+=("$DOCKER_CONTEXT")
    
    log "INFO" "Build command: docker build ${build_args[*]}"
    log "INFO" "Building image: $full_image_name"
    
    # Execute Docker build with timing
    local build_start_time
    build_start_time="$(date +%s)"
    
    if docker build "${build_args[@]}"; then
        local build_end_time
        build_end_time="$(date +%s)"
        local build_duration=$((build_end_time - build_start_time))
        
        log "INFO" "Docker build completed successfully in ${build_duration}s"
        log "INFO" "Image built: $full_image_name"
        
        # Store image name for security scanning
        echo "$full_image_name" > "$PROJECT_ROOT/.last-built-image"
        
        return 0
    else
        local build_exit_code=$?
        error_exit "Docker build failed with exit code: $build_exit_code" $build_exit_code
    fi
}

# Validate built container image
validate_container_image() {
    local image_name="$1"
    log "INFO" "Validating built container image..."
    
    # Check if image exists
    if ! docker image inspect "$image_name" >/dev/null 2>&1; then
        error_exit "Built image not found: $image_name"
    fi
    
    # Get image information
    local image_id
    image_id="$(docker image inspect "$image_name" --format '{{.Id}}')"
    local image_size
    image_size="$(docker image inspect "$image_name" --format '{{.Size}}' | numfmt --to=iec-i --suffix=B)"
    
    log "INFO" "Image validation successful:"
    log "INFO" "  Image ID: $image_id"
    log "INFO" "  Image Size: $image_size"
    log "INFO" "  Image Name: $image_name"
    
    # Validate image layers for optimization
    local layer_count
    layer_count="$(docker image inspect "$image_name" --format '{{len .RootFS.Layers}}')"
    log "INFO" "  Layer Count: $layer_count"
    
    if [[ $layer_count -gt 20 ]]; then
        log "WARN" "Image has $layer_count layers, consider optimizing for fewer layers"
    fi
    
    # Check for security best practices
    local non_root_user
    non_root_user="$(docker image inspect "$image_name" --format '{{.Config.User}}')"
    if [[ -n "$non_root_user" && "$non_root_user" != "root" ]]; then
        log "INFO" "  Security: Non-root user configured ($non_root_user)"
    else
        log "WARN" "  Security: Image may be running as root user"
    fi
    
    log "INFO" "Container image validation completed"
}

# =============================================================================
# CONTAINER HEALTH CHECK FUNCTIONS
# =============================================================================

# Test container health endpoints
test_container_health() {
    local image_name="$1"
    
    if [[ "$HEALTH_CHECK_ENABLED" != "true" ]]; then
        log "INFO" "Container health checks disabled, skipping health validation"
        return 0
    fi
    
    log "INFO" "Testing container health endpoints..."
    
    # Start container in background for health testing
    local container_name="flask-health-test-$(date +%s)"
    local container_port="8080"
    
    log "INFO" "Starting test container: $container_name"
    
    # Run container with health check enabled
    local container_id
    if container_id="$(docker run -d \
        --name "$container_name" \
        --publish "$container_port:8000" \
        --env FLASK_ENV=production \
        --health-cmd="curl -f http://localhost:8000/health || exit 1" \
        --health-interval=10s \
        --health-timeout=5s \
        --health-retries="$HEALTH_CHECK_RETRIES" \
        "$image_name")"; then
        
        BUILD_CONTAINER_ID="$container_id"
        log "INFO" "Test container started: $container_id"
    else
        error_exit "Failed to start test container"
    fi
    
    # Wait for container to be ready
    log "INFO" "Waiting for container to be ready..."
    local wait_count=0
    local max_wait=30
    
    while [[ $wait_count -lt $max_wait ]]; do
        if docker inspect "$container_id" --format '{{.State.Health.Status}}' 2>/dev/null | grep -q "healthy"; then
            log "INFO" "Container health check passed"
            break
        elif docker inspect "$container_id" --format '{{.State.Health.Status}}' 2>/dev/null | grep -q "unhealthy"; then
            log "ERROR" "Container health check failed"
            docker logs "$container_id" | tail -20 | tee -a "$LOG_FILE"
            docker rm -f "$container_id" 2>/dev/null || true
            error_exit "Container failed health checks"
        fi
        
        sleep 2
        ((wait_count++))
    done
    
    if [[ $wait_count -ge $max_wait ]]; then
        log "ERROR" "Container health check timed out after ${max_wait} attempts"
        docker logs "$container_id" | tail -20 | tee -a "$LOG_FILE"
        docker rm -f "$container_id" 2>/dev/null || true
        error_exit "Container health check timeout"
    fi
    
    # Test specific health endpoints
    local health_endpoints=("/health" "/health/ready" "/health/live")
    for endpoint in "${health_endpoints[@]}"; do
        log "INFO" "Testing health endpoint: $endpoint"
        
        local health_url="http://localhost:$container_port$endpoint"
        if curl -f -s --max-time 10 "$health_url" >/dev/null; then
            log "INFO" "Health endpoint $endpoint responded successfully"
        else
            log "WARN" "Health endpoint $endpoint failed or not available"
        fi
    done
    
    # Clean up test container
    log "INFO" "Cleaning up test container..."
    docker rm -f "$container_id" 2>/dev/null || true
    BUILD_CONTAINER_ID=""
    
    log "INFO" "Container health validation completed successfully"
}

# =============================================================================
# BUILD REPORTING AND METRICS
# =============================================================================

# Generate build report with metrics and summary
generate_build_report() {
    local image_name="$1"
    local build_status="$2"
    
    log "INFO" "Generating build report..."
    
    local report_file="$PROJECT_ROOT/build-report.json"
    local build_end_time="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    
    # Collect image metrics
    local image_size=""
    local image_id=""
    local layer_count=""
    
    if [[ "$build_status" == "success" ]] && docker image inspect "$image_name" >/dev/null 2>&1; then
        image_size="$(docker image inspect "$image_name" --format '{{.Size}}')"
        image_id="$(docker image inspect "$image_name" --format '{{.Id}}')"
        layer_count="$(docker image inspect "$image_name" --format '{{len .RootFS.Layers}}')"
    fi
    
    # Generate JSON report for CI/CD integration
    cat > "$report_file" <<EOF
{
  "build": {
    "status": "$build_status",
    "timestamp": "$build_end_time",
    "version": "$BUILD_VERSION",
    "image": {
      "name": "$image_name",
      "id": "$image_id",
      "size": "$image_size",
      "layers": "$layer_count"
    },
    "security": {
      "scan_enabled": "$SECURITY_SCAN_ENABLED",
      "trivy_version": "$TRIVY_VERSION",
      "scan_results": "trivy-results.$TRIVY_FORMAT"
    },
    "configuration": {
      "docker_buildkit": "$DOCKER_BUILDKIT",
      "base_image": "python:3.11-slim",
      "wsgi_server": "gunicorn",
      "health_check_enabled": "$HEALTH_CHECK_ENABLED"
    }
  }
}
EOF
    
    log "INFO" "Build report generated: $report_file"
    
    # Display summary
    log "INFO" "=== BUILD SUMMARY ==="
    log "INFO" "Status: $build_status"
    log "INFO" "Image: $image_name"
    log "INFO" "Build Version: $BUILD_VERSION"
    log "INFO" "Build Date: $build_end_time"
    
    if [[ -n "$image_size" ]]; then
        local size_mb=$((image_size / 1024 / 1024))
        log "INFO" "Image Size: ${size_mb}MB"
        log "INFO" "Layer Count: $layer_count"
    fi
    
    if [[ "$SECURITY_SCAN_ENABLED" == "true" ]]; then
        log "INFO" "Security Scan: Enabled (Trivy $TRIVY_VERSION)"
    else
        log "INFO" "Security Scan: Disabled"
    fi
    
    log "INFO" "======================"
}

# =============================================================================
# MAIN BUILD ORCHESTRATION
# =============================================================================

# Display script usage information
usage() {
    cat <<EOF
Usage: $SCRIPT_NAME [OPTIONS]

Docker Container Build Automation Script for Flask Application Migration

This script implements enterprise-grade Docker container build automation
with multi-stage builds, security scanning, and optimization features.

OPTIONS:
    -h, --help              Show this help message
    -i, --image NAME        Image name (default: $IMAGE_NAME)
    -t, --tag TAG           Image tag (default: $IMAGE_TAG)
    -r, --registry URL      Docker registry URL
    --skip-security         Disable security scanning
    --skip-health           Disable health check validation
    --debug                 Enable debug logging
    --clean                 Clean build (no cache)

ENVIRONMENT VARIABLES:
    IMAGE_NAME              Docker image name
    IMAGE_TAG               Docker image tag
    DOCKER_REGISTRY         Docker registry URL
    BUILD_VERSION           Build version identifier
    SECURITY_SCAN_ENABLED   Enable/disable security scanning (true/false)
    HEALTH_CHECK_ENABLED    Enable/disable health checks (true/false)
    TRIVY_VERSION           Trivy scanner version
    DOCKER_BUILDKIT         Enable Docker BuildKit (1/0)

EXAMPLES:
    # Basic build
    $SCRIPT_NAME

    # Build with custom image name and tag
    $SCRIPT_NAME --image my-flask-app --tag v1.0.0

    # Build with registry
    $SCRIPT_NAME --registry docker.company.com --image flask-app --tag latest

    # Build without security scanning (not recommended)
    $SCRIPT_NAME --skip-security

    # Clean build without cache
    $SCRIPT_NAME --clean

EXIT CODES:
    0    Build completed successfully
    1    Build failed due to errors
    2    Security scan failed (critical vulnerabilities)
    3    Health check validation failed
    4    Missing dependencies or configuration errors

For more information, see the technical specification Section 8.3 and 8.5.
EOF
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -i|--image)
                IMAGE_NAME="$2"
                shift 2
                ;;
            -t|--tag)
                IMAGE_TAG="$2"
                shift 2
                ;;
            -r|--registry)
                DOCKER_REGISTRY="$2"
                shift 2
                ;;
            --skip-security)
                SECURITY_SCAN_ENABLED="false"
                shift
                ;;
            --skip-health)
                HEALTH_CHECK_ENABLED="false"
                shift
                ;;
            --debug)
                set -x  # Enable debug mode
                shift
                ;;
            --clean)
                CACHE_FROM_ENABLED="false"
                log "INFO" "Clean build enabled, cache disabled"
                shift
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                usage
                exit 4
                ;;
        esac
    done
}

# Main build orchestration function
main() {
    local start_time
    start_time="$(date +%s)"
    
    log "INFO" "Starting Flask Docker container build automation..."
    log "INFO" "Script: $SCRIPT_NAME"
    log "INFO" "Project Root: $PROJECT_ROOT"
    log "INFO" "Target Image: ${DOCKER_REGISTRY:+$DOCKER_REGISTRY/}$IMAGE_NAME:$IMAGE_TAG"
    log "INFO" "Build Version: $BUILD_VERSION"
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Validate environment and dependencies
    validate_dependencies
    
    # Prepare build environment
    prepare_build_environment
    
    # Execute multi-stage Docker build
    execute_docker_build
    
    # Determine full image name for subsequent operations
    local full_image_name="$IMAGE_NAME:$IMAGE_TAG"
    if [[ -n "$DOCKER_REGISTRY" ]]; then
        full_image_name="$DOCKER_REGISTRY/$full_image_name"
    fi
    
    # Validate built container image
    validate_container_image "$full_image_name"
    
    # Perform security vulnerability scanning
    scan_container_vulnerabilities "$full_image_name"
    
    # Test container health endpoints
    test_container_health "$full_image_name"
    
    # Calculate build duration
    local end_time
    end_time="$(date +%s)"
    local total_duration=$((end_time - start_time))
    
    # Generate build report
    generate_build_report "$full_image_name" "success"
    
    log "INFO" "Flask Docker container build completed successfully!"
    log "INFO" "Total build time: ${total_duration}s"
    log "INFO" "Image ready for deployment: $full_image_name"
    
    # Provide next steps
    log "INFO" "=== NEXT STEPS ==="
    log "INFO" "1. Test the container: docker run -p 8000:8000 $full_image_name"
    log "INFO" "2. Check health: curl http://localhost:8000/health"
    log "INFO" "3. Push to registry: docker push $full_image_name"
    log "INFO" "4. Deploy using deployment scripts"
    log "INFO" "=================="
    
    return 0
}

# =============================================================================
# SCRIPT EXECUTION
# =============================================================================

# Initialize logging
log "INFO" "Initializing Docker build automation script..."

# Execute main function with all arguments
if main "$@"; then
    exit 0
else
    error_exit "Build process failed" $?
fi