#!/bin/bash

# =============================================================================
# Docker Container Build Automation Script
# =============================================================================
# 
# This script implements enterprise-grade Docker container build automation
# for Flask application deployment with multi-stage builds, security scanning,
# and optimized container image generation replacing Node.js build patterns.
#
# Key Features:
# - Multi-stage Docker builds with python:3.11-slim base image
# - Trivy 0.48+ container vulnerability scanning with critical blocking
# - Gunicorn 21.2+ WSGI server configuration as container entrypoint
# - Container health check configuration for orchestration compatibility
# - Build optimization techniques for efficient deployment
# - Security hardening with non-root user execution
#
# Author: Enterprise Software Architecture Team
# Version: 1.0.0
# =============================================================================

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# =============================================================================
# SCRIPT CONFIGURATION AND GLOBAL VARIABLES
# =============================================================================

# Script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Build configuration
DOCKER_REGISTRY="${DOCKER_REGISTRY:-}"
IMAGE_NAME="${IMAGE_NAME:-flask-app}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
BUILD_TARGET="${BUILD_TARGET:-production}"
DOCKERFILE_PATH="${PROJECT_ROOT}/Dockerfile"
DOCKER_CONTEXT="${PROJECT_ROOT}"

# Security scanning configuration
TRIVY_VERSION="${TRIVY_VERSION:-0.48.0}"
TRIVY_SEVERITY="${TRIVY_SEVERITY:-CRITICAL,HIGH,MEDIUM}"
TRIVY_EXIT_CODE="${TRIVY_EXIT_CODE:-1}"  # Fail build on critical vulnerabilities
TRIVY_FORMAT="${TRIVY_FORMAT:-sarif}"
TRIVY_OUTPUT="${PROJECT_ROOT}/trivy-results.sarif"

# Performance and optimization configuration
PARALLEL_BUILDS="${PARALLEL_BUILDS:-true}"
BUILD_CACHE="${BUILD_CACHE:-true}"
BUILD_SQUASH="${BUILD_SQUASH:-false}"
DOCKER_BUILDKIT="${DOCKER_BUILDKIT:-1}"

# Logging configuration
LOG_LEVEL="${LOG_LEVEL:-INFO}"
LOG_FILE="${PROJECT_ROOT}/build.log"

# Health check configuration
HEALTH_CHECK_ENABLED="${HEALTH_CHECK_ENABLED:-true}"
HEALTH_CHECK_INTERVAL="${HEALTH_CHECK_INTERVAL:-30s}"
HEALTH_CHECK_TIMEOUT="${HEALTH_CHECK_TIMEOUT:-10s}"
HEALTH_CHECK_START_PERIOD="${HEALTH_CHECK_START_PERIOD:-5s}"
HEALTH_CHECK_RETRIES="${HEALTH_CHECK_RETRIES:-3}"

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# Logging function with timestamp and log levels
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "${level}" in
        ERROR)
            echo "[${timestamp}] ERROR: ${message}" >&2
            echo "[${timestamp}] ERROR: ${message}" >> "${LOG_FILE}"
            ;;
        WARN)
            echo "[${timestamp}] WARN: ${message}" >&2
            echo "[${timestamp}] WARN: ${message}" >> "${LOG_FILE}"
            ;;
        INFO)
            echo "[${timestamp}] INFO: ${message}"
            echo "[${timestamp}] INFO: ${message}" >> "${LOG_FILE}"
            ;;
        DEBUG)
            if [[ "${LOG_LEVEL}" == "DEBUG" ]]; then
                echo "[${timestamp}] DEBUG: ${message}"
                echo "[${timestamp}] DEBUG: ${message}" >> "${LOG_FILE}"
            fi
            ;;
    esac
}

# Error handling function
handle_error() {
    local exit_code=$?
    local line_number=$1
    log "ERROR" "Script failed at line ${line_number} with exit code ${exit_code}"
    log "ERROR" "Build process terminated due to error"
    exit ${exit_code}
}

# Cleanup function for temporary files
cleanup() {
    log "INFO" "Cleaning up temporary files and resources"
    
    # Remove temporary Trivy cache if exists
    if [[ -d "/tmp/trivy-cache" ]]; then
        rm -rf "/tmp/trivy-cache"
        log "DEBUG" "Removed Trivy cache directory"
    fi
    
    # Clean up any dangling Docker images if build fails
    if docker images -f "dangling=true" -q | grep -q .; then
        log "INFO" "Cleaning up dangling Docker images"
        docker images -f "dangling=true" -q | xargs -r docker rmi || true
    fi
}

# Set error trap
trap 'handle_error ${LINENO}' ERR
trap cleanup EXIT

# =============================================================================
# VALIDATION FUNCTIONS
# =============================================================================

# Validate prerequisites and environment
validate_prerequisites() {
    log "INFO" "Validating build prerequisites and environment"
    
    # Check Docker availability
    if ! command -v docker >/dev/null 2>&1; then
        log "ERROR" "Docker is not installed or not in PATH"
        exit 1
    fi
    
    # Check Docker daemon availability
    if ! docker info >/dev/null 2>&1; then
        log "ERROR" "Docker daemon is not running or accessible"
        exit 1
    fi
    
    # Validate Docker version compatibility
    local docker_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null)
    log "INFO" "Docker version: ${docker_version}"
    
    # Check Dockerfile existence
    if [[ ! -f "${DOCKERFILE_PATH}" ]]; then
        log "ERROR" "Dockerfile not found at ${DOCKERFILE_PATH}"
        exit 1
    fi
    
    # Check project structure
    if [[ ! -f "${PROJECT_ROOT}/requirements.txt" ]]; then
        log "ERROR" "requirements.txt not found in project root"
        exit 1
    fi
    
    if [[ ! -f "${PROJECT_ROOT}/app.py" ]]; then
        log "ERROR" "app.py not found in project root"
        exit 1
    fi
    
    # Check Gunicorn configuration
    if [[ ! -f "${PROJECT_ROOT}/gunicorn.conf.py" ]]; then
        log "WARN" "gunicorn.conf.py not found, using default configuration"
    fi
    
    # Validate environment variables
    if [[ -z "${IMAGE_NAME}" ]]; then
        log "ERROR" "IMAGE_NAME environment variable is required"
        exit 1
    fi
    
    log "INFO" "Prerequisites validation completed successfully"
}

# Validate pip-tools dependency resolution
validate_dependencies() {
    log "INFO" "Validating pip-tools dependency resolution"
    
    if [[ ! -f "${PROJECT_ROOT}/requirements.in" ]]; then
        log "WARN" "requirements.in not found, skipping pip-tools validation"
        return 0
    fi
    
    # Check if requirements.txt is up to date with requirements.in
    local temp_requirements="/tmp/requirements-compiled.txt"
    
    # Use Docker to run pip-compile in consistent environment
    docker run --rm \
        -v "${PROJECT_ROOT}:/workspace" \
        -w /workspace \
        python:3.11-slim \
        bash -c "
            pip install pip-tools==7.3.0 >/dev/null 2>&1 && \
            pip-compile requirements.in --output-file ${temp_requirements} --quiet
        " || {
        log "ERROR" "Failed to compile dependencies with pip-tools"
        exit 1
    }
    
    if ! diff -q "${PROJECT_ROOT}/requirements.txt" "${temp_requirements}" >/dev/null 2>&1; then
        log "ERROR" "requirements.txt is not up to date with requirements.in"
        log "ERROR" "Run 'pip-compile requirements.in' to update"
        rm -f "${temp_requirements}"
        exit 1
    fi
    
    rm -f "${temp_requirements}"
    log "INFO" "Dependency validation completed successfully"
}

# =============================================================================
# TRIVY SECURITY SCANNING FUNCTIONS
# =============================================================================

# Install Trivy if not available
install_trivy() {
    log "INFO" "Checking Trivy installation"
    
    if command -v trivy >/dev/null 2>&1; then
        local current_version=$(trivy version --format json 2>/dev/null | grep -o '"Version":"[^"]*"' | cut -d'"' -f4 || echo "unknown")
        log "INFO" "Trivy is already installed: ${current_version}"
        return 0
    fi
    
    log "INFO" "Installing Trivy ${TRIVY_VERSION}"
    
    # Detect architecture
    local arch=$(uname -m)
    case ${arch} in
        x86_64) arch="64bit" ;;
        aarch64|arm64) arch="ARM64" ;;
        *) 
            log "ERROR" "Unsupported architecture: ${arch}"
            exit 1
            ;;
    esac
    
    # Detect OS
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    
    # Download and install Trivy
    local trivy_url="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${os}-${arch}.tar.gz"
    local temp_dir="/tmp/trivy-install"
    
    mkdir -p "${temp_dir}"
    
    log "INFO" "Downloading Trivy from: ${trivy_url}"
    if ! curl -fsSL "${trivy_url}" | tar -xz -C "${temp_dir}"; then
        log "ERROR" "Failed to download and extract Trivy"
        exit 1
    fi
    
    # Install to system path if we have permissions, otherwise use local bin
    if [[ -w "/usr/local/bin" ]]; then
        mv "${temp_dir}/trivy" "/usr/local/bin/"
        log "INFO" "Trivy installed to /usr/local/bin/trivy"
    else
        mkdir -p "${PROJECT_ROOT}/bin"
        mv "${temp_dir}/trivy" "${PROJECT_ROOT}/bin/"
        export PATH="${PROJECT_ROOT}/bin:${PATH}"
        log "INFO" "Trivy installed to ${PROJECT_ROOT}/bin/trivy"
    fi
    
    rm -rf "${temp_dir}"
    
    # Verify installation
    if ! command -v trivy >/dev/null 2>&1; then
        log "ERROR" "Trivy installation verification failed"
        exit 1
    fi
    
    log "INFO" "Trivy installation completed successfully"
}

# Perform container vulnerability scanning
scan_container_vulnerabilities() {
    local image_ref="$1"
    
    log "INFO" "Starting container vulnerability scanning with Trivy"
    log "INFO" "Scanning image: ${image_ref}"
    log "INFO" "Severity levels: ${TRIVY_SEVERITY}"
    
    # Create cache directory for Trivy
    local trivy_cache_dir="/tmp/trivy-cache"
    mkdir -p "${trivy_cache_dir}"
    
    # Scan container image
    log "INFO" "Executing Trivy security scan"
    local scan_start_time=$(date +%s)
    
    # Run Trivy scan with comprehensive options
    local trivy_cmd=(
        trivy image
        --cache-dir "${trivy_cache_dir}"
        --format "${TRIVY_FORMAT}"
        --output "${TRIVY_OUTPUT}"
        --severity "${TRIVY_SEVERITY}"
        --exit-code "${TRIVY_EXIT_CODE}"
        --no-progress
        --quiet
        "${image_ref}"
    )
    
    log "DEBUG" "Trivy command: ${trivy_cmd[*]}"
    
    if "${trivy_cmd[@]}"; then
        local scan_end_time=$(date +%s)
        local scan_duration=$((scan_end_time - scan_start_time))
        log "INFO" "Container vulnerability scan completed successfully in ${scan_duration}s"
        
        # Generate human-readable summary
        if [[ -f "${TRIVY_OUTPUT}" ]]; then
            log "INFO" "Security scan results saved to: ${TRIVY_OUTPUT}"
            
            # Extract vulnerability count if SARIF format
            if [[ "${TRIVY_FORMAT}" == "sarif" ]]; then
                local vuln_count=$(grep -c '"ruleId"' "${TRIVY_OUTPUT}" 2>/dev/null || echo "0")
                log "INFO" "Total vulnerabilities found: ${vuln_count}"
            fi
        fi
        
        return 0
    else
        local scan_end_time=$(date +%s)
        local scan_duration=$((scan_end_time - scan_start_time))
        log "ERROR" "Container vulnerability scan failed after ${scan_duration}s"
        
        # Try to get more details about failures
        log "ERROR" "Trivy scan failed - checking for critical vulnerabilities"
        
        # Run again with table format for human readable output
        trivy image \
            --cache-dir "${trivy_cache_dir}" \
            --format table \
            --severity CRITICAL,HIGH \
            --no-progress \
            "${image_ref}" || true
        
        return 1
    fi
}

# =============================================================================
# DOCKER BUILD FUNCTIONS
# =============================================================================

# Build Docker image with multi-stage optimization
build_docker_image() {
    log "INFO" "Starting Docker image build process"
    log "INFO" "Image: ${IMAGE_NAME}:${IMAGE_TAG}"
    log "INFO" "Target: ${BUILD_TARGET}"
    log "INFO" "Context: ${DOCKER_CONTEXT}"
    log "INFO" "Dockerfile: ${DOCKERFILE_PATH}"
    
    local build_start_time=$(date +%s)
    local full_image_name="${IMAGE_NAME}:${IMAGE_TAG}"
    
    # Add registry prefix if specified
    if [[ -n "${DOCKER_REGISTRY}" ]]; then
        full_image_name="${DOCKER_REGISTRY}/${full_image_name}"
    fi
    
    # Construct Docker build command with optimizations
    local build_args=(
        docker build
        --file "${DOCKERFILE_PATH}"
        --target "${BUILD_TARGET}"
        --tag "${full_image_name}"
    )
    
    # Add build arguments for optimization
    if [[ "${BUILD_CACHE}" == "true" ]]; then
        build_args+=(--cache-from "${full_image_name}")
        log "DEBUG" "Build cache enabled"
    fi
    
    if [[ "${BUILD_SQUASH}" == "true" ]]; then
        build_args+=(--squash)
        log "DEBUG" "Build squash enabled"
    fi
    
    # Add build arguments for pip-tools and dependencies
    build_args+=(
        --build-arg BUILDKIT_INLINE_CACHE=1
        --build-arg PIP_NO_CACHE_DIR=1
        --build-arg PIP_DISABLE_PIP_VERSION_CHECK=1
        --build-arg PYTHONUNBUFFERED=1
        --build-arg PYTHONDONTWRITEBYTECODE=1
    )
    
    # Add health check configuration if enabled
    if [[ "${HEALTH_CHECK_ENABLED}" == "true" ]]; then
        build_args+=(
            --build-arg HEALTH_CHECK_INTERVAL="${HEALTH_CHECK_INTERVAL}"
            --build-arg HEALTH_CHECK_TIMEOUT="${HEALTH_CHECK_TIMEOUT}"
            --build-arg HEALTH_CHECK_START_PERIOD="${HEALTH_CHECK_START_PERIOD}"
            --build-arg HEALTH_CHECK_RETRIES="${HEALTH_CHECK_RETRIES}"
        )
        log "DEBUG" "Health check configuration enabled"
    fi
    
    # Add Docker context
    build_args+=("${DOCKER_CONTEXT}")
    
    log "DEBUG" "Docker build command: ${build_args[*]}"
    
    # Execute Docker build
    log "INFO" "Executing Docker build command"
    if "${build_args[@]}"; then
        local build_end_time=$(date +%s)
        local build_duration=$((build_end_time - build_start_time))
        log "INFO" "Docker image build completed successfully in ${build_duration}s"
        
        # Get image information
        local image_id=$(docker images --format "{{.ID}}" "${full_image_name}" | head -1)
        local image_size=$(docker images --format "{{.Size}}" "${full_image_name}" | head -1)
        
        log "INFO" "Image ID: ${image_id}"
        log "INFO" "Image Size: ${image_size}"
        
        return 0
    else
        local build_end_time=$(date +%s)
        local build_duration=$((build_end_time - build_start_time))
        log "ERROR" "Docker image build failed after ${build_duration}s"
        
        # Try to get build logs for debugging
        log "ERROR" "Build failed - checking Docker daemon logs"
        docker system events --since "${build_start_time}s" --until "${build_end_time}s" || true
        
        return 1
    fi
}

# Validate built image
validate_built_image() {
    local image_name="$1"
    
    log "INFO" "Validating built Docker image: ${image_name}"
    
    # Check if image exists
    if ! docker images "${image_name}" --format "{{.Repository}}:{{.Tag}}" | grep -q "${image_name}"; then
        log "ERROR" "Built image not found: ${image_name}"
        return 1
    fi
    
    # Inspect image configuration
    local image_config=$(docker inspect "${image_name}" --format '{{json .Config}}' 2>/dev/null)
    if [[ -z "${image_config}" ]]; then
        log "ERROR" "Failed to inspect image configuration"
        return 1
    fi
    
    # Validate entrypoint and command
    local entrypoint=$(echo "${image_config}" | grep -o '"Entrypoint":\[[^]]*\]' || echo "null")
    local cmd=$(echo "${image_config}" | grep -o '"Cmd":\[[^]]*\]' || echo "null")
    
    log "DEBUG" "Image entrypoint: ${entrypoint}"
    log "DEBUG" "Image command: ${cmd}"
    
    # Check for Gunicorn in entrypoint or command
    if echo "${entrypoint}${cmd}" | grep -q "gunicorn"; then
        log "INFO" "Gunicorn WSGI server detected in image configuration"
    else
        log "WARN" "Gunicorn WSGI server not detected in image configuration"
    fi
    
    # Validate health check configuration if enabled
    if [[ "${HEALTH_CHECK_ENABLED}" == "true" ]]; then
        local healthcheck=$(echo "${image_config}" | grep -o '"Healthcheck":{[^}]*}' || echo "null")
        if [[ "${healthcheck}" != "null" ]]; then
            log "INFO" "Health check configuration detected in image"
            log "DEBUG" "Health check: ${healthcheck}"
        else
            log "WARN" "Health check configuration not found in image"
        fi
    fi
    
    # Test basic image functionality
    log "INFO" "Testing basic image functionality"
    
    # Try to run a simple command to verify the image works
    if docker run --rm "${image_name}" python --version >/dev/null 2>&1; then
        log "INFO" "Python runtime validation successful"
    else
        log "ERROR" "Python runtime validation failed"
        return 1
    fi
    
    # Check for Flask application module
    if docker run --rm "${image_name}" python -c "import app; print('Flask app module imported successfully')" >/dev/null 2>&1; then
        log "INFO" "Flask application module validation successful"
    else
        log "ERROR" "Flask application module validation failed"
        return 1
    fi
    
    log "INFO" "Image validation completed successfully"
    return 0
}

# =============================================================================
# PERFORMANCE OPTIMIZATION FUNCTIONS
# =============================================================================

# Optimize Docker build cache
optimize_build_cache() {
    log "INFO" "Optimizing Docker build cache"
    
    # Clean up dangling images
    local dangling_images=$(docker images -f "dangling=true" -q)
    if [[ -n "${dangling_images}" ]]; then
        log "INFO" "Removing dangling images"
        echo "${dangling_images}" | xargs docker rmi || true
    fi
    
    # Prune unused build cache (keep recent)
    log "INFO" "Pruning unused build cache"
    docker builder prune --filter "until=24h" -f || true
    
    # Show disk usage
    local docker_size=$(docker system df --format "table {{.Type}}\t{{.Size}}" | tail -n +2 | awk '{print $2}' | paste -sd+ | bc 2>/dev/null || echo "unknown")
    log "INFO" "Docker disk usage: ${docker_size}"
}

# =============================================================================
# CONTAINER REGISTRY FUNCTIONS
# =============================================================================

# Tag image for registry push
tag_image_for_registry() {
    local source_image="$1"
    local target_image="$2"
    
    log "INFO" "Tagging image for registry: ${source_image} -> ${target_image}"
    
    if docker tag "${source_image}" "${target_image}"; then
        log "INFO" "Image tagged successfully"
        return 0
    else
        log "ERROR" "Failed to tag image"
        return 1
    fi
}

# Push image to registry (optional)
push_image_to_registry() {
    local image_name="$1"
    
    if [[ -z "${DOCKER_REGISTRY}" ]]; then
        log "INFO" "No registry specified, skipping push"
        return 0
    fi
    
    log "INFO" "Pushing image to registry: ${image_name}"
    
    if docker push "${image_name}"; then
        log "INFO" "Image pushed successfully to registry"
        return 0
    else
        log "ERROR" "Failed to push image to registry"
        return 1
    fi
}

# =============================================================================
# MONITORING AND METRICS FUNCTIONS
# =============================================================================

# Generate build metrics
generate_build_metrics() {
    local image_name="$1"
    local build_start_time="$2"
    local build_end_time="$3"
    
    log "INFO" "Generating build metrics"
    
    local build_duration=$((build_end_time - build_start_time))
    local image_size=$(docker images --format "{{.Size}}" "${image_name}" 2>/dev/null || echo "unknown")
    local image_id=$(docker images --format "{{.ID}}" "${image_name}" 2>/dev/null || echo "unknown")
    
    # Create metrics file
    local metrics_file="${PROJECT_ROOT}/build-metrics.json"
    cat > "${metrics_file}" << EOF
{
  "build_timestamp": "$(date -Iseconds)",
  "image_name": "${image_name}",
  "image_id": "${image_id}",
  "image_size": "${image_size}",
  "build_duration_seconds": ${build_duration},
  "build_target": "${BUILD_TARGET}",
  "trivy_scan_results": "${TRIVY_OUTPUT}",
  "docker_version": "$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo 'unknown')",
  "python_version": "3.11",
  "base_image": "python:3.11-slim",
  "wsgi_server": "gunicorn"
}
EOF
    
    log "INFO" "Build metrics saved to: ${metrics_file}"
    log "INFO" "Build Duration: ${build_duration}s"
    log "INFO" "Image Size: ${image_size}"
}

# =============================================================================
# MAIN EXECUTION FUNCTIONS
# =============================================================================

# Display usage information
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Docker Container Build Automation Script for Flask Application

OPTIONS:
    -h, --help              Show this help message
    -n, --name NAME         Set image name (default: flask-app)
    -t, --tag TAG           Set image tag (default: latest)
    -r, --registry REGISTRY Set Docker registry URL
    -s, --scan              Force security scanning even if disabled
    --no-scan              Skip security scanning
    --target TARGET         Set build target (default: production)
    --no-cache             Disable Docker build cache
    --squash               Enable Docker image squashing
    --push                 Push image to registry after build
    --debug                Enable debug logging
    -v, --verbose          Enable verbose output

ENVIRONMENT VARIABLES:
    DOCKER_REGISTRY        Docker registry URL
    IMAGE_NAME             Docker image name
    IMAGE_TAG              Docker image tag
    BUILD_TARGET           Docker build target
    TRIVY_VERSION          Trivy scanner version
    LOG_LEVEL              Logging level (DEBUG, INFO, WARN, ERROR)

EXAMPLES:
    $0                     # Build with defaults
    $0 -n myapp -t v1.0.0  # Build with custom name and tag
    $0 --registry myregistry.com --push  # Build and push to registry
    $0 --no-scan --debug   # Build without scanning, debug mode

EOF
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -n|--name)
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
            -s|--scan)
                FORCE_SCAN="true"
                shift
                ;;
            --no-scan)
                SKIP_SCAN="true"
                shift
                ;;
            --target)
                BUILD_TARGET="$2"
                shift 2
                ;;
            --no-cache)
                BUILD_CACHE="false"
                shift
                ;;
            --squash)
                BUILD_SQUASH="true"
                shift
                ;;
            --push)
                PUSH_TO_REGISTRY="true"
                shift
                ;;
            --debug)
                LOG_LEVEL="DEBUG"
                shift
                ;;
            -v|--verbose)
                set -x
                shift
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Main build orchestration function
main() {
    local overall_start_time=$(date +%s)
    
    log "INFO" "==================================================================="
    log "INFO" "Flask Application Docker Build Process Started"
    log "INFO" "==================================================================="
    
    # Initialize log file
    echo "Flask Docker Build Log - $(date)" > "${LOG_FILE}"
    
    log "INFO" "Project Root: ${PROJECT_ROOT}"
    log "INFO" "Build Configuration:"
    log "INFO" "  - Image Name: ${IMAGE_NAME}"
    log "INFO" "  - Image Tag: ${IMAGE_TAG}"
    log "INFO" "  - Build Target: ${BUILD_TARGET}"
    log "INFO" "  - Docker Registry: ${DOCKER_REGISTRY:-'(none)'}"
    log "INFO" "  - Cache Enabled: ${BUILD_CACHE}"
    log "INFO" "  - Squash Enabled: ${BUILD_SQUASH}"
    log "INFO" "  - Health Check: ${HEALTH_CHECK_ENABLED}"
    
    # Step 1: Validate prerequisites
    log "INFO" "Step 1/8: Validating prerequisites and environment"
    validate_prerequisites
    
    # Step 2: Validate dependencies
    log "INFO" "Step 2/8: Validating pip-tools dependency resolution"
    validate_dependencies
    
    # Step 3: Optimize build cache
    log "INFO" "Step 3/8: Optimizing Docker build cache"
    optimize_build_cache
    
    # Step 4: Build Docker image
    log "INFO" "Step 4/8: Building Docker image"
    local build_start_time=$(date +%s)
    
    local full_image_name="${IMAGE_NAME}:${IMAGE_TAG}"
    if [[ -n "${DOCKER_REGISTRY}" ]]; then
        full_image_name="${DOCKER_REGISTRY}/${full_image_name}"
    fi
    
    if ! build_docker_image; then
        log "ERROR" "Docker image build failed"
        exit 1
    fi
    
    local build_end_time=$(date +%s)
    
    # Step 5: Validate built image
    log "INFO" "Step 5/8: Validating built Docker image"
    if ! validate_built_image "${full_image_name}"; then
        log "ERROR" "Image validation failed"
        exit 1
    fi
    
    # Step 6: Security scanning
    if [[ "${SKIP_SCAN:-false}" != "true" ]]; then
        log "INFO" "Step 6/8: Performing container security scanning"
        
        # Install Trivy if needed
        install_trivy
        
        # Perform security scan
        if ! scan_container_vulnerabilities "${full_image_name}"; then
            log "ERROR" "Container security scan failed or found critical vulnerabilities"
            if [[ "${FORCE_SCAN:-false}" != "true" ]]; then
                log "ERROR" "Build failed due to security policy violation"
                exit 1
            else
                log "WARN" "Continuing despite security scan failures (forced)"
            fi
        fi
    else
        log "INFO" "Step 6/8: Skipping container security scanning (disabled)"
    fi
    
    # Step 7: Registry operations
    log "INFO" "Step 7/8: Handling registry operations"
    if [[ "${PUSH_TO_REGISTRY:-false}" == "true" ]]; then
        if ! push_image_to_registry "${full_image_name}"; then
            log "ERROR" "Failed to push image to registry"
            exit 1
        fi
    else
        log "INFO" "Registry push skipped (not requested)"
    fi
    
    # Step 8: Generate metrics and summary
    log "INFO" "Step 8/8: Generating build metrics and summary"
    generate_build_metrics "${full_image_name}" "${build_start_time}" "${build_end_time}"
    
    local overall_end_time=$(date +%s)
    local total_duration=$((overall_end_time - overall_start_time))
    
    log "INFO" "==================================================================="
    log "INFO" "Flask Application Docker Build Process Completed Successfully"
    log "INFO" "==================================================================="
    log "INFO" "Summary:"
    log "INFO" "  - Total Build Time: ${total_duration}s"
    log "INFO" "  - Final Image: ${full_image_name}"
    log "INFO" "  - Build Target: ${BUILD_TARGET}"
    log "INFO" "  - Base Image: python:3.11-slim"
    log "INFO" "  - WSGI Server: Gunicorn 21.2+"
    log "INFO" "  - Security Scan: ${SKIP_SCAN:-false}" 
    if [[ -f "${TRIVY_OUTPUT}" ]]; then
        log "INFO" "  - Security Results: ${TRIVY_OUTPUT}"
    fi
    log "INFO" "  - Build Log: ${LOG_FILE}"
    log "INFO" "  - Build Metrics: ${PROJECT_ROOT}/build-metrics.json"
    
    # Display next steps
    log "INFO" ""
    log "INFO" "Next Steps:"
    log "INFO" "  1. Test the container:"
    log "INFO" "     docker run --rm -p 8000:8000 ${full_image_name}"
    log "INFO" "  2. Check health endpoint:"
    log "INFO" "     curl http://localhost:8000/health"
    log "INFO" "  3. Deploy to staging environment for performance validation"
    
    return 0
}

# =============================================================================
# SCRIPT ENTRY POINT
# =============================================================================

# Parse command line arguments
parse_arguments "$@"

# Enable BuildKit for improved performance
export DOCKER_BUILDKIT="${DOCKER_BUILDKIT}"

# Execute main function
main "$@"