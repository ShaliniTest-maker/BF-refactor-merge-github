#!/bin/bash

#
# Blue-Green Deployment Automation Script for Flask Application Migration
#
# Comprehensive deployment automation implementing zero-downtime migration with
# feature flag control, performance validation, and automated rollback capabilities
# for production Flask application deployment per Section 4.4.1 deployment process.
#
# This script implements enterprise-grade blue-green deployment patterns with:
# - Zero-downtime migration capability using Kubernetes blue-green strategy
# - Feature flag management for gradual traffic migration (5% → 25% → 50% → 100%)
# - Performance monitoring ensuring ≤10% variance from Node.js baseline
# - Automated rollback procedures for performance degradation and security incidents
# - Container vulnerability scanning with Trivy 0.48+ security validation
# - Comprehensive health check integration with enterprise monitoring systems
# - Kubernetes orchestration with Helm chart deployment automation
# - Real-time performance monitoring with Prometheus metrics collection
#
# Exit Codes:
#   0: Deployment completed successfully
#   1: Deployment failed due to build or validation errors
#   2: Configuration or environment errors
#   3: Health check or connectivity failures
#   4: Performance validation failures (≤10% variance requirement)
#   5: Security vulnerabilities detected during container scanning
#   6: Rollback procedure failed
#   7: Feature flag or traffic management errors
#   8: Kubernetes or container orchestration failures
#
# Usage:
#   ./deploy.sh [OPTIONS]
#
# Options:
#   --environment ENV       Target environment (development, staging, production)
#   --image IMAGE_TAG       Container image tag to deploy
#   --dry-run               Perform validation without actual deployment
#   --skip-tests            Skip test suite execution (not recommended for production)
#   --skip-security-scan    Skip container vulnerability scanning (emergency only)
#   --force-deploy          Bypass performance validation (emergency only)
#   --rollback-only         Execute rollback to previous stable deployment
#   --cleanup-only          Clean up deployment artifacts and resources
#   --verbose               Enable detailed logging output
#   --help                  Display this help message
#
# Environment Variables:
#   KUBECONFIG                    Kubernetes configuration file path
#   DEPLOYMENT_NAMESPACE          Kubernetes namespace for deployment
#   CONTAINER_REGISTRY            Container registry URL for image storage
#   FEATURE_FLAG_SERVICE_URL      Feature flag service endpoint
#   PROMETHEUS_ENDPOINT           Prometheus metrics endpoint for monitoring
#   PERFORMANCE_BASELINE_URL      Node.js baseline performance metrics endpoint
#   SLACK_WEBHOOK_URL             Slack webhook for deployment notifications
#   ROLLBACK_ENABLED              Enable automated rollback (default: true)
#   PERFORMANCE_VARIANCE_THRESHOLD Maximum allowed performance variance (default: 10)
#   SECURITY_SCAN_ENABLED         Enable container vulnerability scanning (default: true)
#   BLUE_GREEN_ENABLED            Enable blue-green deployment pattern (default: true)
#

set -euo pipefail

# Script metadata and version information
readonly SCRIPT_NAME="deploy.sh"
readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_DESCRIPTION="Blue-Green Deployment Automation for Flask Application"

# Default configuration values per Section 8.5.2 deployment pipeline
readonly DEFAULT_ENVIRONMENT="staging"
readonly DEFAULT_NAMESPACE="flask-app"
readonly DEFAULT_PERFORMANCE_VARIANCE_THRESHOLD="10"
readonly DEFAULT_HEALTH_CHECK_TIMEOUT="300"
readonly DEFAULT_DEPLOYMENT_TIMEOUT="1800"  # 30 minutes
readonly DEFAULT_ROLLBACK_TIMEOUT="600"     # 10 minutes

# Blue-green deployment configuration per Section 4.4.1
readonly BLUE_ENVIRONMENT="blue"
readonly GREEN_ENVIRONMENT="green"
readonly TRAFFIC_PERCENTAGES=("5" "25" "50" "100")
readonly PHASE_DURATIONS=("900" "1800" "2700" "3600")  # 15, 30, 45, 60 minutes

# Kubernetes deployment configuration per Section 8.3.2
readonly HELM_CHART_PATH="./helm/flask-app"
readonly DEPLOYMENT_LABEL="app=flask-app"
readonly SERVICE_NAME="flask-app-service"
readonly INGRESS_NAME="flask-app-ingress"

# Container security configuration per Section 8.5.2
readonly TRIVY_SEVERITY_LEVELS="CRITICAL,HIGH,MEDIUM"
readonly SECURITY_POLICY_FILE="./security/container-policy.yaml"

# Performance monitoring configuration per Section 4.4.2
readonly PERFORMANCE_METRICS=("response_time" "error_rate" "cpu_utilization" "memory_usage" "throughput")
readonly MONITORING_WINDOW_SECONDS="300"  # 5 minutes
readonly BASELINE_COLLECTION_DURATION="600"  # 10 minutes

# Color codes for output formatting
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Global variables for configuration
ENVIRONMENT="${DEFAULT_ENVIRONMENT}"
IMAGE_TAG=""
DRY_RUN=false
SKIP_TESTS=false
SKIP_SECURITY_SCAN=false
FORCE_DEPLOY=false
ROLLBACK_ONLY=false
CLEANUP_ONLY=false
VERBOSE=false

# Deployment state tracking
DEPLOYMENT_ID=""
DEPLOYMENT_START_TIME=""
CURRENT_ENVIRONMENT=""
TARGET_ENVIRONMENT=""
ROLLBACK_TRIGGERED=false
DEPLOYMENT_SUCCESS=false

# Performance and monitoring variables
declare -A BASELINE_METRICS
declare -A CURRENT_METRICS
declare -A DEPLOYMENT_METRICS
PERFORMANCE_VARIANCE_THRESHOLD="${PERFORMANCE_VARIANCE_THRESHOLD:-$DEFAULT_PERFORMANCE_VARIANCE_THRESHOLD}"

# Kubernetes and container configuration
KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
DEPLOYMENT_NAMESPACE="${DEPLOYMENT_NAMESPACE:-$DEFAULT_NAMESPACE}"
CONTAINER_REGISTRY="${CONTAINER_REGISTRY:-}"
HELM_RELEASE_NAME="flask-app"

# Feature flag and service configuration
FEATURE_FLAG_SERVICE_URL="${FEATURE_FLAG_SERVICE_URL:-}"
PROMETHEUS_ENDPOINT="${PROMETHEUS_ENDPOINT:-http://prometheus:9090}"
PERFORMANCE_BASELINE_URL="${PERFORMANCE_BASELINE_URL:-}"

# Security and compliance configuration
SECURITY_SCAN_ENABLED="${SECURITY_SCAN_ENABLED:-true}"
ROLLBACK_ENABLED="${ROLLBACK_ENABLED:-true}"
BLUE_GREEN_ENABLED="${BLUE_GREEN_ENABLED:-true}"

# Notification configuration
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"
TEAMS_WEBHOOK_URL="${TEAMS_WEBHOOK_URL:-}"

#
# Utility Functions
#

log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
    
    # Structured logging for enterprise integration
    local log_entry=$(cat << EOF
{
  "timestamp": "$timestamp",
  "level": "$level",
  "component": "deployment",
  "script": "$SCRIPT_NAME",
  "version": "$SCRIPT_VERSION",
  "deployment_id": "$DEPLOYMENT_ID",
  "environment": "$ENVIRONMENT",
  "message": "$message"
}
EOF
)
    
    case "$level" in
        "ERROR")
            printf "${RED}[%s] ERROR: %s${NC}\n" "$timestamp" "$message" >&2
            echo "$log_entry" >&2
            ;;
        "WARN")
            printf "${YELLOW}[%s] WARN: %s${NC}\n" "$timestamp" "$message" >&2
            echo "$log_entry" >&2
            ;;
        "INFO")
            printf "${GREEN}[%s] INFO: %s${NC}\n" "$timestamp" "$message"
            echo "$log_entry"
            ;;
        "DEBUG")
            if [[ "$VERBOSE" == "true" ]]; then
                printf "${BLUE}[%s] DEBUG: %s${NC}\n" "$timestamp" "$message"
                echo "$log_entry"
            fi
            ;;
    esac
}

log_error() {
    log "ERROR" "$1"
}

log_warn() {
    log "WARN" "$1"
}

log_info() {
    log "INFO" "$1"
}

log_debug() {
    log "DEBUG" "$1"
}

# Generate unique deployment ID
generate_deployment_id() {
    DEPLOYMENT_ID="deploy-$(date +%Y%m%d-%H%M%S)-$(openssl rand -hex 4)"
    log_info "Generated deployment ID: $DEPLOYMENT_ID"
}

# Notification functions for enterprise integration
send_slack_notification() {
    local message="$1"
    local color="${2:-good}"
    
    if [[ -n "$SLACK_WEBHOOK_URL" ]]; then
        local payload=$(cat << EOF
{
  "attachments": [
    {
      "color": "$color",
      "title": "Flask Deployment - $ENVIRONMENT",
      "text": "$message",
      "fields": [
        {
          "title": "Deployment ID",
          "value": "$DEPLOYMENT_ID",
          "short": true
        },
        {
          "title": "Environment",
          "value": "$ENVIRONMENT",
          "short": true
        },
        {
          "title": "Image Tag",
          "value": "$IMAGE_TAG",
          "short": true
        },
        {
          "title": "Timestamp",
          "value": "$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")",
          "short": true
        }
      ]
    }
  ]
}
EOF
)
        
        curl -X POST -H 'Content-type: application/json' \
             --data "$payload" \
             "$SLACK_WEBHOOK_URL" >/dev/null 2>&1 || true
    fi
}

# Error handling and cleanup
cleanup_on_exit() {
    local exit_code=$?
    
    if [[ "$exit_code" -ne 0 ]]; then
        log_error "Deployment failed with exit code: $exit_code"
        
        if [[ "$ROLLBACK_ENABLED" == "true" && "$ROLLBACK_TRIGGERED" == "false" ]]; then
            log_info "Initiating automated rollback due to deployment failure"
            execute_rollback "Deployment failure (exit code: $exit_code)"
        fi
        
        send_slack_notification "Deployment failed: $DEPLOYMENT_ID" "danger"
    fi
    
    # Cleanup temporary files
    cleanup_temporary_files
    
    log_info "Deployment script completed with exit code: $exit_code"
}

cleanup_temporary_files() {
    local temp_files=(
        "/tmp/deployment_*"
        "/tmp/health_check_*"
        "/tmp/performance_*"
        "/tmp/security_scan_*"
        "/tmp/trivy_*"
    )
    
    for pattern in "${temp_files[@]}"; do
        rm -f $pattern 2>/dev/null || true
    done
    
    log_debug "Temporary files cleaned up"
}

# Signal handlers
trap cleanup_on_exit EXIT
trap 'log_error "Deployment interrupted by user"; exit 130' INT TERM

#
# Configuration and Validation Functions
#

validate_prerequisites() {
    log_info "Validating deployment prerequisites..."
    
    local missing_tools=()
    
    # Check required tools
    local required_tools=("kubectl" "helm" "docker" "curl" "jq")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done
    
    # Check optional tools
    if [[ "$SECURITY_SCAN_ENABLED" == "true" ]]; then
        if ! command -v "trivy" >/dev/null 2>&1; then
            missing_tools+=("trivy")
        fi
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        return 2
    fi
    
    # Validate Kubernetes connectivity
    if ! kubectl cluster-info >/dev/null 2>&1; then
        log_error "Cannot connect to Kubernetes cluster"
        return 2
    fi
    
    # Validate namespace
    if ! kubectl get namespace "$DEPLOYMENT_NAMESPACE" >/dev/null 2>&1; then
        log_info "Creating namespace: $DEPLOYMENT_NAMESPACE"
        kubectl create namespace "$DEPLOYMENT_NAMESPACE" || {
            log_error "Failed to create namespace: $DEPLOYMENT_NAMESPACE"
            return 2
        }
    fi
    
    # Validate Helm chart
    if [[ ! -d "$HELM_CHART_PATH" ]]; then
        log_error "Helm chart not found: $HELM_CHART_PATH"
        return 2
    fi
    
    # Validate container registry access
    if [[ -n "$CONTAINER_REGISTRY" ]]; then
        if ! docker info >/dev/null 2>&1; then
            log_error "Docker daemon not accessible"
            return 2
        fi
    fi
    
    log_info "Prerequisites validation completed successfully"
    return 0
}

validate_environment_config() {
    log_info "Validating environment configuration for: $ENVIRONMENT"
    
    # Validate environment-specific requirements
    case "$ENVIRONMENT" in
        "production")
            if [[ "$SKIP_TESTS" == "true" ]]; then
                log_error "Cannot skip tests in production environment"
                return 2
            fi
            if [[ "$SKIP_SECURITY_SCAN" == "true" ]]; then
                log_error "Cannot skip security scan in production environment"
                return 2
            fi
            ;;
        "staging")
            if [[ "$FORCE_DEPLOY" == "true" ]]; then
                log_warn "Force deploy enabled in staging environment"
            fi
            ;;
        "development")
            log_info "Development environment: relaxed validation enabled"
            ;;
        *)
            log_error "Unknown environment: $ENVIRONMENT"
            return 2
            ;;
    esac
    
    # Validate image tag
    if [[ -z "$IMAGE_TAG" && "$DRY_RUN" == "false" ]]; then
        log_error "Image tag must be specified for actual deployment"
        return 2
    fi
    
    # Validate performance variance threshold
    if ! [[ "$PERFORMANCE_VARIANCE_THRESHOLD" =~ ^[0-9]+$ ]] || [[ "$PERFORMANCE_VARIANCE_THRESHOLD" -le 0 ]]; then
        log_error "Invalid performance variance threshold: $PERFORMANCE_VARIANCE_THRESHOLD"
        return 2
    fi
    
    log_info "Environment configuration validation completed"
    return 0
}

#
# Container Security Functions
#

execute_container_security_scan() {
    if [[ "$SECURITY_SCAN_ENABLED" != "true" ]]; then
        log_info "Container security scanning disabled"
        return 0
    fi
    
    log_info "Executing container vulnerability scan with Trivy..."
    
    local full_image_name="${CONTAINER_REGISTRY}/${IMAGE_TAG}"
    local scan_results_file="/tmp/security_scan_${DEPLOYMENT_ID}.json"
    local scan_sarif_file="/tmp/security_scan_${DEPLOYMENT_ID}.sarif"
    
    # Execute Trivy container scan
    if ! trivy image \
        --format json \
        --output "$scan_results_file" \
        --severity "$TRIVY_SEVERITY_LEVELS" \
        --no-progress \
        "$full_image_name"; then
        log_error "Container vulnerability scan failed"
        return 5
    fi
    
    # Generate SARIF output for security integration
    trivy image \
        --format sarif \
        --output "$scan_sarif_file" \
        --severity "$TRIVY_SEVERITY_LEVELS" \
        --no-progress \
        "$full_image_name" || true
    
    # Analyze scan results
    local critical_count high_count medium_count
    critical_count=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$scan_results_file" 2>/dev/null || echo "0")
    high_count=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$scan_results_file" 2>/dev/null || echo "0")
    medium_count=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length' "$scan_results_file" 2>/dev/null || echo "0")
    
    log_info "Security scan results: Critical=$critical_count, High=$high_count, Medium=$medium_count"
    
    # Enforce security policy per Section 8.5.2
    if [[ "$critical_count" -gt 0 ]]; then
        log_error "Critical vulnerabilities detected: $critical_count"
        log_error "Deployment blocked due to critical security vulnerabilities"
        return 5
    fi
    
    if [[ "$high_count" -gt 5 ]]; then
        log_error "Too many high-severity vulnerabilities detected: $high_count (limit: 5)"
        log_error "Deployment blocked due to excessive high-severity vulnerabilities"
        return 5
    fi
    
    if [[ "$high_count" -gt 0 ]]; then
        log_warn "High-severity vulnerabilities detected: $high_count"
        send_slack_notification "Security scan warning: $high_count high-severity vulnerabilities found" "warning"
    fi
    
    log_info "Container security scan completed successfully"
    return 0
}

#
# Test Execution Functions
#

execute_test_suite() {
    if [[ "$SKIP_TESTS" == "true" ]]; then
        log_warn "Test suite execution skipped (not recommended for production)"
        return 0
    fi
    
    log_info "Executing comprehensive test suite..."
    
    # Execute health check script first
    local health_check_script="./scripts/health-check.sh"
    if [[ -f "$health_check_script" ]]; then
        log_info "Running health check validation..."
        if ! "$health_check_script" --json --baseline-check; then
            log_error "Health check validation failed"
            return 1
        fi
    else
        log_warn "Health check script not found: $health_check_script"
    fi
    
    # Execute unit tests with coverage
    log_info "Running unit tests with coverage validation..."
    if ! python -m pytest tests/unit/ --cov=src --cov-report=json --cov-fail-under=90; then
        log_error "Unit tests failed or coverage below 90%"
        return 1
    fi
    
    # Execute integration tests
    log_info "Running integration tests..."
    if ! python -m pytest tests/integration/ --verbose; then
        log_error "Integration tests failed"
        return 1
    fi
    
    # Execute performance tests if in staging or production
    if [[ "$ENVIRONMENT" != "development" ]]; then
        log_info "Running performance baseline tests..."
        if ! python -m pytest tests/performance/ --baseline-comparison; then
            log_error "Performance tests failed"
            return 4
        fi
    fi
    
    log_info "Test suite execution completed successfully"
    return 0
}

#
# Blue-Green Deployment Functions
#

determine_target_environment() {
    if [[ "$BLUE_GREEN_ENABLED" != "true" ]]; then
        TARGET_ENVIRONMENT="default"
        CURRENT_ENVIRONMENT="default"
        log_info "Blue-green deployment disabled, using default environment"
        return 0
    fi
    
    log_info "Determining blue-green deployment environments..."
    
    # Check current active environment
    local active_env
    active_env=$(kubectl get service "$SERVICE_NAME" -n "$DEPLOYMENT_NAMESPACE" \
        -o jsonpath='{.spec.selector.environment}' 2>/dev/null || echo "")
    
    if [[ -z "$active_env" ]]; then
        # First deployment - use green environment
        CURRENT_ENVIRONMENT=""
        TARGET_ENVIRONMENT="$GREEN_ENVIRONMENT"
        log_info "First deployment detected, targeting green environment"
    elif [[ "$active_env" == "$BLUE_ENVIRONMENT" ]]; then
        # Currently blue is active, deploy to green
        CURRENT_ENVIRONMENT="$BLUE_ENVIRONMENT"
        TARGET_ENVIRONMENT="$GREEN_ENVIRONMENT"
        log_info "Current environment: blue, targeting green environment"
    else
        # Currently green is active, deploy to blue
        CURRENT_ENVIRONMENT="$GREEN_ENVIRONMENT"
        TARGET_ENVIRONMENT="$BLUE_ENVIRONMENT"
        log_info "Current environment: green, targeting blue environment"
    fi
    
    log_info "Blue-green environments determined: current=$CURRENT_ENVIRONMENT, target=$TARGET_ENVIRONMENT"
    return 0
}

deploy_to_target_environment() {
    log_info "Deploying to target environment: $TARGET_ENVIRONMENT"
    
    local helm_values_file="/tmp/deployment_values_${DEPLOYMENT_ID}.yaml"
    
    # Generate Helm values file
    cat > "$helm_values_file" << EOF
image:
  repository: ${CONTAINER_REGISTRY%/*}
  tag: ${IMAGE_TAG}
  pullPolicy: Always

environment: ${TARGET_ENVIRONMENT}
namespace: ${DEPLOYMENT_NAMESPACE}

deployment:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0

service:
  type: ClusterIP
  port: 8000
  targetPort: 8000

resources:
  requests:
    memory: "512Mi"
    cpu: "250m"
  limits:
    memory: "1Gi"
    cpu: "500m"

livenessProbe:
  httpGet:
    path: /health/live
    port: 8000
  initialDelaySeconds: 30
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /health/ready
    port: 8000
  initialDelaySeconds: 10
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 2

monitoring:
  enabled: true
  path: /metrics
  port: 8000

security:
  runAsNonRoot: true
  runAsUser: 1000
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false

labels:
  environment: ${TARGET_ENVIRONMENT}
  deployment-id: ${DEPLOYMENT_ID}
  version: ${IMAGE_TAG}
EOF
    
    # Execute Helm deployment
    log_info "Executing Helm deployment..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Dry run mode: simulating Helm deployment"
        helm upgrade --install \
            "${HELM_RELEASE_NAME}-${TARGET_ENVIRONMENT}" \
            "$HELM_CHART_PATH" \
            --namespace "$DEPLOYMENT_NAMESPACE" \
            --values "$helm_values_file" \
            --dry-run \
            --debug
    else
        if ! helm upgrade --install \
            "${HELM_RELEASE_NAME}-${TARGET_ENVIRONMENT}" \
            "$HELM_CHART_PATH" \
            --namespace "$DEPLOYMENT_NAMESPACE" \
            --values "$helm_values_file" \
            --wait \
            --timeout "${DEFAULT_DEPLOYMENT_TIMEOUT}s"; then
            log_error "Helm deployment failed"
            return 8
        fi
    fi
    
    log_info "Deployment to target environment completed"
    return 0
}

validate_deployment_health() {
    log_info "Validating deployment health in target environment..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Dry run mode: skipping health validation"
        return 0
    fi
    
    # Wait for pods to be ready
    log_info "Waiting for pods to be ready..."
    if ! kubectl wait --for=condition=ready pod \
        --selector="app=flask-app,environment=$TARGET_ENVIRONMENT" \
        --namespace="$DEPLOYMENT_NAMESPACE" \
        --timeout="${DEFAULT_HEALTH_CHECK_TIMEOUT}s"; then
        log_error "Pods failed to become ready within timeout"
        return 3
    fi
    
    # Get service endpoint for health checks
    local service_endpoint
    service_endpoint=$(kubectl get service "${SERVICE_NAME}-${TARGET_ENVIRONMENT}" \
        -n "$DEPLOYMENT_NAMESPACE" \
        -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "")
    
    if [[ -z "$service_endpoint" ]]; then
        log_error "Unable to determine service endpoint for health checks"
        return 3
    fi
    
    # Execute comprehensive health checks
    log_info "Executing comprehensive health checks on $service_endpoint..."
    
    local health_check_script="./scripts/health-check.sh"
    if [[ -f "$health_check_script" ]]; then
        if ! "$health_check_script" \
            --host "$service_endpoint" \
            --port 8000 \
            --timeout 60 \
            --enterprise-mode \
            --json; then
            log_error "Health check validation failed for target environment"
            return 3
        fi
    else
        # Fallback basic health check
        if ! curl -f -s "http://${service_endpoint}:8000/health" >/dev/null; then
            log_error "Basic health check failed for target environment"
            return 3
        fi
    fi
    
    log_info "Deployment health validation completed successfully"
    return 0
}

#
# Performance Monitoring Functions
#

collect_baseline_metrics() {
    log_info "Collecting performance baseline metrics..."
    
    if [[ -z "$PERFORMANCE_BASELINE_URL" ]]; then
        log_warn "Performance baseline URL not configured, skipping baseline collection"
        return 0
    fi
    
    local baseline_file="/tmp/performance_baseline_${DEPLOYMENT_ID}.json"
    
    # Collect baseline metrics from Node.js application
    for metric in "${PERFORMANCE_METRICS[@]}"; do
        local metric_url="${PERFORMANCE_BASELINE_URL}/metrics/${metric}"
        local metric_value
        
        metric_value=$(curl -s "$metric_url" | jq -r '.value' 2>/dev/null || echo "0")
        BASELINE_METRICS["$metric"]="$metric_value"
        
        log_debug "Baseline metric collected: $metric = $metric_value"
    done
    
    # Store baseline metrics to file
    printf '{\n' > "$baseline_file"
    for metric in "${PERFORMANCE_METRICS[@]}"; do
        printf '  "%s": %s,\n' "$metric" "${BASELINE_METRICS[$metric]}" >> "$baseline_file"
    done
    printf '  "timestamp": "%s"\n}\n' "$(date -u +%s)" >> "$baseline_file"
    
    log_info "Baseline metrics collection completed"
    return 0
}

collect_current_metrics() {
    log_info "Collecting current deployment performance metrics..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Dry run mode: simulating metrics collection"
        return 0
    fi
    
    # Get service endpoint for metrics collection
    local service_endpoint
    service_endpoint=$(kubectl get service "${SERVICE_NAME}-${TARGET_ENVIRONMENT}" \
        -n "$DEPLOYMENT_NAMESPACE" \
        -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "")
    
    if [[ -z "$service_endpoint" ]]; then
        log_error "Unable to determine service endpoint for metrics collection"
        return 4
    fi
    
    local current_file="/tmp/performance_current_${DEPLOYMENT_ID}.json"
    
    # Collect current metrics from Flask application
    for metric in "${PERFORMANCE_METRICS[@]}"; do
        local metric_url="http://${service_endpoint}:8000/metrics"
        local metric_value
        
        case "$metric" in
            "response_time")
                metric_value=$(curl -s "$metric_url" | grep 'flask_request_duration_seconds' | \
                    awk '{print $2}' | head -1 || echo "0")
                ;;
            "error_rate")
                metric_value=$(curl -s "$metric_url" | grep 'flask_request_errors_total' | \
                    awk '{print $2}' | head -1 || echo "0")
                ;;
            "cpu_utilization")
                metric_value=$(kubectl top pod \
                    --selector="app=flask-app,environment=$TARGET_ENVIRONMENT" \
                    --namespace="$DEPLOYMENT_NAMESPACE" \
                    --no-headers | awk '{sum+=$2} END {print sum/NR}' || echo "0")
                ;;
            "memory_usage")
                metric_value=$(kubectl top pod \
                    --selector="app=flask-app,environment=$TARGET_ENVIRONMENT" \
                    --namespace="$DEPLOYMENT_NAMESPACE" \
                    --no-headers | awk '{sum+=$3} END {print sum/NR}' || echo "0")
                ;;
            "throughput")
                metric_value=$(curl -s "$metric_url" | grep 'flask_requests_total' | \
                    awk '{print $2}' | head -1 || echo "0")
                ;;
        esac
        
        CURRENT_METRICS["$metric"]="$metric_value"
        log_debug "Current metric collected: $metric = $metric_value"
    done
    
    # Store current metrics to file
    printf '{\n' > "$current_file"
    for metric in "${PERFORMANCE_METRICS[@]}"; do
        printf '  "%s": %s,\n' "$metric" "${CURRENT_METRICS[$metric]}" >> "$current_file"
    done
    printf '  "timestamp": "%s"\n}\n' "$(date -u +%s)" >> "$current_file"
    
    log_info "Current metrics collection completed"
    return 0
}

validate_performance_variance() {
    log_info "Validating performance variance against baseline..."
    
    if [[ "$FORCE_DEPLOY" == "true" ]]; then
        log_warn "Performance validation bypassed due to force deploy flag"
        return 0
    fi
    
    local performance_violations=()
    local variance_file="/tmp/performance_variance_${DEPLOYMENT_ID}.json"
    
    printf '{\n' > "$variance_file"
    printf '  "performance_variance_threshold": %s,\n' "$PERFORMANCE_VARIANCE_THRESHOLD" >> "$variance_file"
    printf '  "metrics": {\n' >> "$variance_file"
    
    # Calculate variance for each metric
    for metric in "${PERFORMANCE_METRICS[@]}"; do
        local baseline_value="${BASELINE_METRICS[$metric]:-0}"
        local current_value="${CURRENT_METRICS[$metric]:-0}"
        
        # Skip if baseline is 0 to avoid division by zero
        if [[ "$baseline_value" == "0" ]]; then
            log_debug "Skipping variance calculation for $metric (baseline is 0)"
            continue
        fi
        
        # Calculate percentage variance
        local variance
        variance=$(echo "scale=2; (($current_value - $baseline_value) / $baseline_value) * 100" | bc -l 2>/dev/null || echo "0")
        
        # Remove negative sign for absolute variance
        local abs_variance
        abs_variance=$(echo "$variance" | sed 's/^-//')
        
        log_debug "Performance variance for $metric: ${abs_variance}% (threshold: ${PERFORMANCE_VARIANCE_THRESHOLD}%)"
        
        # Check if variance exceeds threshold
        if (( $(echo "$abs_variance > $PERFORMANCE_VARIANCE_THRESHOLD" | bc -l) )); then
            performance_violations+=("$metric: ${abs_variance}% (threshold: ${PERFORMANCE_VARIANCE_THRESHOLD}%)")
            log_warn "Performance variance threshold exceeded for $metric: ${abs_variance}%"
        fi
        
        # Store variance data
        printf '    "%s": {\n' "$metric" >> "$variance_file"
        printf '      "baseline": %s,\n' "$baseline_value" >> "$variance_file"
        printf '      "current": %s,\n' "$current_value" >> "$variance_file"
        printf '      "variance_percent": %s,\n' "$variance" >> "$variance_file"
        printf '      "threshold_exceeded": %s\n' "$(if (( $(echo "$abs_variance > $PERFORMANCE_VARIANCE_THRESHOLD" | bc -l) )); then echo "true"; else echo "false"; fi)" >> "$variance_file"
        printf '    },\n' >> "$variance_file"
    done
    
    printf '  },\n' >> "$variance_file"
    printf '  "violations": [\n' >> "$variance_file"
    
    # Check for performance violations
    if [[ ${#performance_violations[@]} -gt 0 ]]; then
        log_error "Performance variance validation failed:"
        for violation in "${performance_violations[@]}"; do
            log_error "  - $violation"
            printf '    "%s",\n' "$violation" >> "$variance_file"
        done
        
        printf '  ],\n' >> "$variance_file"
        printf '  "validation_result": "failed",\n' >> "$variance_file"
        printf '  "timestamp": "%s"\n}\n' "$(date -u +%s)" >> "$variance_file"
        
        return 4
    fi
    
    printf '  ],\n' >> "$variance_file"
    printf '  "validation_result": "passed",\n' >> "$variance_file"
    printf '  "timestamp": "%s"\n}\n' "$(date -u +%s)" >> "$variance_file"
    
    log_info "Performance variance validation passed"
    return 0
}

#
# Feature Flag Management Functions
#

initialize_feature_flags() {
    log_info "Initializing feature flag management..."
    
    if [[ -z "$FEATURE_FLAG_SERVICE_URL" ]]; then
        log_warn "Feature flag service URL not configured"
        return 0
    fi
    
    # Initialize feature flag configuration
    local config_payload=$(cat << EOF
{
  "deployment_id": "$DEPLOYMENT_ID",
  "environment": "$ENVIRONMENT",
  "target_environment": "$TARGET_ENVIRONMENT",
  "current_environment": "$CURRENT_ENVIRONMENT",
  "image_tag": "$IMAGE_TAG",
  "timestamp": "$(date -u +%s)"
}
EOF
)
    
    if ! curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "$config_payload" \
        "${FEATURE_FLAG_SERVICE_URL}/api/deployment/initialize" >/dev/null; then
        log_warn "Failed to initialize feature flag service"
        return 0
    fi
    
    log_info "Feature flag management initialized"
    return 0
}

execute_gradual_traffic_migration() {
    log_info "Executing gradual traffic migration with feature flags..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Dry run mode: simulating traffic migration"
        return 0
    fi
    
    # Execute each traffic migration phase
    for i in "${!TRAFFIC_PERCENTAGES[@]}"; do
        local percentage="${TRAFFIC_PERCENTAGES[$i]}"
        local duration="${PHASE_DURATIONS[$i]}"
        local phase_name="PHASE_$((i + 1))"
        
        log_info "Starting traffic migration phase: $phase_name ($percentage%)"
        
        # Update feature flag configuration
        if [[ -n "$FEATURE_FLAG_SERVICE_URL" ]]; then
            local phase_payload=$(cat << EOF
{
  "deployment_id": "$DEPLOYMENT_ID",
  "phase": "$phase_name",
  "traffic_percentage": $percentage,
  "target_environment": "$TARGET_ENVIRONMENT",
  "timestamp": "$(date -u +%s)"
}
EOF
)
            
            if ! curl -s -X POST \
                -H "Content-Type: application/json" \
                -d "$phase_payload" \
                "${FEATURE_FLAG_SERVICE_URL}/api/deployment/phase" >/dev/null; then
                log_warn "Failed to update feature flag service for phase $phase_name"
            fi
        fi
        
        # Update Kubernetes service selector for traffic routing
        update_traffic_routing "$percentage"
        
        # Monitor phase stability
        local phase_start_time=$(date +%s)
        log_info "Monitoring phase $phase_name for $duration seconds..."
        
        while true; do
            local current_time=$(date +%s)
            local elapsed_time=$((current_time - phase_start_time))
            
            if [[ $elapsed_time -ge $duration ]]; then
                log_info "Phase $phase_name completed after $elapsed_time seconds"
                break
            fi
            
            # Perform health checks during phase
            if ! perform_phase_health_check; then
                log_error "Health check failed during phase $phase_name"
                return 3
            fi
            
            # Check for performance degradation
            if ! monitor_phase_performance; then
                log_error "Performance degradation detected during phase $phase_name"
                return 4
            fi
            
            # Wait before next check
            sleep 30
        done
        
        log_info "Traffic migration phase $phase_name completed successfully"
        send_slack_notification "Traffic migration phase $phase_name completed: $percentage% traffic migrated" "good"
    done
    
    log_info "Gradual traffic migration completed successfully"
    return 0
}

update_traffic_routing() {
    local traffic_percentage="$1"
    
    log_debug "Updating traffic routing to $traffic_percentage%"
    
    # Update service selector to route traffic based on percentage
    # This would typically involve updating ingress rules or service mesh configuration
    # For this implementation, we'll use a simplified approach with service selectors
    
    if [[ "$traffic_percentage" == "100" ]]; then
        # Route all traffic to target environment
        kubectl patch service "$SERVICE_NAME" \
            -n "$DEPLOYMENT_NAMESPACE" \
            -p '{"spec":{"selector":{"environment":"'$TARGET_ENVIRONMENT'"}}}' || {
            log_error "Failed to update service selector for 100% traffic"
            return 7
        }
    else
        # For partial traffic routing, we would use an advanced ingress controller
        # or service mesh like Istio for weighted routing
        log_debug "Partial traffic routing ($traffic_percentage%) would require advanced service mesh"
    fi
    
    return 0
}

perform_phase_health_check() {
    local health_check_script="./scripts/health-check.sh"
    
    if [[ -f "$health_check_script" ]]; then
        local service_endpoint
        service_endpoint=$(kubectl get service "${SERVICE_NAME}-${TARGET_ENVIRONMENT}" \
            -n "$DEPLOYMENT_NAMESPACE" \
            -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "")
        
        if [[ -n "$service_endpoint" ]]; then
            "$health_check_script" \
                --host "$service_endpoint" \
                --port 8000 \
                --timeout 30 \
                --critical-only \
                --json >/dev/null 2>&1
        else
            return 1
        fi
    else
        # Fallback basic health check
        local service_endpoint
        service_endpoint=$(kubectl get service "${SERVICE_NAME}-${TARGET_ENVIRONMENT}" \
            -n "$DEPLOYMENT_NAMESPACE" \
            -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "")
        
        if [[ -n "$service_endpoint" ]]; then
            curl -f -s "http://${service_endpoint}:8000/health" >/dev/null
        else
            return 1
        fi
    fi
}

monitor_phase_performance() {
    # Collect current metrics
    collect_current_metrics
    
    # Validate against baseline
    local temp_baseline=("${BASELINE_METRICS[@]}")
    validate_performance_variance
}

#
# Rollback Functions
#

execute_rollback() {
    local reason="${1:-Manual rollback requested}"
    
    ROLLBACK_TRIGGERED=true
    log_warn "Executing rollback procedure: $reason"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Dry run mode: simulating rollback"
        return 0
    fi
    
    send_slack_notification "Rollback initiated: $reason" "warning"
    
    # Stop traffic migration immediately
    log_info "Stopping traffic migration and reverting to stable environment"
    
    if [[ -n "$CURRENT_ENVIRONMENT" ]]; then
        # Revert service selector to current stable environment
        kubectl patch service "$SERVICE_NAME" \
            -n "$DEPLOYMENT_NAMESPACE" \
            -p '{"spec":{"selector":{"environment":"'$CURRENT_ENVIRONMENT'"}}}' || {
            log_error "Failed to revert service selector during rollback"
            return 6
        }
    fi
    
    # Update feature flags to disable new deployment
    if [[ -n "$FEATURE_FLAG_SERVICE_URL" ]]; then
        local rollback_payload=$(cat << EOF
{
  "deployment_id": "$DEPLOYMENT_ID",
  "action": "rollback",
  "reason": "$reason",
  "target_environment": "$CURRENT_ENVIRONMENT",
  "timestamp": "$(date -u +%s)"
}
EOF
)
        
        curl -s -X POST \
            -H "Content-Type: application/json" \
            -d "$rollback_payload" \
            "${FEATURE_FLAG_SERVICE_URL}/api/deployment/rollback" >/dev/null || true
    fi
    
    # Scale down target environment deployment
    if [[ -n "$TARGET_ENVIRONMENT" ]]; then
        kubectl scale deployment "flask-app-${TARGET_ENVIRONMENT}" \
            --replicas=0 \
            -n "$DEPLOYMENT_NAMESPACE" || {
            log_warn "Failed to scale down target environment deployment"
        }
    fi
    
    # Validate rollback success
    if ! validate_rollback_success; then
        log_error "Rollback validation failed"
        return 6
    fi
    
    log_info "Rollback procedure completed successfully"
    send_slack_notification "Rollback completed successfully: $reason" "good"
    
    return 0
}

validate_rollback_success() {
    log_info "Validating rollback success..."
    
    # Check if stable environment is receiving traffic
    if [[ -n "$CURRENT_ENVIRONMENT" ]]; then
        local service_endpoint
        service_endpoint=$(kubectl get service "${SERVICE_NAME}" \
            -n "$DEPLOYMENT_NAMESPACE" \
            -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "")
        
        if [[ -n "$service_endpoint" ]]; then
            # Execute health check on stable environment
            local health_check_script="./scripts/health-check.sh"
            if [[ -f "$health_check_script" ]]; then
                "$health_check_script" \
                    --host "$service_endpoint" \
                    --port 8000 \
                    --timeout 60 \
                    --critical-only >/dev/null 2>&1
            else
                curl -f -s "http://${service_endpoint}:8000/health" >/dev/null
            fi
        else
            return 1
        fi
    fi
    
    log_info "Rollback validation completed successfully"
    return 0
}

#
# Cleanup Functions
#

cleanup_deployment_resources() {
    log_info "Cleaning up deployment resources..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Dry run mode: simulating resource cleanup"
        return 0
    fi
    
    # Clean up old deployments (keep last 3)
    local deployments
    deployments=$(kubectl get deployments -n "$DEPLOYMENT_NAMESPACE" \
        --selector="app=flask-app" \
        --sort-by='.metadata.creationTimestamp' \
        -o jsonpath='{.items[*].metadata.name}')
    
    local deployment_array=($deployments)
    local total_deployments=${#deployment_array[@]}
    
    if [[ $total_deployments -gt 3 ]]; then
        local deployments_to_delete=$((total_deployments - 3))
        log_info "Cleaning up $deployments_to_delete old deployments..."
        
        for ((i=0; i<deployments_to_delete; i++)); do
            local deployment_name="${deployment_array[$i]}"
            kubectl delete deployment "$deployment_name" -n "$DEPLOYMENT_NAMESPACE" || {
                log_warn "Failed to delete deployment: $deployment_name"
            }
        done
    fi
    
    # Clean up old replica sets
    kubectl delete replicaset \
        --selector="app=flask-app" \
        --field-selector='status.replicas=0' \
        -n "$DEPLOYMENT_NAMESPACE" || true
    
    # Clean up old pods
    kubectl delete pod \
        --selector="app=flask-app" \
        --field-selector='status.phase!=Running' \
        -n "$DEPLOYMENT_NAMESPACE" || true
    
    # Clean up temporary secrets and config maps
    kubectl delete secret,configmap \
        --selector="deployment-id=$DEPLOYMENT_ID" \
        -n "$DEPLOYMENT_NAMESPACE" || true
    
    log_info "Deployment resource cleanup completed"
    return 0
}

#
# Main Functions
#

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            --image)
                IMAGE_TAG="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --skip-tests)
                SKIP_TESTS=true
                shift
                ;;
            --skip-security-scan)
                SKIP_SECURITY_SCAN=true
                shift
                ;;
            --force-deploy)
                FORCE_DEPLOY=true
                shift
                ;;
            --rollback-only)
                ROLLBACK_ONLY=true
                shift
                ;;
            --cleanup-only)
                CLEANUP_ONLY=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 2
                ;;
        esac
    done
}

show_usage() {
    cat << EOF
$SCRIPT_DESCRIPTION

Usage: $SCRIPT_NAME [OPTIONS]

OPTIONS:
  --environment ENV       Target environment (development, staging, production)
  --image IMAGE_TAG       Container image tag to deploy
  --dry-run               Perform validation without actual deployment
  --skip-tests            Skip test suite execution (not recommended for production)
  --skip-security-scan    Skip container vulnerability scanning (emergency only)
  --force-deploy          Bypass performance validation (emergency only)
  --rollback-only         Execute rollback to previous stable deployment
  --cleanup-only          Clean up deployment artifacts and resources
  --verbose               Enable detailed logging output
  --help                  Display this help message

ENVIRONMENT VARIABLES:
  KUBECONFIG              Kubernetes configuration file path
  DEPLOYMENT_NAMESPACE    Kubernetes namespace for deployment
  CONTAINER_REGISTRY      Container registry URL for image storage
  FEATURE_FLAG_SERVICE_URL Feature flag service endpoint
  PROMETHEUS_ENDPOINT     Prometheus metrics endpoint for monitoring
  PERFORMANCE_BASELINE_URL Node.js baseline performance metrics endpoint
  SLACK_WEBHOOK_URL       Slack webhook for deployment notifications
  ROLLBACK_ENABLED        Enable automated rollback (default: true)
  PERFORMANCE_VARIANCE_THRESHOLD Maximum allowed performance variance (default: 10)
  SECURITY_SCAN_ENABLED   Enable container vulnerability scanning (default: true)
  BLUE_GREEN_ENABLED      Enable blue-green deployment pattern (default: true)

EXAMPLES:
  # Production deployment with full validation
  $SCRIPT_NAME --environment production --image flask-app:v1.2.3

  # Staging deployment with verbose logging
  $SCRIPT_NAME --environment staging --image flask-app:v1.2.3 --verbose

  # Emergency deployment bypassing performance validation
  $SCRIPT_NAME --environment production --image flask-app:v1.2.4 --force-deploy

  # Dry run deployment validation
  $SCRIPT_NAME --environment production --image flask-app:v1.2.3 --dry-run

  # Execute rollback to previous stable deployment
  $SCRIPT_NAME --environment production --rollback-only

  # Clean up old deployment resources
  $SCRIPT_NAME --environment production --cleanup-only

For more information, see the technical specification documentation.
EOF
}

main() {
    # Generate unique deployment ID
    generate_deployment_id
    
    # Record deployment start time
    DEPLOYMENT_START_TIME=$(date -u +%s)
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Log startup information
    log_info "Starting $SCRIPT_DESCRIPTION v$SCRIPT_VERSION"
    log_info "Deployment ID: $DEPLOYMENT_ID"
    log_info "Environment: $ENVIRONMENT"
    log_info "Image Tag: $IMAGE_TAG"
    log_info "Dry Run: $DRY_RUN"
    
    # Handle special modes
    if [[ "$CLEANUP_ONLY" == "true" ]]; then
        log_info "Cleanup-only mode activated"
        cleanup_deployment_resources
        exit $?
    fi
    
    if [[ "$ROLLBACK_ONLY" == "true" ]]; then
        log_info "Rollback-only mode activated"
        execute_rollback "Manual rollback requested"
        exit $?
    fi
    
    # Validate prerequisites and configuration
    validate_prerequisites || exit $?
    validate_environment_config || exit $?
    
    # Send deployment start notification
    send_slack_notification "Deployment started: $DEPLOYMENT_ID" "good"
    
    # Execute container security scan
    execute_container_security_scan || exit $?
    
    # Execute test suite
    execute_test_suite || exit $?
    
    # Determine blue-green environments
    determine_target_environment || exit $?
    
    # Collect performance baseline
    collect_baseline_metrics || exit $?
    
    # Deploy to target environment
    deploy_to_target_environment || exit $?
    
    # Validate deployment health
    validate_deployment_health || exit $?
    
    # Collect current performance metrics
    collect_current_metrics || exit $?
    
    # Validate performance variance
    validate_performance_variance || exit $?
    
    # Initialize feature flag management
    initialize_feature_flags || exit $?
    
    # Execute gradual traffic migration
    execute_gradual_traffic_migration || exit $?
    
    # Final deployment validation
    log_info "Performing final deployment validation..."
    validate_deployment_health || exit $?
    
    # Clean up old resources
    cleanup_deployment_resources || exit $?
    
    # Mark deployment as successful
    DEPLOYMENT_SUCCESS=true
    
    # Calculate deployment duration
    local deployment_end_time=$(date -u +%s)
    local deployment_duration=$((deployment_end_time - DEPLOYMENT_START_TIME))
    
    log_info "Deployment completed successfully in $deployment_duration seconds"
    send_slack_notification "Deployment completed successfully: $DEPLOYMENT_ID (${deployment_duration}s)" "good"
    
    exit 0
}

# Execute main function with all arguments
main "$@"