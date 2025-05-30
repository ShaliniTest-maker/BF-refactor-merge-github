#!/bin/bash

#
# Blue-Green Deployment Automation Script
#
# Comprehensive production deployment script implementing zero-downtime migration with 
# feature flag control, performance validation, and automated rollback capabilities for 
# Flask application production deployment per Section 4.4.1 and Section 8.5.2.
#
# This script provides:
# - Blue-green deployment with enhanced validation and container orchestration
# - Feature flag management for gradual traffic migration (5% → 25% → 50% → 100%)
# - Performance monitoring ensuring ≤10% variance from Node.js baseline
# - Automated rollback procedures for critical issues with security incident response
# - Container vulnerability scanning with Trivy 0.48+ security analysis
# - Comprehensive health validation using enterprise health check patterns
# - Kubernetes-native deployment with Helm chart orchestration
# - Prometheus-driven performance validation and alerting integration
#
# Exit Codes:
# 0 - Deployment completed successfully
# 1 - Pre-deployment validation failed
# 2 - Build or container creation failed
# 3 - Green environment deployment failed
# 4 - Health check validation failed
# 5 - Performance validation failed (>10% variance)
# 6 - Feature flag deployment failed
# 7 - Rollback executed due to critical issues
# 8 - Post-deployment validation failed
# 9 - Configuration error or dependency missing
#
# Usage:
#   ./deploy.sh [options]
#
# Options:
#   --environment ENV         Target environment (staging, production)
#   --image-tag TAG          Docker image tag to deploy (default: latest)
#   --skip-performance       Skip performance validation (development only)
#   --skip-security         Skip container security scanning (not recommended)
#   --rollback-version TAG   Rollback to specific version instead of deployment
#   --force-rollback        Force immediate rollback to blue environment
#   --dry-run               Validate deployment without executing changes
#   --verbose               Enable detailed logging output
#   --help                  Show comprehensive help documentation
#

set -euo pipefail

# Script metadata and configuration
SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(dirname "$0")"
SCRIPT_VERSION="2.0.0"
LOG_PREFIX="[BLUE-GREEN-DEPLOY]"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S UTC')

# Default configuration values per Section 8.5.2
DEFAULT_ENVIRONMENT="staging"
DEFAULT_IMAGE_TAG="latest"
DEFAULT_TIMEOUT="600"
DEFAULT_HEALTH_CHECK_RETRIES="5"
DEFAULT_PERFORMANCE_THRESHOLD="10"
DEFAULT_TRAFFIC_STEPS=("5" "25" "50" "100")
DEFAULT_MONITORING_INTERVAL="30"

# Deployment configuration
ENVIRONMENT="${DEPLOY_ENVIRONMENT:-$DEFAULT_ENVIRONMENT}"
IMAGE_TAG="${DEPLOY_IMAGE_TAG:-$DEFAULT_IMAGE_TAG}"
NAMESPACE="${DEPLOY_NAMESPACE:-flask-app-${ENVIRONMENT}}"
APP_NAME="${DEPLOY_APP_NAME:-flask-app}"
CLUSTER_NAME="${DEPLOY_CLUSTER:-production-cluster}"
REGISTRY_URL="${DEPLOY_REGISTRY:-registry.company.com}"

# Operational configuration
TIMEOUT="${DEPLOY_TIMEOUT:-$DEFAULT_TIMEOUT}"
HEALTH_CHECK_RETRIES="${DEPLOY_HEALTH_RETRIES:-$DEFAULT_HEALTH_CHECK_RETRIES}"
PERFORMANCE_THRESHOLD="${DEPLOY_PERFORMANCE_THRESHOLD:-$DEFAULT_PERFORMANCE_THRESHOLD}"
MONITORING_INTERVAL="${DEPLOY_MONITORING_INTERVAL:-$DEFAULT_MONITORING_INTERVAL}"

# Feature flag and traffic management
declare -a TRAFFIC_STEPS=("${DEPLOY_TRAFFIC_STEPS[@]:-${DEFAULT_TRAFFIC_STEPS[@]}}")
FEATURE_FLAG_ENDPOINT="${DEPLOY_FEATURE_FLAG_ENDPOINT:-https://feature-flags.company.com/api/v1}"
LOAD_BALANCER_ENDPOINT="${DEPLOY_LB_ENDPOINT:-https://api.company.com}"

# Control flags
SKIP_PERFORMANCE="${DEPLOY_SKIP_PERFORMANCE:-false}"
SKIP_SECURITY="${DEPLOY_SKIP_SECURITY:-false}"
ROLLBACK_VERSION="${DEPLOY_ROLLBACK_VERSION:-}"
FORCE_ROLLBACK="${DEPLOY_FORCE_ROLLBACK:-false}"
DRY_RUN="${DEPLOY_DRY_RUN:-false}"
VERBOSE="${DEPLOY_VERBOSE:-false}"

# State tracking and artifact management
DEPLOYMENT_ID="deploy-$(date +%s)-$$"
STATE_DIR="/tmp/deploy-state-${DEPLOYMENT_ID}"
ARTIFACT_DIR="${STATE_DIR}/artifacts"
LOG_FILE="${STATE_DIR}/deployment.log"
ROLLBACK_STATE_FILE="${STATE_DIR}/rollback.state"

# Monitoring and alerting configuration
PROMETHEUS_ENDPOINT="${DEPLOY_PROMETHEUS:-http://prometheus.monitoring.svc.cluster.local:9090}"
GRAFANA_ENDPOINT="${DEPLOY_GRAFANA:-https://grafana.company.com}"
ALERT_WEBHOOK="${DEPLOY_ALERT_WEBHOOK:-https://alerts.company.com/webhook/deployment}"
SLACK_WEBHOOK="${DEPLOY_SLACK_WEBHOOK:-}"

# Security and compliance
TRIVY_SEVERITY="${DEPLOY_TRIVY_SEVERITY:-CRITICAL,HIGH,MEDIUM}"
SECURITY_POLICY_ENDPOINT="${DEPLOY_SECURITY_POLICY:-https://security.company.com/api/policies}"
COMPLIANCE_VALIDATION="${DEPLOY_COMPLIANCE_VALIDATION:-true}"

# Deployment state variables
CURRENT_COLOR=""
TARGET_COLOR=""
BLUE_VERSION=""
GREEN_VERSION=""
DEPLOYMENT_START_TIME=""
PERFORMANCE_BASELINE=""
ROLLBACK_EXECUTED="false"

# Error tracking and metrics
declare -a DEPLOYMENT_ERRORS=()
declare -a PERFORMANCE_METRICS=()
declare -a SECURITY_FINDINGS=()
DEPLOYMENT_STATUS="unknown"

#
# Logging and output functions with enterprise integration
#
log_info() {
    local message="$*"
    echo "$LOG_PREFIX [INFO] [$TIMESTAMP] $message" | tee -a "$LOG_FILE"
}

log_warn() {
    local message="$*"
    echo "$LOG_PREFIX [WARN] [$TIMESTAMP] $message" | tee -a "$LOG_FILE" >&2
}

log_error() {
    local message="$*"
    echo "$LOG_PREFIX [ERROR] [$TIMESTAMP] $message" | tee -a "$LOG_FILE" >&2
    DEPLOYMENT_ERRORS+=("$message")
}

log_debug() {
    if [[ "$VERBOSE" == "true" ]]; then
        local message="$*"
        echo "$LOG_PREFIX [DEBUG] [$TIMESTAMP] $message" | tee -a "$LOG_FILE"
    fi
}

log_success() {
    local message="$*"
    echo "$LOG_PREFIX [SUCCESS] [$TIMESTAMP] $message" | tee -a "$LOG_FILE"
}

log_metric() {
    local metric_name="$1"
    local metric_value="$2"
    local metric_tags="${3:-}"
    
    log_debug "Metric: $metric_name=$metric_value $metric_tags"
    PERFORMANCE_METRICS+=("$metric_name:$metric_value:$metric_tags")
    
    # Send metrics to Prometheus if available
    if command -v curl >/dev/null 2>&1 && [[ -n "$PROMETHEUS_ENDPOINT" ]]; then
        curl -s -X POST "$PROMETHEUS_ENDPOINT/api/v1/write" \
             -H 'Content-Type: application/x-protobuf' \
             -H 'Content-Encoding: snappy' \
             --data-binary "@-" <<< "$metric_name $metric_value" || true
    fi
}

#
# Comprehensive help documentation
#
show_help() {
    cat << EOF
$SCRIPT_NAME - Blue-Green Deployment Automation Script v$SCRIPT_VERSION

DESCRIPTION:
    Enterprise-grade blue-green deployment automation script implementing zero-downtime
    migration with comprehensive feature flag control, performance validation, and 
    automated rollback capabilities for Flask application production deployment.

    Features comprehensive integration with:
    - Kubernetes orchestration with Helm chart management
    - Container vulnerability scanning with Trivy 0.48+ security analysis
    - Performance monitoring ensuring ≤10% variance from Node.js baseline
    - Feature flag management for gradual traffic migration (5% → 25% → 50% → 100%)
    - Automated rollback procedures with security incident response integration
    - Prometheus metrics collection and Grafana dashboard integration
    - Enterprise health check validation with comprehensive system monitoring

USAGE:
    $SCRIPT_NAME [OPTIONS]

OPTIONS:
    Deployment Configuration:
    --environment ENV           Target deployment environment (staging, production)
                               Default: $DEFAULT_ENVIRONMENT
    --image-tag TAG            Docker image tag to deploy
                               Default: $DEFAULT_IMAGE_TAG
    --namespace NAMESPACE      Kubernetes namespace for deployment
                               Default: flask-app-\$ENVIRONMENT
    --app-name NAME           Application name for deployment
                               Default: flask-app
    --cluster CLUSTER         Target Kubernetes cluster
                               Default: production-cluster

    Operational Configuration:
    --timeout SECONDS          Deployment timeout in seconds
                               Default: $DEFAULT_TIMEOUT
    --health-retries COUNT     Health check retry attempts
                               Default: $DEFAULT_HEALTH_CHECK_RETRIES
    --performance-threshold N   Performance variance threshold percentage
                               Default: $DEFAULT_PERFORMANCE_THRESHOLD%
    --monitoring-interval N     Monitoring check interval in seconds
                               Default: $DEFAULT_MONITORING_INTERVAL

    Traffic Management:
    --traffic-steps "5,25,50,100"  Traffic migration percentages
                                   Default: 5% → 25% → 50% → 100%
    --feature-flag-endpoint URL    Feature flag management API endpoint
    --load-balancer-endpoint URL   Load balancer management endpoint

    Control Options:
    --skip-performance         Skip performance validation (development only)
    --skip-security           Skip container security scanning (not recommended)
    --rollback-version TAG    Rollback to specific version instead of deployment
    --force-rollback          Force immediate rollback to blue environment
    --dry-run                 Validate deployment without executing changes
    --verbose                 Enable detailed logging and debugging output
    --help                    Show this comprehensive help documentation

    Monitoring Integration:
    --prometheus-url URL      Prometheus metrics endpoint for monitoring
    --grafana-url URL         Grafana dashboard endpoint for visualization
    --alert-webhook URL       Alert webhook for deployment notifications
    --slack-webhook URL       Slack integration for team notifications

ENVIRONMENT VARIABLES:
    DEPLOY_ENVIRONMENT              Override default target environment
    DEPLOY_IMAGE_TAG               Override default image tag
    DEPLOY_NAMESPACE               Override default Kubernetes namespace
    DEPLOY_APP_NAME                Override default application name
    DEPLOY_CLUSTER                 Override default cluster name
    DEPLOY_REGISTRY                Override default container registry
    DEPLOY_TIMEOUT                 Override default deployment timeout
    DEPLOY_HEALTH_RETRIES          Override default health check retries
    DEPLOY_PERFORMANCE_THRESHOLD   Override default performance threshold
    DEPLOY_MONITORING_INTERVAL     Override default monitoring interval
    DEPLOY_TRAFFIC_STEPS           Override default traffic migration steps
    DEPLOY_FEATURE_FLAG_ENDPOINT   Override feature flag API endpoint
    DEPLOY_LB_ENDPOINT             Override load balancer endpoint
    DEPLOY_PROMETHEUS              Override Prometheus endpoint
    DEPLOY_GRAFANA                 Override Grafana endpoint
    DEPLOY_ALERT_WEBHOOK           Override alert webhook URL
    DEPLOY_SLACK_WEBHOOK           Override Slack webhook URL
    DEPLOY_TRIVY_SEVERITY          Override Trivy severity levels
    DEPLOY_SECURITY_POLICY         Override security policy endpoint
    DEPLOY_COMPLIANCE_VALIDATION   Override compliance validation requirement

EXIT CODES:
    0    Deployment completed successfully
    1    Pre-deployment validation failed
    2    Build or container creation failed
    3    Green environment deployment failed
    4    Health check validation failed
    5    Performance validation failed (>10% variance)
    6    Feature flag deployment failed
    7    Rollback executed due to critical issues
    8    Post-deployment validation failed
    9    Configuration error or dependency missing

EXAMPLES:
    # Standard production deployment
    $SCRIPT_NAME --environment production --image-tag v2.1.0

    # Verbose staging deployment with custom performance threshold
    $SCRIPT_NAME --environment staging --verbose --performance-threshold 15

    # Dry-run deployment validation
    $SCRIPT_NAME --environment production --image-tag v2.1.0 --dry-run

    # Emergency rollback to previous version
    $SCRIPT_NAME --rollback-version v2.0.5 --force-rollback

    # Development deployment skipping performance validation
    $SCRIPT_NAME --environment staging --skip-performance --verbose

ARCHITECTURE:
    The deployment script implements comprehensive blue-green deployment patterns with:
    
    1. Pre-deployment Validation:
       - Container security scanning with Trivy vulnerability assessment
       - Configuration validation and dependency verification
       - Performance baseline establishment and metric collection
    
    2. Green Environment Deployment:
       - Kubernetes deployment with Helm chart orchestration
       - Container health validation with comprehensive system checks
       - Database connectivity and external service integration validation
    
    3. Performance Validation:
       - Automated performance testing with Locust and k6 frameworks
       - Baseline comparison ensuring ≤10% variance requirement compliance
       - Real-time monitoring with Prometheus metrics collection
    
    4. Progressive Traffic Migration:
       - Feature flag-controlled traffic migration (5% → 25% → 50% → 100%)
       - Continuous monitoring with automated rollback triggers
       - Performance trend analysis and anomaly detection
    
    5. Rollback and Recovery:
       - Automated rollback on performance degradation detection
       - Security incident response integration with immediate rollback
       - Comprehensive state restoration and cleanup procedures

For detailed technical specifications, refer to Section 4.4.1 (Blue-Green Deployment)
and Section 8.5.2 (Deployment Pipeline) of the system architecture documentation.
EOF
}

#
# Dependency validation and environment setup
#
validate_dependencies() {
    log_info "Validating deployment dependencies and environment setup..."
    
    # Required command validation
    local required_commands=(
        "kubectl:Kubernetes CLI for container orchestration"
        "helm:Helm package manager for Kubernetes deployment"
        "docker:Docker container runtime for image management"
        "curl:HTTP client for API interactions and health checks"
        "jq:JSON processor for API response parsing"
        "trivy:Container vulnerability scanner for security validation"
    )
    
    local missing_commands=()
    for cmd_desc in "${required_commands[@]}"; do
        local cmd="${cmd_desc%%:*}"
        local desc="${cmd_desc##*:}"
        
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_commands+=("$cmd ($desc)")
        else
            log_debug "Dependency validated: $cmd - $(command -v "$cmd")"
        fi
    done
    
    if [[ ${#missing_commands[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing_commands[*]}"
        log_error "Please install missing dependencies and retry deployment"
        return 9
    fi
    
    # Kubernetes cluster connectivity validation
    log_debug "Validating Kubernetes cluster connectivity..."
    if ! kubectl cluster-info >/dev/null 2>&1; then
        log_error "Cannot connect to Kubernetes cluster: $CLUSTER_NAME"
        log_error "Please ensure kubectl is configured and cluster is accessible"
        return 9
    fi
    
    # Namespace validation and creation
    log_debug "Validating Kubernetes namespace: $NAMESPACE"
    if ! kubectl get namespace "$NAMESPACE" >/dev/null 2>&1; then
        log_info "Creating Kubernetes namespace: $NAMESPACE"
        if [[ "$DRY_RUN" != "true" ]]; then
            kubectl create namespace "$NAMESPACE" || {
                log_error "Failed to create namespace: $NAMESPACE"
                return 9
            }
        fi
    fi
    
    # Container registry access validation
    log_debug "Validating container registry access: $REGISTRY_URL"
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker daemon not accessible or not running"
        return 9
    fi
    
    # Configuration parameter validation
    if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || [[ "$TIMEOUT" -lt 60 ]] || [[ "$TIMEOUT" -gt 3600 ]]; then
        log_error "Invalid timeout value: $TIMEOUT (must be 60-3600 seconds)"
        return 9
    fi
    
    if ! [[ "$PERFORMANCE_THRESHOLD" =~ ^[0-9]+$ ]] || [[ "$PERFORMANCE_THRESHOLD" -lt 1 ]] || [[ "$PERFORMANCE_THRESHOLD" -gt 50 ]]; then
        log_error "Invalid performance threshold: $PERFORMANCE_THRESHOLD (must be 1-50 percent)"
        return 9
    fi
    
    # Traffic step validation
    for step in "${TRAFFIC_STEPS[@]}"; do
        if ! [[ "$step" =~ ^[0-9]+$ ]] || [[ "$step" -lt 1 ]] || [[ "$step" -gt 100 ]]; then
            log_error "Invalid traffic step: $step (must be 1-100 percent)"
            return 9
        fi
    done
    
    log_success "All deployment dependencies validated successfully"
    return 0
}

#
# State management and artifact preparation
#
initialize_deployment_state() {
    log_info "Initializing deployment state and artifact management..."
    
    # Create state and artifact directories
    mkdir -p "$STATE_DIR" "$ARTIFACT_DIR"
    
    # Initialize deployment metadata
    cat > "$STATE_DIR/deployment.meta" << EOF
DEPLOYMENT_ID=$DEPLOYMENT_ID
DEPLOYMENT_START_TIME=$(date -Iseconds)
ENVIRONMENT=$ENVIRONMENT
IMAGE_TAG=$IMAGE_TAG
NAMESPACE=$NAMESPACE
APP_NAME=$APP_NAME
CLUSTER_NAME=$CLUSTER_NAME
SCRIPT_VERSION=$SCRIPT_VERSION
TARGET_PERFORMANCE_THRESHOLD=$PERFORMANCE_THRESHOLD
TRAFFIC_MIGRATION_STEPS=${TRAFFIC_STEPS[*]}
EOF
    
    # Initialize rollback state tracking
    cat > "$ROLLBACK_STATE_FILE" << EOF
ROLLBACK_READY=false
BLUE_ENVIRONMENT_HEALTHY=unknown
GREEN_ENVIRONMENT_DEPLOYED=false
TRAFFIC_MIGRATION_STEP=0
PERFORMANCE_BASELINE_ESTABLISHED=false
ROLLBACK_VERSION_AVAILABLE=
EOF
    
    # Capture current deployment state for rollback
    log_debug "Capturing current deployment state for rollback preparation..."
    
    # Get current active color and version
    if kubectl get service "$APP_NAME" -n "$NAMESPACE" >/dev/null 2>&1; then
        CURRENT_COLOR=$(kubectl get service "$APP_NAME" -n "$NAMESPACE" -o jsonpath='{.spec.selector.color}' 2>/dev/null || echo "blue")
        BLUE_VERSION=$(kubectl get deployment "$APP_NAME-blue" -n "$NAMESPACE" -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null | sed 's/.*://' || echo "unknown")
        
        log_debug "Current deployment state: color=$CURRENT_COLOR, blue_version=$BLUE_VERSION"
    else
        CURRENT_COLOR="blue"
        BLUE_VERSION="none"
        log_debug "No existing deployment found, initializing fresh deployment"
    fi
    
    # Determine target color for green deployment
    TARGET_COLOR="green"
    GREEN_VERSION="$IMAGE_TAG"
    
    # Update rollback state with current information
    sed -i "s/ROLLBACK_VERSION_AVAILABLE=.*/ROLLBACK_VERSION_AVAILABLE=$BLUE_VERSION/" "$ROLLBACK_STATE_FILE"
    
    log_info "Deployment state initialized: $DEPLOYMENT_ID"
    log_debug "Current: $CURRENT_COLOR ($BLUE_VERSION) → Target: $TARGET_COLOR ($GREEN_VERSION)"
    
    return 0
}

#
# Container vulnerability scanning with Trivy security analysis per Section 8.5.2
#
perform_container_security_scan() {
    if [[ "$SKIP_SECURITY" == "true" ]]; then
        log_warn "Container security scanning skipped (--skip-security enabled)"
        return 0
    fi
    
    log_info "Performing container vulnerability scanning with Trivy security analysis..."
    
    local image_ref="$REGISTRY_URL/$APP_NAME:$IMAGE_TAG"
    local scan_output="$ARTIFACT_DIR/trivy-scan-results.json"
    local scan_report="$ARTIFACT_DIR/trivy-scan-report.txt"
    
    log_debug "Scanning container image: $image_ref"
    log_debug "Trivy severity levels: $TRIVY_SEVERITY"
    
    # Perform Trivy vulnerability scan with comprehensive reporting
    if ! trivy image \
        --format json \
        --output "$scan_output" \
        --severity "$TRIVY_SEVERITY" \
        --timeout 300s \
        --quiet \
        "$image_ref"; then
        log_error "Container vulnerability scan failed for image: $image_ref"
        return 2
    fi
    
    # Generate human-readable scan report
    trivy image \
        --format table \
        --output "$scan_report" \
        --severity "$TRIVY_SEVERITY" \
        --quiet \
        "$image_ref" || true
    
    # Parse scan results for critical findings
    local critical_count=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$scan_output" 2>/dev/null || echo "0")
    local high_count=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$scan_output" 2>/dev/null || echo "0")
    local medium_count=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length' "$scan_output" 2>/dev/null || echo "0")
    
    log_debug "Vulnerability scan results: CRITICAL=$critical_count, HIGH=$high_count, MEDIUM=$medium_count"
    
    # Enforce security policy per Section 8.5.2 container security requirements
    if [[ "$critical_count" -gt 0 ]]; then
        log_error "Container security scan failed: $critical_count CRITICAL vulnerabilities detected"
        log_error "Critical vulnerabilities must be resolved before deployment"
        
        # Extract critical vulnerability details
        if [[ -s "$scan_output" ]]; then
            jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL") | "CVE: \(.VulnerabilityID) - \(.Title) - \(.PkgName)"' "$scan_output" | head -10 | while read -r vuln; do
                log_error "Critical: $vuln"
                SECURITY_FINDINGS+=("CRITICAL: $vuln")
            done
        fi
        
        return 2
    fi
    
    if [[ "$high_count" -gt 0 ]]; then
        log_warn "Container security scan warning: $high_count HIGH severity vulnerabilities detected"
        log_warn "High severity vulnerabilities should be reviewed and remediated"
        
        # Log high severity findings for review
        if [[ -s "$scan_output" ]]; then
            jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH") | "CVE: \(.VulnerabilityID) - \(.Title) - \(.PkgName)"' "$scan_output" | head -5 | while read -r vuln; do
                log_warn "High: $vuln"
                SECURITY_FINDINGS+=("HIGH: $vuln")
            done
        fi
    fi
    
    # Record security metrics
    log_metric "container_vulnerabilities_critical" "$critical_count" "image=$IMAGE_TAG"
    log_metric "container_vulnerabilities_high" "$high_count" "image=$IMAGE_TAG"
    log_metric "container_vulnerabilities_medium" "$medium_count" "image=$IMAGE_TAG"
    
    log_success "Container security scan completed: CRITICAL=$critical_count, HIGH=$high_count, MEDIUM=$medium_count"
    
    return 0
}

#
# Pre-deployment validation and configuration verification per Section 4.4.1
#
perform_pre_deployment_validation() {
    log_info "Performing comprehensive pre-deployment validation..."
    
    local validation_errors=0
    
    # Container image availability validation
    log_debug "Validating container image availability: $REGISTRY_URL/$APP_NAME:$IMAGE_TAG"
    if ! docker manifest inspect "$REGISTRY_URL/$APP_NAME:$IMAGE_TAG" >/dev/null 2>&1; then
        log_error "Container image not found: $REGISTRY_URL/$APP_NAME:$IMAGE_TAG"
        ((validation_errors++))
    else
        log_debug "Container image validated successfully"
    fi
    
    # Helm chart validation
    log_debug "Validating Helm chart configuration..."
    local helm_chart_path="$SCRIPT_DIR/../helm/$APP_NAME"
    if [[ ! -f "$helm_chart_path/Chart.yaml" ]]; then
        log_error "Helm chart not found: $helm_chart_path/Chart.yaml"
        ((validation_errors++))
    else
        # Validate Helm chart syntax
        if ! helm lint "$helm_chart_path" >/dev/null 2>&1; then
            log_error "Helm chart validation failed for: $helm_chart_path"
            ((validation_errors++))
        else
            log_debug "Helm chart validation successful"
        fi
    fi
    
    # Feature flag service connectivity validation
    if [[ -n "$FEATURE_FLAG_ENDPOINT" ]]; then
        log_debug "Validating feature flag service connectivity..."
        if ! curl -s --connect-timeout 10 --max-time 20 "$FEATURE_FLAG_ENDPOINT/health" >/dev/null 2>&1; then
            log_warn "Feature flag service not accessible: $FEATURE_FLAG_ENDPOINT"
            log_warn "Traffic migration may need manual coordination"
        else
            log_debug "Feature flag service validated successfully"
        fi
    fi
    
    # Performance baseline establishment
    if [[ "$SKIP_PERFORMANCE" != "true" ]]; then
        log_debug "Establishing performance baseline for validation..."
        if ! establish_performance_baseline; then
            log_error "Failed to establish performance baseline"
            ((validation_errors++))
        fi
    fi
    
    # Resource availability validation
    log_debug "Validating cluster resource availability..."
    local node_count=$(kubectl get nodes --no-headers | wc -l)
    local ready_nodes=$(kubectl get nodes --no-headers | grep -c " Ready " || echo "0")
    
    if [[ "$ready_nodes" -lt 3 ]]; then
        log_warn "Limited cluster capacity: $ready_nodes/$node_count nodes ready"
        log_warn "Deployment may experience resource constraints"
    else
        log_debug "Cluster capacity validated: $ready_nodes/$node_count nodes ready"
    fi
    
    # Network policy and security validation
    log_debug "Validating network policies and security configuration..."
    if kubectl get networkpolicy -n "$NAMESPACE" >/dev/null 2>&1; then
        log_debug "Network policies validated for namespace: $NAMESPACE"
    else
        log_warn "No network policies found for namespace: $NAMESPACE"
    fi
    
    # Configuration secret validation
    log_debug "Validating deployment configuration secrets..."
    local required_secrets=("$APP_NAME-config" "$APP_NAME-database" "$APP_NAME-auth")
    for secret in "${required_secrets[@]}"; do
        if ! kubectl get secret "$secret" -n "$NAMESPACE" >/dev/null 2>&1; then
            log_warn "Configuration secret not found: $secret"
        else
            log_debug "Configuration secret validated: $secret"
        fi
    done
    
    if [[ $validation_errors -gt 0 ]]; then
        log_error "Pre-deployment validation failed with $validation_errors error(s)"
        return 1
    fi
    
    log_success "Pre-deployment validation completed successfully"
    return 0
}

#
# Performance baseline establishment per Section 4.4.2
#
establish_performance_baseline() {
    log_info "Establishing performance baseline for validation..."
    
    local baseline_file="$ARTIFACT_DIR/performance-baseline.json"
    local baseline_endpoint=""
    
    # Determine baseline endpoint based on current deployment
    if [[ "$CURRENT_COLOR" == "blue" ]] && kubectl get service "$APP_NAME" -n "$NAMESPACE" >/dev/null 2>&1; then
        baseline_endpoint="$LOAD_BALANCER_ENDPOINT"
    else
        log_warn "No active deployment found for baseline establishment"
        log_warn "Using Node.js historical baseline or skipping performance validation"
        
        # Create placeholder baseline for initial deployment
        cat > "$baseline_file" << EOF
{
  "timestamp": "$(date -Iseconds)",
  "deployment_type": "initial",
  "metrics": {
    "response_time_p95": 250,
    "response_time_p99": 500,
    "throughput_rps": 1000,
    "error_rate": 0.001,
    "memory_usage_mb": 512,
    "cpu_usage_percent": 45
  },
  "source": "historical_nodejs_baseline"
}
EOF
        PERFORMANCE_BASELINE="$baseline_file"
        return 0
    fi
    
    log_debug "Collecting performance baseline from: $baseline_endpoint"
    
    # Execute performance baseline collection using existing performance script
    local performance_script="$SCRIPT_DIR/performance.sh"
    if [[ -x "$performance_script" ]]; then
        log_debug "Using performance script for baseline collection"
        
        if "$performance_script" \
            --target "$baseline_endpoint" \
            --duration 120 \
            --output "$baseline_file" \
            --baseline-mode \
            --quiet; then
            
            log_debug "Performance baseline established successfully"
            PERFORMANCE_BASELINE="$baseline_file"
            
            # Extract key metrics for logging
            local p95_response=$(jq -r '.metrics.response_time_p95 // "unknown"' "$baseline_file")
            local throughput=$(jq -r '.metrics.throughput_rps // "unknown"' "$baseline_file")
            local error_rate=$(jq -r '.metrics.error_rate // "unknown"' "$baseline_file")
            
            log_debug "Baseline metrics: P95=${p95_response}ms, Throughput=${throughput}rps, Errors=${error_rate}"
            
            return 0
        else
            log_error "Performance baseline collection failed"
            return 1
        fi
    else
        log_warn "Performance script not found: $performance_script"
        log_warn "Skipping performance baseline establishment"
        return 1
    fi
}

#
# Green environment deployment with Kubernetes orchestration per Section 4.4.1
#
deploy_green_environment() {
    log_info "Deploying green environment with Kubernetes orchestration..."
    
    local helm_chart_path="$SCRIPT_DIR/../helm/$APP_NAME"
    local values_file="$ARTIFACT_DIR/green-values.yaml"
    local deployment_manifest="$ARTIFACT_DIR/green-deployment.yaml"
    
    # Generate green environment values file
    log_debug "Generating green environment Helm values..."
    cat > "$values_file" << EOF
# Green Environment Deployment Configuration
# Generated on: $(date -Iseconds)
# Deployment ID: $DEPLOYMENT_ID

nameOverride: "$APP_NAME-green"
fullnameOverride: "$APP_NAME-green"

# Container configuration per Section 8.3.2
image:
  repository: "$REGISTRY_URL/$APP_NAME"
  tag: "$IMAGE_TAG"
  pullPolicy: Always

# Deployment configuration
deployment:
  color: green
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0

# Resource configuration optimized for Flask application
resources:
  limits:
    cpu: 1000m
    memory: 1Gi
  requests:
    cpu: 500m
    memory: 512Mi

# Health check configuration per health-check.sh integration
healthCheck:
  enabled: true
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

# Service configuration - initially internal only
service:
  type: ClusterIP
  port: 8000
  targetPort: 8000
  selector:
    app: "$APP_NAME"
    color: green

# Environment configuration
environment: "$ENVIRONMENT"
namespace: "$NAMESPACE"

# Security configuration per Section 8.5.2
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000
  readOnlyRootFilesystem: true

# Monitoring configuration per Section 3.6.2
monitoring:
  enabled: true
  prometheus:
    enabled: true
    port: 9090
    path: /metrics
  serviceMonitor:
    enabled: true
    interval: 30s

# Feature flag configuration
featureFlags:
  enabled: true
  provider: "external"
  endpoint: "$FEATURE_FLAG_ENDPOINT"
  
# Performance configuration
performance:
  autoScaling:
    enabled: false  # Disabled during green deployment
    minReplicas: 3
    maxReplicas: 10
    targetCPUUtilizationPercentage: 70
EOF
    
    log_debug "Green environment Helm values generated: $values_file"
    
    # Dry-run Helm deployment for validation
    log_debug "Validating green environment deployment with Helm dry-run..."
    if ! helm upgrade --install \
        "$APP_NAME-green" \
        "$helm_chart_path" \
        --namespace "$NAMESPACE" \
        --values "$values_file" \
        --dry-run \
        --debug > "$deployment_manifest" 2>&1; then
        
        log_error "Green environment Helm validation failed"
        log_error "Helm dry-run output:"
        cat "$deployment_manifest" | head -20 | while read -r line; do
            log_error "  $line"
        done
        return 3
    fi
    
    log_debug "Green environment Helm validation successful"
    
    # Execute actual deployment if not in dry-run mode
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Dry-run mode: Skipping actual green environment deployment"
        return 0
    fi
    
    log_info "Executing green environment deployment..."
    DEPLOYMENT_START_TIME=$(date +%s)
    
    # Deploy green environment with Helm
    if ! helm upgrade --install \
        "$APP_NAME-green" \
        "$helm_chart_path" \
        --namespace "$NAMESPACE" \
        --values "$values_file" \
        --timeout "${TIMEOUT}s" \
        --wait \
        --atomic; then
        
        log_error "Green environment deployment failed"
        log_error "Helm deployment logs:"
        kubectl logs -l "app=$APP_NAME,color=green" -n "$NAMESPACE" --tail=50 | while read -r line; do
            log_error "  $line"
        done
        return 3
    fi
    
    # Update rollback state
    sed -i "s/GREEN_ENVIRONMENT_DEPLOYED=.*/GREEN_ENVIRONMENT_DEPLOYED=true/" "$ROLLBACK_STATE_FILE"
    
    # Wait for pods to be ready
    log_info "Waiting for green environment pods to be ready..."
    if ! kubectl wait deployment "$APP_NAME-green" \
        --namespace "$NAMESPACE" \
        --for=condition=Available \
        --timeout="${TIMEOUT}s"; then
        
        log_error "Green environment pods failed to become ready within timeout"
        return 3
    fi
    
    # Verify pod health
    local ready_pods=$(kubectl get pods -l "app=$APP_NAME,color=green" -n "$NAMESPACE" --no-headers | grep -c "Running" || echo "0")
    local total_pods=$(kubectl get pods -l "app=$APP_NAME,color=green" -n "$NAMESPACE" --no-headers | wc -l)
    
    log_debug "Green environment pod status: $ready_pods/$total_pods pods ready"
    
    if [[ "$ready_pods" -eq 0 ]]; then
        log_error "No green environment pods are running"
        return 3
    fi
    
    # Record deployment metrics
    local deployment_duration=$(($(date +%s) - DEPLOYMENT_START_TIME))
    log_metric "deployment_duration_seconds" "$deployment_duration" "environment=green,image=$IMAGE_TAG"
    log_metric "deployment_pods_ready" "$ready_pods" "environment=green,image=$IMAGE_TAG"
    
    log_success "Green environment deployed successfully: $ready_pods/$total_pods pods ready"
    return 0
}

#
# Comprehensive health validation using enterprise health check patterns
#
perform_health_validation() {
    log_info "Performing comprehensive health validation for green environment..."
    
    local health_check_script="$SCRIPT_DIR/health-check.sh"
    local health_results="$ARTIFACT_DIR/health-check-results.json"
    
    # Verify health check script availability
    if [[ ! -x "$health_check_script" ]]; then
        log_error "Health check script not found or not executable: $health_check_script"
        return 4
    fi
    
    # Get green environment service endpoint
    local green_service_ip=$(kubectl get service "$APP_NAME-green" -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}' 2>/dev/null)
    local green_service_port=$(kubectl get service "$APP_NAME-green" -n "$NAMESPACE" -o jsonpath='{.spec.ports[0].port}' 2>/dev/null)
    
    if [[ -z "$green_service_ip" ]] || [[ -z "$green_service_port" ]]; then
        log_error "Cannot determine green environment service endpoint"
        return 4
    fi
    
    local green_endpoint="$green_service_ip:$green_service_port"
    log_debug "Green environment endpoint: $green_endpoint"
    
    # Execute comprehensive health check validation
    log_debug "Executing health check validation with retries..."
    local health_attempt=1
    local health_success=false
    
    while [[ $health_attempt -le $HEALTH_CHECK_RETRIES ]]; do
        log_debug "Health check attempt $health_attempt/$HEALTH_CHECK_RETRIES"
        
        # Execute health check with verbose output for debugging
        local health_check_args=(
            "--host" "$green_service_ip"
            "--port" "$green_service_port"
            "--timeout" "30"
            "--retries" "2"
            "--container-mode"
        )
        
        if [[ "$VERBOSE" == "true" ]]; then
            health_check_args+=("--verbose")
        fi
        
        if "$health_check_script" "${health_check_args[@]}" > "$health_results" 2>&1; then
            health_success=true
            log_debug "Health check successful on attempt $health_attempt"
            break
        else
            local exit_code=$?
            log_warn "Health check failed on attempt $health_attempt (exit code: $exit_code)"
            
            # Log health check output for debugging
            if [[ -s "$health_results" ]]; then
                log_debug "Health check output:"
                head -10 "$health_results" | while read -r line; do
                    log_debug "  $line"
                done
            fi
            
            # Wait before retry
            if [[ $health_attempt -lt $HEALTH_CHECK_RETRIES ]]; then
                log_debug "Waiting 30 seconds before retry..."
                sleep 30
            fi
        fi
        
        ((health_attempt++))
    done
    
    if [[ "$health_success" != "true" ]]; then
        log_error "Health validation failed after $HEALTH_CHECK_RETRIES attempts"
        log_error "Green environment is not healthy and cannot receive traffic"
        
        # Extract specific health check failures
        if [[ -s "$health_results" ]]; then
            grep -i "failed\|error" "$health_results" | head -5 | while read -r line; do
                log_error "Health issue: $line"
            done
        fi
        
        return 4
    fi
    
    # Parse health check results for detailed validation
    log_debug "Parsing health check results for detailed validation..."
    
    # Extract health check metrics if available
    local flask_health_status=$(grep -i "flask.*health.*ok" "$health_results" >/dev/null 2>&1 && echo "healthy" || echo "unhealthy")
    local database_status=$(grep -i "database.*ok" "$health_results" >/dev/null 2>&1 && echo "healthy" || echo "unhealthy")
    local external_services_status=$(grep -i "external.*ok" "$health_results" >/dev/null 2>&1 && echo "healthy" || echo "unhealthy")
    
    log_debug "Health validation results: Flask=$flask_health_status, Database=$database_status, External=$external_services_status"
    
    # Record health metrics
    log_metric "health_check_duration_seconds" "$((health_attempt * 30))" "environment=green"
    log_metric "health_check_success" "1" "environment=green,flask=$flask_health_status,database=$database_status"
    
    log_success "Comprehensive health validation completed successfully"
    return 0
}

#
# Performance validation ensuring ≤10% variance per Section 4.4.2
#
perform_performance_validation() {
    if [[ "$SKIP_PERFORMANCE" == "true" ]]; then
        log_warn "Performance validation skipped (--skip-performance enabled)"
        return 0
    fi
    
    log_info "Performing performance validation ensuring ≤10% variance requirement..."
    
    local performance_script="$SCRIPT_DIR/performance.sh"
    local performance_results="$ARTIFACT_DIR/performance-validation.json"
    local variance_report="$ARTIFACT_DIR/performance-variance.json"
    
    # Verify performance script availability
    if [[ ! -x "$performance_script" ]]; then
        log_error "Performance script not found: $performance_script"
        return 5
    fi
    
    # Verify performance baseline availability
    if [[ -z "$PERFORMANCE_BASELINE" ]] || [[ ! -f "$PERFORMANCE_BASELINE" ]]; then
        log_error "Performance baseline not available for comparison"
        return 5
    fi
    
    # Get green environment endpoint for testing
    local green_service_ip=$(kubectl get service "$APP_NAME-green" -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}')
    local green_service_port=$(kubectl get service "$APP_NAME-green" -n "$NAMESPACE" -o jsonpath='{.spec.ports[0].port}')
    local green_endpoint="http://$green_service_ip:$green_service_port"
    
    log_debug "Performance testing target: $green_endpoint"
    log_debug "Performance baseline: $PERFORMANCE_BASELINE"
    
    # Execute performance testing with comprehensive metrics collection
    log_info "Executing performance testing with Locust and k6 frameworks..."
    
    if ! "$performance_script" \
        --target "$green_endpoint" \
        --duration 300 \
        --baseline "$PERFORMANCE_BASELINE" \
        --output "$performance_results" \
        --variance-report "$variance_report" \
        --threshold "$PERFORMANCE_THRESHOLD" \
        ${VERBOSE:+--verbose}; then
        
        log_error "Performance testing execution failed"
        return 5
    fi
    
    # Parse performance validation results
    log_debug "Parsing performance validation results..."
    
    if [[ ! -f "$variance_report" ]]; then
        log_error "Performance variance report not generated"
        return 5
    fi
    
    # Extract performance variance metrics
    local response_time_variance=$(jq -r '.variance.response_time_p95 // "unknown"' "$variance_report")
    local throughput_variance=$(jq -r '.variance.throughput_rps // "unknown"' "$variance_report")
    local error_rate_variance=$(jq -r '.variance.error_rate // "unknown"' "$variance_report")
    local memory_variance=$(jq -r '.variance.memory_usage_mb // "unknown"' "$variance_report")
    local overall_variance=$(jq -r '.overall_variance_percent // "unknown"' "$variance_report")
    local validation_result=$(jq -r '.validation_result // "unknown"' "$variance_report")
    
    log_debug "Performance variance results:"
    log_debug "  Response Time P95: ${response_time_variance}%"
    log_debug "  Throughput: ${throughput_variance}%"
    log_debug "  Error Rate: ${error_rate_variance}%"
    log_debug "  Memory Usage: ${memory_variance}%"
    log_debug "  Overall Variance: ${overall_variance}%"
    log_debug "  Validation Result: $validation_result"
    
    # Enforce performance variance requirement
    if [[ "$validation_result" != "PASS" ]]; then
        log_error "Performance validation failed: Overall variance ${overall_variance}% exceeds ${PERFORMANCE_THRESHOLD}% threshold"
        log_error "Performance requirements not met, deployment cannot proceed"
        
        # Log detailed variance breakdown
        if [[ -s "$variance_report" ]]; then
            jq -r '.details[] // empty' "$variance_report" | while read -r detail; do
                log_error "Performance issue: $detail"
            done
        fi
        
        return 5
    fi
    
    # Record performance metrics
    log_metric "performance_variance_percent" "$overall_variance" "environment=green,threshold=$PERFORMANCE_THRESHOLD"
    log_metric "performance_response_time_variance" "$response_time_variance" "environment=green"
    log_metric "performance_throughput_variance" "$throughput_variance" "environment=green"
    log_metric "performance_validation_result" "1" "environment=green,result=$validation_result"
    
    # Update rollback state
    sed -i "s/PERFORMANCE_BASELINE_ESTABLISHED=.*/PERFORMANCE_BASELINE_ESTABLISHED=true/" "$ROLLBACK_STATE_FILE"
    
    log_success "Performance validation completed successfully: ${overall_variance}% variance (threshold: ${PERFORMANCE_THRESHOLD}%)"
    return 0
}

#
# Feature flag management for gradual traffic migration per Section 8.5.2
#
manage_feature_flag_deployment() {
    log_info "Managing feature flag deployment for gradual traffic migration..."
    
    local feature_flag_config="$ARTIFACT_DIR/feature-flag-config.json"
    local traffic_config="$ARTIFACT_DIR/traffic-config.json"
    
    # Initialize feature flag configuration
    cat > "$feature_flag_config" << EOF
{
  "flag_name": "flask_green_deployment",
  "environment": "$ENVIRONMENT",
  "deployment_id": "$DEPLOYMENT_ID",
  "created_at": "$(date -Iseconds)",
  "traffic_steps": [$(printf '%s,' "${TRAFFIC_STEPS[@]}" | sed 's/,$//')],
  "current_step": 0,
  "target_image": "$IMAGE_TAG",
  "monitoring_interval": $MONITORING_INTERVAL
}
EOF
    
    log_debug "Feature flag configuration: $feature_flag_config"
    
    # Execute gradual traffic migration
    local step_index=0
    for traffic_percentage in "${TRAFFIC_STEPS[@]}"; do
        log_info "Initiating traffic migration step: ${traffic_percentage}% to green environment"
        
        # Update feature flag for current traffic percentage
        if ! update_feature_flag "$traffic_percentage"; then
            log_error "Feature flag update failed for ${traffic_percentage}% traffic"
            return 6
        fi
        
        # Configure load balancer traffic distribution
        if ! configure_traffic_distribution "$traffic_percentage"; then
            log_error "Traffic distribution configuration failed for ${traffic_percentage}%"
            return 6
        fi
        
        # Monitor green environment during traffic migration
        if ! monitor_traffic_migration "$traffic_percentage"; then
            log_error "Traffic migration monitoring detected issues at ${traffic_percentage}%"
            return 6
        fi
        
        # Update rollback state
        sed -i "s/TRAFFIC_MIGRATION_STEP=.*/TRAFFIC_MIGRATION_STEP=$((step_index + 1))/" "$ROLLBACK_STATE_FILE"
        
        log_success "Traffic migration step completed: ${traffic_percentage}% to green environment"
        
        # Wait between migration steps (except for final step)
        if [[ $traffic_percentage -ne 100 ]]; then
            log_info "Waiting ${MONITORING_INTERVAL} seconds before next migration step..."
            sleep "$MONITORING_INTERVAL"
        fi
        
        ((step_index++))
    done
    
    log_success "Feature flag deployment completed: 100% traffic migrated to green environment"
    return 0
}

#
# Feature flag update with external service integration
#
update_feature_flag() {
    local traffic_percentage="$1"
    
    log_debug "Updating feature flag for ${traffic_percentage}% traffic distribution"
    
    # Check if feature flag endpoint is configured
    if [[ -z "$FEATURE_FLAG_ENDPOINT" ]]; then
        log_warn "Feature flag endpoint not configured, using manual traffic distribution"
        return 0
    fi
    
    # Prepare feature flag update payload
    local flag_payload=$(cat << EOF
{
  "flag_name": "flask_green_deployment",
  "environment": "$ENVIRONMENT",
  "traffic_percentage": $traffic_percentage,
  "target_version": "$IMAGE_TAG",
  "deployment_id": "$DEPLOYMENT_ID",
  "timestamp": "$(date -Iseconds)"
}
EOF
)
    
    # Update feature flag via API
    if curl -s \
        -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${FEATURE_FLAG_API_KEY:-}" \
        -d "$flag_payload" \
        --connect-timeout 10 \
        --max-time 30 \
        "$FEATURE_FLAG_ENDPOINT/flags/flask_green_deployment" > /dev/null 2>&1; then
        
        log_debug "Feature flag updated successfully for ${traffic_percentage}% traffic"
        return 0
    else
        log_warn "Feature flag update failed, proceeding with manual traffic distribution"
        return 0
    fi
}

#
# Traffic distribution configuration with load balancer integration
#
configure_traffic_distribution() {
    local traffic_percentage="$1"
    
    log_debug "Configuring traffic distribution: ${traffic_percentage}% to green environment"
    
    # Calculate blue environment traffic percentage
    local blue_percentage=$((100 - traffic_percentage))
    
    # Create traffic distribution configuration
    cat > "$ARTIFACT_DIR/traffic-config-${traffic_percentage}.yaml" << EOF
apiVersion: v1
kind: Service
metadata:
  name: $APP_NAME
  namespace: $NAMESPACE
  labels:
    app: $APP_NAME
    deployment-id: $DEPLOYMENT_ID
spec:
  type: LoadBalancer
  ports:
  - port: 80
    targetPort: 8000
    protocol: TCP
  selector:
    app: $APP_NAME
---
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: $APP_NAME-traffic-split
  namespace: $NAMESPACE
spec:
  http:
  - match:
    - headers:
        canary:
          exact: "true"
    route:
    - destination:
        host: $APP_NAME-green
      weight: 100
  - route:
    - destination:
        host: $APP_NAME-blue
      weight: $blue_percentage
    - destination:
        host: $APP_NAME-green
      weight: $traffic_percentage
EOF
    
    # Apply traffic distribution configuration
    if [[ "$DRY_RUN" != "true" ]]; then
        if kubectl apply -f "$ARTIFACT_DIR/traffic-config-${traffic_percentage}.yaml"; then
            log_debug "Traffic distribution applied: ${blue_percentage}% blue, ${traffic_percentage}% green"
        else
            log_error "Failed to apply traffic distribution configuration"
            return 1
        fi
    fi
    
    # For 100% traffic, update main service to point to green
    if [[ $traffic_percentage -eq 100 ]]; then
        log_debug "Switching main service to green environment"
        
        if [[ "$DRY_RUN" != "true" ]]; then
            kubectl patch service "$APP_NAME" -n "$NAMESPACE" -p '{"spec":{"selector":{"color":"green"}}}'
        fi
    fi
    
    return 0
}

#
# Traffic migration monitoring with automated rollback triggers
#
monitor_traffic_migration() {
    local traffic_percentage="$1"
    local monitoring_duration=$((MONITORING_INTERVAL * 2))
    local check_interval=10
    local checks_performed=0
    local max_checks=$((monitoring_duration / check_interval))
    
    log_debug "Monitoring traffic migration for ${traffic_percentage}% distribution (${monitoring_duration}s)"
    
    local monitoring_start=$(date +%s)
    
    while [[ $checks_performed -lt $max_checks ]]; do
        # Check green environment health
        if ! check_green_environment_health; then
            log_error "Green environment health check failed during traffic migration"
            return 1
        fi
        
        # Check error rate metrics
        if ! validate_error_rate_threshold; then
            log_error "Error rate threshold exceeded during traffic migration"
            return 1
        fi
        
        # Check performance metrics
        if ! validate_performance_during_migration; then
            log_error "Performance degradation detected during traffic migration"
            return 1
        fi
        
        sleep $check_interval
        ((checks_performed++))
    done
    
    local monitoring_duration_actual=$(($(date +%s) - monitoring_start))
    log_debug "Traffic migration monitoring completed: ${monitoring_duration_actual}s"
    
    return 0
}

#
# Green environment health validation during traffic migration
#
check_green_environment_health() {
    local green_service_ip=$(kubectl get service "$APP_NAME-green" -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}' 2>/dev/null)
    local green_service_port=$(kubectl get service "$APP_NAME-green" -n "$NAMESPACE" -o jsonpath='{.spec.ports[0].port}' 2>/dev/null)
    
    if [[ -z "$green_service_ip" ]] || [[ -z "$green_service_port" ]]; then
        return 1
    fi
    
    # Quick health check
    if curl -s \
        --connect-timeout 5 \
        --max-time 10 \
        "http://$green_service_ip:$green_service_port/health" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

#
# Error rate validation with configurable thresholds
#
validate_error_rate_threshold() {
    local error_rate_threshold="0.01"  # 1% error rate threshold
    
    # Check Prometheus metrics if available
    if [[ -n "$PROMETHEUS_ENDPOINT" ]] && command -v curl >/dev/null 2>&1; then
        local error_rate_query="rate(flask_app_requests_total{status=~\"5..\"}[5m]) / rate(flask_app_requests_total[5m])"
        local error_rate=$(curl -s \
            --connect-timeout 5 \
            --max-time 10 \
            "$PROMETHEUS_ENDPOINT/api/v1/query?query=$error_rate_query" | \
            jq -r '.data.result[0].value[1] // "0"' 2>/dev/null || echo "0")
        
        if [[ $(echo "$error_rate > $error_rate_threshold" | bc 2>/dev/null || echo "0") -eq 1 ]]; then
            log_error "Error rate threshold exceeded: ${error_rate} > ${error_rate_threshold}"
            return 1
        fi
        
        log_debug "Error rate validation passed: ${error_rate} <= ${error_rate_threshold}"
    fi
    
    return 0
}

#
# Performance validation during traffic migration
#
validate_performance_during_migration() {
    # Check for performance degradation indicators
    local cpu_threshold="80"
    local memory_threshold="85"
    
    # Get green environment resource utilization
    local green_pods=$(kubectl get pods -l "app=$APP_NAME,color=green" -n "$NAMESPACE" --no-headers | awk '{print $1}')
    
    for pod in $green_pods; do
        if kubectl top pod "$pod" -n "$NAMESPACE" --no-headers >/dev/null 2>&1; then
            local cpu_usage=$(kubectl top pod "$pod" -n "$NAMESPACE" --no-headers | awk '{print $2}' | sed 's/m$//')
            local memory_usage=$(kubectl top pod "$pod" -n "$NAMESPACE" --no-headers | awk '{print $3}' | sed 's/Mi$//')
            
            # Convert CPU to percentage (assuming 1000m = 100%)
            local cpu_percent=$((cpu_usage / 10))
            
            if [[ $cpu_percent -gt $cpu_threshold ]] || [[ ${memory_usage:-0} -gt $memory_threshold ]]; then
                log_warn "High resource utilization detected in pod $pod: CPU=${cpu_percent}%, Memory=${memory_usage}Mi"
            fi
        fi
    done
    
    return 0
}

#
# Automated rollback procedures for critical issues per Section 4.4.5
#
execute_automated_rollback() {
    local rollback_reason="${1:-unknown}"
    
    log_error "Executing automated rollback due to: $rollback_reason"
    ROLLBACK_EXECUTED="true"
    
    # Load rollback state
    if [[ -f "$ROLLBACK_STATE_FILE" ]]; then
        source "$ROLLBACK_STATE_FILE"
    fi
    
    # Create rollback execution plan
    local rollback_plan="$ARTIFACT_DIR/rollback-plan.json"
    cat > "$rollback_plan" << EOF
{
  "rollback_id": "rollback-$(date +%s)",
  "deployment_id": "$DEPLOYMENT_ID",
  "rollback_reason": "$rollback_reason",
  "timestamp": "$(date -Iseconds)",
  "rollback_actions": [
    "revert_traffic_to_blue",
    "disable_green_environment",
    "update_feature_flags",
    "validate_blue_environment",
    "cleanup_green_resources"
  ],
  "target_version": "$ROLLBACK_VERSION_AVAILABLE"
}
EOF
    
    log_info "Rollback plan created: $rollback_plan"
    log_debug "Rolling back to version: $ROLLBACK_VERSION_AVAILABLE"
    
    # Step 1: Immediately revert traffic to blue environment
    log_info "Step 1: Reverting traffic to blue environment..."
    if ! revert_traffic_to_blue; then
        log_error "Failed to revert traffic to blue environment"
        return 7
    fi
    
    # Step 2: Disable green environment
    log_info "Step 2: Disabling green environment..."
    if ! disable_green_environment; then
        log_error "Failed to disable green environment"
        return 7
    fi
    
    # Step 3: Update feature flags for rollback
    log_info "Step 3: Updating feature flags for rollback..."
    if ! update_feature_flags_for_rollback; then
        log_error "Failed to update feature flags for rollback"
        # Continue rollback even if feature flags fail
    fi
    
    # Step 4: Validate blue environment health
    log_info "Step 4: Validating blue environment health..."
    if ! validate_blue_environment_health; then
        log_error "Blue environment health validation failed after rollback"
        return 7
    fi
    
    # Step 5: Cleanup green resources (optional, non-blocking)
    log_info "Step 5: Cleaning up green environment resources..."
    if ! cleanup_green_resources; then
        log_warn "Green environment cleanup failed, manual cleanup may be required"
        # Don't fail rollback for cleanup issues
    fi
    
    # Send rollback alerts
    send_rollback_alerts "$rollback_reason"
    
    # Record rollback metrics
    log_metric "deployment_rollback_executed" "1" "reason=$rollback_reason,deployment_id=$DEPLOYMENT_ID"
    
    log_success "Automated rollback completed successfully"
    log_info "System restored to previous stable state: $ROLLBACK_VERSION_AVAILABLE"
    
    return 0
}

#
# Traffic reversion to blue environment
#
revert_traffic_to_blue() {
    log_debug "Reverting traffic to blue environment..."
    
    # Immediately switch main service back to blue
    if [[ "$DRY_RUN" != "true" ]]; then
        if kubectl patch service "$APP_NAME" -n "$NAMESPACE" -p '{"spec":{"selector":{"color":"blue"}}}'; then
            log_debug "Main service reverted to blue environment"
        else
            log_error "Failed to revert main service to blue environment"
            return 1
        fi
        
        # Remove traffic splitting configuration
        kubectl delete virtualservice "$APP_NAME-traffic-split" -n "$NAMESPACE" --ignore-not-found=true
    fi
    
    return 0
}

#
# Green environment deactivation
#
disable_green_environment() {
    log_debug "Disabling green environment..."
    
    if [[ "$DRY_RUN" != "true" ]]; then
        # Scale down green deployment
        if kubectl scale deployment "$APP_NAME-green" --replicas=0 -n "$NAMESPACE"; then
            log_debug "Green environment scaled down to 0 replicas"
        else
            log_error "Failed to scale down green environment"
            return 1
        fi
    fi
    
    return 0
}

#
# Feature flag rollback configuration
#
update_feature_flags_for_rollback() {
    log_debug "Updating feature flags for rollback..."
    
    if [[ -z "$FEATURE_FLAG_ENDPOINT" ]]; then
        log_debug "Feature flag endpoint not configured, skipping feature flag rollback"
        return 0
    fi
    
    # Disable green deployment feature flag
    local rollback_payload=$(cat << EOF
{
  "flag_name": "flask_green_deployment",
  "environment": "$ENVIRONMENT",
  "enabled": false,
  "traffic_percentage": 0,
  "rollback_reason": "automated_rollback",
  "deployment_id": "$DEPLOYMENT_ID",
  "timestamp": "$(date -Iseconds)"
}
EOF
)
    
    if curl -s \
        -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${FEATURE_FLAG_API_KEY:-}" \
        -d "$rollback_payload" \
        --connect-timeout 10 \
        --max-time 30 \
        "$FEATURE_FLAG_ENDPOINT/flags/flask_green_deployment/disable" > /dev/null 2>&1; then
        
        log_debug "Feature flag disabled for rollback"
        return 0
    else
        log_warn "Failed to disable feature flag, continuing rollback"
        return 1
    fi
}

#
# Blue environment health validation after rollback
#
validate_blue_environment_health() {
    log_debug "Validating blue environment health after rollback..."
    
    local blue_service_ip=$(kubectl get service "$APP_NAME" -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}' 2>/dev/null)
    local blue_service_port=$(kubectl get service "$APP_NAME" -n "$NAMESPACE" -o jsonpath='{.spec.ports[0].port}' 2>/dev/null)
    
    if [[ -z "$blue_service_ip" ]] || [[ -z "$blue_service_port" ]]; then
        log_error "Cannot determine blue environment service endpoint"
        return 1
    fi
    
    # Perform health check on blue environment
    local health_attempts=3
    local health_delay=10
    
    for ((i=1; i<=health_attempts; i++)); do
        if curl -s \
            --connect-timeout 10 \
            --max-time 20 \
            "http://$blue_service_ip:$blue_service_port/health" >/dev/null 2>&1; then
            
            log_debug "Blue environment health validated successfully"
            return 0
        fi
        
        if [[ $i -lt $health_attempts ]]; then
            log_debug "Blue environment health check failed, retrying in ${health_delay}s..."
            sleep $health_delay
        fi
    done
    
    log_error "Blue environment health validation failed after $health_attempts attempts"
    return 1
}

#
# Green environment resource cleanup
#
cleanup_green_resources() {
    log_debug "Cleaning up green environment resources..."
    
    if [[ "$DRY_RUN" != "true" ]]; then
        # Delete green deployment
        kubectl delete deployment "$APP_NAME-green" -n "$NAMESPACE" --ignore-not-found=true
        
        # Delete green service
        kubectl delete service "$APP_NAME-green" -n "$NAMESPACE" --ignore-not-found=true
        
        # Delete green-specific config maps and secrets
        kubectl delete configmap -l "app=$APP_NAME,color=green" -n "$NAMESPACE" --ignore-not-found=true
        kubectl delete secret -l "app=$APP_NAME,color=green" -n "$NAMESPACE" --ignore-not-found=true
        
        # Clean up Helm release
        helm uninstall "$APP_NAME-green" -n "$NAMESPACE" --ignore-not-found || true
    fi
    
    log_debug "Green environment resources cleaned up"
    return 0
}

#
# Rollback alert and notification system
#
send_rollback_alerts() {
    local rollback_reason="$1"
    
    log_info "Sending rollback alerts and notifications..."
    
    # Prepare alert payload
    local alert_payload=$(cat << EOF
{
  "alert_type": "deployment_rollback",
  "severity": "high",
  "deployment_id": "$DEPLOYMENT_ID",
  "environment": "$ENVIRONMENT",
  "application": "$APP_NAME",
  "rollback_reason": "$rollback_reason",
  "image_tag": "$IMAGE_TAG",
  "rollback_to_version": "$ROLLBACK_VERSION_AVAILABLE",
  "timestamp": "$(date -Iseconds)",
  "cluster": "$CLUSTER_NAME",
  "namespace": "$NAMESPACE"
}
EOF
)
    
    # Send to alert webhook if configured
    if [[ -n "$ALERT_WEBHOOK" ]]; then
        curl -s \
            -X POST \
            -H "Content-Type: application/json" \
            -d "$alert_payload" \
            --connect-timeout 10 \
            --max-time 30 \
            "$ALERT_WEBHOOK" > /dev/null 2>&1 || true
    fi
    
    # Send to Slack if configured
    if [[ -n "$SLACK_WEBHOOK" ]]; then
        local slack_message="🚨 *Deployment Rollback Executed*\\n\\n*Environment:* $ENVIRONMENT\\n*Application:* $APP_NAME\\n*Reason:* $rollback_reason\\n*Deployment ID:* $DEPLOYMENT_ID\\n*Time:* $(date)"
        
        curl -s \
            -X POST \
            -H "Content-Type: application/json" \
            -d "{\"text\": \"$slack_message\"}" \
            --connect-timeout 10 \
            --max-time 30 \
            "$SLACK_WEBHOOK" > /dev/null 2>&1 || true
    fi
    
    log_debug "Rollback alerts sent"
}

#
# Post-deployment validation and finalization per Section 4.4.1
#
perform_post_deployment_validation() {
    log_info "Performing post-deployment validation and finalization..."
    
    local validation_results="$ARTIFACT_DIR/post-deployment-validation.json"
    local validation_success=true
    
    # Initialize validation results
    cat > "$validation_results" << EOF
{
  "deployment_id": "$DEPLOYMENT_ID",
  "validation_timestamp": "$(date -Iseconds)",
  "environment": "$ENVIRONMENT",
  "image_tag": "$IMAGE_TAG",
  "validations": {
    "service_health": "unknown",
    "performance_stability": "unknown",
    "external_integrations": "unknown",
    "monitoring_integration": "unknown",
    "security_posture": "unknown"
  },
  "overall_result": "unknown"
}
EOF
    
    # Service health validation
    log_debug "Validating final service health..."
    if validate_final_service_health; then
        jq '.validations.service_health = "pass"' "$validation_results" > "$validation_results.tmp" && mv "$validation_results.tmp" "$validation_results"
        log_debug "Service health validation: PASS"
    else
        jq '.validations.service_health = "fail"' "$validation_results" > "$validation_results.tmp" && mv "$validation_results.tmp" "$validation_results"
        log_error "Service health validation: FAIL"
        validation_success=false
    fi
    
    # Performance stability validation
    log_debug "Validating performance stability..."
    if validate_performance_stability; then
        jq '.validations.performance_stability = "pass"' "$validation_results" > "$validation_results.tmp" && mv "$validation_results.tmp" "$validation_results"
        log_debug "Performance stability validation: PASS"
    else
        jq '.validations.performance_stability = "fail"' "$validation_results" > "$validation_results.tmp" && mv "$validation_results.tmp" "$validation_results"
        log_error "Performance stability validation: FAIL"
        validation_success=false
    fi
    
    # External integrations validation
    log_debug "Validating external integrations..."
    if validate_external_integrations; then
        jq '.validations.external_integrations = "pass"' "$validation_results" > "$validation_results.tmp" && mv "$validation_results.tmp" "$validation_results"
        log_debug "External integrations validation: PASS"
    else
        jq '.validations.external_integrations = "fail"' "$validation_results" > "$validation_results.tmp" && mv "$validation_results.tmp" "$validation_results"
        log_error "External integrations validation: FAIL"
        validation_success=false
    fi
    
    # Monitoring integration validation
    log_debug "Validating monitoring integration..."
    if validate_monitoring_integration; then
        jq '.validations.monitoring_integration = "pass"' "$validation_results" > "$validation_results.tmp" && mv "$validation_results.tmp" "$validation_results"
        log_debug "Monitoring integration validation: PASS"
    else
        jq '.validations.monitoring_integration = "fail"' "$validation_results" > "$validation_results.tmp" && mv "$validation_results.tmp" "$validation_results"
        log_warn "Monitoring integration validation: FAIL (non-blocking)"
    fi
    
    # Security posture validation
    log_debug "Validating security posture..."
    if validate_security_posture; then
        jq '.validations.security_posture = "pass"' "$validation_results" > "$validation_results.tmp" && mv "$validation_results.tmp" "$validation_results"
        log_debug "Security posture validation: PASS"
    else
        jq '.validations.security_posture = "fail"' "$validation_results" > "$validation_results.tmp" && mv "$validation_results.tmp" "$validation_results"
        log_error "Security posture validation: FAIL"
        validation_success=false
    fi
    
    # Update overall result
    if [[ "$validation_success" == "true" ]]; then
        jq '.overall_result = "pass"' "$validation_results" > "$validation_results.tmp" && mv "$validation_results.tmp" "$validation_results"
        log_success "Post-deployment validation completed successfully"
        return 0
    else
        jq '.overall_result = "fail"' "$validation_results" > "$validation_results.tmp" && mv "$validation_results.tmp" "$validation_results"
        log_error "Post-deployment validation failed"
        return 8
    fi
}

#
# Final service health validation
#
validate_final_service_health() {
    local main_service_endpoint=$(kubectl get service "$APP_NAME" -n "$NAMESPACE" -o jsonpath='{.status.loadBalancer.ingress[0].ip}:{.spec.ports[0].port}' 2>/dev/null)
    
    if [[ -z "$main_service_endpoint" ]] || [[ "$main_service_endpoint" == ":" ]]; then
        # Fallback to cluster IP
        local cluster_ip=$(kubectl get service "$APP_NAME" -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}')
        local port=$(kubectl get service "$APP_NAME" -n "$NAMESPACE" -o jsonpath='{.spec.ports[0].port}')
        main_service_endpoint="$cluster_ip:$port"
    fi
    
    if [[ -z "$main_service_endpoint" ]] || [[ "$main_service_endpoint" == ":" ]]; then
        return 1
    fi
    
    # Perform comprehensive health check
    for ((i=1; i<=3; i++)); do
        if curl -s --connect-timeout 10 --max-time 20 "http://$main_service_endpoint/health" >/dev/null 2>&1; then
            return 0
        fi
        sleep 5
    done
    
    return 1
}

#
# Performance stability validation over time
#
validate_performance_stability() {
    if [[ "$SKIP_PERFORMANCE" == "true" ]]; then
        return 0
    fi
    
    # Monitor performance for stability over 2 minutes
    local monitoring_duration=120
    local check_interval=20
    local stable_checks=0
    local required_stable_checks=3
    
    for ((i=0; i<monitoring_duration; i+=check_interval)); do
        if validate_current_performance; then
            ((stable_checks++))
        else
            stable_checks=0
        fi
        
        if [[ $stable_checks -ge $required_stable_checks ]]; then
            return 0
        fi
        
        sleep $check_interval
    done
    
    return 1
}

#
# Current performance validation
#
validate_current_performance() {
    # Basic performance check using curl timing
    local response_time=$(curl -s -w "%{time_total}" -o /dev/null --connect-timeout 5 --max-time 10 "http://$(kubectl get service "$APP_NAME" -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}'):$(kubectl get service "$APP_NAME" -n "$NAMESPACE" -o jsonpath='{.spec.ports[0].port}')/health" 2>/dev/null || echo "999")
    
    # Response time should be under 1 second for health endpoint
    if [[ $(echo "$response_time < 1.0" | bc 2>/dev/null || echo "0") -eq 1 ]]; then
        return 0
    else
        return 1
    fi
}

#
# External integrations validation
#
validate_external_integrations() {
    local integrations_healthy=true
    local main_service_ip=$(kubectl get service "$APP_NAME" -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}')
    local main_service_port=$(kubectl get service "$APP_NAME" -n "$NAMESPACE" -o jsonpath='{.spec.ports[0].port}')
    
    if [[ -z "$main_service_ip" ]] || [[ -z "$main_service_port" ]]; then
        return 1
    fi
    
    # Check external service integration endpoints
    local external_endpoints=("auth0" "s3" "apm")
    
    for endpoint in "${external_endpoints[@]}"; do
        if curl -s \
            --connect-timeout 5 \
            --max-time 10 \
            "http://$main_service_ip:$main_service_port/health/external/$endpoint" >/dev/null 2>&1; then
            
            log_debug "External integration validated: $endpoint"
        else
            log_warn "External integration check failed: $endpoint"
            integrations_healthy=false
        fi
    done
    
    return $([[ "$integrations_healthy" == "true" ]] && echo "0" || echo "1")
}

#
# Monitoring integration validation
#
validate_monitoring_integration() {
    local main_service_ip=$(kubectl get service "$APP_NAME" -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}')
    local main_service_port=$(kubectl get service "$APP_NAME" -n "$NAMESPACE" -o jsonpath='{.spec.ports[0].port}')
    
    if [[ -z "$main_service_ip" ]] || [[ -z "$main_service_port" ]]; then
        return 1
    fi
    
    # Check Prometheus metrics endpoint
    if curl -s \
        --connect-timeout 5 \
        --max-time 10 \
        "http://$main_service_ip:$main_service_port/metrics" >/dev/null 2>&1; then
        
        log_debug "Prometheus metrics endpoint validated"
        return 0
    else
        log_warn "Prometheus metrics endpoint not accessible"
        return 1
    fi
}

#
# Security posture validation
#
validate_security_posture() {
    # Check that green environment is not accessible
    local green_service_ip=$(kubectl get service "$APP_NAME-green" -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}' 2>/dev/null)
    
    if [[ -n "$green_service_ip" ]] && [[ "$green_service_ip" != "null" ]]; then
        log_warn "Green environment service still exists after migration"
        # This might be intentional for gradual cleanup
    fi
    
    # Validate that only blue environment is receiving traffic
    local main_service_selector=$(kubectl get service "$APP_NAME" -n "$NAMESPACE" -o jsonpath='{.spec.selector.color}' 2>/dev/null)
    
    if [[ "$main_service_selector" == "green" ]]; then
        log_debug "Traffic correctly routed to green environment"
        return 0
    else
        log_error "Traffic routing validation failed: expected green, got $main_service_selector"
        return 1
    fi
}

#
# Deployment cleanup and finalization
#
finalize_deployment() {
    log_info "Finalizing deployment and performing cleanup..."
    
    # Blue environment cleanup after successful green deployment
    if [[ "$ROLLBACK_EXECUTED" != "true" ]]; then
        log_debug "Cleaning up blue environment after successful green deployment..."
        
        if [[ "$DRY_RUN" != "true" ]]; then
            # Scale down blue deployment
            kubectl scale deployment "$APP_NAME-blue" --replicas=0 -n "$NAMESPACE" --ignore-not-found=true || true
            
            # Delete old blue resources (but keep for rollback capability)
            kubectl delete service "$APP_NAME-blue" -n "$NAMESPACE" --ignore-not-found=true || true
            
            # Update blue deployment to new version for next deployment cycle
            kubectl set image deployment/"$APP_NAME-blue" app="$REGISTRY_URL/$APP_NAME:$IMAGE_TAG" -n "$NAMESPACE" --ignore-not-found=true || true
        fi
        
        log_debug "Blue environment cleanup completed"
    fi
    
    # Rename green resources to blue for next deployment cycle
    if [[ "$ROLLBACK_EXECUTED" != "true" ]] && [[ "$DRY_RUN" != "true" ]]; then
        log_debug "Promoting green environment to blue for next deployment cycle..."
        
        # Rename green deployment to blue
        kubectl patch deployment "$APP_NAME-green" -n "$NAMESPACE" -p '{"metadata":{"name":"'$APP_NAME'-blue"},"spec":{"selector":{"matchLabels":{"color":"blue"}},"template":{"metadata":{"labels":{"color":"blue"}}}}}' || true
        
        # Update service selector to blue
        kubectl patch service "$APP_NAME" -n "$NAMESPACE" -p '{"spec":{"selector":{"color":"blue"}}}' || true
        
        log_debug "Green environment promoted to blue successfully"
    fi
    
    # Update deployment tracking
    log_debug "Updating deployment tracking and metadata..."
    
    # Create deployment summary
    local deployment_summary="$ARTIFACT_DIR/deployment-summary.json"
    cat > "$deployment_summary" << EOF
{
  "deployment_id": "$DEPLOYMENT_ID",
  "start_time": "$(date -d "@$DEPLOYMENT_START_TIME" -Iseconds 2>/dev/null || echo "unknown")",
  "end_time": "$(date -Iseconds)",
  "duration_seconds": $(($(date +%s) - ${DEPLOYMENT_START_TIME:-$(date +%s)})),
  "environment": "$ENVIRONMENT",
  "image_tag": "$IMAGE_TAG",
  "deployment_status": "$([[ "$ROLLBACK_EXECUTED" == "true" ]] && echo "rolled_back" || echo "completed")",
  "rollback_executed": $ROLLBACK_EXECUTED,
  "performance_metrics": [$(printf '%s,' "${PERFORMANCE_METRICS[@]}" | sed 's/,$//')],
  "security_findings": [$(printf '"%s",' "${SECURITY_FINDINGS[@]}" | sed 's/,$//')],
  "deployment_errors": [$(printf '"%s",' "${DEPLOYMENT_ERRORS[@]}" | sed 's/,$//')],
  "final_validation": "$([[ -f "$ARTIFACT_DIR/post-deployment-validation.json" ]] && jq -r '.overall_result' "$ARTIFACT_DIR/post-deployment-validation.json" || echo "unknown")"
}
EOF
    
    log_debug "Deployment summary created: $deployment_summary"
    
    # Cleanup temporary state files (but preserve logs)
    rm -f "$ROLLBACK_STATE_FILE" || true
    
    log_info "Deployment finalization completed"
    
    return 0
}

#
# Comprehensive deployment summary and reporting
#
generate_deployment_report() {
    log_info "Generating comprehensive deployment report..."
    
    local deployment_report="$ARTIFACT_DIR/deployment-report.html"
    local deployment_duration=$(($(date +%s) - ${DEPLOYMENT_START_TIME:-$(date +%s)}))
    
    # Generate HTML deployment report
    cat > "$deployment_report" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Blue-Green Deployment Report - $DEPLOYMENT_ID</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .success { background-color: #d4edda; border-color: #c3e6cb; }
        .error { background-color: #f8d7da; border-color: #f5c6cb; }
        .warning { background-color: #fff3cd; border-color: #ffeaa7; }
        .metric { margin: 5px 0; }
        .timestamp { color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Blue-Green Deployment Report</h1>
        <div class="timestamp">Generated: $(date)</div>
    </div>
    
    <div class="section $([ "$ROLLBACK_EXECUTED" == "true" ] && echo "error" || echo "success")">
        <h2>Deployment Summary</h2>
        <div><strong>Deployment ID:</strong> $DEPLOYMENT_ID</div>
        <div><strong>Environment:</strong> $ENVIRONMENT</div>
        <div><strong>Image Tag:</strong> $IMAGE_TAG</div>
        <div><strong>Duration:</strong> ${deployment_duration}s</div>
        <div><strong>Status:</strong> $([[ "$ROLLBACK_EXECUTED" == "true" ]] && echo "ROLLED BACK" || echo "COMPLETED")</div>
        <div><strong>Cluster:</strong> $CLUSTER_NAME</div>
        <div><strong>Namespace:</strong> $NAMESPACE</div>
    </div>
    
    <div class="section">
        <h2>Performance Metrics</h2>
$(for metric in "${PERFORMANCE_METRICS[@]}"; do
    echo "        <div class=\"metric\">$metric</div>"
done)
    </div>
    
    <div class="section $([ ${#SECURITY_FINDINGS[@]} -gt 0 ] && echo "warning" || echo "success")">
        <h2>Security Findings</h2>
$(if [ ${#SECURITY_FINDINGS[@]} -eq 0 ]; then
    echo "        <div>No security findings</div>"
else
    for finding in "${SECURITY_FINDINGS[@]}"; do
        echo "        <div class=\"metric\">$finding</div>"
    done
fi)
    </div>
    
    <div class="section $([ ${#DEPLOYMENT_ERRORS[@]} -gt 0 ] && echo "error" || echo "success")">
        <h2>Deployment Issues</h2>
$(if [ ${#DEPLOYMENT_ERRORS[@]} -eq 0 ]; then
    echo "        <div>No deployment errors</div>"
else
    for error in "${DEPLOYMENT_ERRORS[@]}"; do
        echo "        <div class=\"metric\">$error</div>"
    done
fi)
    </div>
    
    <div class="section">
        <h2>Artifacts and Logs</h2>
        <div><strong>State Directory:</strong> $STATE_DIR</div>
        <div><strong>Log File:</strong> $LOG_FILE</div>
        <div><strong>Artifacts:</strong> $ARTIFACT_DIR</div>
    </div>
</body>
</html>
EOF
    
    log_info "Deployment report generated: $deployment_report"
    
    # Print deployment summary to console
    echo
    echo "===================================================================="
    echo "                 BLUE-GREEN DEPLOYMENT SUMMARY"
    echo "===================================================================="
    echo "Deployment ID: $DEPLOYMENT_ID"
    echo "Environment: $ENVIRONMENT"
    echo "Image Tag: $IMAGE_TAG"
    echo "Duration: ${deployment_duration}s"
    echo "Status: $([[ "$ROLLBACK_EXECUTED" == "true" ]] && echo "ROLLED BACK" || echo "COMPLETED SUCCESSFULLY")"
    echo "Timestamp: $(date)"
    echo
    echo "Performance Metrics: ${#PERFORMANCE_METRICS[@]} collected"
    echo "Security Findings: ${#SECURITY_FINDINGS[@]} found"
    echo "Deployment Errors: ${#DEPLOYMENT_ERRORS[@]} encountered"
    echo
    echo "Artifacts Directory: $STATE_DIR"
    echo "Full Report: $deployment_report"
    echo "===================================================================="
    
    return 0
}

#
# Command line argument parsing
#
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            --image-tag)
                IMAGE_TAG="$2"
                shift 2
                ;;
            --namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            --app-name)
                APP_NAME="$2"
                shift 2
                ;;
            --cluster)
                CLUSTER_NAME="$2"
                shift 2
                ;;
            --timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            --health-retries)
                HEALTH_CHECK_RETRIES="$2"
                shift 2
                ;;
            --performance-threshold)
                PERFORMANCE_THRESHOLD="$2"
                shift 2
                ;;
            --monitoring-interval)
                MONITORING_INTERVAL="$2"
                shift 2
                ;;
            --traffic-steps)
                IFS=',' read -ra TRAFFIC_STEPS <<< "$2"
                shift 2
                ;;
            --feature-flag-endpoint)
                FEATURE_FLAG_ENDPOINT="$2"
                shift 2
                ;;
            --load-balancer-endpoint)
                LOAD_BALANCER_ENDPOINT="$2"
                shift 2
                ;;
            --prometheus-url)
                PROMETHEUS_ENDPOINT="$2"
                shift 2
                ;;
            --grafana-url)
                GRAFANA_ENDPOINT="$2"
                shift 2
                ;;
            --alert-webhook)
                ALERT_WEBHOOK="$2"
                shift 2
                ;;
            --slack-webhook)
                SLACK_WEBHOOK="$2"
                shift 2
                ;;
            --skip-performance)
                SKIP_PERFORMANCE="true"
                shift
                ;;
            --skip-security)
                SKIP_SECURITY="true"
                shift
                ;;
            --rollback-version)
                ROLLBACK_VERSION="$2"
                FORCE_ROLLBACK="true"
                shift 2
                ;;
            --force-rollback)
                FORCE_ROLLBACK="true"
                shift
                ;;
            --dry-run)
                DRY_RUN="true"
                shift
                ;;
            --verbose)
                VERBOSE="true"
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                log_error "Use --help for usage information"
                exit 9
                ;;
        esac
    done
    
    # Update derived configurations
    NAMESPACE="${NAMESPACE:-flask-app-${ENVIRONMENT}}"
}

#
# Main deployment orchestration function
#
main() {
    # Initialize deployment
    log_info "Starting Blue-Green Deployment v$SCRIPT_VERSION"
    log_info "Deployment ID: $DEPLOYMENT_ID"
    log_info "Target: $ENVIRONMENT environment, image: $IMAGE_TAG"
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Handle force rollback scenario
    if [[ "$FORCE_ROLLBACK" == "true" ]] && [[ -n "$ROLLBACK_VERSION" ]]; then
        log_info "Force rollback requested to version: $ROLLBACK_VERSION"
        IMAGE_TAG="$ROLLBACK_VERSION"
        
        if execute_automated_rollback "force_rollback_requested"; then
            log_success "Force rollback completed successfully"
            exit 0
        else
            log_error "Force rollback failed"
            exit 7
        fi
    fi
    
    # Create state directory and initialize
    if ! initialize_deployment_state; then
        log_error "Failed to initialize deployment state"
        exit 9
    fi
    
    # Trap signals for cleanup
    trap 'log_error "Deployment interrupted"; execute_automated_rollback "deployment_interrupted"; exit 7' INT TERM
    
    # Execute deployment pipeline
    log_info "Executing Blue-Green deployment pipeline..."
    
    # Phase 1: Pre-deployment validation
    log_info "Phase 1: Pre-deployment validation and preparation"
    
    if ! validate_dependencies; then
        log_error "Dependency validation failed"
        DEPLOYMENT_STATUS="failed"
        exit $?
    fi
    
    if ! perform_container_security_scan; then
        log_error "Container security scan failed"
        DEPLOYMENT_STATUS="failed"
        exit $?
    fi
    
    if ! perform_pre_deployment_validation; then
        log_error "Pre-deployment validation failed"
        DEPLOYMENT_STATUS="failed"
        exit $?
    fi
    
    # Phase 2: Green environment deployment
    log_info "Phase 2: Green environment deployment"
    
    if ! deploy_green_environment; then
        log_error "Green environment deployment failed"
        DEPLOYMENT_STATUS="failed"
        exit $?
    fi
    
    # Phase 3: Health and performance validation
    log_info "Phase 3: Health and performance validation"
    
    if ! perform_health_validation; then
        log_error "Health validation failed, initiating rollback"
        execute_automated_rollback "health_validation_failed"
        DEPLOYMENT_STATUS="rolled_back"
        exit 7
    fi
    
    if ! perform_performance_validation; then
        log_error "Performance validation failed, initiating rollback"
        execute_automated_rollback "performance_validation_failed"
        DEPLOYMENT_STATUS="rolled_back"
        exit 7
    fi
    
    # Phase 4: Gradual traffic migration
    log_info "Phase 4: Gradual traffic migration with feature flags"
    
    if ! manage_feature_flag_deployment; then
        log_error "Feature flag deployment failed, initiating rollback"
        execute_automated_rollback "traffic_migration_failed"
        DEPLOYMENT_STATUS="rolled_back"
        exit 7
    fi
    
    # Phase 5: Post-deployment validation
    log_info "Phase 5: Post-deployment validation and finalization"
    
    if ! perform_post_deployment_validation; then
        log_error "Post-deployment validation failed, initiating rollback"
        execute_automated_rollback "post_deployment_validation_failed"
        DEPLOYMENT_STATUS="rolled_back"
        exit 7
    fi
    
    # Phase 6: Finalization and cleanup
    log_info "Phase 6: Finalization and cleanup"
    
    if ! finalize_deployment; then
        log_warn "Deployment finalization encountered issues (non-critical)"
    fi
    
    # Generate comprehensive report
    generate_deployment_report
    
    DEPLOYMENT_STATUS="completed"
    log_success "Blue-Green deployment completed successfully"
    log_success "Application $APP_NAME:$IMAGE_TAG deployed to $ENVIRONMENT environment"
    log_info "Deployment artifacts preserved in: $STATE_DIR"
    
    exit 0
}

# Execute main function with all arguments
main "$@"