#!/bin/bash

# System Cleanup and Maintenance Script
# Flask Application Operational Maintenance and System Hygiene
# Manages container image cleanup, log rotation, cache management, and resource optimization

set -euo pipefail

# Configuration Variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${LOG_FILE:-/var/log/flask-app/cleanup.log}"
CONFIG_FILE="${PROJECT_ROOT}/src/config/cleanup.conf"

# Default configuration values
DEFAULT_DOCKER_RETENTION_DAYS=7
DEFAULT_LOG_RETENTION_DAYS=30
DEFAULT_CACHE_MAX_MEMORY="2GB"
DEFAULT_PROMETHEUS_RETENTION_DAYS=15

# Logging functions
log() {
    local level="$1"
    shift
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }

# Load configuration
load_config() {
    log_info "Loading cleanup configuration..."
    
    # Create default config if it doesn't exist
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_warn "Configuration file not found, creating defaults at $CONFIG_FILE"
        mkdir -p "$(dirname "$CONFIG_FILE")"
        cat > "$CONFIG_FILE" << EOF
# Flask Application Cleanup Configuration
DOCKER_RETENTION_DAYS=${DEFAULT_DOCKER_RETENTION_DAYS}
LOG_RETENTION_DAYS=${DEFAULT_LOG_RETENTION_DAYS}
CACHE_MAX_MEMORY=${DEFAULT_CACHE_MAX_MEMORY}
PROMETHEUS_RETENTION_DAYS=${DEFAULT_PROMETHEUS_RETENTION_DAYS}
ENABLE_DOCKER_CLEANUP=true
ENABLE_LOG_CLEANUP=true
ENABLE_CACHE_CLEANUP=true
ENABLE_RESOURCE_OPTIMIZATION=true
REDIS_HOST=${REDIS_HOST:-localhost}
REDIS_PORT=${REDIS_PORT:-6379}
REDIS_PASSWORD=${REDIS_PASSWORD:-}
EOF
    fi
    
    # Source configuration
    source "$CONFIG_FILE"
    log_info "Configuration loaded successfully"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    local missing_tools=()
    
    # Check for required tools
    command -v docker >/dev/null 2>&1 || missing_tools+=("docker")
    command -v kubectl >/dev/null 2>&1 || missing_tools+=("kubectl")
    command -v redis-cli >/dev/null 2>&1 || missing_tools+=("redis-cli")
    command -v logrotate >/dev/null 2>&1 || missing_tools+=("logrotate")
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_error "Please install missing tools before running cleanup"
        exit 1
    fi
    
    # Verify Docker daemon is running
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker daemon is not running or accessible"
        exit 1
    fi
    
    # Verify Kubernetes context (optional, with fallback)
    if ! kubectl cluster-info >/dev/null 2>&1; then
        log_warn "Kubernetes cluster not accessible, skipping K8s resource cleanup"
        export KUBERNETES_AVAILABLE=false
    else
        export KUBERNETES_AVAILABLE=true
        log_info "Kubernetes cluster accessible"
    fi
    
    log_info "Prerequisites check completed"
}

# Docker Image Cleanup (Section 4.4.1)
cleanup_docker_images() {
    if [[ "${ENABLE_DOCKER_CLEANUP:-true}" != "true" ]]; then
        log_info "Docker cleanup disabled, skipping..."
        return 0
    fi
    
    log_info "Starting Docker image cleanup..."
    local retention_days="${DOCKER_RETENTION_DAYS:-$DEFAULT_DOCKER_RETENTION_DAYS}"
    
    # Get current application images to preserve
    local current_images
    current_images=$(docker images --format "table {{.Repository}}:{{.Tag}}" | grep -E "(flask-app|python.*flask)" | head -5 || true)
    
    log_info "Preserving current application images: $current_images"
    
    # Remove old application images (older than retention period)
    log_info "Removing Docker images older than $retention_days days..."
    local old_images
    old_images=$(docker images --format "table {{.Repository}}:{{.Tag}}\t{{.CreatedAt}}" | \
        awk -v days="$retention_days" '
        {
            # Skip header
            if (NR == 1) next
            
            # Parse created date
            split($0, parts, "\t")
            image = parts[1]
            created = parts[2]
            
            # Simple date comparison (images older than X days)
            cmd = "date -d \"" created "\" +%s"
            cmd | getline created_epoch
            close(cmd)
            
            cmd = "date -d \"" days " days ago\" +%s"
            cmd | getline cutoff_epoch
            close(cmd)
            
            if (created_epoch < cutoff_epoch && image !~ /^<none>/) {
                print image
            }
        }' 2>/dev/null || true)
    
    if [[ -n "$old_images" ]]; then
        echo "$old_images" | while read -r image; do
            if [[ -n "$image" && "$image" != "REPOSITORY:TAG" ]]; then
                log_info "Removing old image: $image"
                docker rmi "$image" 2>/dev/null || log_warn "Failed to remove image: $image"
            fi
        done
    fi
    
    # Remove dangling images
    log_info "Removing dangling Docker images..."
    local dangling_images
    dangling_images=$(docker images -f "dangling=true" -q || true)
    if [[ -n "$dangling_images" ]]; then
        echo "$dangling_images" | xargs docker rmi 2>/dev/null || log_warn "Some dangling images could not be removed"
        log_info "Removed dangling images"
    else
        log_info "No dangling images found"
    fi
    
    # Remove unused volumes
    log_info "Removing unused Docker volumes..."
    docker volume prune -f >/dev/null 2>&1 || log_warn "Failed to prune volumes"
    
    # Remove unused networks
    log_info "Removing unused Docker networks..."
    docker network prune -f >/dev/null 2>&1 || log_warn "Failed to prune networks"
    
    # Docker system cleanup
    log_info "Running Docker system cleanup..."
    docker system prune -f >/dev/null 2>&1 || log_warn "Failed to run system prune"
    
    log_info "Docker image cleanup completed"
}

# Kubernetes Resource Cleanup (Section 4.4.1)
cleanup_kubernetes_resources() {
    if [[ "${KUBERNETES_AVAILABLE:-false}" != "true" ]]; then
        log_info "Kubernetes not available, skipping K8s resource cleanup"
        return 0
    fi
    
    if [[ "${ENABLE_DOCKER_CLEANUP:-true}" != "true" ]]; then
        log_info "Docker cleanup disabled, skipping K8s cleanup..."
        return 0
    fi
    
    log_info "Starting Kubernetes resource cleanup..."
    
    # Get current namespace
    local namespace
    namespace=$(kubectl config view --minify -o jsonpath='{..namespace}' 2>/dev/null || echo "default")
    log_info "Cleaning up resources in namespace: $namespace"
    
    # Remove completed jobs older than retention period
    log_info "Removing completed Kubernetes jobs..."
    kubectl get jobs -n "$namespace" --field-selector=status.successful=1 -o json | \
        jq -r --arg days "$DOCKER_RETENTION_DAYS" '
        .items[] | 
        select(.status.completionTime != null) |
        select((now - (.status.completionTime | strptime("%Y-%m-%dT%H:%M:%SZ") | mktime)) > ($days | tonumber * 86400)) |
        .metadata.name
        ' 2>/dev/null | while read -r job; do
            if [[ -n "$job" ]]; then
                log_info "Removing completed job: $job"
                kubectl delete job "$job" -n "$namespace" 2>/dev/null || log_warn "Failed to delete job: $job"
            fi
        done
    
    # Remove failed pods older than retention period
    log_info "Removing failed pods..."
    kubectl get pods -n "$namespace" --field-selector=status.phase=Failed -o json | \
        jq -r --arg days "$DOCKER_RETENTION_DAYS" '
        .items[] |
        select(.status.startTime != null) |
        select((now - (.status.startTime | strptime("%Y-%m-%dT%H:%M:%SZ") | mktime)) > ($days | tonumber * 86400)) |
        .metadata.name
        ' 2>/dev/null | while read -r pod; do
            if [[ -n "$pod" ]]; then
                log_info "Removing failed pod: $pod"
                kubectl delete pod "$pod" -n "$namespace" 2>/dev/null || log_warn "Failed to delete pod: $pod"
            fi
        done
    
    # Remove old replica sets (keep last 3)
    log_info "Cleaning up old replica sets..."
    kubectl get rs -n "$namespace" --sort-by=.metadata.creationTimestamp -o name | head -n -3 | while read -r rs; do
        if [[ -n "$rs" ]]; then
            local replicas
            replicas=$(kubectl get "$rs" -n "$namespace" -o jsonpath='{.status.replicas}' 2>/dev/null || echo "0")
            if [[ "$replicas" == "0" ]]; then
                log_info "Removing old replica set: $rs"
                kubectl delete "$rs" -n "$namespace" 2>/dev/null || log_warn "Failed to delete replica set: $rs"
            fi
        fi
    done
    
    log_info "Kubernetes resource cleanup completed"
}

# Redis Cache Management and Cleanup (Section 6.2.4)
cleanup_redis_cache() {
    if [[ "${ENABLE_CACHE_CLEANUP:-true}" != "true" ]]; then
        log_info "Cache cleanup disabled, skipping..."
        return 0
    fi
    
    log_info "Starting Redis cache cleanup..."
    
    local redis_host="${REDIS_HOST:-localhost}"
    local redis_port="${REDIS_PORT:-6379}"
    local redis_password="${REDIS_PASSWORD:-}"
    local max_memory="${CACHE_MAX_MEMORY:-$DEFAULT_CACHE_MAX_MEMORY}"
    
    # Build Redis CLI command
    local redis_cmd="redis-cli -h $redis_host -p $redis_port"
    if [[ -n "$redis_password" ]]; then
        redis_cmd="$redis_cmd -a $redis_password"
    fi
    
    # Test Redis connectivity
    if ! $redis_cmd ping >/dev/null 2>&1; then
        log_error "Cannot connect to Redis at $redis_host:$redis_port"
        return 1
    fi
    
    log_info "Connected to Redis successfully"
    
    # Get Redis info before cleanup
    local memory_used_before
    memory_used_before=$($redis_cmd info memory | grep used_memory_human | cut -d: -f2 | tr -d '\r')
    local keys_before
    keys_before=$($redis_cmd dbsize | tr -d '\r')
    
    log_info "Redis status before cleanup - Memory used: $memory_used_before, Keys: $keys_before"
    
    # Remove expired keys
    log_info "Removing expired Redis keys..."
    local expired_keys=0
    
    # Scan for keys with TTL and check expiration
    $redis_cmd --scan --pattern "*" | while read -r key; do
        if [[ -n "$key" ]]; then
            local ttl
            ttl=$($redis_cmd ttl "$key" 2>/dev/null || echo "-1")
            if [[ "$ttl" == "0" ]]; then
                $redis_cmd del "$key" >/dev/null 2>&1 && ((expired_keys++)) || true
            fi
        fi
    done
    
    # Clean up Flask session cache (if using Redis for sessions)
    log_info "Cleaning up Flask session cache..."
    local session_keys
    session_keys=$($redis_cmd keys "session:*" | wc -l)
    if [[ "$session_keys" -gt 0 ]]; then
        # Remove sessions older than 24 hours without activity
        $redis_cmd --scan --pattern "session:*" | while read -r session_key; do
            if [[ -n "$session_key" ]]; then
                local last_access
                last_access=$($redis_cmd hget "$session_key" "last_access" 2>/dev/null || echo "0")
                local current_time
                current_time=$(date +%s)
                local age=$((current_time - last_access))
                
                # Remove sessions older than 24 hours (86400 seconds)
                if [[ "$age" -gt 86400 ]]; then
                    $redis_cmd del "$session_key" >/dev/null 2>&1 || true
                    log_info "Removed expired session: $session_key"
                fi
            fi
        done
    fi
    
    # Clean up application response cache
    log_info "Cleaning up application response cache..."
    local cache_pattern="flask_cache:*"
    local cache_keys
    cache_keys=$($redis_cmd keys "$cache_pattern" | wc -l)
    if [[ "$cache_keys" -gt 100 ]]; then
        # Remove oldest cache entries if we have too many
        $redis_cmd --scan --pattern "$cache_pattern" | head -50 | while read -r cache_key; do
            if [[ -n "$cache_key" ]]; then
                $redis_cmd del "$cache_key" >/dev/null 2>&1 || true
            fi
        done
        log_info "Removed old cache entries to maintain performance"
    fi
    
    # Optimize memory usage
    log_info "Optimizing Redis memory usage..."
    
    # Run memory optimization commands
    $redis_cmd memory purge >/dev/null 2>&1 || log_warn "Memory purge not supported in this Redis version"
    
    # Defragment if supported
    if $redis_cmd memory help 2>/dev/null | grep -q "MEMORY DEFRAG"; then
        log_info "Running Redis memory defragmentation..."
        $redis_cmd memory defrag >/dev/null 2>&1 || log_warn "Memory defragmentation failed"
    fi
    
    # Check memory usage and implement eviction if needed
    local current_memory
    current_memory=$($redis_cmd info memory | grep used_memory: | cut -d: -f2 | tr -d '\r')
    
    # Convert max_memory to bytes for comparison
    local max_memory_bytes
    case "${max_memory^^}" in
        *GB) max_memory_bytes=$((${max_memory%GB} * 1024 * 1024 * 1024)) ;;
        *MB) max_memory_bytes=$((${max_memory%MB} * 1024 * 1024)) ;;
        *KB) max_memory_bytes=$((${max_memory%KB} * 1024)) ;;
        *) max_memory_bytes="$max_memory" ;;
    esac
    
    if [[ "$current_memory" -gt "$max_memory_bytes" ]]; then
        log_warn "Redis memory usage ($current_memory bytes) exceeds limit ($max_memory_bytes bytes)"
        log_info "Implementing LRU eviction for cache optimization..."
        
        # Set maxmemory and eviction policy temporarily
        $redis_cmd config set maxmemory "$max_memory_bytes" >/dev/null 2>&1 || true
        $redis_cmd config set maxmemory-policy allkeys-lru >/dev/null 2>&1 || true
        
        # Force eviction by attempting a small operation
        $redis_cmd set temp_key temp_value >/dev/null 2>&1 || true
        $redis_cmd del temp_key >/dev/null 2>&1 || true
    fi
    
    # Get Redis info after cleanup
    local memory_used_after
    memory_used_after=$($redis_cmd info memory | grep used_memory_human | cut -d: -f2 | tr -d '\r')
    local keys_after
    keys_after=$($redis_cmd dbsize | tr -d '\r')
    
    log_info "Redis status after cleanup - Memory used: $memory_used_after, Keys: $keys_after"
    log_info "Redis cache cleanup completed"
}

# Log Management and Rotation (Section 3.5.1)
cleanup_logs() {
    if [[ "${ENABLE_LOG_CLEANUP:-true}" != "true" ]]; then
        log_info "Log cleanup disabled, skipping..."
        return 0
    fi
    
    log_info "Starting log cleanup and rotation..."
    
    local retention_days="${LOG_RETENTION_DAYS:-$DEFAULT_LOG_RETENTION_DAYS}"
    local log_dirs=(
        "/var/log/flask-app"
        "/var/log/gunicorn"
        "/var/log/nginx"
        "$PROJECT_ROOT/logs"
        "/tmp/flask-*.log"
    )
    
    # Create logrotate configuration for Flask application
    local logrotate_config="/etc/logrotate.d/flask-app"
    if [[ ! -f "$logrotate_config" ]] && [[ -w "/etc/logrotate.d" ]]; then
        log_info "Creating logrotate configuration..."
        cat > "$logrotate_config" << EOF
# Flask Application Log Rotation Configuration
# Structured logging cleanup and rotation with enterprise integration

/var/log/flask-app/*.log {
    daily
    rotate $retention_days
    compress
    delaycompress
    missingok
    notifempty
    create 644 flask flask
    postrotate
        # Send HUP signal to gunicorn master process to reopen log files
        if [ -f /var/run/gunicorn.pid ]; then
            kill -HUP \$(cat /var/run/gunicorn.pid) 2>/dev/null || true
        fi
        
        # Restart rsyslog if using system logging
        systemctl reload rsyslog 2>/dev/null || true
    endscript
}

/var/log/gunicorn/*.log {
    daily
    rotate $retention_days
    compress
    delaycompress
    missingok
    notifempty
    create 644 gunicorn gunicorn
    copytruncate
}

$PROJECT_ROOT/logs/*.log {
    daily
    rotate $retention_days
    compress
    delaycompress
    missingok
    notifempty
    create 644 $(whoami) $(whoami)
}
EOF
        log_info "Logrotate configuration created"
    fi
    
    # Run logrotate manually if configuration exists
    if [[ -f "$logrotate_config" ]]; then
        log_info "Running logrotate for Flask application logs..."
        logrotate -f "$logrotate_config" 2>/dev/null || log_warn "Logrotate execution had warnings"
    fi
    
    # Manual cleanup for log directories
    for log_dir in "${log_dirs[@]}"; do
        if [[ -d "$log_dir" ]]; then
            log_info "Cleaning logs in directory: $log_dir"
            
            # Remove logs older than retention period
            find "$log_dir" -name "*.log" -type f -mtime "+$retention_days" -delete 2>/dev/null || true
            find "$log_dir" -name "*.log.gz" -type f -mtime "+$retention_days" -delete 2>/dev/null || true
            
            # Remove empty log files
            find "$log_dir" -name "*.log" -type f -empty -delete 2>/dev/null || true
            
            log_info "Cleaned logs in $log_dir"
        elif [[ -f "$log_dir" ]]; then
            # Handle file patterns like /tmp/flask-*.log
            eval "ls $log_dir 2>/dev/null" | while read -r log_file; do
                if [[ -f "$log_file" && $(stat -c %Y "$log_file") -lt $(($(date +%s) - retention_days * 86400)) ]]; then
                    rm -f "$log_file" 2>/dev/null || true
                    log_info "Removed old log file: $log_file"
                fi
            done
        fi
    done
    
    # Clean up systemd journal logs if applicable
    if command -v journalctl >/dev/null 2>&1; then
        log_info "Cleaning systemd journal logs..."
        journalctl --vacuum-time="${retention_days}d" >/dev/null 2>&1 || log_warn "Failed to clean journal logs"
    fi
    
    # Clean up Prometheus metrics logs if exists
    local prometheus_retention="${PROMETHEUS_RETENTION_DAYS:-$DEFAULT_PROMETHEUS_RETENTION_DAYS}"
    local prometheus_data_dir="/var/lib/prometheus"
    if [[ -d "$prometheus_data_dir" ]]; then
        log_info "Cleaning Prometheus metrics older than $prometheus_retention days..."
        find "$prometheus_data_dir" -name "*.db" -type f -mtime "+$prometheus_retention" -delete 2>/dev/null || true
    fi
    
    # Compress large log files
    log_info "Compressing large log files..."
    for log_dir in "${log_dirs[@]}"; do
        if [[ -d "$log_dir" ]]; then
            find "$log_dir" -name "*.log" -type f -size +10M -exec gzip {} \; 2>/dev/null || true
        fi
    done
    
    log_info "Log cleanup and rotation completed"
}

# Resource Optimization and System Cleanup
optimize_system_resources() {
    if [[ "${ENABLE_RESOURCE_OPTIMIZATION:-true}" != "true" ]]; then
        log_info "Resource optimization disabled, skipping..."
        return 0
    fi
    
    log_info "Starting system resource optimization..."
    
    # Clear system caches
    log_info "Clearing system caches..."
    sync
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || log_warn "Cannot clear system caches (requires root)"
    
    # Clean up temporary files
    log_info "Cleaning up temporary files..."
    local temp_dirs=(
        "/tmp"
        "/var/tmp"
        "$PROJECT_ROOT/tmp"
        "$PROJECT_ROOT/.pytest_cache"
        "$PROJECT_ROOT/__pycache__"
    )
    
    for temp_dir in "${temp_dirs[@]}"; do
        if [[ -d "$temp_dir" ]]; then
            # Remove files older than 7 days
            find "$temp_dir" -type f -mtime +7 -delete 2>/dev/null || true
            
            # Remove Python cache files
            if [[ "$temp_dir" == *"pycache"* ]] || [[ "$temp_dir" == *"pytest"* ]]; then
                rm -rf "$temp_dir" 2>/dev/null || true
                log_info "Removed Python cache directory: $temp_dir"
            fi
        fi
    done
    
    # Clean up pip cache
    if command -v pip >/dev/null 2>&1; then
        log_info "Cleaning pip cache..."
        pip cache purge >/dev/null 2>&1 || log_warn "Failed to clean pip cache"
    fi
    
    # Clean up package manager caches
    if command -v apt-get >/dev/null 2>&1; then
        log_info "Cleaning apt cache..."
        apt-get clean >/dev/null 2>&1 || log_warn "Failed to clean apt cache"
    elif command -v yum >/dev/null 2>&1; then
        log_info "Cleaning yum cache..."
        yum clean all >/dev/null 2>&1 || log_warn "Failed to clean yum cache"
    fi
    
    # Optimize Python bytecode
    log_info "Optimizing Python bytecode..."
    if [[ -d "$PROJECT_ROOT/src" ]]; then
        python -m compileall "$PROJECT_ROOT/src" >/dev/null 2>&1 || log_warn "Failed to compile Python bytecode"
    fi
    
    # Check disk usage and warn if high
    log_info "Checking disk usage..."
    local disk_usage
    disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [[ "$disk_usage" -gt 80 ]]; then
        log_warn "Disk usage is high: ${disk_usage}%"
        log_warn "Consider increasing cleanup frequency or expanding storage"
    else
        log_info "Disk usage is acceptable: ${disk_usage}%"
    fi
    
    # Check memory usage
    local memory_usage
    memory_usage=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100.0}')
    log_info "Current memory usage: ${memory_usage}%"
    
    if [[ "$memory_usage" -gt 85 ]]; then
        log_warn "Memory usage is high: ${memory_usage}%"
        log_info "Running memory optimization..."
        
        # Force garbage collection in Python processes if possible
        pkill -USR1 gunicorn 2>/dev/null || true
        
        # Restart application if memory usage is critical
        if [[ "$memory_usage" -gt 95 ]]; then
            log_warn "Critical memory usage detected, consider application restart"
        fi
    fi
    
    log_info "System resource optimization completed"
}

# Health check after cleanup
post_cleanup_health_check() {
    log_info "Running post-cleanup health check..."
    
    # Check if Flask application is responsive
    local health_endpoint="${FLASK_HEALTH_ENDPOINT:-http://localhost:8000/health}"
    if command -v curl >/dev/null 2>&1; then
        if curl -s -f "$health_endpoint" >/dev/null 2>&1; then
            log_info "Flask application health check passed"
        else
            log_warn "Flask application health check failed"
        fi
    fi
    
    # Check Redis connectivity
    local redis_host="${REDIS_HOST:-localhost}"
    local redis_port="${REDIS_PORT:-6379}"
    local redis_password="${REDIS_PASSWORD:-}"
    local redis_cmd="redis-cli -h $redis_host -p $redis_port"
    if [[ -n "$redis_password" ]]; then
        redis_cmd="$redis_cmd -a $redis_password"
    fi
    
    if $redis_cmd ping >/dev/null 2>&1; then
        log_info "Redis connectivity check passed"
    else
        log_warn "Redis connectivity check failed"
    fi
    
    # Check Docker daemon
    if docker info >/dev/null 2>&1; then
        log_info "Docker daemon check passed"
    else
        log_warn "Docker daemon check failed"
    fi
    
    # Check available disk space
    local available_space
    available_space=$(df / | awk 'NR==2 {print $4}')
    log_info "Available disk space: $(df -h / | awk 'NR==2 {print $4}')"
    
    log_info "Post-cleanup health check completed"
}

# Generate cleanup report
generate_cleanup_report() {
    log_info "Generating cleanup report..."
    
    local report_file="${PROJECT_ROOT}/logs/cleanup-report-$(date +%Y%m%d-%H%M%S).json"
    mkdir -p "$(dirname "$report_file")"
    
    # Gather system metrics
    local disk_usage
    disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    local memory_usage
    memory_usage=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100.0}')
    local docker_images
    docker_images=$(docker images | wc -l)
    local docker_containers
    docker_containers=$(docker ps -a | wc -l)
    
    # Redis metrics
    local redis_keys=0
    local redis_memory="N/A"
    if redis-cli ping >/dev/null 2>&1; then
        redis_keys=$(redis-cli dbsize 2>/dev/null || echo "0")
        redis_memory=$(redis-cli info memory 2>/dev/null | grep used_memory_human | cut -d: -f2 | tr -d '\r' || echo "N/A")
    fi
    
    cat > "$report_file" << EOF
{
    "cleanup_report": {
        "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        "script_version": "1.0.0",
        "configuration": {
            "docker_retention_days": ${DOCKER_RETENTION_DAYS:-$DEFAULT_DOCKER_RETENTION_DAYS},
            "log_retention_days": ${LOG_RETENTION_DAYS:-$DEFAULT_LOG_RETENTION_DAYS},
            "cache_max_memory": "${CACHE_MAX_MEMORY:-$DEFAULT_CACHE_MAX_MEMORY}",
            "prometheus_retention_days": ${PROMETHEUS_RETENTION_DAYS:-$DEFAULT_PROMETHEUS_RETENTION_DAYS}
        },
        "system_metrics": {
            "disk_usage_percent": $disk_usage,
            "memory_usage_percent": $memory_usage,
            "docker_images_count": $((docker_images - 1)),
            "docker_containers_count": $((docker_containers - 1))
        },
        "redis_metrics": {
            "keys_count": $redis_keys,
            "memory_used": "$redis_memory"
        },
        "enabled_operations": {
            "docker_cleanup": ${ENABLE_DOCKER_CLEANUP:-true},
            "log_cleanup": ${ENABLE_LOG_CLEANUP:-true},
            "cache_cleanup": ${ENABLE_CACHE_CLEANUP:-true},
            "resource_optimization": ${ENABLE_RESOURCE_OPTIMIZATION:-true}
        },
        "cleanup_status": "completed"
    }
}
EOF
    
    log_info "Cleanup report generated: $report_file"
}

# Main execution function
main() {
    local start_time
    start_time=$(date +%s)
    
    log_info "Starting Flask application cleanup process..."
    log_info "Script: $0"
    log_info "Arguments: $*"
    
    # Create log directory if it doesn't exist
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # Parse command line arguments
    local skip_docker=false
    local skip_cache=false
    local skip_logs=false
    local skip_resources=false
    local dry_run=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-docker)
                skip_docker=true
                export ENABLE_DOCKER_CLEANUP=false
                shift
                ;;
            --skip-cache)
                skip_cache=true
                export ENABLE_CACHE_CLEANUP=false
                shift
                ;;
            --skip-logs)
                skip_logs=true
                export ENABLE_LOG_CLEANUP=false
                shift
                ;;
            --skip-resources)
                skip_resources=true
                export ENABLE_RESOURCE_OPTIMIZATION=false
                shift
                ;;
            --dry-run)
                dry_run=true
                log_info "DRY RUN MODE: No actual cleanup will be performed"
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo "Flask Application Cleanup Script"
                echo ""
                echo "Options:"
                echo "  --skip-docker      Skip Docker image cleanup"
                echo "  --skip-cache       Skip Redis cache cleanup"
                echo "  --skip-logs        Skip log rotation and cleanup"
                echo "  --skip-resources   Skip system resource optimization"
                echo "  --dry-run          Show what would be done without executing"
                echo "  --help, -h         Show this help message"
                echo ""
                echo "Configuration:"
                echo "  Config file: $CONFIG_FILE"
                echo "  Log file: $LOG_FILE"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    if [[ "$dry_run" == "true" ]]; then
        log_info "DRY RUN: Would load configuration from $CONFIG_FILE"
        log_info "DRY RUN: Would check prerequisites for docker, kubectl, redis-cli, logrotate"
        log_info "DRY RUN: Would cleanup Docker images older than ${DOCKER_RETENTION_DAYS:-$DEFAULT_DOCKER_RETENTION_DAYS} days"
        log_info "DRY RUN: Would cleanup Kubernetes resources"
        log_info "DRY RUN: Would cleanup Redis cache and optimize memory"
        log_info "DRY RUN: Would rotate logs older than ${LOG_RETENTION_DAYS:-$DEFAULT_LOG_RETENTION_DAYS} days"
        log_info "DRY RUN: Would optimize system resources"
        log_info "DRY RUN: Would run post-cleanup health check"
        log_info "DRY RUN: Would generate cleanup report"
        exit 0
    fi
    
    # Execute cleanup operations
    load_config
    check_prerequisites
    
    # Execute cleanup operations based on configuration
    cleanup_docker_images
    cleanup_kubernetes_resources
    cleanup_redis_cache
    cleanup_logs
    optimize_system_resources
    
    # Post-cleanup operations
    post_cleanup_health_check
    generate_cleanup_report
    
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_info "Flask application cleanup completed successfully"
    log_info "Total execution time: ${duration} seconds"
    log_info "Log file: $LOG_FILE"
}

# Execute main function with all arguments
main "$@"