#!/bin/bash

# Dependency Management Script for Flask Application
# Implements pip-tools for deterministic dependency resolution, security vulnerability scanning,
# and automated dependency upgrade management per Section 8.5.1 CI/CD Pipeline requirements

set -euo pipefail

# Color codes for output formatting
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Script configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
readonly REQUIREMENTS_IN="${PROJECT_ROOT}/requirements.in"
readonly REQUIREMENTS_TXT="${PROJECT_ROOT}/requirements.txt"
readonly REQUIREMENTS_DEV_IN="${PROJECT_ROOT}/requirements-dev.in"
readonly REQUIREMENTS_DEV_TXT="${PROJECT_ROOT}/requirements-dev.txt"
readonly SECURITY_REPORT_DIR="${PROJECT_ROOT}/security-reports"
readonly LICENSE_REPORT_DIR="${PROJECT_ROOT}/license-reports"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" >&2
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Error handling
error_exit() {
    log_error "$1"
    exit 1
}

# Cleanup function for signal handling
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_error "Script execution failed with exit code $exit_code"
    fi
    exit $exit_code
}

trap cleanup EXIT INT TERM

# Help function
show_help() {
    cat << EOF
Dependency Management Script for Flask Application

USAGE:
    $(basename "$0") [COMMAND] [OPTIONS]

COMMANDS:
    install         Install all dependencies using pinned versions
    compile         Compile requirements.in to requirements.txt using pip-tools
    upgrade         Upgrade dependencies with security validation
    security-scan   Run comprehensive security vulnerability scanning
    license-check   Validate license compliance for enterprise requirements
    validate        Validate current dependency resolution and security
    clean          Clean temporary files and caches
    help           Show this help message

OPTIONS:
    --env ENV       Target environment (dev, staging, prod) [default: dev]
    --force         Force regeneration of pinned dependencies
    --security-only Only upgrade packages with security vulnerabilities
    --dry-run       Show what would be done without making changes
    --verbose       Enable verbose output

EXAMPLES:
    $(basename "$0") install
    $(basename "$0") compile --force
    $(basename "$0") upgrade --security-only
    $(basename "$0") security-scan --env prod
    $(basename "$0") license-check

ENVIRONMENT VARIABLES:
    PIP_TOOLS_VERSION   pip-tools version to use [default: 7.3.0]
    SAFETY_VERSION      safety version to use [default: 3.0.1]
    PIP_AUDIT_VERSION   pip-audit version to use [default: 2.7.2]
    PYTHON_VERSION      Python version requirement [default: 3.8]
    SECURITY_LEVEL      Security enforcement level (strict, moderate, permissive) [default: strict]

EOF
}

# Environment configuration
setup_environment() {
    log_info "Setting up dependency management environment..."
    
    # Create required directories
    mkdir -p "$SECURITY_REPORT_DIR" "$LICENSE_REPORT_DIR"
    
    # Set default values
    export PIP_TOOLS_VERSION="${PIP_TOOLS_VERSION:-7.3.0}"
    export SAFETY_VERSION="${SAFETY_VERSION:-3.0.1}"
    export PIP_AUDIT_VERSION="${PIP_AUDIT_VERSION:-2.7.2}"
    export PYTHON_VERSION="${PYTHON_VERSION:-3.8}"
    export SECURITY_LEVEL="${SECURITY_LEVEL:-strict}"
    
    # Validate Python version
    if ! python3 --version | grep -qE "Python 3\.(8|9|10|11|12)"; then
        error_exit "Python 3.8+ is required. Current version: $(python3 --version)"
    fi
    
    log_success "Environment setup completed"
}

# Install development tools
install_dev_tools() {
    local force_install="${1:-false}"
    
    log_info "Installing dependency management tools..."
    
    # List of required tools with versions
    local tools=(
        "pip-tools==$PIP_TOOLS_VERSION"
        "safety==$SAFETY_VERSION"
        "pip-audit==$PIP_AUDIT_VERSION"
        "licensecheck==2023.1.1"
        "pip-licenses==4.3"
    )
    
    for tool in "${tools[@]}"; do
        local tool_name="${tool%%=*}"
        if [[ "$force_install" == "true" ]] || ! python3 -c "import ${tool_name//-/_}" 2>/dev/null; then
            log_info "Installing $tool..."
            python3 -m pip install --upgrade "$tool" || error_exit "Failed to install $tool"
        else
            log_info "$tool_name is already installed"
        fi
    done
    
    log_success "Development tools installation completed"
}

# Compile requirements using pip-tools
compile_requirements() {
    local force="${1:-false}"
    local env="${2:-dev}"
    
    log_info "Compiling requirements for environment: $env"
    
    # Validate input files exist
    if [[ ! -f "$REQUIREMENTS_IN" ]]; then
        error_exit "requirements.in not found at $REQUIREMENTS_IN"
    fi
    
    # Compile production requirements
    local compile_args=("--resolver=backtracking" "--allow-unsafe" "--generate-hashes")
    
    if [[ "$force" == "true" ]]; then
        compile_args+=("--upgrade")
        log_info "Force upgrade enabled - regenerating all pins"
    fi
    
    if [[ "$env" == "dev" ]]; then
        compile_args+=("--extra-index-url" "https://test.pypi.org/simple/")
    fi
    
    log_info "Running pip-compile with args: ${compile_args[*]}"
    
    # Compile main requirements
    python3 -m piptools compile "${compile_args[@]}" \
        --output-file "$REQUIREMENTS_TXT" \
        "$REQUIREMENTS_IN" || error_exit "Failed to compile requirements.txt"
    
    # Compile development requirements if file exists
    if [[ -f "$REQUIREMENTS_DEV_IN" ]]; then
        python3 -m piptools compile "${compile_args[@]}" \
            --output-file "$REQUIREMENTS_DEV_TXT" \
            --constraint "$REQUIREMENTS_TXT" \
            "$REQUIREMENTS_DEV_IN" || error_exit "Failed to compile requirements-dev.txt"
    fi
    
    log_success "Requirements compilation completed"
}

# Validate requirements synchronization
validate_requirements() {
    log_info "Validating requirements synchronization..."
    
    # Check if requirements.txt is up to date
    if [[ -f "$REQUIREMENTS_TXT" ]]; then
        local temp_file
        temp_file=$(mktemp)
        
        python3 -m piptools compile \
            --resolver=backtracking \
            --allow-unsafe \
            --generate-hashes \
            --quiet \
            --output-file "$temp_file" \
            "$REQUIREMENTS_IN" || error_exit "Failed to validate requirements compilation"
        
        if ! diff -q "$REQUIREMENTS_TXT" "$temp_file" >/dev/null; then
            log_warning "requirements.txt is not up to date with requirements.in"
            log_warning "Run '$(basename "$0") compile --force' to update"
            rm -f "$temp_file"
            return 1
        fi
        
        rm -f "$temp_file"
    fi
    
    log_success "Requirements validation completed"
}

# Security vulnerability scanning
security_scan() {
    local env="${1:-dev}"
    local report_format="${2:-json}"
    
    log_info "Running comprehensive security vulnerability scanning..."
    
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")
    local safety_report="${SECURITY_REPORT_DIR}/safety_report_${timestamp}.json"
    local pip_audit_report="${SECURITY_REPORT_DIR}/pip_audit_report_${timestamp}.json"
    
    # Run safety vulnerability scan
    log_info "Running safety vulnerability scan..."
    
    local safety_exit_code=0
    python3 -m safety check \
        --json \
        --output "$safety_report" \
        --require "$REQUIREMENTS_TXT" || safety_exit_code=$?
    
    if [[ $safety_exit_code -eq 0 ]]; then
        log_success "Safety scan: No vulnerabilities found"
    else
        log_warning "Safety scan: Vulnerabilities detected (exit code: $safety_exit_code)"
        if [[ -f "$safety_report" ]]; then
            log_info "Safety report saved to: $safety_report"
            # Display summary of findings
            python3 -c "
import json
import sys
try:
    with open('$safety_report', 'r') as f:
        data = json.load(f)
    if isinstance(data, list) and data:
        print(f'Found {len(data)} vulnerabilities:')
        for vuln in data[:5]:  # Show first 5
            pkg = vuln.get('package_name', 'Unknown')
            installed = vuln.get('installed_version', 'Unknown')
            vuln_id = vuln.get('vulnerability_id', 'Unknown')
            severity = vuln.get('more_info_url', '').split('/')[-1] if vuln.get('more_info_url') else 'Unknown'
            print(f'  - {pkg} {installed}: {vuln_id}')
        if len(data) > 5:
            print(f'  ... and {len(data) - 5} more')
except Exception as e:
    print(f'Error reading safety report: {e}')
"
        fi
    fi
    
    # Run pip-audit vulnerability scan
    log_info "Running pip-audit vulnerability scan..."
    
    local pip_audit_exit_code=0
    python3 -m pip_audit \
        --requirement "$REQUIREMENTS_TXT" \
        --format=json \
        --output="$pip_audit_report" || pip_audit_exit_code=$?
    
    if [[ $pip_audit_exit_code -eq 0 ]]; then
        log_success "pip-audit scan: No vulnerabilities found"
    else
        log_warning "pip-audit scan: Vulnerabilities detected (exit code: $pip_audit_exit_code)"
        if [[ -f "$pip_audit_report" ]]; then
            log_info "pip-audit report saved to: $pip_audit_report"
        fi
    fi
    
    # Security policy enforcement based on SECURITY_LEVEL
    case "$SECURITY_LEVEL" in
        "strict")
            if [[ $safety_exit_code -ne 0 ]] || [[ $pip_audit_exit_code -ne 0 ]]; then
                error_exit "Security scan failed with strict enforcement policy"
            fi
            ;;
        "moderate")
            if [[ $safety_exit_code -gt 1 ]] || [[ $pip_audit_exit_code -gt 1 ]]; then
                error_exit "Security scan failed with critical vulnerabilities"
            fi
            ;;
        "permissive")
            log_info "Security scan completed with permissive policy"
            ;;
        *)
            log_warning "Unknown security level: $SECURITY_LEVEL. Using strict policy."
            if [[ $safety_exit_code -ne 0 ]] || [[ $pip_audit_exit_code -ne 0 ]]; then
                error_exit "Security scan failed with strict enforcement policy"
            fi
            ;;
    esac
    
    log_success "Security vulnerability scanning completed"
}

# License compliance validation
license_check() {
    log_info "Validating license compliance for enterprise requirements..."
    
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")
    local license_report="${LICENSE_REPORT_DIR}/license_report_${timestamp}.json"
    
    # Generate license report
    python3 -m pip_licenses \
        --format=json \
        --output-file="$license_report" \
        --with-urls \
        --with-description || error_exit "Failed to generate license report"
    
    log_info "License report saved to: $license_report"
    
    # Define enterprise-approved licenses
    local approved_licenses=(
        "MIT License"
        "MIT"
        "Apache Software License"
        "Apache License 2.0"
        "Apache 2.0"
        "BSD License"
        "BSD-3-Clause"
        "BSD-2-Clause"
        "ISC License"
        "ISC"
        "Mozilla Public License 2.0 (MPL 2.0)"
        "MPL-2.0"
        "Python Software Foundation License"
        "PSF"
    )
    
    # Define restricted licenses
    local restricted_licenses=(
        "GNU General Public License"
        "GPL"
        "GNU Lesser General Public License"
        "LGPL"
        "Copyleft"
        "AGPL"
        "GPL-3.0"
        "GPL-2.0"
    )
    
    # Analyze license compliance
    local compliance_issues=()
    
    log_info "Analyzing license compliance..."
    
    # Parse license report and check compliance
    python3 << EOF
import json
import sys

try:
    with open('$license_report', 'r') as f:
        licenses = json.load(f)
    
    approved = [${approved_licenses[@]/#/\"} ${approved_licenses[@]/%/\",}]
    approved = [license.strip('",') for license in approved if license.strip('",')]
    
    restricted = [${restricted_licenses[@]/#/\"} ${restricted_licenses[@]/%/\",}]
    restricted = [license.strip('",') for license in restricted if license.strip('",')]
    
    issues = []
    unknown = []
    
    for pkg in licenses:
        pkg_name = pkg.get('Name', 'Unknown')
        pkg_license = pkg.get('License', 'Unknown')
        
        # Normalize license name
        license_normalized = pkg_license.strip().replace('_', ' ')
        
        # Check if license is restricted
        is_restricted = any(restr.lower() in license_normalized.lower() for restr in restricted)
        if is_restricted:
            issues.append(f'{pkg_name}: {pkg_license} (RESTRICTED)')
            continue
        
        # Check if license is approved
        is_approved = any(appr.lower() in license_normalized.lower() for appr in approved)
        if not is_approved and pkg_license not in ['UNKNOWN', 'Unknown']:
            unknown.append(f'{pkg_name}: {pkg_license} (NEEDS_REVIEW)')
    
    if issues:
        print(f'RESTRICTED LICENSE VIOLATIONS ({len(issues)}):')
        for issue in issues:
            print(f'  - {issue}')
        sys.exit(1)
    
    if unknown:
        print(f'UNKNOWN LICENSES REQUIRING REVIEW ({len(unknown)}):')
        for unk in unknown:
            print(f'  - {unk}')
        print('\\nPlease review these licenses with your legal team.')
    
    print(f'\\nLicense compliance check completed.')
    print(f'Total packages: {len(licenses)}')
    print(f'Restricted violations: {len(issues)}')
    print(f'Unknown licenses: {len(unknown)}')
    
except Exception as e:
    print(f'Error analyzing license compliance: {e}')
    sys.exit(1)
EOF
    
    local license_exit_code=$?
    
    if [[ $license_exit_code -eq 0 ]]; then
        log_success "License compliance validation passed"
    else
        error_exit "License compliance validation failed"
    fi
}

# Upgrade dependencies with security focus
upgrade_dependencies() {
    local security_only="${1:-false}"
    local dry_run="${2:-false}"
    local env="${3:-dev}"
    
    log_info "Upgrading dependencies (security_only: $security_only, dry_run: $dry_run)..."
    
    if [[ "$security_only" == "true" ]]; then
        log_info "Security-focused upgrade: Only packages with known vulnerabilities will be upgraded"
        
        # Get list of vulnerable packages from safety
        local vulnerable_packages
        vulnerable_packages=$(python3 -m safety check --json --require "$REQUIREMENTS_TXT" 2>/dev/null | \
            python3 -c "
import json
import sys
try:
    data = json.load(sys.stdin)
    if isinstance(data, list):
        packages = set()
        for vuln in data:
            pkg = vuln.get('package_name')
            if pkg:
                packages.add(pkg)
        print(' '.join(packages))
except:
    pass
" 2>/dev/null)
        
        if [[ -n "$vulnerable_packages" ]]; then
            log_info "Vulnerable packages to upgrade: $vulnerable_packages"
            
            if [[ "$dry_run" == "false" ]]; then
                # Upgrade only vulnerable packages
                for pkg in $vulnerable_packages; do
                    log_info "Upgrading vulnerable package: $pkg"
                    python3 -m pip install --upgrade "$pkg" || log_warning "Failed to upgrade $pkg"
                done
                
                # Recompile requirements
                compile_requirements "true" "$env"
            else
                log_info "DRY RUN: Would upgrade packages: $vulnerable_packages"
            fi
        else
            log_success "No vulnerable packages found"
        fi
    else
        log_info "Full dependency upgrade"
        
        if [[ "$dry_run" == "false" ]]; then
            compile_requirements "true" "$env"
        else
            log_info "DRY RUN: Would recompile all requirements with --upgrade"
        fi
    fi
    
    # Run security scan after upgrade
    if [[ "$dry_run" == "false" ]]; then
        log_info "Running post-upgrade security scan..."
        security_scan "$env"
    fi
    
    log_success "Dependency upgrade completed"
}

# Install dependencies
install_dependencies() {
    local env="${1:-dev}"
    
    log_info "Installing dependencies for environment: $env"
    
    # Validate requirements file exists
    if [[ ! -f "$REQUIREMENTS_TXT" ]]; then
        log_warning "requirements.txt not found. Compiling from requirements.in..."
        compile_requirements "false" "$env"
    fi
    
    # Install production dependencies
    log_info "Installing production dependencies..."
    python3 -m pip install --requirement "$REQUIREMENTS_TXT" || error_exit "Failed to install production dependencies"
    
    # Install development dependencies if in dev environment
    if [[ "$env" == "dev" ]] && [[ -f "$REQUIREMENTS_DEV_TXT" ]]; then
        log_info "Installing development dependencies..."
        python3 -m pip install --requirement "$REQUIREMENTS_DEV_TXT" || error_exit "Failed to install development dependencies"
    fi
    
    log_success "Dependencies installation completed"
}

# Clean temporary files and caches
clean_dependencies() {
    log_info "Cleaning dependency management artifacts..."
    
    # Clean pip cache
    python3 -m pip cache purge || log_warning "Failed to clean pip cache"
    
    # Clean temporary files
    find "$PROJECT_ROOT" -name "*.pyc" -delete 2>/dev/null || true
    find "$PROJECT_ROOT" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
    
    # Clean old reports (keep last 10)
    if [[ -d "$SECURITY_REPORT_DIR" ]]; then
        find "$SECURITY_REPORT_DIR" -name "*.json" -type f | sort -r | tail -n +11 | xargs rm -f 2>/dev/null || true
    fi
    
    if [[ -d "$LICENSE_REPORT_DIR" ]]; then
        find "$LICENSE_REPORT_DIR" -name "*.json" -type f | sort -r | tail -n +11 | xargs rm -f 2>/dev/null || true
    fi
    
    log_success "Cleanup completed"
}

# Comprehensive validation
validate_all() {
    local env="${1:-dev}"
    
    log_info "Running comprehensive dependency validation..."
    
    # Validate requirements synchronization
    validate_requirements
    
    # Run security scans
    security_scan "$env"
    
    # Check license compliance
    license_check
    
    # Verify installation
    log_info "Verifying core dependencies installation..."
    python3 -c "
import sys
required_packages = [
    'flask', 'werkzeug', 'jinja2', 'pyjwt', 'cryptography',
    'pymongo', 'motor', 'redis', 'requests', 'httpx',
    'marshmallow', 'pydantic', 'python_dateutil', 'bleach'
]

missing = []
for pkg in required_packages:
    try:
        __import__(pkg.replace('-', '_'))
    except ImportError:
        missing.append(pkg)

if missing:
    print(f'Missing required packages: {missing}')
    sys.exit(1)
else:
    print('All core dependencies are properly installed')
" || error_exit "Core dependency validation failed"
    
    log_success "Comprehensive validation completed successfully"
}

# Main execution function
main() {
    local command="${1:-help}"
    shift || true
    
    # Parse command line arguments
    local env="dev"
    local force="false"
    local security_only="false"
    local dry_run="false"
    local verbose="false"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --env)
                env="$2"
                shift 2
                ;;
            --force)
                force="true"
                shift
                ;;
            --security-only)
                security_only="true"
                shift
                ;;
            --dry-run)
                dry_run="true"
                shift
                ;;
            --verbose)
                verbose="true"
                set -x
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Setup environment
    setup_environment
    
    # Install development tools
    install_dev_tools "$force"
    
    # Execute command
    case "$command" in
        "install")
            install_dependencies "$env"
            ;;
        "compile")
            compile_requirements "$force" "$env"
            ;;
        "upgrade")
            upgrade_dependencies "$security_only" "$dry_run" "$env"
            ;;
        "security-scan")
            security_scan "$env"
            ;;
        "license-check")
            license_check
            ;;
        "validate")
            validate_all "$env"
            ;;
        "clean")
            clean_dependencies
            ;;
        "help"|"")
            show_help
            ;;
        *)
            log_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi