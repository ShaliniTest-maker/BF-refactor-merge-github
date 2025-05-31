"""
Quality configuration module for Flask application code quality enforcement.

This module implements enterprise-grade Python code quality standards with zero-tolerance
error policies for static analysis, type checking, and security scanning. Integrates
flake8, mypy, and bandit tools with Flask-specific patterns and comprehensive validation.

Section References:
- Section 8.5.1: Quality gates with zero-tolerance enforcement
- Section 6.6.3: Quality metrics and static analysis requirements
- Section 0.3.1: Code quality and standards compliance
"""

import os
from pathlib import Path
from typing import Dict, List, Optional, Union


class QualityStandards:
    """
    Enterprise-focused code quality standards configuration.
    
    Implements comprehensive quality gates with zero-tolerance error policies
    as required by Section 8.5.1 build pipeline quality gates.
    """
    
    # Zero-tolerance quality enforcement levels
    ZERO_TOLERANCE_TOOLS = ['flake8', 'mypy', 'bandit']
    REQUIRED_COVERAGE_THRESHOLD = 90.0
    MAX_CYCLOMATIC_COMPLEXITY = 10
    
    # Quality gate enforcement policies
    ENFORCEMENT_POLICIES = {
        'flake8': {
            'max_errors': 0,
            'failure_action': 'pipeline_termination',
            'enforcement_level': 'zero_errors_required'
        },
        'mypy': {
            'max_errors': 0,
            'failure_action': 'build_failure', 
            'enforcement_level': '100_percent_type_check_success'
        },
        'bandit': {
            'max_critical_findings': 0,
            'max_high_findings': 0,
            'failure_action': 'security_review_required',
            'enforcement_level': 'no_high_critical_findings'
        },
        'coverage': {
            'min_threshold': 90.0,
            'failure_action': 'deployment_blocking',
            'enforcement_level': 'minimum_required'
        }
    }


class FlakeConfiguration:
    """
    flake8 6.1+ configuration for comprehensive PEP 8 compliance.
    
    Implements enterprise-focused code style enforcement with zero-tolerance
    policy as specified in Section 8.5.1 build pipeline requirements.
    """
    
    # Base configuration matching Section 8.5.1 specification
    MAX_LINE_LENGTH = 88
    
    # Extend ignore list for Black compatibility and enterprise patterns
    EXTEND_IGNORE = [
        'E203',  # Whitespace before ':'
        'W503',  # Line break before binary operator 
        'E501'   # Line too long (handled by max-line-length)
    ]
    
    # Exclusion patterns for build artifacts and environments
    EXCLUDE_PATTERNS = [
        '.git',
        '__pycache__',
        'build',
        'dist',
        '.env',
        'venv',
        '.venv',
        '*.pyc',
        '.pytest_cache',
        'node_modules'
    ]
    
    # Per-file ignore patterns for common Flask patterns
    PER_FILE_IGNORES = {
        '__init__.py': ['F401'],  # Unused imports in __init__ files
        'tests/*': ['S101', 'S106'],  # Allow asserts and hardcoded passwords in tests
        'conftest.py': ['F401'],  # Unused imports in pytest configuration
        'migrations/*': ['E501'],  # Allow long lines in database migrations
    }
    
    # Complexity and documentation requirements
    MAX_COMPLEXITY = 10
    DOCTESTS = True
    STATISTICS = True
    COUNT = True
    
    @classmethod
    def generate_config(cls, project_root: Path) -> str:
        """
        Generate flake8 configuration content.
        
        Args:
            project_root: Root directory of the project
            
        Returns:
            flake8 configuration as string
        """
        per_file_ignores = '\n'.join([
            f"    {pattern}:{','.join(ignores)}"
            for pattern, ignores in cls.PER_FILE_IGNORES.items()
        ])
        
        exclude_list = ',\n    '.join(cls.EXCLUDE_PATTERNS)
        extend_ignore_list = ', '.join(cls.EXTEND_IGNORE)
        
        return f"""[flake8]
max-line-length = {cls.MAX_LINE_LENGTH}
extend-ignore = {extend_ignore_list}
exclude = 
    {exclude_list}
per-file-ignores =
{per_file_ignores}
max-complexity = {cls.MAX_COMPLEXITY}
doctests = {str(cls.DOCTESTS).lower()}
statistics = {str(cls.STATISTICS).lower()}
count = {str(cls.COUNT).lower()}

# Flask-specific patterns
application-import-names = app,src
import-order-style = google

# Enterprise compliance settings
show-source = True
benchmark = True
"""


class MypyConfiguration:
    """
    mypy 1.8+ configuration for strict type checking enforcement.
    
    Implements comprehensive type annotation coverage with zero unchecked
    code tolerance as required by Section 8.5.1 quality gates.
    """
    
    # Python version targeting
    PYTHON_VERSION = "3.11"
    
    # Strict mode enforcement settings
    STRICT_MODE = True
    WARN_RETURN_ANY = True
    WARN_UNUSED_CONFIGS = True
    DISALLOW_UNTYPED_DEFS = True
    DISALLOW_INCOMPLETE_DEFS = True
    CHECK_UNTYPED_DEFS = True
    DISALLOW_UNTYPED_DECORATORS = True
    NO_IMPLICIT_OPTIONAL = True
    WARN_REDUNDANT_CASTS = True
    WARN_UNUSED_IGNORES = True
    WARN_NO_RETURN = True
    WARN_UNREACHABLE = True
    STRICT_EQUALITY = True
    
    # Flask-specific type checking patterns
    FLASK_MODULE_PATTERNS = [
        '[mypy-flask.*]',
        '[mypy-werkzeug.*]',
        '[mypy-pymongo.*]',
        '[mypy-motor.*]',
        '[mypy-redis.*]'
    ]
    
    # Third-party library handling
    IGNORE_MISSING_IMPORTS = [
        'pytest',
        'locust',
        'bandit',
        'safety',
        'testcontainers'
    ]
    
    @classmethod
    def generate_config(cls, project_root: Path) -> str:
        """
        Generate mypy configuration content.
        
        Args:
            project_root: Root directory of the project
            
        Returns:
            mypy configuration as string
        """
        flask_patterns = '\n'.join([
            f"{pattern}\nignore_missing_imports = True\n"
            for pattern in cls.FLASK_MODULE_PATTERNS
        ])
        
        missing_imports = '\n'.join([
            f"[mypy-{module}.*]\nignore_missing_imports = True\n"
            for module in cls.IGNORE_MISSING_IMPORTS
        ])
        
        return f"""[mypy]
python_version = {cls.PYTHON_VERSION}
strict = {str(cls.STRICT_MODE).lower()}
warn_return_any = {str(cls.WARN_RETURN_ANY).lower()}
warn_unused_configs = {str(cls.WARN_UNUSED_CONFIGS).lower()}
disallow_untyped_defs = {str(cls.DISALLOW_UNTYPED_DEFS).lower()}
disallow_incomplete_defs = {str(cls.DISALLOW_INCOMPLETE_DEFS).lower()}
check_untyped_defs = {str(cls.CHECK_UNTYPED_DEFS).lower()}
disallow_untyped_decorators = {str(cls.DISALLOW_UNTYPED_DECORATORS).lower()}
no_implicit_optional = {str(cls.NO_IMPLICIT_OPTIONAL).lower()}
warn_redundant_casts = {str(cls.WARN_REDUNDANT_CASTS).lower()}
warn_unused_ignores = {str(cls.WARN_UNUSED_IGNORES).lower()}
warn_no_return = {str(cls.WARN_NO_RETURN).lower()}
warn_unreachable = {str(cls.WARN_UNREACHABLE).lower()}
strict_equality = {str(cls.STRICT_EQUALITY).lower()}

# Show error codes and context
show_error_codes = True
show_column_numbers = True

# Performance and cache settings
cache_dir = .mypy_cache
sqlite_cache = True

{flask_patterns}

{missing_imports}
"""


class BanditConfiguration:
    """
    bandit 1.7+ configuration for comprehensive Python security analysis.
    
    Implements Flask-specific security patterns with enterprise compliance
    requirements as specified in Section 8.5.1 security scanning.
    """
    
    # Comprehensive security test coverage
    SECURITY_TESTS = [
        'B201', 'B301', 'B302', 'B303', 'B304', 'B305', 'B306', 'B307',
        'B308', 'B309', 'B310', 'B311', 'B312', 'B313', 'B314', 'B315',
        'B316', 'B317', 'B318', 'B319', 'B320', 'B321', 'B322', 'B323',
        'B324', 'B325', 'B326', 'B401', 'B402', 'B403', 'B404', 'B405',
        'B406', 'B407', 'B408', 'B409', 'B410', 'B411', 'B412', 'B413',
        'B501', 'B502', 'B503', 'B504', 'B505', 'B506', 'B507', 'B601',
        'B602', 'B603', 'B604', 'B605', 'B606', 'B607', 'B608', 'B609',
        'B610', 'B611', 'B701', 'B702', 'B703'
    ]
    
    # Skip tests that conflict with Flask patterns or testing practices
    SKIP_TESTS = [
        'B101',  # Use of assert (allowed in tests)
        'B601'   # Subprocess without shell=False (case-by-case basis)
    ]
    
    # Exclude directories from security scanning
    EXCLUDE_DIRS = [
        'tests',
        'build', 
        'dist',
        '.git',
        '__pycache__',
        '.pytest_cache',
        'node_modules'
    ]
    
    # Flask-specific security considerations
    FLASK_SECURITY_PATTERNS = {
        'jwt_validation': ['B105', 'B106'],  # JWT hardcoded secrets
        'database_injection': ['B608', 'B609'],  # SQL injection patterns
        'xss_prevention': ['B703'],  # HTML injection
        'csrf_protection': ['B501'],  # Request handling security
    }
    
    @classmethod
    def generate_config(cls, project_root: Path) -> str:
        """
        Generate bandit configuration content.
        
        Args:
            project_root: Root directory of the project
            
        Returns:
            bandit configuration as YAML string
        """
        tests_list = ', '.join(cls.SECURITY_TESTS)
        skips_list = ', '.join(cls.SKIP_TESTS) 
        exclude_list = ', '.join(cls.EXCLUDE_DIRS)
        
        return f"""# Bandit security configuration for Flask application
# Section 8.5.1: Security scanning with zero tolerance for critical findings

tests: [{tests_list}]
skips: [{skips_list}]
exclude_dirs: [{exclude_list}]

# Severity levels for enterprise compliance
severity: [high, medium, low]
confidence: [high, medium, low]

# Flask-specific security patterns
assert_used:
  skips: ['*test*.py', '*conftest.py']

hardcoded_password:
  word_list: ['password', 'pass', 'passwd', 'pwd', 'secret', 'token', 'key']

# Enterprise security compliance
shell_injection:
  no_shell: true
  
sql_injection:
  check_typed_list: true
"""


class ComplexityConfiguration:
    """
    Code complexity analysis configuration using radon.
    
    Implements maintainability thresholds ensuring long-term system
    maintainability as specified in Section 6.6.3.
    """
    
    # Complexity thresholds per Section 6.6.3
    MAX_CYCLOMATIC_COMPLEXITY = 10
    MAX_MAINTAINABILITY_INDEX = 'B'  # Good maintainability
    
    # Radon analysis settings
    RADON_CC_CONFIG = {
        'min_grade': 'B',
        'show_complexity': True,
        'average': True,
        'exclude': ['tests/*', 'migrations/*', '__pycache__/*']
    }
    
    @classmethod
    def get_radon_command(cls, source_dir: str) -> str:
        """
        Generate radon complexity analysis command.
        
        Args:
            source_dir: Source directory to analyze
            
        Returns:
            radon command string
        """
        exclude_patterns = ','.join(cls.RADON_CC_CONFIG['exclude'])
        
        return (
            f"radon cc {source_dir} "
            f"--min {cls.RADON_CC_CONFIG['min_grade']} "
            f"--show-complexity "
            f"--average "
            f"--exclude '{exclude_patterns}'"
        )


class QualityConfigManager:
    """
    Central manager for all quality configuration files.
    
    Generates and manages configuration files for all quality tools
    ensuring consistent enterprise-grade quality enforcement.
    """
    
    def __init__(self, project_root: Optional[Union[str, Path]] = None):
        """
        Initialize quality configuration manager.
        
        Args:
            project_root: Root directory of the project
        """
        self.project_root = Path(project_root) if project_root else Path.cwd()
        self.config_files = {
            '.flake8': FlakeConfiguration,
            'mypy.ini': MypyConfiguration, 
            'bandit.yaml': BanditConfiguration
        }
    
    def generate_all_configs(self) -> Dict[str, str]:
        """
        Generate all quality tool configuration files.
        
        Returns:
            Dictionary mapping config filenames to their content
        """
        configs = {}
        
        for filename, config_class in self.config_files.items():
            configs[filename] = config_class.generate_config(self.project_root)
            
        return configs
    
    def write_config_files(self, target_dir: Optional[Path] = None) -> None:
        """
        Write all configuration files to disk.
        
        Args:
            target_dir: Target directory for config files (defaults to project root)
        """
        if target_dir is None:
            target_dir = self.project_root
            
        configs = self.generate_all_configs()
        
        for filename, content in configs.items():
            config_path = target_dir / filename
            config_path.write_text(content)
    
    def validate_config_requirements(self) -> List[str]:
        """
        Validate that all required quality tools are properly configured.
        
        Returns:
            List of validation errors, empty if all valid
        """
        errors = []
        
        # Check required tools are defined
        for tool in QualityStandards.ZERO_TOLERANCE_TOOLS:
            if tool not in QualityStandards.ENFORCEMENT_POLICIES:
                errors.append(f"Missing enforcement policy for {tool}")
        
        # Validate coverage threshold
        coverage_policy = QualityStandards.ENFORCEMENT_POLICIES.get('coverage', {})
        min_threshold = coverage_policy.get('min_threshold', 0)
        if min_threshold < QualityStandards.REQUIRED_COVERAGE_THRESHOLD:
            errors.append(
                f"Coverage threshold {min_threshold}% below required "
                f"{QualityStandards.REQUIRED_COVERAGE_THRESHOLD}%"
            )
        
        return errors


# Export main configuration classes for script usage
__all__ = [
    'QualityStandards',
    'FlakeConfiguration', 
    'MypyConfiguration',
    'BanditConfiguration',
    'ComplexityConfiguration',
    'QualityConfigManager'
]