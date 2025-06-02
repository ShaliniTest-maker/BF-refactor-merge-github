"""
Configuration management utilities providing enterprise-grade environment variable handling,
configuration validation, and settings management using python-dotenv 1.0+.

This module implements the configuration file format migration from JSON to Python modules
as specified in Section 0.2.5 and provides environment-specific configuration loading
supporting the Flask application factory pattern per Section 6.1.1.

Key Features:
- Environment variable management using python-dotenv 1.0+ per Section 0.2.4 dependency decisions
- Configuration validation and settings management per Section 5.4.1 cross-cutting concerns
- Environment-specific configuration loading for deployment flexibility per Section 0.2.5
- Flask application factory pattern support with centralized configuration management
- Enterprise-grade configuration patterns with comprehensive validation and error handling
- Type-safe configuration access with validation and default value management
- Configuration inheritance and environment-specific overrides
"""

import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, Union, Callable, TypeVar, Generic
from urllib.parse import urlparse
import structlog

from dotenv import load_dotenv, find_dotenv
from .validators import (
    ValidationResult, 
    validate_required_string, 
    validate_optional_string,
    validate_url,
    validate_numeric_range,
    validate_email_address,
    sanitize_input
)

# Type variable for configuration classes
ConfigType = TypeVar('ConfigType')

# Get structured logger
logger = structlog.get_logger(__name__)

# Default environment configuration
DEFAULT_ENV_FILE = '.env'
DEFAULT_ENVIRONMENT = 'development'

# Configuration validation patterns
CONFIG_VALIDATION_RULES = {
    'string_required': validate_required_string,
    'string_optional': validate_optional_string,
    'url': lambda value, field_name='url': validate_url(value, require_https=False),
    'url_https': lambda value, field_name='url': validate_url(value, require_https=True),
    'email': validate_email_address,
    'port': lambda value, field_name='port': validate_numeric_range(
        value, min_value=1, max_value=65535, allow_decimal=False
    ),
    'positive_integer': lambda value, field_name='number': validate_numeric_range(
        value, min_value=1, allow_decimal=False
    ),
    'non_negative_integer': lambda value, field_name='number': validate_numeric_range(
        value, min_value=0, allow_decimal=False
    ),
    'percentage': lambda value, field_name='percentage': validate_numeric_range(
        value, min_value=0, max_value=100, allow_decimal=True
    )
}


class ConfigurationError(Exception):
    """
    Configuration-specific exception for configuration validation and loading errors.
    
    Provides structured error reporting for configuration issues with detailed
    context and validation failure information per Section 5.4.2 error handling patterns.
    """
    
    def __init__(
        self,
        message: str,
        field_name: Optional[str] = None,
        validation_errors: Optional[List[str]] = None,
        config_source: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message)
        self.message = message
        self.field_name = field_name
        self.validation_errors = validation_errors or []
        self.config_source = config_source
        self.details = details or {}
        self.timestamp = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration error to dictionary format for logging."""
        return {
            'message': self.message,
            'field_name': self.field_name,
            'validation_errors': self.validation_errors,
            'config_source': self.config_source,
            'details': self.details,
            'timestamp': self.timestamp.isoformat()
        }


class ConfigurationManager:
    """
    Central configuration manager providing environment variable loading, validation,
    and settings management using python-dotenv 1.0+ per Section 0.2.4 dependency decisions.
    
    Implements enterprise-grade configuration patterns supporting Flask application factory
    pattern with environment-specific settings and comprehensive validation capabilities.
    """
    
    def __init__(
        self,
        env_file: Optional[str] = None,
        environment: Optional[str] = None,
        auto_load: bool = True,
        validate_on_load: bool = True
    ):
        """
        Initialize configuration manager with environment-specific loading.
        
        Args:
            env_file: Path to .env file (defaults to finding .env)
            environment: Target environment (development, testing, production)
            auto_load: Whether to automatically load environment variables
            validate_on_load: Whether to validate configuration on load
        """
        self.env_file = env_file
        self.environment = environment or os.getenv('FLASK_ENV', DEFAULT_ENVIRONMENT)
        self.validate_on_load = validate_on_load
        self._loaded_vars: Dict[str, str] = {}
        self._validation_rules: Dict[str, Callable] = {}
        self._required_vars: List[str] = []
        self._default_values: Dict[str, Any] = {}
        
        logger.info(
            "Initializing configuration manager",
            environment=self.environment,
            env_file=self.env_file,
            auto_load=auto_load,
            validate_on_load=validate_on_load
        )
        
        if auto_load:
            self.load_environment()
    
    def load_environment(self, env_file: Optional[str] = None) -> Dict[str, str]:
        """
        Load environment variables from .env file using python-dotenv 1.0+.
        
        Implements environment variable management per Section 0.2.4 dependency decisions
        with comprehensive error handling and validation support.
        
        Args:
            env_file: Specific .env file path to load
        
        Returns:
            Dictionary of loaded environment variables
        
        Raises:
            ConfigurationError: For environment loading failures
        """
        target_env_file = env_file or self.env_file
        
        try:
            # Find .env file if not specified
            if not target_env_file:
                target_env_file = find_dotenv()
                if not target_env_file:
                    # Try common .env file locations
                    possible_locations = [
                        '.env',
                        '.env.local',
                        f'.env.{self.environment}',
                        f'.env.{self.environment}.local'
                    ]
                    
                    for location in possible_locations:
                        if os.path.exists(location):
                            target_env_file = location
                            break
            
            # Load environment variables
            if target_env_file and os.path.exists(target_env_file):
                load_dotenv(target_env_file, override=True)
                self.env_file = target_env_file
                
                # Track loaded variables for validation
                self._loaded_vars = self._get_env_vars_from_file(target_env_file)
                
                logger.info(
                    "Environment variables loaded successfully",
                    env_file=target_env_file,
                    variables_count=len(self._loaded_vars),
                    environment=self.environment
                )
            else:
                logger.warning(
                    "No .env file found, using system environment variables only",
                    environment=self.environment,
                    attempted_file=target_env_file
                )
                self._loaded_vars = dict(os.environ)
            
            # Validate configuration if enabled
            if self.validate_on_load:
                validation_result = self.validate_configuration()
                if not validation_result.is_valid:
                    raise ConfigurationError(
                        message="Configuration validation failed",
                        validation_errors=validation_result.errors,
                        config_source=target_env_file,
                        details={"environment": self.environment}
                    )
            
            return self._loaded_vars
            
        except Exception as e:
            error_msg = f"Failed to load environment configuration: {str(e)}"
            logger.error(
                "Environment loading failed",
                error=str(e),
                env_file=target_env_file,
                environment=self.environment
            )
            
            raise ConfigurationError(
                message=error_msg,
                config_source=target_env_file,
                details={"environment": self.environment, "error": str(e)}
            )
    
    def _get_env_vars_from_file(self, env_file_path: str) -> Dict[str, str]:
        """Extract environment variables from .env file for tracking."""
        env_vars = {}
        try:
            with open(env_file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")
                        env_vars[key] = value
        except Exception as e:
            logger.warning(
                "Failed to parse .env file for tracking",
                env_file=env_file_path,
                error=str(e)
            )
        
        return env_vars
    
    def get_config_value(
        self,
        key: str,
        default: Any = None,
        required: bool = False,
        value_type: Type = str,
        validator: Optional[Callable] = None
    ) -> Any:
        """
        Get configuration value with validation and type conversion.
        
        Provides type-safe configuration access with comprehensive validation
        per Section 5.4.1 configuration validation and settings management.
        
        Args:
            key: Environment variable key
            default: Default value if not found
            required: Whether the configuration value is required
            value_type: Expected value type for conversion
            validator: Custom validation function
        
        Returns:
            Configuration value with appropriate type conversion
        
        Raises:
            ConfigurationError: For missing required values or validation failures
        """
        # Get raw value from environment
        raw_value = os.getenv(key, default)
        
        # Check required values
        if required and raw_value is None:
            error_msg = f"Required configuration value '{key}' is missing"
            logger.error(
                "Missing required configuration",
                key=key,
                environment=self.environment
            )
            raise ConfigurationError(
                message=error_msg,
                field_name=key,
                config_source=self.env_file,
                details={"required": True, "environment": self.environment}
            )
        
        # Return None for optional missing values
        if raw_value is None:
            return None
        
        try:
            # Type conversion
            if value_type == bool:
                converted_value = str(raw_value).lower() in ('true', '1', 'yes', 'on')
            elif value_type == int:
                converted_value = int(raw_value)
            elif value_type == float:
                converted_value = float(raw_value)
            elif value_type == list:
                # Support comma-separated lists
                converted_value = [item.strip() for item in str(raw_value).split(',') if item.strip()]
            else:
                converted_value = value_type(raw_value)
            
            # Apply custom validation if provided
            if validator:
                validation_result = validator(converted_value, key)
                if isinstance(validation_result, ValidationResult) and not validation_result.is_valid:
                    raise ConfigurationError(
                        message=f"Configuration validation failed for '{key}'",
                        field_name=key,
                        validation_errors=validation_result.errors,
                        config_source=self.env_file,
                        details={"value": str(raw_value), "environment": self.environment}
                    )
                elif isinstance(validation_result, ValidationResult):
                    # Use validated value if available
                    converted_value = validation_result.value or converted_value
            
            logger.debug(
                "Configuration value retrieved",
                key=key,
                value_type=value_type.__name__,
                has_validator=validator is not None,
                environment=self.environment
            )
            
            return converted_value
            
        except (ValueError, TypeError) as e:
            error_msg = f"Configuration value '{key}' type conversion failed: {str(e)}"
            logger.error(
                "Configuration type conversion failed",
                key=key,
                raw_value=raw_value,
                target_type=value_type.__name__,
                error=str(e)
            )
            
            raise ConfigurationError(
                message=error_msg,
                field_name=key,
                config_source=self.env_file,
                details={
                    "raw_value": str(raw_value),
                    "target_type": value_type.__name__,
                    "conversion_error": str(e)
                }
            )
    
    def register_validation_rule(self, key: str, validator: Callable, required: bool = False) -> None:
        """
        Register validation rule for configuration key.
        
        Provides configuration validation management supporting enterprise-grade
        configuration patterns per Section 5.4.1 cross-cutting concerns.
        
        Args:
            key: Configuration key to validate
            validator: Validation function
            required: Whether the configuration value is required
        """
        self._validation_rules[key] = validator
        if required and key not in self._required_vars:
            self._required_vars.append(key)
        
        logger.debug(
            "Configuration validation rule registered",
            key=key,
            required=required,
            validator_name=validator.__name__ if hasattr(validator, '__name__') else str(validator)
        )
    
    def set_default_value(self, key: str, value: Any) -> None:
        """Set default value for configuration key."""
        self._default_values[key] = value
        logger.debug("Configuration default value set", key=key, value=str(value))
    
    def validate_configuration(self) -> ValidationResult:
        """
        Validate all registered configuration values.
        
        Implements comprehensive configuration validation per Section 5.4.1
        configuration validation and settings management with structured error reporting.
        
        Returns:
            ValidationResult with overall configuration validation status
        """
        all_errors = []
        
        # Check required variables
        for required_var in self._required_vars:
            if not os.getenv(required_var) and required_var not in self._default_values:
                all_errors.append(f"Required configuration variable '{required_var}' is missing")
        
        # Validate registered rules
        for key, validator in self._validation_rules.items():
            try:
                value = os.getenv(key, self._default_values.get(key))
                if value is not None:
                    validation_result = validator(value, key)
                    if isinstance(validation_result, ValidationResult) and not validation_result.is_valid:
                        all_errors.extend([f"{key}: {error}" for error in validation_result.errors])
            except Exception as e:
                all_errors.append(f"Validation error for '{key}': {str(e)}")
        
        is_valid = len(all_errors) == 0
        
        logger.info(
            "Configuration validation completed",
            is_valid=is_valid,
            errors_count=len(all_errors),
            validated_keys=len(self._validation_rules),
            required_keys=len(self._required_vars)
        )
        
        return ValidationResult(is_valid, None, all_errors, "configuration")
    
    def get_database_url(
        self,
        db_type: str = 'mongodb',
        require_ssl: bool = False
    ) -> Optional[str]:
        """
        Get database connection URL with validation.
        
        Supports MongoDB and Redis connection URL generation with enterprise-grade
        validation and security requirements per Section 6.1.3 resource optimization.
        
        Args:
            db_type: Database type ('mongodb', 'redis')
            require_ssl: Whether to require SSL/TLS connection
        
        Returns:
            Validated database connection URL
        
        Raises:
            ConfigurationError: For invalid database configuration
        """
        if db_type.lower() == 'mongodb':
            url_key = 'MONGODB_URL'
            default_port = 27017
        elif db_type.lower() == 'redis':
            url_key = 'REDIS_URL'
            default_port = 6379
        else:
            raise ConfigurationError(
                message=f"Unsupported database type: {db_type}",
                details={"supported_types": ["mongodb", "redis"]}
            )
        
        # Try to get full URL first
        full_url = self.get_config_value(url_key)
        if full_url:
            # Validate URL format
            validation_result = validate_url(full_url, require_https=require_ssl)
            if not validation_result.is_valid:
                raise ConfigurationError(
                    message=f"Invalid {db_type} URL format",
                    field_name=url_key,
                    validation_errors=validation_result.errors,
                    config_source=self.env_file
                )
            return full_url
        
        # Build URL from components
        host = self.get_config_value(f'{db_type.upper()}_HOST', 'localhost')
        port = self.get_config_value(f'{db_type.upper()}_PORT', default_port, value_type=int)
        username = self.get_config_value(f'{db_type.upper()}_USERNAME')
        password = self.get_config_value(f'{db_type.upper()}_PASSWORD')
        database = self.get_config_value(f'{db_type.upper()}_DATABASE')
        
        # Construct URL
        if db_type.lower() == 'mongodb':
            scheme = 'mongodb+srv' if require_ssl else 'mongodb'
            if username and password:
                auth_part = f"{username}:{password}@"
            else:
                auth_part = ""
            
            if database:
                url = f"{scheme}://{auth_part}{host}:{port}/{database}"
            else:
                url = f"{scheme}://{auth_part}{host}:{port}"
        else:  # redis
            scheme = 'rediss' if require_ssl else 'redis'
            if password:
                auth_part = f":{password}@"
            else:
                auth_part = ""
            
            if database:
                url = f"{scheme}://{auth_part}{host}:{port}/{database}"
            else:
                url = f"{scheme}://{auth_part}{host}:{port}"
        
        logger.info(
            f"{db_type} URL constructed from components",
            db_type=db_type,
            host=host,
            port=port,
            has_auth=bool(username and password),
            has_database=bool(database),
            ssl_required=require_ssl
        )
        
        return url
    
    def get_flask_config_class(self, environment: Optional[str] = None) -> str:
        """
        Get Flask configuration class name for the specified environment.
        
        Supports Flask application factory pattern per Section 6.1.1 with
        environment-specific configuration class selection.
        
        Args:
            environment: Target environment (defaults to current environment)
        
        Returns:
            Flask configuration class name
        """
        target_env = environment or self.environment
        
        # Configuration class mapping
        config_classes = {
            'development': 'DevelopmentConfig',
            'testing': 'TestingConfig',
            'production': 'ProductionConfig'
        }
        
        config_class = config_classes.get(target_env.lower(), 'DevelopmentConfig')
        
        logger.debug(
            "Flask configuration class selected",
            environment=target_env,
            config_class=config_class
        )
        
        return config_class
    
    def export_environment_variables(self) -> Dict[str, str]:
        """
        Export current environment variables for subprocess or external use.
        
        Returns:
            Dictionary of current environment variables
        """
        return dict(os.environ)
    
    def create_config_dict(self, prefix: str = '') -> Dict[str, Any]:
        """
        Create configuration dictionary with optional prefix filtering.
        
        Provides configuration dictionary generation supporting Flask configuration
        patterns and external service configuration requirements.
        
        Args:
            prefix: Variable prefix filter (e.g., 'FLASK_', 'DATABASE_')
        
        Returns:
            Filtered configuration dictionary
        """
        config_dict = {}
        
        for key, value in os.environ.items():
            if not prefix or key.startswith(prefix):
                # Remove prefix for cleaner keys
                clean_key = key[len(prefix):] if prefix else key
                config_dict[clean_key] = value
        
        logger.debug(
            "Configuration dictionary created",
            prefix=prefix,
            keys_count=len(config_dict)
        )
        
        return config_dict
    
    def reload_configuration(self) -> Dict[str, str]:
        """
        Reload environment configuration for runtime updates.
        
        Provides configuration hot-reloading capability supporting enterprise
        deployment patterns with runtime configuration updates.
        
        Returns:
            Updated environment variables dictionary
        """
        logger.info("Reloading configuration", environment=self.environment)
        return self.load_environment()


class FlaskConfigBuilder:
    """
    Flask configuration builder providing dynamic configuration class generation
    supporting the Flask application factory pattern per Section 6.1.1.
    
    Enables enterprise-grade configuration management with environment-specific
    settings and comprehensive validation capabilities.
    """
    
    def __init__(self, config_manager: ConfigurationManager):
        """
        Initialize Flask configuration builder.
        
        Args:
            config_manager: ConfigurationManager instance for environment handling
        """
        self.config_manager = config_manager
        self.logger = structlog.get_logger(__name__)
    
    def build_config_dict(self, environment: str = 'development') -> Dict[str, Any]:
        """
        Build Flask configuration dictionary for the specified environment.
        
        Implements configuration file format migration from JSON to Python modules
        per Section 0.2.5 with comprehensive Flask configuration support.
        
        Args:
            environment: Target environment for configuration
        
        Returns:
            Flask configuration dictionary
        """
        config = {}
        
        # Base Flask configuration
        config['SECRET_KEY'] = self.config_manager.get_config_value(
            'SECRET_KEY',
            required=True,
            validator=lambda v, k: validate_required_string(v, k)
        )
        
        config['FLASK_ENV'] = environment
        config['DEBUG'] = environment == 'development'
        config['TESTING'] = environment == 'testing'
        
        # Database configuration
        try:
            config['MONGODB_URL'] = self.config_manager.get_database_url('mongodb')
            config['REDIS_URL'] = self.config_manager.get_database_url('redis')
        except ConfigurationError as e:
            self.logger.warning("Database URL configuration incomplete", error=str(e))
        
        # Security configuration
        config['JWT_SECRET_KEY'] = self.config_manager.get_config_value(
            'JWT_SECRET_KEY',
            default=config['SECRET_KEY']
        )
        
        config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(
            hours=self.config_manager.get_config_value(
                'JWT_ACCESS_TOKEN_EXPIRES_HOURS',
                default=24,
                value_type=int
            )
        )
        
        # CORS configuration
        config['CORS_ORIGINS'] = self.config_manager.get_config_value(
            'CORS_ORIGINS',
            default=['http://localhost:3000'],
            value_type=list
        )
        
        # Rate limiting configuration
        config['RATELIMIT_STORAGE_URL'] = config.get('REDIS_URL', 'memory://')
        config['RATELIMIT_DEFAULT'] = self.config_manager.get_config_value(
            'RATELIMIT_DEFAULT',
            default='100 per hour'
        )
        
        # File upload configuration
        config['MAX_CONTENT_LENGTH'] = self.config_manager.get_config_value(
            'MAX_CONTENT_LENGTH',
            default=16 * 1024 * 1024,  # 16MB
            value_type=int
        )
        
        # External service configuration
        config['AUTH0_DOMAIN'] = self.config_manager.get_config_value('AUTH0_DOMAIN')
        config['AUTH0_CLIENT_ID'] = self.config_manager.get_config_value('AUTH0_CLIENT_ID')
        config['AUTH0_CLIENT_SECRET'] = self.config_manager.get_config_value('AUTH0_CLIENT_SECRET')
        
        # AWS configuration
        config['AWS_ACCESS_KEY_ID'] = self.config_manager.get_config_value('AWS_ACCESS_KEY_ID')
        config['AWS_SECRET_ACCESS_KEY'] = self.config_manager.get_config_value('AWS_SECRET_ACCESS_KEY')
        config['AWS_REGION'] = self.config_manager.get_config_value('AWS_REGION', default='us-east-1')
        config['AWS_S3_BUCKET'] = self.config_manager.get_config_value('AWS_S3_BUCKET')
        
        # Monitoring configuration
        config['MONITORING_ENABLED'] = self.config_manager.get_config_value(
            'MONITORING_ENABLED',
            default=True,
            value_type=bool
        )
        
        config['METRICS_ENABLED'] = self.config_manager.get_config_value(
            'METRICS_ENABLED',
            default=True,
            value_type=bool
        )
        
        # Environment-specific overrides
        if environment == 'production':
            config['DEBUG'] = False
            config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Shorter in production
        elif environment == 'testing':
            config['TESTING'] = True
            config['WTF_CSRF_ENABLED'] = False
        
        self.logger.info(
            "Flask configuration built",
            environment=environment,
            config_keys=len(config),
            has_database=bool(config.get('MONGODB_URL')),
            has_cache=bool(config.get('REDIS_URL'))
        )
        
        return config


# Convenience functions for common configuration patterns
def load_dotenv_config(
    env_file: Optional[str] = None,
    environment: Optional[str] = None,
    validate: bool = True
) -> ConfigurationManager:
    """
    Load configuration using python-dotenv with validation.
    
    Convenience function implementing python-dotenv 1.0+ configuration loading
    per Section 0.2.4 dependency decisions with enterprise-grade validation.
    
    Args:
        env_file: Path to .env file
        environment: Target environment
        validate: Whether to validate configuration
    
    Returns:
        Configured ConfigurationManager instance
    """
    config_manager = ConfigurationManager(
        env_file=env_file,
        environment=environment,
        validate_on_load=validate
    )
    
    # Register common validation rules
    config_manager.register_validation_rule(
        'SECRET_KEY',
        CONFIG_VALIDATION_RULES['string_required'],
        required=True
    )
    
    config_manager.register_validation_rule(
        'MONGODB_URL',
        CONFIG_VALIDATION_RULES['url']
    )
    
    config_manager.register_validation_rule(
        'REDIS_URL',
        CONFIG_VALIDATION_RULES['url']
    )
    
    return config_manager


def get_flask_config_for_environment(environment: str = 'development') -> Dict[str, Any]:
    """
    Get Flask configuration dictionary for specified environment.
    
    Provides direct Flask configuration generation supporting the application
    factory pattern per Section 6.1.1 with comprehensive configuration management.
    
    Args:
        environment: Target environment (development, testing, production)
    
    Returns:
        Flask configuration dictionary
    """
    config_manager = load_dotenv_config(environment=environment)
    builder = FlaskConfigBuilder(config_manager)
    return builder.build_config_dict(environment)


def validate_required_config_vars(*var_names: str) -> ValidationResult:
    """
    Validate that required configuration variables are present.
    
    Provides configuration validation utility supporting enterprise-grade
    configuration management with structured error reporting.
    
    Args:
        *var_names: Variable names to validate as required
    
    Returns:
        ValidationResult with validation status
    """
    missing_vars = []
    
    for var_name in var_names:
        if not os.getenv(var_name):
            missing_vars.append(var_name)
    
    if missing_vars:
        errors = [f"Required environment variable '{var}' is missing" for var in missing_vars]
        return ValidationResult(False, None, errors, "required_config_vars")
    
    return ValidationResult(True, var_names, [], "required_config_vars")


def sanitize_config_value(value: str, max_length: int = 1000) -> str:
    """
    Sanitize configuration value for security.
    
    Provides configuration value sanitization supporting enterprise security
    patterns per Section 5.4.3 authentication and authorization framework.
    
    Args:
        value: Configuration value to sanitize
        max_length: Maximum allowed length
    
    Returns:
        Sanitized configuration value
    """
    sanitization_result = sanitize_input(
        value,
        max_length=max_length,
        strip_whitespace=True,
        check_sql_injection=True,
        sanitize_html=True
    )
    
    if not sanitization_result.is_valid:
        raise ConfigurationError(
            message="Configuration value sanitization failed",
            validation_errors=sanitization_result.errors,
            details={"original_value_length": len(value)}
        )
    
    return sanitization_result.value


# Export all public classes and functions
__all__ = [
    'ConfigurationError',
    'ConfigurationManager',
    'FlaskConfigBuilder',
    'load_dotenv_config',
    'get_flask_config_for_environment',
    'validate_required_config_vars',
    'sanitize_config_value',
    'CONFIG_VALIDATION_RULES'
]