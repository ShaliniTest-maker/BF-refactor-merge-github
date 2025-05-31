"""
Production Environment Configuration Module

This module implements production-specific configuration with enterprise-grade security settings,
performance optimizations, production database configurations, and comprehensive monitoring
integration for the Flask application migration from Node.js.

This configuration extends the base configuration with production-specific overrides that ensure:
- Enterprise security compliance per Section 6.4.3 (TLS 1.3, security headers)
- Production database performance and encryption per Section 3.4.1
- Enterprise APM and monitoring integration per Section 3.6.1
- Comprehensive production security controls per Section 6.4.1
- Production deployment compliance per Section 8.1.2

Key Features:
- Flask-Talisman 1.1.0+ for TLS 1.3 enforcement and HTTP security headers
- AWS KMS integration for encryption key management (Section 6.4.3)
- Production-optimized MongoDB and Redis connection pooling
- Comprehensive Prometheus metrics and APM integration
- Rate limiting and CORS policies for production security
- Enterprise audit logging with structured JSON output
- Container orchestration health check endpoints
- Blue-green deployment and feature flag support

Dependencies:
- Flask 2.3+ with production WSGI configuration
- Flask-Talisman 1.1.0+ for security header enforcement
- PyMongo 4.5+ and Motor 3.3+ for MongoDB with production pooling
- redis-py 5.0+ with production connection optimization
- prometheus-client 0.17+ for comprehensive metrics collection
- structlog 23.1+ for enterprise audit logging
- boto3 1.28+ for AWS KMS and S3 integration

Author: Flask Migration Team
Version: 1.0.0
Environment: Production
Security Level: Enterprise
"""

import os
import sys
import ssl
import logging
import secrets
import base64
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List, Union
from pathlib import Path

# Configuration base classes
from config.settings import BaseConfig, EnvironmentManager, ConfigurationError
from config.database import DatabaseManager, AWSKMSKeyManager
from config.security import SecurityConfig
from config.monitoring import MonitoringConfig

# Production-specific security libraries
try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

# APM and monitoring libraries
try:
    import ddtrace
    from ddtrace import tracer, patch_all
    DATADOG_APM_AVAILABLE = True
except ImportError:
    DATADOG_APM_AVAILABLE = False

try:
    import newrelic.agent
    NEWRELIC_APM_AVAILABLE = True
except ImportError:
    NEWRELIC_APM_AVAILABLE = False

# Prometheus metrics
try:
    from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

# Configure production logging
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ProductionSecurityEnforcer:
    """
    Production security enforcement with comprehensive validation and enterprise controls.
    
    This class implements production-specific security validations beyond the base
    configuration, ensuring enterprise compliance and security standard adherence.
    """
    
    def __init__(self):
        """Initialize production security enforcer."""
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.required_production_vars = [
            'SECRET_KEY',
            'AUTH0_DOMAIN',
            'AUTH0_CLIENT_ID', 
            'AUTH0_CLIENT_SECRET',
            'MONGODB_URI',
            'REDIS_HOST',
            'AWS_ACCESS_KEY_ID',
            'AWS_SECRET_ACCESS_KEY',
            'AWS_KMS_CMK_ARN'
        ]
        
    def validate_production_requirements(self) -> None:
        """
        Validate all production security requirements are met.
        
        Raises:
            ConfigurationError: When production requirements are not satisfied
        """
        validation_errors = []
        
        # Check required environment variables
        missing_vars = []
        for var in self.required_production_vars:
            if not os.getenv(var):
                missing_vars.append(var)
        
        if missing_vars:
            validation_errors.append(
                f"Missing required production environment variables: {', '.join(missing_vars)}"
            )
        
        # Validate secret key strength
        secret_key = os.getenv('SECRET_KEY', '')
        if len(secret_key) < 64:
            validation_errors.append(
                "Production SECRET_KEY must be at least 64 characters for enterprise security"
            )
        
        # Validate TLS certificate paths if provided
        tls_cert_path = os.getenv('TLS_CERT_PATH')
        tls_key_path = os.getenv('TLS_KEY_PATH')
        
        if tls_cert_path and not Path(tls_cert_path).exists():
            validation_errors.append(f"TLS certificate file not found: {tls_cert_path}")
        
        if tls_key_path and not Path(tls_key_path).exists():
            validation_errors.append(f"TLS private key file not found: {tls_key_path}")
        
        # Validate AWS KMS configuration
        if AWS_AVAILABLE:
            try:
                self._validate_aws_kms_access()
            except Exception as e:
                validation_errors.append(f"AWS KMS validation failed: {str(e)}")
        
        # Check database connectivity requirements
        mongodb_uri = os.getenv('MONGODB_URI', '')
        if not mongodb_uri.startswith('mongodb://') and not mongodb_uri.startswith('mongodb+srv://'):
            validation_errors.append("Invalid MongoDB URI format for production")
        
        # Validate Redis configuration
        redis_host = os.getenv('REDIS_HOST')
        if not redis_host or redis_host == 'localhost':
            validation_errors.append("Production Redis host must not be localhost")
        
        if validation_errors:
            error_message = "Production security validation failed:\n" + "\n".join(
                f"- {error}" for error in validation_errors
            )
            self.logger.error(error_message)
            raise ConfigurationError(error_message)
        
        self.logger.info("Production security validation completed successfully")
    
    def _validate_aws_kms_access(self) -> None:
        """
        Validate AWS KMS access and permissions.
        
        Raises:
            ConfigurationError: When AWS KMS validation fails
        """
        try:
            kms_client = boto3.client(
                'kms',
                region_name=os.getenv('AWS_REGION', 'us-east-1'),
                aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
            )
            
            cmk_arn = os.getenv('AWS_KMS_CMK_ARN')
            if cmk_arn:
                # Test key access by describing the key
                kms_client.describe_key(KeyId=cmk_arn)
                self.logger.info("AWS KMS access validation successful")
            
        except (ClientError, BotoCoreError) as e:
            raise ConfigurationError(f"AWS KMS access validation failed: {str(e)}")


class ProductionPerformanceOptimizer:
    """
    Production performance optimization configuration for meeting ≤10% variance requirement.
    
    This class implements production-specific performance optimizations for database
    connections, caching, and application server configuration to ensure the migration
    meets the ≤10% performance variance requirement from Node.js baseline.
    """
    
    def __init__(self):
        """Initialize production performance optimizer."""
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def get_optimized_mongodb_settings(self) -> Dict[str, Any]:
        """
        Get production-optimized MongoDB connection settings.
        
        Returns:
            Optimized MongoDB configuration for production performance
        """
        return {
            'maxPoolSize': int(os.getenv('MONGODB_MAX_POOL_SIZE', '100')),
            'minPoolSize': int(os.getenv('MONGODB_MIN_POOL_SIZE', '20')),
            'maxIdleTimeMS': int(os.getenv('MONGODB_MAX_IDLE_TIME_MS', '20000')),
            'connectTimeoutMS': int(os.getenv('MONGODB_CONNECT_TIMEOUT_MS', '5000')),
            'serverSelectionTimeoutMS': int(os.getenv('MONGODB_SERVER_SELECTION_TIMEOUT_MS', '3000')),
            'socketTimeoutMS': int(os.getenv('MONGODB_SOCKET_TIMEOUT_MS', '20000')),
            'maxConnecting': int(os.getenv('MONGODB_MAX_CONNECTING', '10')),
            'retryWrites': True,
            'retryReads': True,
            'readPreference': 'primaryPreferred',
            'readConcern': {'level': 'majority'},
            'writeConcern': {'w': 'majority', 'j': True, 'wtimeout': 5000}
        }
    
    def get_optimized_redis_settings(self) -> Dict[str, Any]:
        """
        Get production-optimized Redis connection settings.
        
        Returns:
            Optimized Redis configuration for production performance
        """
        return {
            'max_connections': int(os.getenv('REDIS_MAX_CONNECTIONS', '100')),
            'socket_timeout': float(os.getenv('REDIS_SOCKET_TIMEOUT', '20.0')),
            'socket_connect_timeout': float(os.getenv('REDIS_SOCKET_CONNECT_TIMEOUT', '5.0')),
            'socket_keepalive': True,
            'socket_keepalive_options': {
                'TCP_KEEPIDLE': 600,
                'TCP_KEEPINTVL': 30,
                'TCP_KEEPCNT': 3
            },
            'health_check_interval': int(os.getenv('REDIS_HEALTH_CHECK_INTERVAL', '60')),
            'retry_on_timeout': True,
            'decode_responses': True
        }
    
    def get_optimized_gunicorn_settings(self) -> Dict[str, Any]:
        """
        Get production-optimized Gunicorn WSGI server settings.
        
        Returns:
            Optimized Gunicorn configuration for production performance
        """
        # Calculate optimal worker count based on CPU cores
        cpu_count = os.cpu_count() or 1
        worker_count = int(os.getenv('GUNICORN_WORKERS', str(2 * cpu_count + 1)))
        
        return {
            'bind': f"0.0.0.0:{os.getenv('PORT', '8000')}",
            'workers': worker_count,
            'worker_class': 'sync',  # or 'gevent' for async workloads
            'worker_connections': int(os.getenv('GUNICORN_WORKER_CONNECTIONS', '1000')),
            'max_requests': int(os.getenv('GUNICORN_MAX_REQUESTS', '1000')),
            'max_requests_jitter': int(os.getenv('GUNICORN_MAX_REQUESTS_JITTER', '100')),
            'timeout': int(os.getenv('GUNICORN_TIMEOUT', '30')),
            'keepalive': int(os.getenv('GUNICORN_KEEPALIVE', '5')),
            'preload_app': True,
            'enable_stdio_inheritance': True,
            'access_log_format': '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s',
            'accesslog': '-',
            'errorlog': '-',
            'loglevel': 'warning',
            'capture_output': True
        }


class ProductionMonitoringIntegrator:
    """
    Production monitoring and observability integration.
    
    This class configures enterprise APM integration, Prometheus metrics collection,
    and comprehensive monitoring capabilities for production deployment.
    """
    
    def __init__(self):
        """Initialize production monitoring integrator."""
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.apm_enabled = os.getenv('APM_ENABLED', 'true').lower() == 'true'
        self.prometheus_enabled = os.getenv('PROMETHEUS_METRICS_ENABLED', 'true').lower() == 'true'
    
    def configure_datadog_apm(self) -> Dict[str, Any]:
        """
        Configure Datadog APM for production monitoring.
        
        Returns:
            Datadog APM configuration settings
        """
        if not DATADOG_APM_AVAILABLE or not self.apm_enabled:
            return {}
        
        config = {
            'enabled': True,
            'service_name': os.getenv('DATADOG_SERVICE_NAME', 'flask-migration-app'),
            'env': os.getenv('DATADOG_ENV', 'production'),
            'version': os.getenv('DATADOG_VERSION', '1.0.0'),
            'sample_rate': float(os.getenv('DATADOG_SAMPLE_RATE', '0.1')),
            'agent_hostname': os.getenv('DATADOG_AGENT_HOST', 'localhost'),
            'agent_port': int(os.getenv('DATADOG_AGENT_PORT', '8126')),
            'distributed_tracing': True,
            'priority_sampling': True,
            'analytics_enabled': True,
            'trace_sampling_rules': [
                {'service': 'flask-migration-app', 'sample_rate': 0.1},
                {'service': 'flask-migration-app', 'name': 'flask.request', 'sample_rate': 0.5}
            ]
        }
        
        self.logger.info("Datadog APM configuration initialized for production")
        return config
    
    def configure_newrelic_apm(self) -> Dict[str, Any]:
        """
        Configure New Relic APM for production monitoring.
        
        Returns:
            New Relic APM configuration settings
        """
        if not NEWRELIC_APM_AVAILABLE or not self.apm_enabled:
            return {}
        
        config = {
            'enabled': True,
            'app_name': os.getenv('NEW_RELIC_APP_NAME', 'Flask Migration App (Production)'),
            'license_key': os.getenv('NEW_RELIC_LICENSE_KEY'),
            'environment': 'production',
            'distributed_tracing': {'enabled': True},
            'cross_application_tracer': {'enabled': True},
            'error_collector': {
                'enabled': True,
                'ignore_status_codes': [404, 405]
            },
            'browser_monitoring': {'auto_instrument': True},
            'application_logging': {
                'enabled': True,
                'forwarding': {'enabled': True},
                'metrics': {'enabled': True}
            }
        }
        
        self.logger.info("New Relic APM configuration initialized for production")
        return config
    
    def get_prometheus_metrics_config(self) -> Dict[str, Any]:
        """
        Get Prometheus metrics configuration for production.
        
        Returns:
            Prometheus metrics collection configuration
        """
        if not PROMETHEUS_AVAILABLE or not self.prometheus_enabled:
            return {}
        
        return {
            'enabled': True,
            'multiproc_dir': os.getenv('PROMETHEUS_MULTIPROC_DIR', '/tmp/prometheus_multiproc'),
            'metrics_path': '/metrics',
            'registry': CollectorRegistry(),
            'collect_default_metrics': True,
            'include_gunicorn_metrics': True,
            'custom_metrics': {
                'flask_requests_total': Counter(
                    'flask_requests_total',
                    'Total Flask requests',
                    ['method', 'endpoint', 'status']
                ),
                'flask_request_duration_seconds': Histogram(
                    'flask_request_duration_seconds',
                    'Flask request duration in seconds',
                    ['method', 'endpoint']
                ),
                'flask_database_operations_total': Counter(
                    'flask_database_operations_total',
                    'Total database operations',
                    ['operation', 'collection', 'status']
                ),
                'flask_cache_operations_total': Counter(
                    'flask_cache_operations_total',
                    'Total cache operations',
                    ['operation', 'cache_type', 'status']
                ),
                'flask_active_sessions': Gauge(
                    'flask_active_sessions',
                    'Number of active user sessions'
                )
            }
        }


class ProductionConfig(BaseConfig):
    """
    Production environment configuration with enterprise-grade security, performance
    optimization, and comprehensive monitoring integration.
    
    This configuration class extends BaseConfig with production-specific settings that:
    - Enforce TLS 1.3 and comprehensive security headers (Section 6.4.3)
    - Optimize database and cache performance for ≤10% variance (Section 3.4.1)
    - Integrate enterprise APM and monitoring (Section 3.6.1)
    - Implement comprehensive security controls (Section 6.4.1)
    - Support production deployment requirements (Section 8.1.2)
    """
    
    def __init__(self):
        """Initialize production configuration with enterprise settings."""
        # Initialize security enforcer first
        self.security_enforcer = ProductionSecurityEnforcer()
        self.performance_optimizer = ProductionPerformanceOptimizer()
        self.monitoring_integrator = ProductionMonitoringIntegrator()
        
        # Validate production requirements before configuration
        self.security_enforcer.validate_production_requirements()
        
        # Initialize base configuration
        super().__init__()
        
        # Apply production-specific configurations
        self._configure_production_security()
        self._configure_production_performance()
        self._configure_production_monitoring()
        self._configure_production_database()
        self._configure_production_cache()
        self._configure_production_external_services()
        self._configure_production_logging()
        self._configure_production_deployment()
        
        # Final production validation
        self._validate_production_configuration()
        
        logger.info("Production configuration initialized with enterprise security and performance settings")
    
    def _configure_production_security(self) -> None:
        """Configure production-specific security settings."""
        # Strict production security enforcement
        self.DEBUG = False
        self.TESTING = False
        self.FLASK_ENV = 'production'
        
        # Enhanced HTTPS enforcement (Flask-Talisman)
        self.FORCE_HTTPS = True
        self.SSL_DISABLE = False
        
        # TLS 1.3 enforcement configuration
        self.TLS_VERSION = 'TLSv1_3'
        self.TLS_CIPHERS = 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS'
        self.TLS_CERT_PATH = os.getenv('TLS_CERT_PATH')
        self.TLS_KEY_PATH = os.getenv('TLS_KEY_PATH')
        self.TLS_CA_PATH = os.getenv('TLS_CA_PATH')
        
        # Enhanced Flask-Talisman configuration for production
        self.TALISMAN_CONFIG = {
            'force_https': True,
            'force_https_permanent': True,
            'strict_transport_security': True,
            'strict_transport_security_max_age': 63072000,  # 2 years for production
            'strict_transport_security_include_subdomains': True,
            'strict_transport_security_preload': True,
            'content_security_policy': {
                'default-src': "'self'",
                'script-src': [
                    "'self'",
                    "'nonce-{nonce}'",  # Dynamic nonce for scripts
                    "https://cdn.auth0.com"
                ],
                'style-src': [
                    "'self'",
                    "'nonce-{nonce}'"  # Dynamic nonce for styles
                ],
                'img-src': [
                    "'self'",
                    "data:",
                    "https:"
                ],
                'connect-src': [
                    "'self'",
                    "https://*.auth0.com",
                    "https://*.amazonaws.com",
                    "https://*.datadoghq.com"  # APM endpoints
                ],
                'font-src': "'self'",
                'object-src': "'none'",
                'base-uri': "'self'",
                'frame-ancestors': "'none'",
                'upgrade-insecure-requests': True,
                'block-all-mixed-content': True
            },
            'content_security_policy_nonce_in': ['script-src', 'style-src'],
            'content_security_policy_report_only': False,
            'content_security_policy_report_uri': '/csp-report',
            'referrer_policy': 'strict-origin-when-cross-origin',
            'feature_policy': {
                'geolocation': "'none'",
                'microphone': "'none'",
                'camera': "'none'",
                'accelerometer': "'none'",
                'gyroscope': "'none'",
                'payment': "'none'",
                'usb': "'none'"
            },
            'permissions_policy': {
                'geolocation': '()',
                'microphone': '()',
                'camera': '()',
                'payment': '()',
                'usb': '()'
            }
        }
        
        # Production session security
        self.SESSION_COOKIE_SECURE = True
        self.SESSION_COOKIE_HTTPONLY = True
        self.SESSION_COOKIE_SAMESITE = 'Strict'
        self.SESSION_COOKIE_DOMAIN = os.getenv('SESSION_COOKIE_DOMAIN')
        self.PERMANENT_SESSION_LIFETIME = timedelta(
            hours=int(os.getenv('SESSION_LIFETIME_HOURS', '8'))  # Shorter for production
        )
        
        # Enhanced rate limiting for production
        self.RATELIMIT_ENABLED = True
        self.RATELIMIT_DEFAULT = '1000 per hour, 100 per minute, 10 per second'
        self.RATELIMIT_HEADERS_ENABLED = True
        
        # Strict CORS policy for production
        self.CORS_ORIGINS = [
            'https://app.company.com',
            'https://admin.company.com'
        ]
        
        # Add environment-specific origins
        custom_origins = os.getenv('CORS_ALLOWED_ORIGINS')
        if custom_origins:
            self.CORS_ORIGINS.extend([origin.strip() for origin in custom_origins.split(',')])
        
        # Production JWT settings
        self.JWT_EXPIRATION_DELTA = timedelta(hours=8)  # Shorter expiration for production
        self.JWT_REFRESH_EXPIRATION_DELTA = timedelta(days=7)  # Reduced refresh window
        
        logger.info("Production security configuration applied with TLS 1.3 and enhanced headers")
    
    def _configure_production_performance(self) -> None:
        """Configure production performance optimizations."""
        # WSGI server optimization
        self.GUNICORN_CONFIG = self.performance_optimizer.get_optimized_gunicorn_settings()
        
        # Request handling optimization
        self.MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB for production file uploads
        
        # JSON response optimization
        self.JSON_SORT_KEYS = False  # Disable for performance
        self.JSONIFY_PRETTYPRINT_REGULAR = False  # Disable for bandwidth optimization
        
        # Connection timeout optimization
        self.HTTP_TIMEOUT = 20.0  # Reduced timeout for production
        self.HTTP_RETRIES = 2  # Reduced retries for faster failure detection
        
        # Circuit breaker configuration for production reliability
        self.CIRCUIT_BREAKER_ENABLED = True
        self.CIRCUIT_BREAKER_FAILURE_THRESHOLD = 3  # Lower threshold for production
        self.CIRCUIT_BREAKER_TIMEOUT = 30  # Faster recovery attempts
        
        logger.info("Production performance optimizations applied for ≤10% variance requirement")
    
    def _configure_production_monitoring(self) -> None:
        """Configure production monitoring and observability."""
        # Enable comprehensive monitoring
        self.PROMETHEUS_METRICS_ENABLED = True
        self.APM_ENABLED = True
        self.HEALTH_CHECK_ENABLED = True
        
        # Datadog APM configuration
        if DATADOG_APM_AVAILABLE:
            self.DATADOG_CONFIG = self.monitoring_integrator.configure_datadog_apm()
        
        # New Relic APM configuration
        if NEWRELIC_APM_AVAILABLE:
            self.NEWRELIC_CONFIG = self.monitoring_integrator.configure_newrelic_apm()
        
        # Prometheus metrics configuration
        if PROMETHEUS_AVAILABLE:
            self.PROMETHEUS_CONFIG = self.monitoring_integrator.get_prometheus_metrics_config()
        
        # Performance monitoring for migration variance tracking
        self.PERFORMANCE_MONITORING = {
            'enabled': True,
            'baseline_tracking': True,
            'variance_threshold': 0.10,  # 10% variance limit
            'metrics_collection_interval': 60,  # 1 minute
            'performance_alerts_enabled': True,
            'alert_thresholds': {
                'response_time_p95': 500,  # milliseconds
                'error_rate': 0.01,  # 1%
                'database_connection_time': 100,  # milliseconds
                'cache_hit_ratio': 0.90  # 90%
            }
        }
        
        # Health check configuration for Kubernetes
        self.HEALTH_CHECK_CONFIG = {
            'liveness_endpoint': '/health/live',
            'readiness_endpoint': '/health/ready',
            'startup_endpoint': '/health/startup',
            'metrics_endpoint': '/metrics',
            'timeout': 5,
            'include_database_check': True,
            'include_cache_check': True,
            'include_external_services_check': True
        }
        
        logger.info("Production monitoring configuration applied with APM and metrics collection")
    
    def _configure_production_database(self) -> None:
        """Configure production database settings with optimization."""
        # Production MongoDB configuration
        mongodb_settings = self.performance_optimizer.get_optimized_mongodb_settings()
        self.MONGODB_SETTINGS.update(mongodb_settings)
        
        # Enhanced MongoDB TLS configuration for production
        if os.getenv('MONGODB_TLS_ENABLED', 'true').lower() == 'true':
            self.MONGODB_SETTINGS.update({
                'tls': True,
                'tlsAllowInvalidCertificates': False,
                'tlsAllowInvalidHostnames': False,
                'tlsCAFile': os.getenv('MONGODB_TLS_CA_FILE'),
                'tlsCertificateKeyFile': os.getenv('MONGODB_TLS_CERT_FILE'),
                'tlsInsecure': False
            })
        
        # Production connection validation
        mongodb_uri = os.getenv('MONGODB_URI')
        if not mongodb_uri:
            raise ConfigurationError("MONGODB_URI is required for production")
        
        # Validate MongoDB URI format
        if not (mongodb_uri.startswith('mongodb://') or mongodb_uri.startswith('mongodb+srv://')):
            raise ConfigurationError("Invalid MongoDB URI format for production")
        
        self.MONGODB_URI = mongodb_uri
        
        logger.info("Production database configuration applied with enhanced security and performance")
    
    def _configure_production_cache(self) -> None:
        """Configure production Redis caching with optimization."""
        # Production Redis configuration
        redis_settings = self.performance_optimizer.get_optimized_redis_settings()
        self.REDIS_CONNECTION_POOL_KWARGS.update(redis_settings)
        
        # Enhanced Redis TLS configuration for production
        if os.getenv('REDIS_TLS_ENABLED', 'false').lower() == 'true':
            self.REDIS_CONNECTION_POOL_KWARGS.update({
                'ssl': True,
                'ssl_cert_reqs': ssl.CERT_REQUIRED,
                'ssl_ca_certs': os.getenv('REDIS_TLS_CA_FILE'),
                'ssl_certfile': os.getenv('REDIS_TLS_CERT_FILE'),
                'ssl_keyfile': os.getenv('REDIS_TLS_KEY_FILE'),
                'ssl_check_hostname': True
            })
        
        # Production Redis host validation
        redis_host = os.getenv('REDIS_HOST')
        if not redis_host or redis_host == 'localhost':
            raise ConfigurationError("Production Redis host must not be localhost")
        
        self.REDIS_HOST = redis_host
        
        # Session encryption configuration for production
        self.SESSION_ENCRYPTION_ENABLED = True
        self.SESSION_ENCRYPTION_KEY = os.getenv('SESSION_ENCRYPTION_KEY')
        
        if not self.SESSION_ENCRYPTION_KEY and not os.getenv('AWS_KMS_CMK_ARN'):
            raise ConfigurationError(
                "Session encryption requires either SESSION_ENCRYPTION_KEY or AWS_KMS_CMK_ARN"
            )
        
        logger.info("Production cache configuration applied with TLS and session encryption")
    
    def _configure_production_external_services(self) -> None:
        """Configure production external service integration."""
        # AWS services configuration with enhanced security
        self.AWS_ACCESS_KEY_ID = self.env_manager.get_required_env('AWS_ACCESS_KEY_ID')
        self.AWS_SECRET_ACCESS_KEY = self.env_manager.get_required_env('AWS_SECRET_ACCESS_KEY')
        self.AWS_DEFAULT_REGION = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
        self.AWS_KMS_KEY_ARN = self.env_manager.get_required_env('AWS_KMS_CMK_ARN')
        
        # S3 configuration for production
        self.S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME')
        self.S3_REGION = os.getenv('S3_REGION', self.AWS_DEFAULT_REGION)
        self.S3_SERVER_SIDE_ENCRYPTION = 'AES256'
        self.S3_USE_SSL = True
        
        # Auth0 production configuration
        self.AUTH0_DOMAIN = self.env_manager.get_required_env('AUTH0_DOMAIN')
        self.AUTH0_CLIENT_ID = self.env_manager.get_required_env('AUTH0_CLIENT_ID')
        self.AUTH0_CLIENT_SECRET = self.env_manager.get_required_env('AUTH0_CLIENT_SECRET')
        self.AUTH0_AUDIENCE = os.getenv('AUTH0_AUDIENCE')
        
        # Production HTTP client configuration
        self.HTTP_TIMEOUT = 20.0
        self.HTTP_RETRIES = 2
        self.HTTP_BACKOFF_FACTOR = 0.5
        
        # SSL/TLS verification for external services
        self.VERIFY_SSL = True
        self.SSL_CERT_PATH = os.getenv('SSL_CERT_PATH')
        
        logger.info("Production external services configuration applied with enhanced security")
    
    def _configure_production_logging(self) -> None:
        """Configure production logging with structured output."""
        # Production logging configuration
        self.LOG_LEVEL = os.getenv('LOG_LEVEL', 'WARNING')
        self.LOG_FORMAT = 'json'  # Structured JSON logging for production
        
        # Audit logging configuration
        self.AUDIT_LOGGING_ENABLED = True
        self.AUDIT_LOG_LEVEL = 'INFO'
        self.AUDIT_LOG_FILE = os.getenv('AUDIT_LOG_FILE', '/var/log/flask-app/audit.log')
        
        # Security event logging
        self.SECURITY_LOGGING_ENABLED = True
        self.SECURITY_LOG_LEVEL = 'WARNING'
        self.SECURITY_LOG_FILE = os.getenv('SECURITY_LOG_FILE', '/var/log/flask-app/security.log')
        
        # Performance logging
        self.PERFORMANCE_LOGGING_ENABLED = True
        self.PERFORMANCE_LOG_LEVEL = 'INFO'
        self.PERFORMANCE_LOG_FILE = os.getenv('PERFORMANCE_LOG_FILE', '/var/log/flask-app/performance.log')
        
        # Log rotation configuration
        self.LOG_ROTATION_ENABLED = True
        self.LOG_MAX_SIZE = int(os.getenv('LOG_MAX_SIZE', '100')) * 1024 * 1024  # 100MB
        self.LOG_BACKUP_COUNT = int(os.getenv('LOG_BACKUP_COUNT', '5'))
        
        # External log aggregation
        self.LOG_AGGREGATION_ENABLED = os.getenv('LOG_AGGREGATION_ENABLED', 'false').lower() == 'true'
        self.LOG_AGGREGATION_ENDPOINT = os.getenv('LOG_AGGREGATION_ENDPOINT')
        
        logger.info("Production logging configuration applied with structured JSON output")
    
    def _configure_production_deployment(self) -> None:
        """Configure production deployment settings."""
        # Container configuration
        self.CONTAINER_PORT = int(os.getenv('PORT', '8000'))
        self.CONTAINER_HEALTH_CHECK_PATH = '/health/live'
        
        # Blue-green deployment support
        self.DEPLOYMENT_VERSION = os.getenv('DEPLOYMENT_VERSION', '1.0.0')
        self.DEPLOYMENT_ENVIRONMENT = 'production'
        self.FEATURE_FLAGS_ENABLED = os.getenv('FEATURE_FLAGS_ENABLED', 'true').lower() == 'true'
        
        # Kubernetes configuration
        self.KUBERNETES_NAMESPACE = os.getenv('KUBERNETES_NAMESPACE', 'default')
        self.KUBERNETES_SERVICE_NAME = os.getenv('KUBERNETES_SERVICE_NAME', 'flask-migration-app')
        
        # Load balancer configuration
        self.LOAD_BALANCER_HEALTH_CHECK = '/health/ready'
        self.LOAD_BALANCER_TIMEOUT = int(os.getenv('LOAD_BALANCER_TIMEOUT', '30'))
        
        # Graceful shutdown configuration
        self.GRACEFUL_SHUTDOWN_TIMEOUT = int(os.getenv('GRACEFUL_SHUTDOWN_TIMEOUT', '30'))
        self.SHUTDOWN_SIGNALS = ['SIGTERM', 'SIGINT']
        
        # Auto-scaling configuration
        self.AUTOSCALING_ENABLED = os.getenv('AUTOSCALING_ENABLED', 'true').lower() == 'true'
        self.AUTOSCALING_MIN_REPLICAS = int(os.getenv('AUTOSCALING_MIN_REPLICAS', '3'))
        self.AUTOSCALING_MAX_REPLICAS = int(os.getenv('AUTOSCALING_MAX_REPLICAS', '20'))
        
        logger.info("Production deployment configuration applied with container orchestration support")
    
    def _validate_production_configuration(self) -> None:
        """Validate complete production configuration."""
        validation_errors = []
        
        # Validate TLS configuration
        if self.FORCE_HTTPS and not self.TLS_CERT_PATH:
            self.logger.warning("TLS certificate path not specified - using system defaults")
        
        # Validate monitoring configuration
        if not self.PROMETHEUS_METRICS_ENABLED and not self.APM_ENABLED:
            validation_errors.append("Production requires either Prometheus or APM monitoring enabled")
        
        # Validate security headers
        if not hasattr(self, 'TALISMAN_CONFIG'):
            validation_errors.append("Flask-Talisman configuration missing for production security")
        
        # Validate encryption configuration
        if not self.SESSION_ENCRYPTION_KEY and not self.AWS_KMS_KEY_ARN:
            validation_errors.append("Session encryption configuration missing")
        
        # Validate external service configuration
        required_aws_config = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_KMS_KEY_ARN']
        missing_aws_config = [key for key in required_aws_config if not getattr(self, key, None)]
        if missing_aws_config:
            validation_errors.append(f"Missing AWS configuration: {', '.join(missing_aws_config)}")
        
        if validation_errors:
            error_message = "Production configuration validation failed:\n" + "\n".join(
                f"- {error}" for error in validation_errors
            )
            logger.error(error_message)
            raise ConfigurationError(error_message)
        
        logger.info("Production configuration validation completed successfully")
    
    def get_security_headers_config(self) -> Dict[str, Any]:
        """
        Get Flask-Talisman security headers configuration for production.
        
        Returns:
            Complete Flask-Talisman configuration with enterprise security headers
        """
        return self.TALISMAN_CONFIG
    
    def get_monitoring_config(self) -> Dict[str, Any]:
        """
        Get comprehensive monitoring configuration for production.
        
        Returns:
            Complete monitoring configuration including APM and metrics
        """
        config = {
            'prometheus': getattr(self, 'PROMETHEUS_CONFIG', {}),
            'performance_monitoring': getattr(self, 'PERFORMANCE_MONITORING', {}),
            'health_checks': getattr(self, 'HEALTH_CHECK_CONFIG', {})
        }
        
        if hasattr(self, 'DATADOG_CONFIG'):
            config['datadog'] = self.DATADOG_CONFIG
        
        if hasattr(self, 'NEWRELIC_CONFIG'):
            config['newrelic'] = self.NEWRELIC_CONFIG
        
        return config
    
    def get_deployment_config(self) -> Dict[str, Any]:
        """
        Get deployment configuration for container orchestration.
        
        Returns:
            Complete deployment configuration for Kubernetes and load balancer integration
        """
        return {
            'container_port': self.CONTAINER_PORT,
            'health_check_path': self.CONTAINER_HEALTH_CHECK_PATH,
            'deployment_version': self.DEPLOYMENT_VERSION,
            'kubernetes_namespace': self.KUBERNETES_NAMESPACE,
            'kubernetes_service_name': self.KUBERNETES_SERVICE_NAME,
            'load_balancer_health_check': self.LOAD_BALANCER_HEALTH_CHECK,
            'load_balancer_timeout': self.LOAD_BALANCER_TIMEOUT,
            'graceful_shutdown_timeout': self.GRACEFUL_SHUTDOWN_TIMEOUT,
            'autoscaling_enabled': self.AUTOSCALING_ENABLED,
            'autoscaling_min_replicas': self.AUTOSCALING_MIN_REPLICAS,
            'autoscaling_max_replicas': self.AUTOSCALING_MAX_REPLICAS
        }
    
    def export_environment_template(self) -> str:
        """
        Export production environment variable template.
        
        Returns:
            Environment variable template for production deployment
        """
        template = """
# Flask Application Configuration
SECRET_KEY=your-production-secret-key-64-chars-minimum
FLASK_ENV=production
FLASK_DEBUG=false

# Database Configuration
MONGODB_URI=mongodb://username:password@host:port/database?ssl=true
MONGODB_TLS_ENABLED=true
MONGODB_TLS_CERT_FILE=/path/to/mongodb-client.pem
MONGODB_TLS_CA_FILE=/path/to/mongodb-ca.pem
MONGODB_MAX_POOL_SIZE=100
MONGODB_MIN_POOL_SIZE=20

# Redis Configuration
REDIS_HOST=production-redis-host
REDIS_PORT=6379
REDIS_PASSWORD=your-redis-password
REDIS_TLS_ENABLED=false
REDIS_MAX_CONNECTIONS=100

# AWS Configuration
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
AWS_DEFAULT_REGION=us-east-1
AWS_KMS_CMK_ARN=arn:aws:kms:region:account:key/key-id

# Auth0 Configuration
AUTH0_DOMAIN=your-domain.auth0.com
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret
AUTH0_AUDIENCE=your-api-audience

# TLS Configuration
TLS_CERT_PATH=/path/to/certificate.pem
TLS_KEY_PATH=/path/to/private-key.pem
TLS_CA_PATH=/path/to/ca-certificate.pem

# Session Configuration
SESSION_ENCRYPTION_KEY=base64-encoded-32-byte-key
SESSION_LIFETIME_HOURS=8
SESSION_COOKIE_DOMAIN=.company.com

# Monitoring Configuration
APM_ENABLED=true
PROMETHEUS_METRICS_ENABLED=true
DATADOG_APM_ENABLED=true
DATADOG_SERVICE_NAME=flask-migration-app
DATADOG_ENV=production

# Performance Configuration
GUNICORN_WORKERS=9
GUNICORN_MAX_REQUESTS=1000
GUNICORN_TIMEOUT=30

# Security Configuration
CORS_ALLOWED_ORIGINS=https://app.company.com,https://admin.company.com

# Deployment Configuration
PORT=8000
KUBERNETES_NAMESPACE=production
DEPLOYMENT_VERSION=1.0.0
AUTOSCALING_MIN_REPLICAS=3
AUTOSCALING_MAX_REPLICAS=20
"""
        return template.strip()


# Production configuration instance
production_config = ProductionConfig()

# Export production configuration
__all__ = [
    'ProductionConfig',
    'ProductionSecurityEnforcer',
    'ProductionPerformanceOptimizer', 
    'ProductionMonitoringIntegrator',
    'production_config'
]