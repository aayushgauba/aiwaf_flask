# aiwaf_flask package init

from .middleware import register_aiwaf_middlewares
from .ip_and_keyword_block_middleware import IPAndKeywordBlockMiddleware
from .rate_limit_middleware import RateLimitMiddleware
from .honeypot_timing_middleware import HoneypotTimingMiddleware
from .header_validation_middleware import HeaderValidationMiddleware
from .anomaly_middleware import AIAnomalyMiddleware
from .uuid_tamper_middleware import UUIDTamperMiddleware
from .logging_middleware import AIWAFLoggingMiddleware, analyze_access_logs

# Exemption decorators for fine-grained control
from .exemption_decorators import (
    aiwaf_exempt,
    aiwaf_exempt_from, 
    aiwaf_only,
    aiwaf_require_protection,
    is_request_exempt,
    should_apply_middleware
)

# Backward compatibility alias
register_aiwaf_protection = register_aiwaf_middlewares

# CLI management
try:
    from .cli import AIWAFManager
except ImportError:
    AIWAFManager = None


class AIWAF:
    """
    Main AIWAF class for Flask applications with customizable middleware selection.
    
    Usage:
        # Enable all middlewares (default)
        aiwaf = AIWAF(app)
        
        # Enable specific middlewares only
        aiwaf = AIWAF(app, middlewares=[
            'ip_keyword_block',
            'rate_limit', 
            'ai_anomaly'
        ])
        
        # Disable specific middlewares
        aiwaf = AIWAF(app, disable_middlewares=['honeypot', 'uuid_tamper'])
    """
    
    AVAILABLE_MIDDLEWARES = {
        'ip_keyword_block': IPAndKeywordBlockMiddleware,
        'rate_limit': RateLimitMiddleware,
        'honeypot': HoneypotTimingMiddleware,
        'header_validation': HeaderValidationMiddleware,
        'ai_anomaly': AIAnomalyMiddleware,
        'uuid_tamper': UUIDTamperMiddleware,
        'logging': AIWAFLoggingMiddleware
    }
    
    def __init__(self, app=None, middlewares=None, disable_middlewares=None, use_database=None):
        """
        Initialize AIWAF with customizable middleware selection.
        
        Args:
            app: Flask application instance
            middlewares: List of middleware names to enable (if None, enables all)
            disable_middlewares: List of middleware names to disable
            use_database: Optional boolean to force database usage
        """
        self.app = app
        self.enabled_middlewares = set()
        self.middleware_instances = {}
        
        if app is not None:
            self.init_app(app, middlewares, disable_middlewares, use_database)
    
    def init_app(self, app, middlewares=None, disable_middlewares=None, use_database=None):
        """Initialize AIWAF with the Flask app."""
        self.app = app
        
        # Determine which middlewares to enable
        if middlewares is not None:
            # Explicit list of middlewares to enable
            enabled = set(middlewares)
        else:
            # Enable all middlewares by default
            enabled = set(self.AVAILABLE_MIDDLEWARES.keys())
        
        # Remove disabled middlewares
        if disable_middlewares:
            enabled -= set(disable_middlewares)
        
        self.enabled_middlewares = enabled
        
        # Set default configurations
        self._set_default_config(app)
        
        # Initialize database if needed
        if use_database or (use_database is None and self._should_use_database(app)):
            self._init_database(app)
        
        # Register enabled middlewares
        self._register_middlewares(app)
        
        # Store AIWAF instance in app for easy access
        app.aiwaf = self
    
    def _set_default_config(self, app):
        """Set default AIWAF configuration values."""
        defaults = {
            'AIWAF_RATE_WINDOW': 60,
            'AIWAF_RATE_MAX': 100,
            'AIWAF_RATE_FLOOD': 200,
            'AIWAF_MIN_FORM_TIME': 1.0,
            'AIWAF_USE_CSV': True,
            'AIWAF_DATA_DIR': 'aiwaf_data',
            'AIWAF_LOG_DIR': 'aiwaf_logs',
            'AIWAF_ENABLE_LOGGING': True,
            'AIWAF_WINDOW_SECONDS': 60,
            'AIWAF_DYNAMIC_TOP_N': 10,
            'AIWAF_MODEL_PATH': 'aiwaf_flask/resources/model.pkl'
        }
        
        for key, value in defaults.items():
            app.config.setdefault(key, value)
    
    def _register_middlewares(self, app):
        """Register enabled middlewares with the Flask app."""
        # Initialize logging middleware first if enabled (to capture all events)
        if 'logging' in self.enabled_middlewares and app.config.get('AIWAF_ENABLE_LOGGING', True):
            logging_middleware = self.AVAILABLE_MIDDLEWARES['logging'](app)
            self.middleware_instances['logging'] = logging_middleware
            app.aiwaf_logger = logging_middleware
        
        # Register security middlewares
        for middleware_name in self.enabled_middlewares:
            if middleware_name == 'logging':
                continue  # Already handled above
                
            if middleware_name in self.AVAILABLE_MIDDLEWARES:
                middleware_class = self.AVAILABLE_MIDDLEWARES[middleware_name]
                instance = middleware_class(app)
                self.middleware_instances[middleware_name] = instance
            else:
                app.logger.warning(f"Unknown middleware: {middleware_name}")
    
    def _should_use_database(self, app):
        """Check if the app has database configuration."""
        if app.config.get('AIWAF_USE_CSV', True):
            return False
        return (hasattr(app.config, 'get') and 
                app.config.get('SQLALCHEMY_DATABASE_URI') is not None)
    
    def _init_database(self, app):
        """Initialize database if not already done."""
        try:
            from .db_models import db
            
            if not hasattr(app, 'extensions') or 'sqlalchemy' not in app.extensions:
                db.init_app(app)
            
            with app.app_context():
                db.create_all()
        except Exception as e:
            app.logger.warning(f"Database setup failed, using CSV/memory storage: {e}")
    
    def get_enabled_middlewares(self):
        """Get list of currently enabled middlewares."""
        return list(self.enabled_middlewares)
    
    def is_middleware_enabled(self, middleware_name):
        """Check if a specific middleware is enabled."""
        return middleware_name in self.enabled_middlewares
    
    def get_middleware_instance(self, middleware_name):
        """Get instance of a specific middleware."""
        return self.middleware_instances.get(middleware_name)
    
    @classmethod
    def list_available_middlewares(cls):
        """Get list of all available middlewares."""
        return list(cls.AVAILABLE_MIDDLEWARES.keys())
