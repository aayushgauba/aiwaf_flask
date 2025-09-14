# Flask AIWAF master middleware loader
from .ip_and_keyword_block_middleware import IPAndKeywordBlockMiddleware
from .rate_limit_middleware import RateLimitMiddleware
from .honeypot_timing_middleware import HoneypotTimingMiddleware
from .header_validation_middleware import HeaderValidationMiddleware
from .anomaly_middleware import AnomalyDetectionMiddleware
from .uuid_tamper_middleware import UUIDTamperMiddleware
from .logging_middleware import AIWAFLoggingMiddleware

def register_aiwaf_middlewares(app, use_database=None):
    """
    Register all AIWAF middlewares with the Flask app.
    
    Args:
        app: Flask application instance
        use_database: Optional boolean to force database usage.
                     If None, auto-detects based on configuration.
    """
    # Set default configurations if not present
    app.config.setdefault('AIWAF_RATE_WINDOW', 60)
    app.config.setdefault('AIWAF_RATE_MAX', 100)
    app.config.setdefault('AIWAF_RATE_FLOOD', 200)
    app.config.setdefault('AIWAF_MIN_FORM_TIME', 1.0)
    app.config.setdefault('AIWAF_USE_CSV', True)
    app.config.setdefault('AIWAF_DATA_DIR', 'aiwaf_data')
    app.config.setdefault('AIWAF_LOG_DIR', 'aiwaf_logs')
    app.config.setdefault('AIWAF_ENABLE_LOGGING', True)
    
    # Optionally initialize database if configured
    if use_database or (use_database is None and _should_use_database(app)):
        _init_database(app)
    
    # Initialize logging middleware first (to capture all events)
    if app.config.get('AIWAF_ENABLE_LOGGING', True):
        logging_middleware = AIWAFLoggingMiddleware(app)
        # Store reference for other middlewares to use
        app.aiwaf_logger = logging_middleware
    
    # Register all security middleware
    IPAndKeywordBlockMiddleware(app)
    RateLimitMiddleware(app)
    HoneypotTimingMiddleware(app)
    HeaderValidationMiddleware(app)
    AnomalyDetectionMiddleware(app)
    UUIDTamperMiddleware(app)

def _should_use_database(app):
    """Check if the app has database configuration."""
    # If CSV is explicitly enabled, don't use database
    if app.config.get('AIWAF_USE_CSV', True):
        return False
    
    # Only use database if SQLAlchemy URI is configured and CSV is disabled
    return (hasattr(app.config, 'get') and 
            app.config.get('SQLALCHEMY_DATABASE_URI') is not None)

def _init_database(app):
    """Initialize database if not already done."""
    try:
        from .db_models import db
        
        # Only initialize if not already done
        if not hasattr(app, 'extensions') or 'sqlalchemy' not in app.extensions:
            db.init_app(app)
        
        # Create tables within app context
        with app.app_context():
            db.create_all()
    except Exception as e:
        # If database setup fails, continue with CSV/memory storage
        app.logger.warning(f"Database setup failed, using CSV/memory storage: {e}")
