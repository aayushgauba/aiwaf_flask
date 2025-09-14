# aiwaf_flask package init

from .middleware import register_aiwaf_middlewares
from .ip_and_keyword_block_middleware import IPAndKeywordBlockMiddleware
from .rate_limit_middleware import RateLimitMiddleware
from .honeypot_timing_middleware import HoneypotTimingMiddleware
from .header_validation_middleware import HeaderValidationMiddleware
from .anomaly_middleware import AnomalyDetectionMiddleware
from .uuid_tamper_middleware import UUIDTamperMiddleware
from .logging_middleware import AIWAFLoggingMiddleware, analyze_access_logs

# Backward compatibility alias
register_aiwaf_protection = register_aiwaf_middlewares

# CLI management
try:
    from .cli import AIWAFManager
except ImportError:
    AIWAFManager = None
