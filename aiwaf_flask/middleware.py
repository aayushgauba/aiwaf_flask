# Flask AIWAF master middleware loader
from .ip_and_keyword_block_middleware import IPAndKeywordBlockMiddleware
from .rate_limit_middleware import RateLimitMiddleware
from .honeypot_timing_middleware import HoneypotTimingMiddleware
from .header_validation_middleware import HeaderValidationMiddleware
from .anomaly_middleware import AnomalyDetectionMiddleware
from .uuid_tamper_middleware import UUIDTamperMiddleware

def register_aiwaf_middlewares(app):
    IPAndKeywordBlockMiddleware(app)
    RateLimitMiddleware(app)
    HoneypotTimingMiddleware(app)
    HeaderValidationMiddleware(app)
    AnomalyDetectionMiddleware(app)
    UUIDTamperMiddleware(app)
