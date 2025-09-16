# Flask-adapted RateLimitMiddleware
import time
from flask import request, jsonify, current_app
from .utils import get_ip, is_exempt
from .blacklist_manager import BlacklistManager
from .exemption_decorators import should_apply_middleware

_aiwaf_cache = {}

class RateLimitMiddleware:
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        @app.before_request
        def before_request():
            # Check exemption status first - skip if exempt from rate limiting
            if not should_apply_middleware('rate_limit'):
                return None  # Allow request to proceed without rate limiting
            
            # Legacy exemption check for backward compatibility
            if is_exempt(request):
                return None  # Allow request to proceed
            
            ip = get_ip()
            key = f"ratelimit:{ip}"
            now = time.time()
            timestamps = _aiwaf_cache.get(key, [])
            window = app.config.get("AIWAF_RATE_WINDOW", 10)
            max_req = app.config.get("AIWAF_RATE_MAX", 20)
            flood = app.config.get("AIWAF_RATE_FLOOD", 40)
            timestamps = [t for t in timestamps if now - t < window]
            timestamps.append(now)
            _aiwaf_cache[key] = timestamps
            if len(timestamps) > flood:
                BlacklistManager.block(ip, "Flood pattern")
                return jsonify({"error": "blocked"}), 403
            if len(timestamps) > max_req:
                return jsonify({"error": "too_many_requests"}), 429
