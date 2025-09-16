# Flask-adapted HeaderValidationMiddleware
import re
from flask import request, jsonify
from .utils import get_ip, is_exempt
from .blacklist_manager import BlacklistManager
from .exemption_decorators import should_apply_middleware

class HeaderValidationMiddleware:
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        @app.before_request
        def before_request():
            # Check exemption status first - skip if exempt from header validation
            if not should_apply_middleware('header_validation'):
                return None  # Allow request to proceed without header validation
            
            # Legacy exemption check for backward compatibility
            if is_exempt(request):
                return None  # Allow request to proceed
            
            ip = get_ip()
            ua = request.headers.get("User-Agent", "")
            if not ua or len(ua) < 10:
                BlacklistManager.block(ip, "Suspicious User-Agent")
                return jsonify({"error": "blocked"}), 403
            # Add more header checks as needed
