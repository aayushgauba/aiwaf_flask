# Flask-adapted UUIDTamperMiddleware (stub)
from flask import request, jsonify
from .utils import get_ip
from .blacklist_manager import BlacklistManager
import re

class UUIDTamperMiddleware:
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        @app.before_request
        def before_request():
            ip = get_ip()
            uuid_val = request.args.get("uuid")
            if uuid_val and not re.match(r"^[a-f0-9\-]{36}$", uuid_val):
                BlacklistManager.block(ip, "UUID tampering")
                return jsonify({"error": "blocked"}), 403
