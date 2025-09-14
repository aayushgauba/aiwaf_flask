import time
import re
from flask import request, jsonify, current_app
from functools import wraps

# Dummy cache for demonstration (replace with Flask-Caching or Redis in production)
_aiwaf_cache = {}

def get_ip():
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or ""

class BlacklistManager:
    _blocked_ips = set()
    @classmethod
    def is_blocked(cls, ip):
        return ip in cls._blocked_ips
    @classmethod
    def block(cls, ip, reason=None):
        cls._blocked_ips.add(ip)
    @classmethod
    def unblock(cls, ip):
        cls._blocked_ips.discard(ip)

class AIWAF:
    def __init__(self, app=None, aiwaf_middleware=None):
        self.app = app
        self.aiwaf_middleware = aiwaf_middleware
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        @app.before_request
        def before_request():
            ip = get_ip()
            path = request.path.lower()
            # IP block check
            if BlacklistManager.is_blocked(ip):
                return jsonify({"error": "blocked"}), 403
            # Rate limiting
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
            # Honeypot timing (simple demo)
            if request.method == "POST":
                get_time = _aiwaf_cache.get(f"honeypot_get:{ip}")
                if get_time is not None:
                    time_diff = now - get_time
                    min_time = app.config.get("AIWAF_MIN_FORM_TIME", 1.0)
                    if time_diff < min_time:
                        BlacklistManager.block(ip, f"Form submitted too quickly ({time_diff:.2f}s)")
                        return jsonify({"error": "blocked"}), 403
            elif request.method == "GET":
                _aiwaf_cache[f"honeypot_get:{ip}"] = now
            # Header validation (simple demo)
            ua = request.headers.get("User-Agent", "")
            if not ua or len(ua) < 10:
                BlacklistManager.block(ip, "Suspicious User-Agent")
                return jsonify({"error": "blocked"}), 403
            # Add more header checks as needed
            # Keyword blocking (demo)
            malicious_keywords = [".php", "xmlrpc", "wp-", ".env", ".git", ".bak", "shell", "filemanager"]
            for kw in malicious_keywords:
                if kw in path:
                    BlacklistManager.block(ip, f"Keyword block: {kw}")
                    return jsonify({"error": "blocked"}), 403
            # UUID tampering (demo)
            if "uuid" in request.args:
                uuid_val = request.args.get("uuid")
                if not re.match(r"^[a-f0-9\-]{36}$", uuid_val):
                    BlacklistManager.block(ip, "UUID tampering")
                    return jsonify({"error": "blocked"}), 403
            # Anomaly detection placeholder (add ML logic as needed)
            # ...existing code...

        @app.after_request
        def after_request(response):
            # Optionally add post-response logic
            return response
