# Flask-adapted HeaderValidationMiddleware
import re
from flask import request, jsonify, current_app
from .utils import get_ip, is_exempt
from .blacklist_manager import BlacklistManager
from .exemption_decorators import should_apply_middleware
from . import rust_backend

LEGITIMATE_BOTS = [
    re.compile(r"googlebot", re.IGNORECASE),
    re.compile(r"bingbot", re.IGNORECASE),
    re.compile(r"slurp", re.IGNORECASE),
    re.compile(r"duckduckbot", re.IGNORECASE),
    re.compile(r"baiduspider", re.IGNORECASE),
    re.compile(r"yandexbot", re.IGNORECASE),
    re.compile(r"facebookexternalhit", re.IGNORECASE),
    re.compile(r"twitterbot", re.IGNORECASE),
    re.compile(r"linkedinbot", re.IGNORECASE),
    re.compile(r"whatsapp", re.IGNORECASE),
    re.compile(r"telegrambot", re.IGNORECASE),
    re.compile(r"applebot", re.IGNORECASE),
    re.compile(r"pingdom", re.IGNORECASE),
    re.compile(r"uptimerobot", re.IGNORECASE),
    re.compile(r"statuscake", re.IGNORECASE),
    re.compile(r"site24x7", re.IGNORECASE),
]

SUSPICIOUS_UA = [
    ("bot", re.compile(r"bot", re.IGNORECASE)),
    ("crawler", re.compile(r"crawler", re.IGNORECASE)),
    ("spider", re.compile(r"spider", re.IGNORECASE)),
    ("scraper", re.compile(r"scraper", re.IGNORECASE)),
    ("curl", re.compile(r"curl", re.IGNORECASE)),
    ("wget", re.compile(r"wget", re.IGNORECASE)),
    ("python", re.compile(r"python", re.IGNORECASE)),
    ("java", re.compile(r"java", re.IGNORECASE)),
    ("node", re.compile(r"node", re.IGNORECASE)),
    ("go-http", re.compile(r"go-http", re.IGNORECASE)),
    ("axios", re.compile(r"axios", re.IGNORECASE)),
    ("okhttp", re.compile(r"okhttp", re.IGNORECASE)),
    ("libwww", re.compile(r"libwww", re.IGNORECASE)),
    ("lwp-trivial", re.compile(r"lwp-trivial", re.IGNORECASE)),
    ("mechanize", re.compile(r"mechanize", re.IGNORECASE)),
    ("requests", re.compile(r"requests", re.IGNORECASE)),
    ("urllib", re.compile(r"urllib", re.IGNORECASE)),
    ("httpie", re.compile(r"httpie", re.IGNORECASE)),
    ("postman", re.compile(r"postman", re.IGNORECASE)),
    ("insomnia", re.compile(r"insomnia", re.IGNORECASE)),
    ("^$", re.compile(r"^$")),
    ("mozilla/4.0$", re.compile(r"mozilla/4\.0$", re.IGNORECASE)),
]


def _get_header(environ, key):
    value = environ.get(key, "")
    if value is None:
        return ""
    return str(value)


def _has_header(environ, key):
    value = _get_header(environ, key)
    return bool(value)


def _check_user_agent(user_agent):
    if not user_agent:
        return "Empty user agent"

    ua_lower = user_agent.lower()
    for legit in LEGITIMATE_BOTS:
        if legit.search(ua_lower):
            return None

    for pattern, regex in SUSPICIOUS_UA:
        if regex.search(ua_lower):
            return f"Pattern: {pattern}"

    if len(user_agent) < 10:
        return "Too short"
    if len(user_agent) > 500:
        return "Too long"
    return None


def validate_headers_python(environ):
    missing = []
    if not _has_header(environ, "HTTP_USER_AGENT"):
        missing.append("user-agent")
    if not _has_header(environ, "HTTP_ACCEPT"):
        missing.append("accept")
    if missing:
        return f"Missing required headers: {', '.join(missing)}"

    user_agent = _get_header(environ, "HTTP_USER_AGENT")
    reason = _check_user_agent(user_agent)
    if reason:
        return f"Suspicious user agent: {reason}"

    server_protocol = _get_header(environ, "SERVER_PROTOCOL")
    accept = _get_header(environ, "HTTP_ACCEPT")
    accept_language = _get_header(environ, "HTTP_ACCEPT_LANGUAGE")
    accept_encoding = _get_header(environ, "HTTP_ACCEPT_ENCODING")
    connection = _get_header(environ, "HTTP_CONNECTION")

    if server_protocol.startswith("HTTP/2") and "mozilla/4.0" in user_agent.lower():
        return "Suspicious headers: HTTP/2 with old browser user agent"
    if user_agent and not accept:
        return "Suspicious headers: User-Agent present but no Accept header"
    if accept == "*/*" and not accept_language and not accept_encoding:
        return "Suspicious headers: Generic Accept header without language/encoding"
    if user_agent and not accept_language and not accept_encoding and not connection:
        return "Suspicious headers: Missing all browser-standard headers"
    if user_agent and server_protocol == "HTTP/1.0" and "chrome" in user_agent.lower():
        return "Suspicious headers: Modern browser with HTTP/1.0"

    score = 0
    if _has_header(environ, "HTTP_USER_AGENT"):
        score += 2
    if _has_header(environ, "HTTP_ACCEPT"):
        score += 2
    for header in [
        "HTTP_ACCEPT_LANGUAGE",
        "HTTP_ACCEPT_ENCODING",
        "HTTP_CONNECTION",
        "HTTP_CACHE_CONTROL",
    ]:
        if _has_header(environ, header):
            score += 1
    if accept_language and accept_encoding:
        score += 1
    if connection == "keep-alive":
        score += 1
    if "text/html" in accept and "application/xml" in accept:
        score += 1

    if score < 3:
        return f"Low header quality score: {score}"

    return None

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

            use_rust = (
                current_app.config.get("AIWAF_USE_RUST", False)
                and current_app.config.get("AIWAF_USE_CSV", True)
                and rust_backend.rust_available()
            )

            if use_rust:
                reason = rust_backend.validate_headers(request.environ)
            else:
                reason = validate_headers_python(request.environ)

            if reason:
                BlacklistManager.block(ip, reason)
                logger = getattr(current_app, "aiwaf_logger", None)
                if logger is not None:
                    logger.mark_request_blocked(reason)
                return jsonify({"error": "blocked"}), 403
