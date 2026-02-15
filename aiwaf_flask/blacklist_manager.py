from .storage import is_ip_blacklisted, add_ip_blacklist, remove_ip_blacklist
import json

from flask import current_app, has_request_context, request


DEFAULT_CAPTURE_HEADERS = [
    "User-Agent",
    "Accept",
    "Accept-Language",
    "X-Forwarded-For",
    "X-Real-IP",
    "Referer",
]
DEFAULT_REDACT_HEADERS = [
    "Authorization",
    "Cookie",
    "Set-Cookie",
    "X-Api-Key",
]

# Flask-adapted BlacklistManager
class BlacklistManager:
    @classmethod
    def is_blocked(cls, ip):
        return is_ip_blacklisted(ip)
    @classmethod
    def block(cls, ip, reason=None, extended_request_info=None):
        if extended_request_info is None:
            extended_request_info = _build_request_info()
        add_ip_blacklist(ip, reason, extended_request_info=extended_request_info)
    @classmethod
    def unblock(cls, ip):
        remove_ip_blacklist(ip)


def _build_request_info():
    if not has_request_context():
        return None

    enabled = bool(current_app.config.get("AIWAF_CAPTURE_EXTENDED_REQUEST_INFO", False))
    if not enabled:
        return None

    max_bytes = int(current_app.config.get("AIWAF_EXTENDED_REQUEST_INFO_MAX_BYTES", 4096))
    capture_headers = current_app.config.get(
        "AIWAF_EXTENDED_REQUEST_INFO_HEADERS",
        DEFAULT_CAPTURE_HEADERS,
    )
    redact_headers = current_app.config.get(
        "AIWAF_EXTENDED_REQUEST_INFO_REDACT_HEADERS",
        DEFAULT_REDACT_HEADERS,
    )

    redact_set = {str(h).strip().lower() for h in redact_headers if h}
    selected_headers = {}
    for header_name in capture_headers:
        if not header_name:
            continue
        key = str(header_name).strip()
        value = request.headers.get(key)
        if value is None:
            continue
        if key.lower() in redact_set:
            selected_headers[key] = "[REDACTED]"
        else:
            selected_headers[key] = value

    payload = {
        "url": request.url,
        "path": request.path,
        "query": request.query_string.decode("utf-8", errors="ignore"),
        "method": request.method,
        "host": request.host,
        "headers": selected_headers,
    }

    # Keep payload under configured byte limit by dropping large fields first.
    compact = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    if len(compact.encode("utf-8")) <= max_bytes:
        return payload

    payload["headers"] = {}
    compact = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    if len(compact.encode("utf-8")) <= max_bytes:
        return payload

    query_val = payload.get("query", "")
    if query_val:
        payload["query"] = query_val[:256]
        compact = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        if len(compact.encode("utf-8")) <= max_bytes:
            return payload

    url_val = payload.get("url", "")
    if url_val:
        payload["url"] = url_val[:256]
        compact = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        if len(compact.encode("utf-8")) <= max_bytes:
            return payload

    return {
        "path": request.path,
        "method": request.method,
        "host": request.host,
        "truncated": True,
    }
