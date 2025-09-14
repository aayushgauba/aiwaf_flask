import re
from flask import request
from .storage import is_ip_whitelisted

def get_ip():
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or ""

def is_exempt(request):
    ip = get_ip()
    return is_ip_whitelisted(ip)
