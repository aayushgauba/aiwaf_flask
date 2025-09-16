import re
from flask import request
from .storage import is_ip_whitelisted

def get_ip():
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or ""

def is_exempt(request):
    """Check if request should be exempt from AIWAF protection."""
    ip = get_ip()
    
    # IP-based exemption
    if is_ip_whitelisted(ip):
        return True
    
    # Path-based exemption
    if is_path_exempt(request.path):
        return True
    
    # Decorator-based exemption
    if hasattr(request, 'endpoint') and request.endpoint:
        try:
            from flask import current_app
            endpoint_func = current_app.view_functions.get(request.endpoint)
            if endpoint_func and getattr(endpoint_func, '_aiwaf_exempt', False):
                return True
        except:
            pass
    
    return False

def is_path_exempt(path):
    """Check if a path should be exempt from AIWAF protection."""
    try:
        from flask import current_app
        exempt_paths = current_app.config.get('AIWAF_EXEMPT_PATHS', get_default_exempt_paths())
    except:
        exempt_paths = get_default_exempt_paths()
    
    path_lower = path.lower()
    
    # Check exact matches
    if path_lower in exempt_paths:
        return True
    
    # Check pattern matches (for paths that support wildcards)
    for exempt_path in exempt_paths:
        if '*' in exempt_path:
            # Convert wildcard pattern to regex
            pattern = exempt_path.replace('*', '.*')
            if re.match(f'^{pattern}$', path_lower, re.IGNORECASE):
                return True
        elif exempt_path.endswith('/') and path_lower.startswith(exempt_path):
            # Directory-based exemption
            return True
    
    return False

def get_default_exempt_paths():
    """Get default list of paths that should be exempt from AIWAF protection."""
    return {
        # Common static files that may legitimately 404
        '/favicon.ico',
        '/robots.txt',
        '/sitemap.xml',
        '/sitemap.txt',
        '/ads.txt',
        '/security.txt',
        '/.well-known/',
        
        # Apple touch icons
        '/apple-touch-icon.png',
        '/apple-touch-icon-precomposed.png',
        
        # Manifest files
        '/manifest.json',
        '/browserconfig.xml',
        
        # Common legitimate endpoints that might 404
        '/health',
        '/healthcheck',
        '/ping',
        '/status',
        
        # Static file extensions (with wildcards)
        '*.css',
        '*.js', 
        '*.png',
        '*.jpg',
        '*.jpeg',
        '*.gif',
        '*.ico',
        '*.svg',
        '*.woff',
        '*.woff2',
        '*.ttf',
        '*.eot',
        
        # Static directories
        '/static/',
        '/assets/',
        '/css/',
        '/js/',
        '/images/',
        '/img/',
        '/fonts/',
    }
