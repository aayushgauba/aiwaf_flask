#!/usr/bin/env python3
"""
AIWAF Flask Path Exemption Configuration Example

This demonstrates how to configure path exemptions to prevent false positives
for legitimate resources like favicon.ico, robots.txt, static files, etc.
"""

from flask import Flask, jsonify, send_from_directory
from aiwaf_flask import register_aiwaf_middlewares

# Create Flask app
app = Flask(__name__)

# Basic AIWAF Configuration
app.config.update({
    'AIWAF_RATE_WINDOW': 60,
    'AIWAF_RATE_MAX': 100,
    'AIWAF_RATE_FLOOD': 200,
    'AIWAF_MIN_FORM_TIME': 1.0,
    'AIWAF_USE_CSV': True,
    'AIWAF_DATA_DIR': 'aiwaf_data',
})

# Configure Path Exemptions
# These paths will be exempt from ALL AIWAF protection
app.config['AIWAF_EXEMPT_PATHS'] = {
    # SEO and crawlers
    '/favicon.ico',
    '/robots.txt',
    '/sitemap.xml',
    '/sitemap.txt',
    '/ads.txt',
    '/security.txt',
    
    # Apple and mobile
    '/apple-touch-icon.png',
    '/apple-touch-icon-precomposed.png',
    '/manifest.json',
    '/browserconfig.xml',
    
    # Health checks and monitoring
    '/health',
    '/healthcheck', 
    '/ping',
    '/status',
    '/metrics',
    
    # Well-known URIs (RFC 8615)
    '/.well-known/',
    
    # Static file extensions (with wildcards)
    '*.css',
    '*.js',
    '*.map',  # Source maps
    '*.png',
    '*.jpg',
    '*.jpeg',
    '*.gif',
    '*.ico',
    '*.svg',
    '*.webp',
    '*.woff',
    '*.woff2',
    '*.ttf',
    '*.eot',
    '*.pdf',
    '*.zip',
    '*.tar.gz',
    
    # Static directories
    '/static/',
    '/assets/',
    '/css/',
    '/js/',
    '/images/',
    '/img/',
    '/fonts/',
    '/uploads/',
    '/media/',
    '/downloads/',
    
    # API endpoints that should be public
    '/api/public/',
    '/api/v1/public/',
    
    # Custom application-specific exemptions
    '/special-public-endpoint',
    '/custom-webhook-receiver',
}

# Register AIWAF middlewares
register_aiwaf_middlewares(app)

# Demo routes
@app.route('/')
def index():
    return jsonify({
        "message": "AIWAF Flask with Path Exemptions Demo",
        "status": "protected",
        "note": "Try accessing exempt paths like /favicon.ico or /robots.txt"
    })

@app.route('/admin')
def admin():
    """This route will be protected by AIWAF."""
    return jsonify({"message": "Admin area - protected by AIWAF"})

@app.route('/api/users')
def api_users():
    """This route will be protected by AIWAF."""
    return jsonify({"users": ["alice", "bob"]})

@app.route('/api/public/status')
def public_status():
    """This route is exempt from AIWAF protection."""
    return jsonify({"status": "ok", "protected": False})

@app.route('/health')
def health_check():
    """Health check endpoint - exempt from AIWAF."""
    return jsonify({"status": "healthy", "timestamp": "2024-01-01T00:00:00Z"})

@app.route('/robots.txt')
def robots_txt():
    """Robots.txt - exempt from AIWAF protection."""
    return """User-agent: *
Allow: /
Disallow: /admin/
Disallow: /api/private/

Sitemap: /sitemap.xml"""

@app.route('/favicon.ico')
def favicon():
    """Favicon - exempt from AIWAF protection."""
    # In a real app, you'd serve an actual favicon file
    return '', 204

@app.route('/static/<path:filename>')
def static_files(filename):
    """Static files - exempt from AIWAF protection."""
    # In production, serve static files via nginx/apache
    return f"Static file: {filename}", 200, {'Content-Type': 'text/plain'}

@app.route('/.well-known/security.txt')
def security_txt():
    """Security policy - exempt from AIWAF protection."""
    return """Contact: security@example.com
Expires: 2025-12-31T23:59:59.000Z
Preferred-Languages: en
Canonical: https://example.com/.well-known/security.txt"""

# Error handlers
@app.errorhandler(403)
def forbidden(error):
    return jsonify({
        "error": "Forbidden",
        "message": "Request blocked by AIWAF",
        "code": 403
    }), 403

@app.errorhandler(429)
def too_many_requests(error):
    return jsonify({
        "error": "Too Many Requests", 
        "message": "Rate limit exceeded",
        "code": 429
    }), 429

def print_configuration():
    """Print the current AIWAF configuration."""
    print("AIWAF Flask Configuration")
    print("=" * 50)
    print(f"Rate Window: {app.config['AIWAF_RATE_WINDOW']} seconds")
    print(f"Rate Max: {app.config['AIWAF_RATE_MAX']} requests")
    print(f"Rate Flood: {app.config['AIWAF_RATE_FLOOD']} requests")
    print(f"Min Form Time: {app.config['AIWAF_MIN_FORM_TIME']} seconds")
    print(f"Use CSV Storage: {app.config['AIWAF_USE_CSV']}")
    print(f"Data Directory: {app.config['AIWAF_DATA_DIR']}")
    
    print(f"\nExempt Paths ({len(app.config['AIWAF_EXEMPT_PATHS'])} total):")
    print("-" * 30)
    for path in sorted(app.config['AIWAF_EXEMPT_PATHS']):
        print(f"  {path}")
    
    print(f"\nProtected Routes (examples):")
    print("-" * 30)
    print("  /admin - Admin area")
    print("  /api/users - User API")
    print("  /login - Login page")
    print("  /wp-admin/ - WordPress admin")
    print("  /.env - Environment files")

def demo_requests():
    """Demonstrate which requests would be exempt vs protected."""
    from aiwaf_flask.utils import is_path_exempt
    
    test_paths = [
        # Exempt paths
        ('/favicon.ico', '✅ EXEMPT'),
        ('/robots.txt', '✅ EXEMPT'),
        ('/health', '✅ EXEMPT'),
        ('/static/css/style.css', '✅ EXEMPT'),
        ('/assets/js/app.js', '✅ EXEMPT'),
        ('/.well-known/security.txt', '✅ EXEMPT'),
        ('/api/public/status', '✅ EXEMPT'),
        
        # Protected paths
        ('/admin', '🛡️  PROTECTED'),
        ('/api/users', '🛡️  PROTECTED'),
        ('/wp-admin/', '🛡️  PROTECTED'),
        ('/.env', '🛡️  PROTECTED'),
        ('/config.php', '🛡️  PROTECTED'),
        ('/login', '🛡️  PROTECTED'),
    ]
    
    print(f"\nRequest Protection Status:")
    print("-" * 50)
    
    with app.app_context():
        for path, expected_status in test_paths:
            is_exempt = is_path_exempt(path)
            actual_status = '✅ EXEMPT' if is_exempt else '🛡️  PROTECTED'
            status_icon = '✅' if actual_status == expected_status else '❌'
            print(f"{status_icon} {path:<30} | {actual_status}")

if __name__ == '__main__':
    print_configuration()
    demo_requests()
    
    print(f"\n🚀 Starting Flask app with AIWAF protection...")
    print("Try these URLs:")
    print("  http://localhost:5000/              - Protected home page")
    print("  http://localhost:5000/favicon.ico   - Exempt (no AIWAF)")
    print("  http://localhost:5000/robots.txt    - Exempt (no AIWAF)")
    print("  http://localhost:5000/health        - Exempt (no AIWAF)")
    print("  http://localhost:5000/admin         - Protected by AIWAF")
    print("  http://localhost:5000/api/users     - Protected by AIWAF")
    
    app.run(debug=True, host='0.0.0.0', port=5000)