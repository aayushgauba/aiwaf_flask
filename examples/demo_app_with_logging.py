#!/usr/bin/env python3
"""
AIWAF Flask Demo App with Logging

Demonstrates AIWAF protection with web server style logging.
"""

from flask import Flask, request, jsonify
from aiwaf_flask import register_aiwaf_middlewares

# Create Flask app
app = Flask(__name__)

# Configure AIWAF with logging
app.config['AIWAF_LOG_DIR'] = 'demo_logs'
app.config['AIWAF_LOG_FORMAT'] = 'combined'  # Options: combined, common, csv, json
app.config['AIWAF_USE_CSV'] = True
app.config['AIWAF_DATA_DIR'] = 'demo_data'
app.config['AIWAF_RATE_MAX'] = 20  # Lower limit for demo
app.config['AIWAF_RATE_WINDOW'] = 60

# Register AIWAF protection with logging
register_aiwaf_middlewares(app)

@app.route('/')
def index():
    """Main page."""
    return """
    <h1>AIWAF Flask Demo with Logging</h1>
    <p>This demo shows AIWAF protection with web server style logging.</p>
    
    <h2>Test Links:</h2>
    <ul>
        <li><a href="/safe">Safe Page</a> - Normal request</li>
        <li><a href="/api/data">API Endpoint</a> - JSON response</li>
        <li><a href="/admin.php">Admin.php</a> - Should be blocked (malicious keyword)</li>
        <li><a href="/wp-admin">WP-Admin</a> - Should be blocked (WordPress path)</li>
        <li><a href="/shell.php">Shell.php</a> - Should be blocked (shell keyword)</li>
        <li><a href="/nonexistent">404 Page</a> - Will generate 404 error</li>
    </ul>
    
    <h2>Log Analysis:</h2>
    <p>After testing, run:</p>
    <code>python aiwaf_console.py logs --log-dir demo_logs --format combined</code>
    """

@app.route('/safe')
def safe_page():
    """A safe page that should work normally."""
    return {
        "message": "This is a safe page",
        "status": "allowed",
        "client_ip": request.remote_addr
    }

@app.route('/api/data')
def api_data():
    """API endpoint returning JSON."""
    return jsonify({
        "data": [1, 2, 3, 4, 5],
        "timestamp": "2025-09-14T15:00:00Z",
        "version": "1.0"
    })

@app.route('/search')
def search():
    """Search endpoint that accepts query parameters."""
    query = request.args.get('q', '')
    return f"Search results for: {query}"

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({"error": "Page not found", "path": request.path}), 404

@app.errorhandler(403)
def forbidden(error):
    """Handle 403 errors (blocked by AIWAF)."""
    return jsonify({"error": "Access forbidden by AIWAF protection"}), 403

if __name__ == '__main__':
    print("🚀 Starting AIWAF Flask Demo with Logging")
    print("=" * 50)
    print("📁 Logs will be saved to: demo_logs/")
    print("🛡️ AIWAF data saved to: demo_data/")
    print("🌐 Visit: http://localhost:5000")
    print("")
    print("After testing, analyze logs with:")
    print("  python aiwaf_console.py logs --log-dir demo_logs --format combined")
    print("  python aiwaf_console.py stats --data-dir demo_data")
    print("")
    
    app.run(debug=True, host='0.0.0.0', port=5000)