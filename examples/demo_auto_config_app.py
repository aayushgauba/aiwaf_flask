#!/usr/bin/env python3
"""
Demo Flask App with Automatic AIWAF CLI Integration

This demonstrates how the CLI automatically finds and uses the same
data directory as the Flask app without any user configuration.
"""

from flask import Flask, request, jsonify
import aiwaf_flask

# Create Flask app
app = Flask(__name__)

# AIWAF Configuration
app.config.update({
    'AIWAF_DATA_DIR': './my_app_data',  # Custom data directory
    'AIWAF_ENABLED': True,
    'AIWAF_RATE_LIMIT': '100/minute',
    'AIWAF_IP_BLOCK_ENABLED': True,
    'AIWAF_KEYWORD_BLOCK_ENABLED': True,
})

# Register AIWAF middlewares
aiwaf_flask.register_aiwaf_middlewares(app)

@app.route('/')
def index():
    return jsonify({
        'message': 'AIWAF Demo App',
        'data_directory': app.config.get('AIWAF_DATA_DIR'),
        'cli_instructions': {
            'list_all': 'python -m aiwaf_flask.cli list all',
            'add_to_whitelist': 'python -m aiwaf_flask.cli add whitelist 192.168.1.100',
            'add_to_blacklist': 'python -m aiwaf_flask.cli add blacklist 192.168.1.200 --reason "Malicious IP"',
            'note': 'CLI will automatically find and use the same data directory as this Flask app!'
        }
    })

@app.route('/test')
def test():
    return jsonify({
        'message': 'Test endpoint',
        'your_ip': request.remote_addr,
        'note': 'Try accessing this multiple times to trigger rate limiting'
    })

@app.route('/admin')
@aiwaf_flask.aiwaf_exempt  # This route bypasses all AIWAF protection
def admin():
    return jsonify({
        'message': 'Admin endpoint',
        'note': 'This endpoint is exempt from AIWAF protection'
    })

if __name__ == '__main__':
    print("🚀 Starting AIWAF Demo App")
    print(f"📁 AIWAF Data Directory: {app.config.get('AIWAF_DATA_DIR')}")
    print("🔧 CLI Commands:")
    print("   python -m aiwaf_flask.cli list all")
    print("   python -m aiwaf_flask.cli add whitelist 192.168.1.100")
    print("   python -m aiwaf_flask.cli add blacklist 192.168.1.200 --reason 'Test'")
    print()
    
    app.run(debug=True, port=5000)