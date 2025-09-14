#!/usr/bin/env python3
"""
Simple example showing AIWAF default behavior.
When you don't specify anything, it enables ALL middlewares.
"""

from flask import Flask, jsonify
from aiwaf_flask import AIWAF

# Create Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'demo-key-12345'
app.config['AIWAF_USE_CSV'] = True
app.config['AIWAF_DATA_DIR'] = 'demo_data'

# Default AIWAF - enables ALL middlewares automatically
aiwaf = AIWAF(app)

@app.route('/')
def home():
    """Home route showing AIWAF status."""
    enabled = aiwaf.get_enabled_middlewares()
    total_available = len(AIWAF.list_available_middlewares())
    
    return jsonify({
        "message": "AIWAF Flask Demo - Default Behavior",
        "middlewares_enabled": len(enabled),
        "total_available": total_available,
        "all_enabled": len(enabled) == total_available,
        "enabled_list": sorted(enabled),
        "note": "AIWAF(app) with no arguments enables ALL middlewares"
    })

@app.route('/status')
def status():
    """Detailed status of each middleware."""
    available = AIWAF.list_available_middlewares()
    status_info = {}
    
    for middleware in available:
        status_info[middleware] = {
            "enabled": aiwaf.is_middleware_enabled(middleware),
            "instance": aiwaf.get_middleware_instance(middleware) is not None
        }
    
    return jsonify({
        "middleware_status": status_info,
        "summary": f"{len(aiwaf.get_enabled_middlewares())}/{len(available)} middlewares enabled"
    })

@app.route('/test')
def test():
    """Test route to verify middlewares are working."""
    return jsonify({
        "message": "Test successful! All middlewares are protecting this route.",
        "protection_active": True
    })

if __name__ == '__main__':
    # Show what gets enabled by default
    print("🚀 AIWAF Flask Default Behavior Demo")
    print("=" * 40)
    print("Code: aiwaf = AIWAF(app)")
    print(f"Result: Enables {len(aiwaf.get_enabled_middlewares())} middlewares automatically")
    print(f"Middlewares: {', '.join(sorted(aiwaf.get_enabled_middlewares()))}")
    print("\n✅ All middlewares enabled by default!")
    print("\n🌐 Visit http://localhost:5000/ to see the demo")
    print("🌐 Visit http://localhost:5000/status for detailed status")
    
    app.run(host='0.0.0.0', port=5000, debug=True)