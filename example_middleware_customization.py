#!/usr/bin/env python3
"""
Example: AIWAF Flask with middleware customization.
Demonstrates different ways to configure AIWAF middlewares.
"""

from flask import Flask, jsonify, request, render_template_string
from aiwaf_flask import AIWAF

def create_minimal_app():
    """Create a Flask app with minimal AIWAF protection (essentials only)."""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'minimal-security-demo'
    app.config['AIWAF_USE_CSV'] = True
    app.config['AIWAF_DATA_DIR'] = 'minimal_data'
    
    # Enable only essential security middlewares
    aiwaf = AIWAF(app, middlewares=[
        'ip_keyword_block',  # Core IP/keyword blocking
        'rate_limit',        # Rate limiting
        'logging'            # Activity logging
    ])
    
    @app.route('/')
    def home():
        enabled = aiwaf.get_enabled_middlewares()
        return jsonify({
            "message": "Minimal AIWAF Security Active",
            "enabled_middlewares": sorted(enabled),
            "protection_level": "Essential"
        })
    
    @app.route('/status')
    def status():
        return jsonify({
            "total_middlewares": len(AIWAF.AVAILABLE_MIDDLEWARES),
            "enabled_count": len(aiwaf.get_enabled_middlewares()),
            "available": sorted(AIWAF.list_available_middlewares()),
            "enabled": sorted(aiwaf.get_enabled_middlewares())
        })
    
    return app

def create_ai_focused_app():
    """Create a Flask app focused on AI anomaly detection."""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'ai-security-demo'
    app.config['AIWAF_USE_CSV'] = True
    app.config['AIWAF_DATA_DIR'] = 'ai_data'
    
    # Focus on AI and modern security middlewares
    aiwaf = AIWAF(app, middlewares=[
        'ai_anomaly',         # AI-powered anomaly detection
        'header_validation',  # HTTP header validation
        'rate_limit',         # Rate limiting
        'logging'             # Activity logging
    ])
    
    @app.route('/')
    def home():
        return jsonify({
            "message": "AI-Focused AIWAF Security",
            "ai_enabled": aiwaf.is_middleware_enabled('ai_anomaly'),
            "protection_type": "Machine Learning Enhanced"
        })
    
    @app.route('/test-ai')
    def test_ai():
        """Route to test AI anomaly detection."""
        return jsonify({
            "message": "Normal request - AI analyzing patterns",
            "request_path": request.path,
            "args": dict(request.args)
        })
    
    return app

def create_custom_app():
    """Create a Flask app with custom middleware selection."""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'custom-security-demo'
    app.config['AIWAF_USE_CSV'] = True
    app.config['AIWAF_DATA_DIR'] = 'custom_data'
    
    # Custom selection: disable honeypot and UUID tampering
    aiwaf = AIWAF(app, disable_middlewares=[
        'honeypot',    # No honeypot timing protection
        'uuid_tamper'  # No UUID tampering protection
    ])
    
    @app.route('/')
    def home():
        disabled = set(AIWAF.AVAILABLE_MIDDLEWARES.keys()) - set(aiwaf.get_enabled_middlewares())
        return jsonify({
            "message": "Custom AIWAF Configuration",
            "enabled": sorted(aiwaf.get_enabled_middlewares()),
            "disabled": sorted(disabled),
            "customization": "Selective Protection"
        })
    
    @app.route('/middleware/<name>')
    def check_middleware(name):
        """Check if a specific middleware is enabled."""
        enabled = aiwaf.is_middleware_enabled(name)
        return jsonify({
            "middleware": name,
            "enabled": enabled,
            "status": "Active" if enabled else "Disabled"
        })
    
    return app

def demo_app_comparison():
    """Demonstrate different AIWAF configurations."""
    
    print("🚀 AIWAF Middleware Customization Demo")
    print("=" * 50)
    
    # Available middlewares
    available = AIWAF.list_available_middlewares()
    print(f"\n📋 Available Middlewares ({len(available)}):")
    for middleware in sorted(available):
        print(f"  - {middleware}")
    
    print("\n🔧 Configuration Examples:")
    
    # 1. Minimal App
    print("\n1️⃣  Minimal Security App:")
    minimal_app = create_minimal_app()
    with minimal_app.test_client() as client:
        response = client.get('/status')
        data = response.get_json()
        print(f"   Enabled: {data['enabled']}")
        print(f"   Count: {data['enabled_count']}/{data['total_middlewares']}")
    
    # 2. AI-Focused App
    print("\n2️⃣  AI-Focused Security App:")
    ai_app = create_ai_focused_app()
    with ai_app.test_client() as client:
        response = client.get('/')
        data = response.get_json()
        print(f"   AI Enabled: {data['ai_enabled']}")
        print(f"   Type: {data['protection_type']}")
    
    # 3. Custom App
    print("\n3️⃣  Custom Configuration App:")
    custom_app = create_custom_app()
    with custom_app.test_client() as client:
        response = client.get('/')
        data = response.get_json()
        print(f"   Enabled: {data['enabled']}")
        print(f"   Disabled: {data['disabled']}")
    
    print("\n✅ All configurations working correctly!")
    
    print("\n💡 Usage Patterns:")
    print("   🛡️  Minimal: Essential security only (3 middlewares)")
    print("   🤖 AI-Focused: Modern ML-based protection (4 middlewares)")
    print("   🎯 Custom: Selective enable/disable (5 middlewares)")
    print("   🔥 Full: All protections enabled (7 middlewares)")

if __name__ == '__main__':
    # Run the demo
    demo_app_comparison()
    
    print("\n🌐 To run individual apps:")
    print("   minimal_app = create_minimal_app()")
    print("   minimal_app.run(host='0.0.0.0', port=5001)")
    print("")
    print("   ai_app = create_ai_focused_app()")
    print("   ai_app.run(host='0.0.0.0', port=5002)")
    print("")
    print("   custom_app = create_custom_app()")
    print("   custom_app.run(host='0.0.0.0', port=5003)")