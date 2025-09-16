#!/usr/bin/env python3
"""
Example: How to check for AI dependencies in your AIWAF Flask application.
"""

from flask import Flask, jsonify
from aiwaf_flask import AIWAF

def create_app_with_dependency_check():
    """Create Flask app with AI dependency checking."""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'demo-ai-deps'
    app.config['AIWAF_USE_CSV'] = True
    
    # Check AI dependencies before enabling AI middleware
    try:
        import numpy as np
        import sklearn
        ai_available = True
        print("✅ AI dependencies available - enabling AI anomaly detection")
    except ImportError:
        ai_available = False
        print("⚠️  AI dependencies missing - AI features disabled")
        print("   Install with: pip install aiwaf-flask[ai]")
    
    if ai_available:
        # Enable AI middleware when dependencies are available
        aiwaf = AIWAF(app, middlewares=[
            'ip_keyword_block',
            'rate_limit',
            'ai_anomaly',        # AI anomaly detection
            'header_validation',
            'logging'
        ])
    else:
        # Fallback to non-AI middlewares
        aiwaf = AIWAF(app, middlewares=[
            'ip_keyword_block',
            'rate_limit',
            'header_validation',
            'honeypot',
            'logging'
        ])
    
    @app.route('/')
    def home():
        """Show dependency status."""
        enabled = aiwaf.get_enabled_middlewares()
        
        return jsonify({
            "message": "AIWAF Flask with AI Dependency Check",
            "ai_dependencies_available": ai_available,
            "ai_middleware_enabled": aiwaf.is_middleware_enabled('ai_anomaly'),
            "enabled_middlewares": sorted(enabled),
            "installation_guide": {
                "basic": "pip install aiwaf-flask",
                "with_ai": "pip install aiwaf-flask[ai]",
                "ai_only": "pip install numpy>=1.20.0 scikit-learn>=1.0.0"
            }
        })
    
    @app.route('/ai-status')
    def ai_status():
        """Detailed AI status check."""
        status = {
            "ai_middleware_enabled": aiwaf.is_middleware_enabled('ai_anomaly'),
            "dependencies": {}
        }
        
        # Check individual dependencies
        try:
            import numpy as np
            status["dependencies"]["numpy"] = {
                "available": True,
                "version": np.__version__
            }
        except ImportError:
            status["dependencies"]["numpy"] = {
                "available": False,
                "install": "pip install numpy>=1.20.0"
            }
        
        try:
            import sklearn
            status["dependencies"]["scikit_learn"] = {
                "available": True,
                "version": sklearn.__version__
            }
        except ImportError:
            status["dependencies"]["scikit_learn"] = {
                "available": False,
                "install": "pip install scikit-learn>=1.0.0"
            }
        
        # Check if AIWAF detected the dependencies
        try:
            from aiwaf_flask.anomaly_middleware import NUMPY_AVAILABLE
            status["aiwaf_numpy_detected"] = NUMPY_AVAILABLE
        except ImportError:
            status["aiwaf_numpy_detected"] = False
        
        return jsonify(status)
    
    return app, aiwaf

def main():
    """Demo the dependency checking."""
    print("🤖 AIWAF Flask AI Dependency Check Demo")
    print("=" * 45)
    
    app, aiwaf = create_app_with_dependency_check()
    
    print(f"\n📊 Middleware Status:")
    enabled = aiwaf.get_enabled_middlewares()
    
    for middleware in AIWAF.list_available_middlewares():
        status = "✅ ENABLED" if middleware in enabled else "❌ DISABLED"
        print(f"  {middleware}: {status}")
    
    print(f"\n🔧 Total: {len(enabled)}/{len(AIWAF.list_available_middlewares())} middlewares enabled")
    
    # Test route
    with app.test_client() as client:
        response = client.get('/')
        data = response.get_json()
        print(f"\n🌐 AI Available: {data['ai_dependencies_available']}")
        print(f"🤖 AI Middleware: {data['ai_middleware_enabled']}")

if __name__ == '__main__':
    main()
    
    print("\n💡 Installation Options:")
    print("   Basic:  pip install aiwaf-flask")
    print("   AI:     pip install aiwaf-flask[ai]")
    print("   Full:   pip install aiwaf-flask[all]")
    print("\n🚀 To run the demo server:")
    print("   app, aiwaf = create_app_with_dependency_check()")
    print("   app.run(host='0.0.0.0', port=5000)")