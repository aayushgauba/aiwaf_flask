#!/usr/bin/env python3
"""Comprehensive demonstration of AIWAF Flask log threshold features"""

from flask import Flask
from aiwaf_flask.anomaly_middleware import AIAnomalyMiddleware

def demo_threshold_features():
    """Demonstrate all log threshold and dynamic AI features"""
    
    print("🎯 AIWAF Flask: Complete Log Threshold & Dynamic AI Demo")
    print("=" * 70)
    
    # Demo 1: Default behavior with insufficient data
    print("\n📊 Demo 1: Default Configuration (Insufficient Data)")
    print("   Current logs: ~28 lines, Default threshold: 10,000")
    
    app1 = Flask(__name__)
    app1.config.update({
        'AIWAF_LOG_DIR': 'aiwaf_logs',
        'AIWAF_MIN_AI_LOGS': 10000,  # Default
        'AIWAF_FORCE_AI': False,     # Default  
    })
    
    middleware1 = AIAnomalyMiddleware()
    middleware1.init_app(app1)
    
    with app1.app_context():
        status = "🤖 AI Enabled" if middleware1.model else "🔤 Keyword-Only Mode"
        print(f"   Result: {status}")
    
    # Demo 2: Lowered threshold allows AI
    print("\n📊 Demo 2: Lowered Threshold (AI Enabled)")
    print("   Threshold: 20 logs")
    
    app2 = Flask(__name__)
    app2.config.update({
        'AIWAF_LOG_DIR': 'aiwaf_logs',
        'AIWAF_MIN_AI_LOGS': 20,     # Low threshold
        'AIWAF_FORCE_AI': False,
    })
    
    middleware2 = AIAnomalyMiddleware()
    middleware2.init_app(app2)
    
    with app2.app_context():
        status = "🤖 AI Enabled" if middleware2.model else "🔤 Keyword-Only Mode"
        print(f"   Result: {status}")
    
    # Demo 3: Force AI overrides threshold
    print("\n📊 Demo 3: Force AI Override")
    print("   Threshold: 100,000 logs (very high), Force AI: True")
    
    app3 = Flask(__name__)
    app3.config.update({
        'AIWAF_LOG_DIR': 'aiwaf_logs',
        'AIWAF_MIN_AI_LOGS': 100000, # Very high threshold
        'AIWAF_FORCE_AI': True,      # Override
    })
    
    middleware3 = AIAnomalyMiddleware()
    middleware3.init_app(app3)
    
    with app3.app_context():
        status = "🤖 AI Enabled" if middleware3.model else "🔤 Keyword-Only Mode"
        print(f"   Result: {status}")
    
    # Demo 4: Dynamic status changing
    print("\n📊 Demo 4: Dynamic AI Status Changes")
    print("   Testing runtime configuration changes...")
    
    app4 = Flask(__name__)
    app4.config.update({
        'AIWAF_LOG_DIR': 'aiwaf_logs',
        'AIWAF_MIN_AI_LOGS': 50000,    # High threshold
        'AIWAF_FORCE_AI': False,
        'AIWAF_AI_CHECK_INTERVAL': 1,  # Check every second for demo
    })
    
    middleware4 = AIAnomalyMiddleware()
    middleware4.init_app(app4)
    
    with app4.app_context():
        # Initial state
        status = "🤖 AI Enabled" if middleware4.model else "🔤 Keyword-Only Mode"
        print(f"   Initial: {status}")
        
        # Change threshold at runtime
        app4.config['AIWAF_MIN_AI_LOGS'] = 10
        middleware4.last_ai_check = 0  # Force immediate check
        middleware4._check_ai_status_periodically(app4)
        
        status = "🤖 AI Enabled" if middleware4.model else "🔤 Keyword-Only Mode"
        print(f"   After lowering threshold: {status}")
        
        # Enable force AI
        app4.config['AIWAF_FORCE_AI'] = True
        app4.config['AIWAF_MIN_AI_LOGS'] = 100000  # High again
        middleware4.last_ai_check = 0  # Force immediate check
        middleware4._check_ai_status_periodically(app4)
        
        status = "🤖 AI Enabled" if middleware4.model else "🔤 Keyword-Only Mode"
        print(f"   After enabling force AI: {status}")
        
        # Disable force AI
        app4.config['AIWAF_FORCE_AI'] = False
        middleware4.last_ai_check = 0  # Force immediate check
        middleware4._check_ai_status_periodically(app4)
        
        status = "🤖 AI Enabled" if middleware4.model else "🔤 Keyword-Only Mode"
        print(f"   After disabling force AI: {status}")
    
    print("\n🎉 Complete Demonstration Summary:")
    print("   ✅ Default threshold protection (keyword-only for small datasets)")
    print("   ✅ Custom threshold configuration (flexible for different environments)")
    print("   ✅ Force AI override (development/testing scenarios)")
    print("   ✅ Dynamic runtime changes (configuration updates without restart)")
    print("   ✅ Automatic protection mode switching (optimal performance)")
    
    print("\n💡 Key Benefits:")
    print("   🛡️  Never compromises security - always provides protection")
    print("   🚀 Optimizes performance - uses best mode for available data")
    print("   🔧 Highly configurable - adapts to any environment")
    print("   📈 Future-ready - automatically improves as data grows")

if __name__ == '__main__':
    demo_threshold_features()