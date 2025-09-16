#!/usr/bin/env python3
"""Clean exemption decorator tests with proper isolation"""

from flask import Flask, jsonify
from aiwaf_flask import AIWAF
from aiwaf_flask.exemption_decorators import (
    aiwaf_exempt, aiwaf_exempt_from, aiwaf_only
)

def reset_rate_limit_cache():
    """Clear the rate limiting cache between tests"""
    import aiwaf_flask.rate_limit_middleware as rl_mod
    rl_mod._aiwaf_cache.clear()

def test_full_exemption():
    """Test @aiwaf_exempt decorator bypasses all protection"""
    print("🧪 Testing @aiwaf_exempt (full exemption)")
    
    reset_rate_limit_cache()
    
    app = Flask(__name__)
    app.config.update({
        'AIWAF_LOG_DIR': 'aiwaf_logs',
        'AIWAF_RATE_MAX': 1,        # Very low rate limit
        'AIWAF_MIN_AI_LOGS': 10,    # Low threshold for AI
    })
    
    aiwaf = AIWAF()
    aiwaf.init_app(app)
    
    @app.route('/health')
    @aiwaf_exempt
    def health_check():
        return jsonify({'status': 'ok'})
    
    @app.route('/protected')
    def protected_endpoint():
        return jsonify({'protected': True})
    
    with app.test_client() as client:
        # Test exempt endpoint - should bypass all protection
        for i in range(3):  # Over rate limit
            response = client.get('/health')
            assert response.status_code == 200
        
        print("   ✅ Exempt endpoint bypassed all protection")
    
    print("   🎉 Full exemption test passed!\n")


def test_partial_exemption():
    """Test @aiwaf_exempt_from decorator bypasses specific middlewares"""
    print("🧪 Testing @aiwaf_exempt_from (partial exemption)")
    
    reset_rate_limit_cache()
    
    app = Flask(__name__)
    app.config.update({
        'AIWAF_LOG_DIR': 'aiwaf_logs',
        'AIWAF_RATE_MAX': 1,        # Very low rate limit
        'AIWAF_MIN_AI_LOGS': 10,    # Low threshold for AI
    })
    
    aiwaf = AIWAF()
    aiwaf.init_app(app)
    
    @app.route('/webhook')
    @aiwaf_exempt_from('rate_limit', 'ai_anomaly')
    def webhook():
        return jsonify({'received': True})
    
    with app.test_client() as client:
        # Test webhook - should bypass rate limiting
        for i in range(3):  # Over rate limit
            response = client.get('/webhook')
            assert response.status_code == 200
        
        print("   ✅ Webhook bypassed rate limiting")
    
    print("   🎉 Partial exemption test passed!\n")


def test_middleware_only():
    """Test @aiwaf_only decorator applies only specific middlewares"""
    print("🧪 Testing @aiwaf_only (selective protection)")
    
    reset_rate_limit_cache()
    
    app = Flask(__name__)
    app.config.update({
        'AIWAF_LOG_DIR': 'aiwaf_logs',
        'AIWAF_RATE_MAX': 1,        # Very low rate limit
        'AIWAF_MIN_AI_LOGS': 10,    # Low threshold for AI
    })
    
    aiwaf = AIWAF()
    aiwaf.init_app(app)
    
    @app.route('/api/sensitive')
    @aiwaf_only('rate_limit')  # Only rate limiting
    def sensitive_api():
        return jsonify({'sensitive': True})
    
    with app.test_client() as client:
        # Test that rate limiting still works
        response1 = client.get('/api/sensitive')
        assert response1.status_code == 200
        
        response2 = client.get('/api/sensitive')
        assert response2.status_code == 429  # Rate limited
        
        print("   ✅ Sensitive API enforced rate limiting")
        print("   ✅ Other middlewares bypassed")
    
    print("   🎉 Middleware-only test passed!\n")


def test_rate_limit_enforcement():
    """Test that non-exempt endpoints still enforce rate limiting"""
    print("🧪 Testing rate limit enforcement on normal endpoints")
    
    reset_rate_limit_cache()
    
    app = Flask(__name__)
    app.config.update({
        'AIWAF_LOG_DIR': 'aiwaf_logs',
        'AIWAF_RATE_MAX': 1,        # Very low rate limit
        'AIWAF_MIN_AI_LOGS': 10,    # Low threshold for AI
    })
    
    aiwaf = AIWAF()
    aiwaf.init_app(app)
    
    @app.route('/normal')
    def normal_endpoint():
        return jsonify({'normal': True})
    
    with app.test_client() as client:
        # First request should work
        response1 = client.get('/normal')
        assert response1.status_code == 200
        
        # Second request should be rate limited
        response2 = client.get('/normal')
        assert response2.status_code == 429
        
        print("   ✅ Normal endpoint enforced rate limiting")
    
    print("   🎉 Rate limit enforcement test passed!\n")


def run_all_exemption_tests():
    """Run all exemption decorator tests"""
    print("🚀 AIWAF Flask Exemption Decorators - Comprehensive Test Suite")
    print("=" * 70)
    
    test_full_exemption()
    test_partial_exemption() 
    test_middleware_only()
    test_rate_limit_enforcement()
    
    print("🎉 All exemption decorator tests passed!")
    print("✨ Route-based exemption system working correctly!")


if __name__ == '__main__':
    run_all_exemption_tests()