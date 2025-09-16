#!/usr/bin/env python3
"""
Comprehensive tests for AIWAF Flask exemption decorators

Tests all exemption scenarios:
- @aiwaf_exempt: Full exemption from all middlewares
- @aiwaf_exempt_from: Partial exemption from specific middlewares
- @aiwaf_only: Apply only specific middlewares
- @aiwaf_require_protection: Force protection even if exempted elsewhere
"""

import time
from flask import Flask, jsonify, g
from aiwaf_flask import (
    AIWAF, 
    aiwaf_exempt, 
    aiwaf_exempt_from, 
    aiwaf_only,
    aiwaf_require_protection,
    should_apply_middleware
)


def test_full_exemption():
    """Test @aiwaf_exempt decorator bypasses all middlewares"""
    print("🧪 Testing @aiwaf_exempt (full exemption)")
    
    app = Flask(__name__)
    app.config.update({
        'AIWAF_LOG_DIR': 'aiwaf_logs',
        'AIWAF_RATE_MAX': 1,        # Very low limit to trigger easily
        'AIWAF_MIN_FORM_TIME': 10,  # High time to trigger honeypot
        'AIWAF_MIN_AI_LOGS': 10,    # Low threshold for AI
    })
    
    # Register AIWAF with all middlewares
    aiwaf = AIWAF()
    aiwaf.init_app(app)
    
    @app.route('/health')
    @aiwaf_exempt
    def health_check():
        return jsonify({'status': 'ok', 'protected': False})
    
    @app.route('/protected')
    def protected_endpoint():
        return jsonify({'status': 'ok', 'protected': True})
    
    with app.test_client() as client:
        # Test exempt endpoint - should work even with aggressive limits
        for i in range(5):  # Way over rate limit
            response = client.get('/health')
            assert response.status_code == 200
            data = response.get_json()
            assert data['protected'] == False
        
        print("   ✅ Exempt endpoint bypassed rate limiting")
        
        # Test protected endpoint - should be blocked by rate limiting
        response1 = client.get('/protected')
        assert response1.status_code == 200  # First request OK
        
        response2 = client.get('/protected')
        assert response2.status_code == 429  # Second request blocked by rate limit
        
        print("   ✅ Protected endpoint enforced rate limiting")
    
    print("   🎉 Full exemption test passed!\n")


def test_partial_exemption():
    """Test @aiwaf_exempt_from decorator exempts specific middlewares"""
    print("🧪 Testing @aiwaf_exempt_from (partial exemption)")
    
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
        # This should bypass rate limiting and AI but still check other things
        return jsonify({'received': True})
    
    @app.route('/normal')
    def normal_endpoint():
        return jsonify({'normal': True})
    
    with app.test_client() as client:
        # Test webhook - should bypass rate limiting
        for i in range(3):  # Over rate limit
            response = client.get('/webhook')
            assert response.status_code == 200
        
        print("   ✅ Webhook bypassed rate limiting")
        
        # Test normal endpoint - should be rate limited
        response1 = client.get('/normal')
        assert response1.status_code == 200  # First OK
        
        response2 = client.get('/normal')
        assert response2.status_code == 429  # Blocked by rate limit
        
        print("   ✅ Normal endpoint enforced rate limiting")
    
    print("   🎉 Partial exemption test passed!\n")


def test_middleware_only():
    """Test @aiwaf_only decorator applies only specific middlewares"""
    print("🧪 Testing @aiwaf_only (selective protection)")
    
    app = Flask(__name__)
    app.config.update({
        'AIWAF_LOG_DIR': 'aiwaf_logs',
        'AIWAF_RATE_MAX': 1,        # Very low rate limit
        'AIWAF_MIN_AI_LOGS': 10,    # Low threshold for AI
    })
    
    aiwaf = AIWAF()
    aiwaf.init_app(app)
    
    @app.route('/api/sensitive')
    @aiwaf_only('ip_keyword_block', 'rate_limit')  # Only IP blocking and rate limiting
    def sensitive_api():
        return jsonify({'sensitive': True})
    
    with app.test_client() as client:
        # Test that rate limiting still works
        response1 = client.get('/api/sensitive')
        assert response1.status_code == 200
        
        response2 = client.get('/api/sensitive')
        assert response2.status_code == 429  # Rate limited
        
        print("   ✅ Rate limiting applied as expected")
        
        # Test malicious path - should be blocked by IP/keyword blocking
        response3 = client.get('/api/sensitive/.env')
        assert response3.status_code == 403  # Blocked by keyword detection
        
        print("   ✅ Keyword blocking applied as expected")
    
    print("   🎉 Selective protection test passed!\n")


def test_required_protection():
    """Test @aiwaf_require_protection forces middlewares even if exempted"""
    print("🧪 Testing @aiwaf_require_protection (forced protection)")
    
    app = Flask(__name__)
    app.config.update({
        'AIWAF_LOG_DIR': 'aiwaf_logs',
        'AIWAF_RATE_MAX': 1,
        'AIWAF_MIN_AI_LOGS': 10,
    })
    
    aiwaf = AIWAF()
    aiwaf.init_app(app)
    
    @app.route('/admin/critical')
    @aiwaf_exempt_from('rate_limit')  # Try to exempt from rate limiting
    @aiwaf_require_protection('rate_limit')  # But force it anyway
    def critical_admin():
        return jsonify({'admin': True})
    
    with app.test_client() as client:
        # Should still be rate limited despite exemption
        response1 = client.get('/admin/critical')
        assert response1.status_code == 200
        
        response2 = client.get('/admin/critical')
        assert response2.status_code == 429  # Still rate limited!
        
        print("   ✅ Required protection overrode exemption")
    
    print("   🎉 Required protection test passed!\n")


def test_exemption_utilities():
    """Test exemption utility functions work correctly"""
    print("🧪 Testing exemption utility functions")
    
    app = Flask(__name__)
    
    @app.route('/test-utils')
    @aiwaf_exempt_from('rate_limit', 'ai_anomaly')
    def test_utils():
        # Test the utility functions
        results = {
            'should_apply_rate_limit': should_apply_middleware('rate_limit'),
            'should_apply_ip_block': should_apply_middleware('ip_keyword_block'),
            'should_apply_ai': should_apply_middleware('ai_anomaly'),
        }
        return jsonify(results)
    
    @app.route('/test-full-exempt')
    @aiwaf_exempt
    def test_full_exempt():
        results = {
            'should_apply_rate_limit': should_apply_middleware('rate_limit'),
            'should_apply_ip_block': should_apply_middleware('ip_keyword_block'),
        }
        return jsonify(results)
    
    with app.test_client() as client:
        # Test partial exemption utilities
        response = client.get('/test-utils')
        data = response.get_json()
        
        assert data['should_apply_rate_limit'] == False  # Exempt
        assert data['should_apply_ip_block'] == True     # Not exempt
        assert data['should_apply_ai'] == False          # Exempt
        
        print("   ✅ Partial exemption utilities work correctly")
        
        # Test full exemption utilities
        response = client.get('/test-full-exempt')
        data = response.get_json()
        
        assert data['should_apply_rate_limit'] == False  # Fully exempt
        assert data['should_apply_ip_block'] == False    # Fully exempt
        
        print("   ✅ Full exemption utilities work correctly")
    
    print("   🎉 Utility functions test passed!\n")


def test_complex_exemption_combinations():
    """Test complex combinations of exemption decorators"""
    print("🧪 Testing complex exemption combinations")
    
    app = Flask(__name__)
    app.config.update({
        'AIWAF_LOG_DIR': 'aiwaf_logs',
        'AIWAF_RATE_MAX': 1,
        'AIWAF_MIN_AI_LOGS': 10,
    })
    
    aiwaf = AIWAF()
    aiwaf.init_app(app)
    
    @app.route('/complex1')
    @aiwaf_only('rate_limit', 'ip_keyword_block')      # Only these two
    @aiwaf_require_protection('header_validation')     # Plus force this one
    def complex_endpoint1():
        return jsonify({'endpoint': 'complex1'})
    
    @app.route('/complex2') 
    @aiwaf_exempt_from('rate_limit')                   # Exempt from rate limiting
    @aiwaf_require_protection('rate_limit')            # But force it anyway
    def complex_endpoint2():
        return jsonify({'endpoint': 'complex2'})
    
    with app.test_client() as client:
        # Test complex1 - should have rate limiting + IP blocking + forced header validation
        response1 = client.get('/complex1')
        assert response1.status_code == 200
        
        response2 = client.get('/complex1')
        assert response2.status_code == 429  # Rate limited
        
        print("   ✅ Complex combination 1 works correctly")
        
        # Test complex2 - exemption should be overridden by requirement
        response3 = client.get('/complex2')
        assert response3.status_code == 200
        
        response4 = client.get('/complex2')
        assert response4.status_code == 429  # Still rate limited despite exemption
        
        print("   ✅ Complex combination 2 works correctly")
    
    print("   🎉 Complex combinations test passed!\n")


def run_all_exemption_tests():
    """Run all exemption decorator tests"""
    print("🚀 AIWAF Flask Exemption Decorators - Comprehensive Test Suite")
    print("=" * 70)
    
    test_full_exemption()
    test_partial_exemption() 
    test_middleware_only()
    test_required_protection()
    test_exemption_utilities()
    test_complex_exemption_combinations()
    
    print("🎉 All exemption decorator tests passed!")
    print("\n💡 Key Features Validated:")
    print("   ✅ @aiwaf_exempt - Complete bypass of all middlewares")
    print("   ✅ @aiwaf_exempt_from - Selective middleware exemption") 
    print("   ✅ @aiwaf_only - Apply only specific middlewares")
    print("   ✅ @aiwaf_require_protection - Force critical protection")
    print("   ✅ should_apply_middleware() - Runtime exemption checking")
    print("   ✅ Complex decorator combinations work correctly")
    
    print("\n🛡️  Use Cases Covered:")
    print("   🏥 Health checks and monitoring endpoints (@aiwaf_exempt)")
    print("   🪝 Webhooks and API callbacks (@aiwaf_exempt_from)")
    print("   🎯 High-security endpoints (@aiwaf_only + critical middlewares)")
    print("   🔒 Admin functions (@aiwaf_require_protection)")
    print("   🧪 Custom exemption logic (utility functions)")


if __name__ == '__main__':
    run_all_exemption_tests()