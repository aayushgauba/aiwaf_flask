#!/usr/bin/env python3
"""
AIWAF Flask Exemption Decorators - Complete Demonstration

Shows all exemption decorators in action with realistic use cases.
"""

from flask import Flask, jsonify, request
from aiwaf_flask import (
    AIWAF, 
    aiwaf_exempt, 
    aiwaf_exempt_from, 
    aiwaf_only,
    aiwaf_require_protection
)
import time

def create_demo_app():
    """Create a demo Flask app with various exemption scenarios"""
    
    app = Flask(__name__)
    app.config.update({
        'AIWAF_LOG_DIR': 'aiwaf_logs',
        'AIWAF_RATE_MAX': 2,        # Low rate limit for demo
        'AIWAF_MIN_AI_LOGS': 10,    # Enable AI
    })
    
    # Initialize AIWAF with all middlewares
    aiwaf = AIWAF(app)
    
    # ===== MONITORING ENDPOINTS (No Protection Needed) =====
    
    @app.route('/health')
    @aiwaf_exempt
    def health_check():
        """Health check - no security needed"""
        return jsonify({
            'status': 'healthy',
            'timestamp': time.time(),
            'protection': 'none - fully exempt'
        })
    
    @app.route('/metrics')
    @aiwaf_exempt
    def metrics():
        """Metrics endpoint - called frequently by monitoring"""
        return jsonify({
            'requests_total': 1234,
            'errors_total': 5,
            'protection': 'none - fully exempt'
        })
    
    # ===== WEBHOOK ENDPOINTS (Selective Protection) =====
    
    @app.route('/webhooks/github', methods=['POST'])
    @aiwaf_exempt_from('rate_limit', 'honeypot')
    def github_webhook():
        """GitHub webhook - exempt from rate limiting and honeypot"""
        return jsonify({
            'webhook': 'github',
            'received': True,
            'protection': 'partial - exempt from rate_limit, honeypot'
        })
    
    @app.route('/webhooks/stripe', methods=['POST'])
    @aiwaf_exempt_from('ai_anomaly', 'rate_limit')
    def stripe_webhook():
        """Stripe webhook - financial data, exempt from AI analysis"""
        return jsonify({
            'webhook': 'stripe',
            'processed': True,
            'protection': 'partial - exempt from ai_anomaly, rate_limit'
        })
    
    # ===== PUBLIC API (Minimal Protection) =====
    
    @app.route('/api/public/products')
    @aiwaf_only('rate_limit')
    def public_products():
        """Public API - only rate limiting needed"""
        return jsonify({
            'products': ['laptop', 'phone', 'tablet'],
            'protection': 'minimal - only rate_limit'
        })
    
    @app.route('/api/public/search')
    @aiwaf_only('rate_limit', 'ip_keyword_block')
    def public_search():
        """Public search - basic protection"""
        query = request.args.get('q', '')
        return jsonify({
            'query': query,
            'results': ['result1', 'result2'],
            'protection': 'basic - rate_limit + ip_keyword_block'
        })
    
    # ===== ADMIN ENDPOINTS (Full Protection Required) =====
    
    @app.route('/admin/users')
    @aiwaf_require_protection('ip_keyword_block', 'rate_limit', 'ai_anomaly')
    def admin_users():
        """Admin endpoint - always full protection"""
        return jsonify({
            'users': ['admin', 'user1', 'user2'],
            'protection': 'required - ip_keyword_block, rate_limit, ai_anomaly'
        })
    
    @app.route('/admin/critical')
    @aiwaf_exempt_from('logging')  # Try to exempt logging
    @aiwaf_require_protection('ip_keyword_block', 'rate_limit')  # Force critical protection
    def admin_critical():
        """Critical admin - forced protection overrides exemptions"""
        return jsonify({
            'operation': 'critical',
            'protection': 'forced - required protection overrides exemptions'
        })
    
    # ===== REGULAR ENDPOINTS (Full Protection) =====
    
    @app.route('/api/protected/data')
    def protected_data():
        """Regular endpoint with full AIWAF protection"""
        return jsonify({
            'data': 'sensitive information',
            'protection': 'full - all AIWAF middlewares active'
        })
    
    return app

def demonstrate_exemptions():
    """Demonstrate all exemption scenarios"""
    
    print("🚀 AIWAF Flask Exemption Decorators - Complete Demonstration")
    print("=" * 80)
    
    app = create_demo_app()
    
    with app.test_client() as client:
        
        print("\n🏥 MONITORING ENDPOINTS (@aiwaf_exempt)")
        print("-" * 50)
        
        # Test health check - should never be blocked
        for i in range(5):  # Way over rate limit
            response = client.get('/health')
            print(f"   Health check #{i+1}: {response.status_code} - {response.get_json()['protection']}")
        
        print("\n📡 WEBHOOK ENDPOINTS (@aiwaf_exempt_from)")
        print("-" * 50)
        
        # Test GitHub webhook - should bypass rate limiting
        for i in range(3):
            response = client.post('/webhooks/github')
            if response.status_code == 200:
                print(f"   GitHub webhook #{i+1}: {response.status_code} - {response.get_json()['protection']}")
            else:
                print(f"   GitHub webhook #{i+1}: {response.status_code} - Rate limited!")
        
        print("\n🌐 PUBLIC API (@aiwaf_only)")
        print("-" * 50)
        
        # Clear rate limit cache for public API test
        import aiwaf_flask.rate_limit_middleware as rl_mod
        rl_mod._aiwaf_cache.clear()
        
        # Test public API - should have minimal protection
        response = client.get('/api/public/products')
        print(f"   Public products: {response.status_code} - {response.get_json()['protection']}")
        
        # Second request should be rate limited
        response = client.get('/api/public/products')
        if response.status_code == 429:
            print("   Public products #2: 429 - Rate limited (as expected)")
        else:
            print(f"   Public products #2: {response.status_code} - {response.get_json()['protection']}")
        
        print("\n🔐 ADMIN ENDPOINTS (@aiwaf_require_protection)")
        print("-" * 50)
        
        # Clear rate limit cache for admin test
        rl_mod._aiwaf_cache.clear()
        
        # Create new client to reset rate limiting
        with app.test_client() as fresh_client:
            response = fresh_client.get('/admin/users')
            if response.status_code == 200:
                print(f"   Admin users: {response.status_code} - {response.get_json()['protection']}")
            else:
                print(f"   Admin users: {response.status_code} - Rate limited or blocked")
            
            response = fresh_client.get('/admin/critical')
            if response.status_code == 200:
                print(f"   Admin critical: {response.status_code} - {response.get_json()['protection']}")
            else:
                print(f"   Admin critical: {response.status_code} - Rate limited or blocked")
        
        print("\n🛡️  PROTECTED ENDPOINTS (Full Protection)")
        print("-" * 50)
        
        # Clear rate limit cache for protected endpoint test
        rl_mod._aiwaf_cache.clear()
        
        # Create another fresh client
        with app.test_client() as fresh_client:
            response = fresh_client.get('/api/protected/data')
            if response.status_code == 200:
                print(f"   Protected data: {response.status_code} - {response.get_json()['protection']}")
            else:
                print(f"   Protected data: {response.status_code} - Rate limited or blocked")
            
            # Second request should be rate limited
            response = fresh_client.get('/api/protected/data')
            if response.status_code == 429:
                print("   Protected data #2: 429 - Rate limited (full protection active)")
            else:
                print(f"   Protected data #2: {response.status_code} - Unexpected!")
    
    print("\n🎉 DEMONSTRATION COMPLETE!")
    print("\n📋 Summary of Exemption Types:")
    print("   🏥 @aiwaf_exempt: Complete bypass (health, metrics)")
    print("   📡 @aiwaf_exempt_from: Selective bypass (webhooks)")
    print("   🌐 @aiwaf_only: Minimal protection (public APIs)")
    print("   🔐 @aiwaf_require_protection: Forced protection (admin)")
    print("   🛡️  No decorator: Full protection (default)")
    
    print("\n💡 Use Cases Covered:")
    print("   ✅ Health checks and monitoring")
    print("   ✅ External webhooks")
    print("   ✅ Public APIs with controlled access")
    print("   ✅ Admin endpoints with mandatory security")
    print("   ✅ Regular protected endpoints")

if __name__ == '__main__':
    demonstrate_exemptions()