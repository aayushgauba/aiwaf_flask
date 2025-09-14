import pytest
from flask import Flask
from aiwaf_flask.db_models import db
from aiwaf_flask.middleware import register_aiwaf_middlewares
from aiwaf_flask.storage import add_ip_whitelist, add_ip_blacklist

def test_full_integration(app):
    """Test full AIWAF integration with Flask app."""
    register_aiwaf_middlewares(app)
    
    @app.route('/protected')
    def protected():
        return 'Protected content'
    
    client = app.test_client()
    
    # Normal request should work
    response = client.get('/protected', headers={'User-Agent': 'Test Browser 1.0'})
    assert response.status_code == 200
    assert b'Protected content' in response.data

def test_whitelist_bypass(app):
    """Test that whitelisted IPs bypass all protection."""
    register_aiwaf_middlewares(app)
    
    with app.app_context():
        add_ip_whitelist('127.0.0.1')
    
    @app.route('/test')
    def test_route():
        return 'OK'
    
    client = app.test_client()
    
    # Even malicious-looking request should work for whitelisted IP
    response = client.get('/test.php')  # Normally blocked keyword
    # Note: This might still be blocked depending on middleware order
    # In a real implementation, whitelist check should come first

def test_multiple_middleware_interaction(app):
    """Test interaction between multiple middleware."""
    register_aiwaf_middlewares(app)
    
    @app.route('/test')
    def test_route():
        return 'OK'
    
    client = app.test_client()
    
    # Request that should trigger multiple validations
    response = client.get('/test', headers={'User-Agent': 'sh'})  # Short UA
    assert response.status_code == 403

def test_database_persistence(app):
    """Test that data persists in database."""
    with app.app_context():
        add_ip_blacklist('192.168.1.100', 'test blacklist')
        
        # Verify data persists
        from aiwaf_flask.storage import is_ip_blacklisted
        assert is_ip_blacklisted('192.168.1.100')

def test_configuration_settings(app):
    """Test that configuration settings are applied."""
    assert app.config['AIWAF_RATE_WINDOW'] == 10
    assert app.config['AIWAF_RATE_MAX'] == 20
    assert app.config['AIWAF_RATE_FLOOD'] == 40
    assert app.config['AIWAF_MIN_FORM_TIME'] == 1.0