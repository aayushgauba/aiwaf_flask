import pytest
from aiwaf_flask.storage import (
    is_ip_whitelisted, add_ip_whitelist,
    is_ip_blacklisted, add_ip_blacklist, remove_ip_blacklist,
    add_keyword, get_top_keywords
)

def test_add_ip_whitelist(app_context):
    """Test adding IP to whitelist."""
    ip = '192.168.1.1'
    assert not is_ip_whitelisted(ip)
    
    add_ip_whitelist(ip)
    assert is_ip_whitelisted(ip)

def test_add_duplicate_ip_whitelist(app_context):
    """Test adding duplicate IP to whitelist."""
    ip = '192.168.1.1'
    add_ip_whitelist(ip)
    add_ip_whitelist(ip)  # Should not raise error
    assert is_ip_whitelisted(ip)

def test_add_ip_blacklist(app_context):
    """Test adding IP to blacklist."""
    ip = '10.0.0.1'
    reason = 'suspicious activity'
    assert not is_ip_blacklisted(ip)
    
    add_ip_blacklist(ip, reason)
    assert is_ip_blacklisted(ip)

def test_remove_ip_blacklist(app_context):
    """Test removing IP from blacklist."""
    ip = '10.0.0.1'
    add_ip_blacklist(ip, 'test')
    assert is_ip_blacklisted(ip)
    
    remove_ip_blacklist(ip)
    assert not is_ip_blacklisted(ip)

def test_remove_nonexistent_ip_blacklist(app_context):
    """Test removing non-existent IP from blacklist."""
    ip = '10.0.0.1'
    remove_ip_blacklist(ip)  # Should not raise error
    assert not is_ip_blacklisted(ip)

def test_add_keyword(app_context):
    """Test adding keyword."""
    keyword = 'malicious'
    add_keyword(keyword)
    keywords = get_top_keywords()
    assert keyword in keywords

def test_add_duplicate_keyword(app_context):
    """Test adding duplicate keyword."""
    keyword = 'malicious'
    add_keyword(keyword)
    add_keyword(keyword)  # Should not raise error
    keywords = get_top_keywords()
    assert keyword in keywords

def test_get_top_keywords(app_context):
    """Test getting top keywords."""
    keywords = ['kw1', 'kw2', 'kw3']
    for kw in keywords:
        add_keyword(kw)
    
    top_keywords = get_top_keywords(2)
    assert len(top_keywords) == 2
    for kw in top_keywords:
        assert kw in keywords