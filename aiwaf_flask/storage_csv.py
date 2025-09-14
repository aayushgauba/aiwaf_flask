"""Storage functions for AIWAF Flask with CSV, database, and in-memory fallback."""

import csv
import os
from datetime import datetime
from pathlib import Path

try:
    from .db_models import db, WhitelistedIP, BlacklistedIP, Keyword
    from flask import current_app
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False

# Storage paths
DEFAULT_DATA_DIR = "aiwaf_data"
WHITELIST_CSV = "whitelist.csv"
BLACKLIST_CSV = "blacklist.csv"
KEYWORDS_CSV = "keywords.csv"

# In-memory fallback storage
_memory_whitelist = set()
_memory_blacklist = {}
_memory_keywords = set()

def _get_storage_mode():
    """Determine storage mode: 'database', 'csv', or 'memory'."""
    try:
        from flask import current_app
        
        # Check for database first
        if (DB_AVAILABLE and hasattr(current_app, 'extensions') and 
            'sqlalchemy' in current_app.extensions):
            return 'database'
        
        # Check for CSV storage configuration
        if current_app.config.get('AIWAF_USE_CSV', True):
            return 'csv'
            
    except:
        pass
    
    return 'memory'

def _get_data_dir():
    """Get data directory for CSV files."""
    try:
        from flask import current_app
        return current_app.config.get('AIWAF_DATA_DIR', DEFAULT_DATA_DIR)
    except:
        return DEFAULT_DATA_DIR

def _ensure_csv_files():
    """Ensure CSV files and directory exist."""
    data_dir = Path(_get_data_dir())
    data_dir.mkdir(exist_ok=True)
    
    # Create CSV files if they don't exist
    whitelist_file = data_dir / WHITELIST_CSV
    blacklist_file = data_dir / BLACKLIST_CSV
    keywords_file = data_dir / KEYWORDS_CSV
    
    if not whitelist_file.exists():
        with open(whitelist_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['ip', 'added_date'])
    
    if not blacklist_file.exists():
        with open(blacklist_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['ip', 'reason', 'added_date'])
    
    if not keywords_file.exists():
        with open(keywords_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['keyword', 'added_date'])

def _read_csv_whitelist():
    """Read whitelist from CSV."""
    _ensure_csv_files()
    whitelist = set()
    csv_file = Path(_get_data_dir()) / WHITELIST_CSV
    
    try:
        with open(csv_file, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                whitelist.add(row['ip'])
    except Exception:
        pass
    
    return whitelist

def _append_csv_whitelist(ip):
    """Append IP to whitelist CSV."""
    _ensure_csv_files()
    csv_file = Path(_get_data_dir()) / WHITELIST_CSV
    
    try:
        with open(csv_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([ip, datetime.now().isoformat()])
    except Exception:
        pass

def _read_csv_blacklist():
    """Read blacklist from CSV."""
    _ensure_csv_files()
    blacklist = {}
    csv_file = Path(_get_data_dir()) / BLACKLIST_CSV
    
    try:
        with open(csv_file, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                blacklist[row['ip']] = row['reason']
    except Exception:
        pass
    
    return blacklist

def _append_csv_blacklist(ip, reason):
    """Append IP to blacklist CSV."""
    _ensure_csv_files()
    csv_file = Path(_get_data_dir()) / BLACKLIST_CSV
    
    try:
        with open(csv_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([ip, reason, datetime.now().isoformat()])
    except Exception:
        pass

def _read_csv_keywords():
    """Read keywords from CSV."""
    _ensure_csv_files()
    keywords = set()
    csv_file = Path(_get_data_dir()) / KEYWORDS_CSV
    
    try:
        with open(csv_file, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                keywords.add(row['keyword'])
    except Exception:
        pass
    
    return keywords

def _append_csv_keyword(keyword):
    """Append keyword to CSV."""
    _ensure_csv_files()
    csv_file = Path(_get_data_dir()) / KEYWORDS_CSV
    
    try:
        with open(csv_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([keyword, datetime.now().isoformat()])
    except Exception:
        pass

def _rewrite_csv_blacklist(blacklist):
    """Rewrite blacklist CSV file."""
    _ensure_csv_files()
    csv_file = Path(_get_data_dir()) / BLACKLIST_CSV
    
    try:
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['ip', 'reason', 'added_date'])
            for ip, reason in blacklist.items():
                writer.writerow([ip, reason, datetime.now().isoformat()])
    except Exception:
        pass

# Legacy classes for backward compatibility
class ExemptionStore:
    _exempt_ips = set()
    def is_exempted(self, ip):
        return ip in self._exempt_ips
    def add_exempt(self, ip):
        self._exempt_ips.add(ip)

def get_exemption_store():
    return ExemptionStore()

class KeywordStore:
    def add_keyword(self, kw):
        add_keyword(kw)
    def get_top_keywords(self, n=10):
        return get_top_keywords(n)

def get_keyword_store():
    return KeywordStore()

# Public API functions
def is_ip_whitelisted(ip):
    """Check if IP is whitelisted."""
    storage_mode = _get_storage_mode()
    
    if storage_mode == 'database':
        try:
            return WhitelistedIP.query.filter_by(ip=ip).first() is not None
        except Exception:
            storage_mode = 'csv'
    
    if storage_mode == 'csv':
        whitelist = _read_csv_whitelist()
        return ip in whitelist
    else:
        return ip in _memory_whitelist

def add_ip_whitelist(ip):
    """Add IP to whitelist."""
    if is_ip_whitelisted(ip):
        return
    
    storage_mode = _get_storage_mode()
    
    if storage_mode == 'database':
        try:
            db.session.add(WhitelistedIP(ip=ip))
            db.session.commit()
            return
        except Exception:
            storage_mode = 'csv'
    
    if storage_mode == 'csv':
        _append_csv_whitelist(ip)
    else:
        _memory_whitelist.add(ip)

def is_ip_blacklisted(ip):
    """Check if IP is blacklisted."""
    storage_mode = _get_storage_mode()
    
    if storage_mode == 'database':
        try:
            return BlacklistedIP.query.filter_by(ip=ip).first() is not None
        except Exception:
            storage_mode = 'csv'
    
    if storage_mode == 'csv':
        blacklist = _read_csv_blacklist()
        return ip in blacklist
    else:
        return ip in _memory_blacklist

def add_ip_blacklist(ip, reason=None):
    """Add IP to blacklist."""
    if is_ip_blacklisted(ip):
        return
    
    storage_mode = _get_storage_mode()
    reason = reason or "Blocked"
    
    if storage_mode == 'database':
        try:
            db.session.add(BlacklistedIP(ip=ip, reason=reason))
            db.session.commit()
            return
        except Exception:
            storage_mode = 'csv'
    
    if storage_mode == 'csv':
        _append_csv_blacklist(ip, reason)
    else:
        _memory_blacklist[ip] = reason

def remove_ip_blacklist(ip):
    """Remove IP from blacklist."""
    storage_mode = _get_storage_mode()
    
    if storage_mode == 'database':
        try:
            entry = BlacklistedIP.query.filter_by(ip=ip).first()
            if entry:
                db.session.delete(entry)
                db.session.commit()
            return
        except Exception:
            storage_mode = 'csv'
    
    if storage_mode == 'csv':
        # For CSV, we need to rewrite the file without the IP
        blacklist = _read_csv_blacklist()
        if ip in blacklist:
            del blacklist[ip]
            _rewrite_csv_blacklist(blacklist)
    else:
        _memory_blacklist.pop(ip, None)

def add_keyword(kw):
    """Add keyword to blocked list."""
    storage_mode = _get_storage_mode()
    
    if storage_mode == 'database':
        try:
            if not Keyword.query.filter_by(keyword=kw).first():
                db.session.add(Keyword(keyword=kw))
                db.session.commit()
            return
        except Exception:
            storage_mode = 'csv'
    
    if storage_mode == 'csv':
        keywords = _read_csv_keywords()
        if kw not in keywords:
            _append_csv_keyword(kw)
    else:
        _memory_keywords.add(kw)

def get_top_keywords(n=10):
    """Get top keywords."""
    storage_mode = _get_storage_mode()
    
    if storage_mode == 'database':
        try:
            return [k.keyword for k in Keyword.query.limit(n).all()]
        except Exception:
            storage_mode = 'csv'
    
    if storage_mode == 'csv':
        keywords = _read_csv_keywords()
        return list(keywords)[:n]
    else:
        return list(_memory_keywords)[:n]