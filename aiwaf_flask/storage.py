"""Storage functions for AIWAF Flask with CSV, database, and in-memory fallback."""

import csv
import os
import threading
import time
import logging
import random
from datetime import datetime
from pathlib import Path
from contextlib import contextmanager

# Cross-platform file locking imports
try:
    import fcntl  # Unix/Linux/macOS
    FCNTL_AVAILABLE = True
except ImportError:
    FCNTL_AVAILABLE = False

try:
    import msvcrt  # Windows
    MSVCRT_AVAILABLE = True
except ImportError:
    MSVCRT_AVAILABLE = False

try:
    from .db_models import db, WhitelistedIP, BlacklistedIP, Keyword, GeoBlockedCountry
    from flask import current_app
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False

# Storage paths
DEFAULT_DATA_DIR = "aiwaf_data"
WHITELIST_CSV = "whitelist.csv"
BLACKLIST_CSV = "blacklist.csv"
KEYWORDS_CSV = "keywords.csv"
GEO_BLOCKED_COUNTRIES_CSV = "geo_blocked_countries.csv"
PATH_EXEMPTIONS_CSV = "path_exemptions.csv"

# Retry configuration for Windows file operations
MAX_RETRIES = 3
RETRY_DELAY = 0.1  # seconds
TIMEOUT_SECONDS = 5  # Maximum time to wait for file access

# In-memory fallback storage
_memory_whitelist = set()
_memory_blacklist = {}
_memory_keywords = set()
_memory_geo_blocked_countries = set()
_memory_path_exemptions = {}

# Thread locks for process-level synchronization
_thread_locks = {
    WHITELIST_CSV: threading.RLock(),
    BLACKLIST_CSV: threading.RLock(),
    KEYWORDS_CSV: threading.RLock(),
    GEO_BLOCKED_COUNTRIES_CSV: threading.RLock()
}

# Configure logging
logger = logging.getLogger(__name__)

@contextmanager
def _file_lock(file_path, mode='r'):
    """Cross-platform file locking context manager with improved Windows support."""
    file_obj = None
    lock_acquired = False
    exc_raised = False

    def _open_with_retries(path, open_mode):
        last_exc = None
        for attempt in range(MAX_RETRIES):
            try:
                return open(path, open_mode, newline='' if 'b' not in open_mode else None)
            except (PermissionError, OSError) as e:
                last_exc = e
                time.sleep(RETRY_DELAY * (attempt + 1))
        if last_exc:
            raise last_exc

    try:
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        file_obj = _open_with_retries(file_path, mode)

        if FCNTL_AVAILABLE and file_obj:
            try:
                if 'w' in mode or 'a' in mode:
                    fcntl.flock(file_obj.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                else:
                    fcntl.flock(file_obj.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
                lock_acquired = True
            except (IOError, OSError):
                logger.debug(f"Could not acquire file lock for {file_path}")
        elif MSVCRT_AVAILABLE:
            # Windows locking is unreliable across threads/processes; rely on thread locks.
            lock_acquired = False

        try:
            if file_obj:
                yield file_obj
        except Exception:
            exc_raised = True
            raise
    finally:
        if file_obj:
            try:
                if lock_acquired:
                    if FCNTL_AVAILABLE:
                        fcntl.flock(file_obj.fileno(), fcntl.LOCK_UN)
                    elif MSVCRT_AVAILABLE:
                        pass
                file_obj.close()
            except Exception as e:
                logger.debug(f"Error closing file {file_path}: {e}")

def _safe_csv_operation(operation, *args, max_retries=5, base_delay=0.01, **kwargs):
    """Safely perform CSV operation with retry logic and exponential backoff."""
    last_exception = None
    
    for attempt in range(max_retries):
        try:
            return operation(*args, **kwargs)
        except (IOError, OSError, PermissionError) as e:
            last_exception = e
            if attempt < max_retries - 1:
                # Exponential backoff with jitter
                delay = base_delay * (2 ** attempt) + random.uniform(0, 0.01)
                time.sleep(delay)
                logger.debug(f"CSV operation retry {attempt + 1}/{max_retries} after {delay:.3f}s delay")
                continue
            logger.error(f"CSV operation failed after {max_retries} attempts: {e}")
            break
        except Exception as e:
            logger.error(f"Unexpected error in CSV operation: {e}")
            last_exception = e
            break
    
    # If all retries failed, raise the last exception
    if last_exception:
        raise last_exception

def _get_storage_mode():
    """Determine storage mode: 'database', 'csv', or 'memory'."""
    try:
        from flask import current_app
        
        # First check if CSV is explicitly enabled
        if current_app.config.get('AIWAF_USE_CSV', True):
            return 'csv'
        
        # Check for database only if CSV is disabled
        if (DB_AVAILABLE and hasattr(current_app, 'extensions') and 
            'sqlalchemy' in current_app.extensions):
            return 'database'
            
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
    """Ensure CSV files and directory exist with thread safety."""
    def _create_files():
        data_dir = Path(_get_data_dir())
        data_dir.mkdir(exist_ok=True)
        
        # Create CSV files if they don't exist
        files_to_create = [
            (data_dir / WHITELIST_CSV, ['ip', 'added_date']),
            (data_dir / BLACKLIST_CSV, ['ip', 'reason', 'added_date']),
            (data_dir / KEYWORDS_CSV, ['keyword', 'added_date']),
            (data_dir / GEO_BLOCKED_COUNTRIES_CSV, ['country', 'added_date']),
            (data_dir / PATH_EXEMPTIONS_CSV, ['path', 'reason', 'added_date'])
        ]
        
        for file_path, headers in files_to_create:
            if not file_path.exists():
                try:
                    thread_lock = _thread_locks.get(file_path.name, threading.RLock())
                    with thread_lock:
                        with _file_lock(file_path, 'w') as f:
                            writer = csv.writer(f)
                            writer.writerow(headers)
                except Exception as e:
                    logger.warning(f"Failed to create CSV file {file_path}: {e}")
    
    return _safe_csv_operation(_create_files)

def _read_csv_whitelist():
    """Read whitelist from CSV with thread safety."""
    def _read_operation():
        _ensure_csv_files()
        whitelist = set()
        csv_file = Path(_get_data_dir()) / WHITELIST_CSV
        thread_lock = _thread_locks.get(csv_file.name, threading.RLock())
        
        with thread_lock:
            try:
                with _file_lock(csv_file, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if 'ip' in row and row['ip'].strip():
                            whitelist.add(row['ip'].strip())
            except FileNotFoundError:
                logger.debug(f"Whitelist CSV file not found: {csv_file}")
            except Exception as e:
                logger.warning(f"Error reading whitelist CSV: {e}")
        
        return whitelist
    
    return _safe_csv_operation(_read_operation)

def _append_csv_whitelist(ip):
    """Append IP to whitelist CSV with thread safety and atomic operations."""
    def _append_operation():
        _ensure_csv_files()
        csv_file = Path(_get_data_dir()) / WHITELIST_CSV
        
        # Check for duplicates before appending
        filename = csv_file.name
        thread_lock = _thread_locks.get(filename, threading.RLock())
        
        with thread_lock:
            current_whitelist = _read_csv_whitelist()
            if ip in current_whitelist:
                return  # Already exists
            
            # Use atomic write pattern on Windows for better concurrency
            if MSVCRT_AVAILABLE:
                # Read all data, add new entry, write atomically
                all_data = []
                
                # Read existing data
                try:
                    with _file_lock(csv_file, 'r') as f:
                        reader = csv.reader(f)
                        all_data = list(reader)
                except FileNotFoundError:
                    all_data = [['ip', 'timestamp']]  # Header
                
                # Add new entry
                all_data.append([ip, datetime.now().isoformat()])
                
                # Write atomically
                with _file_lock(csv_file, 'w') as f:
                    writer = csv.writer(f)
                    writer.writerows(all_data)
            else:
                # Unix systems can use append safely
                with _file_lock(csv_file, 'a') as f:
                    writer = csv.writer(f)
                    writer.writerow([ip, datetime.now().isoformat()])
            
            logger.debug(f"Added IP {ip} to whitelist")
    
    return _safe_csv_operation(_append_operation)

def _read_csv_blacklist():
    """Read blacklist from CSV with thread safety."""
    def _read_operation():
        _ensure_csv_files()
        blacklist = {}
        csv_file = Path(_get_data_dir()) / BLACKLIST_CSV
        thread_lock = _thread_locks.get(csv_file.name, threading.RLock())
        
        with thread_lock:
            try:
                with _file_lock(csv_file, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if 'ip' in row and row['ip'].strip():
                            ip = row['ip'].strip()
                            reason = row.get('reason', 'No reason provided').strip()
                            blacklist[ip] = reason
            except FileNotFoundError:
                logger.debug(f"Blacklist CSV file not found: {csv_file}")
            except Exception as e:
                logger.warning(f"Error reading blacklist CSV: {e}")
        
        return blacklist
    
    return _safe_csv_operation(_read_operation)

def _append_csv_blacklist(ip, reason):
    """Append IP to blacklist CSV with thread safety."""
    def _append_operation():
        _ensure_csv_files()
        csv_file = Path(_get_data_dir()) / BLACKLIST_CSV
        
        # Check for duplicates before appending
        filename = csv_file.name
        thread_lock = _thread_locks.get(filename, threading.RLock())
        
        with thread_lock:
            current_blacklist = _read_csv_blacklist()
            if ip in current_blacklist:
                return  # Already exists
            
            with _file_lock(csv_file, 'a') as f:
                writer = csv.writer(f)
                writer.writerow([ip, reason, datetime.now().isoformat()])
                logger.debug(f"Added IP {ip} to blacklist with reason: {reason}")
    
    return _safe_csv_operation(_append_operation)

def _read_csv_keywords():
    """Read keywords from CSV with thread safety."""
    def _read_operation():
        _ensure_csv_files()
        keywords = set()
        csv_file = Path(_get_data_dir()) / KEYWORDS_CSV
        thread_lock = _thread_locks.get(csv_file.name, threading.RLock())
        
        with thread_lock:
            try:
                with _file_lock(csv_file, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if 'keyword' in row and row['keyword'].strip():
                            keywords.add(row['keyword'].strip())
            except FileNotFoundError:
                logger.debug(f"Keywords CSV file not found: {csv_file}")
            except Exception as e:
                logger.warning(f"Error reading keywords CSV: {e}")
        
        return keywords
    
    return _safe_csv_operation(_read_operation)

def _append_csv_keyword(keyword):
    """Append keyword to CSV with thread safety."""
    def _append_operation():
        _ensure_csv_files()
        csv_file = Path(_get_data_dir()) / KEYWORDS_CSV
        
        # Check for duplicates before appending
        filename = csv_file.name
        thread_lock = _thread_locks.get(filename, threading.RLock())
        
        with thread_lock:
            current_keywords = _read_csv_keywords()
            if keyword in current_keywords:
                return  # Already exists
            
            with _file_lock(csv_file, 'a') as f:
                writer = csv.writer(f)
                writer.writerow([keyword, datetime.now().isoformat()])
                logger.debug(f"Added keyword: {keyword}")
    
    return _safe_csv_operation(_append_operation)

def _read_csv_geo_blocked_countries():
    """Read geo blocked countries from CSV with thread safety."""
    def _read_operation():
        _ensure_csv_files()
        countries = set()
        csv_file = Path(_get_data_dir()) / GEO_BLOCKED_COUNTRIES_CSV
        thread_lock = _thread_locks.get(csv_file.name, threading.RLock())

        with thread_lock:
            try:
                with _file_lock(csv_file, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if 'country' in row and row['country'].strip():
                            countries.add(row['country'].strip().upper())
            except FileNotFoundError:
                logger.debug(f"Geo blocked countries CSV file not found: {csv_file}")
            except Exception as e:
                logger.warning(f"Error reading geo blocked countries CSV: {e}")

        return countries

    return _safe_csv_operation(_read_operation)

def _append_csv_geo_blocked_country(country_code):
    """Append geo blocked country to CSV with thread safety."""
    def _append_operation():
        _ensure_csv_files()
        csv_file = Path(_get_data_dir()) / GEO_BLOCKED_COUNTRIES_CSV

        filename = csv_file.name
        thread_lock = _thread_locks.get(filename, threading.RLock())

        with thread_lock:
            current_countries = _read_csv_geo_blocked_countries()
            if country_code in current_countries:
                return

            with _file_lock(csv_file, 'a') as f:
                writer = csv.writer(f)
                writer.writerow([country_code, datetime.now().isoformat()])
                logger.debug(f"Added geo blocked country: {country_code}")

    return _safe_csv_operation(_append_operation)

def _rewrite_csv_geo_blocked_countries(countries):
    """Rewrite geo blocked countries CSV file with thread safety."""
    def _rewrite_operation():
        _ensure_csv_files()
        csv_file = Path(_get_data_dir()) / GEO_BLOCKED_COUNTRIES_CSV
        temp_file = csv_file.with_suffix('.tmp')

        try:
            with _file_lock(temp_file, 'w') as f:
                writer = csv.writer(f)
                writer.writerow(['country', 'added_date'])
                for country in sorted(countries):
                    writer.writerow([country, datetime.now().isoformat()])

            if os.name == 'nt':
                if csv_file.exists():
                    csv_file.unlink()
                temp_file.rename(csv_file)
            else:
                temp_file.rename(csv_file)

            logger.debug(f"Rewrote geo blocked countries CSV with {len(countries)} entries")
        except Exception as e:
            if temp_file.exists():
                temp_file.unlink()
            raise e

    return _safe_csv_operation(_rewrite_operation)


def _read_csv_path_exemptions():
    """Read path exemptions from CSV with thread safety."""
    def _read_operation():
        _ensure_csv_files()
        exemptions = {}
        csv_file = Path(_get_data_dir()) / PATH_EXEMPTIONS_CSV
        thread_lock = _thread_locks.get(csv_file.name, threading.RLock())

        with thread_lock:
            try:
                with _file_lock(csv_file, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        path = str(row.get('path', '')).strip()
                        if not path:
                            continue
                        reason = str(row.get('reason', '')).strip()
                        exemptions[path.lower()] = reason
            except FileNotFoundError:
                logger.debug(f"Path exemptions CSV file not found: {csv_file}")
            except Exception as e:
                logger.warning(f"Error reading path exemptions CSV: {e}")

        return exemptions

    return _safe_csv_operation(_read_operation)


def _append_csv_path_exemption(path, reason=None):
    """Append path exemption to CSV with thread safety."""
    def _append_operation():
        _ensure_csv_files()
        csv_file = Path(_get_data_dir()) / PATH_EXEMPTIONS_CSV

        filename = csv_file.name
        thread_lock = _thread_locks.get(filename, threading.RLock())

        with thread_lock:
            current_exemptions = _read_csv_path_exemptions()
            if path.lower() in current_exemptions:
                return

            with _file_lock(csv_file, 'a') as f:
                writer = csv.writer(f)
                writer.writerow([path, reason or "", datetime.now().isoformat()])
                logger.debug(f"Added path exemption: {path}")

    return _safe_csv_operation(_append_operation)


def _rewrite_csv_path_exemptions(exemptions):
    """Rewrite path exemptions CSV file with thread safety."""
    def _rewrite_operation():
        _ensure_csv_files()
        csv_file = Path(_get_data_dir()) / PATH_EXEMPTIONS_CSV
        temp_file = csv_file.with_suffix('.tmp')

        try:
            with _file_lock(temp_file, 'w') as f:
                writer = csv.writer(f)
                writer.writerow(['path', 'reason', 'added_date'])
                for path, reason in exemptions.items():
                    writer.writerow([path, reason, datetime.now().isoformat()])

            if os.name == 'nt':
                if csv_file.exists():
                    csv_file.unlink()
                temp_file.rename(csv_file)
            else:
                temp_file.rename(csv_file)

            logger.debug(f"Rewrote path exemptions CSV with {len(exemptions)} entries")
        except Exception as e:
            if temp_file.exists():
                temp_file.unlink()
            raise e

    return _safe_csv_operation(_rewrite_operation)

def _rewrite_csv_blacklist(blacklist):
    """Rewrite blacklist CSV file with thread safety."""
    def _rewrite_operation():
        _ensure_csv_files()
        csv_file = Path(_get_data_dir()) / BLACKLIST_CSV
        temp_file = csv_file.with_suffix('.tmp')
        
        try:
            # Write to temporary file first
            with _file_lock(temp_file, 'w') as f:
                writer = csv.writer(f)
                writer.writerow(['ip', 'reason', 'added_date'])
                for ip, reason in blacklist.items():
                    writer.writerow([ip, reason, datetime.now().isoformat()])
            
            # Atomically replace the original file
            if os.name == 'nt':  # Windows
                if csv_file.exists():
                    csv_file.unlink()
                temp_file.rename(csv_file)
            else:  # Unix-like systems
                temp_file.rename(csv_file)
            
            logger.debug(f"Rewrote blacklist CSV with {len(blacklist)} entries")
            
        except Exception as e:
            # Clean up temp file on error
            if temp_file.exists():
                temp_file.unlink()
            raise e
    
    return _safe_csv_operation(_rewrite_operation)

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
    def add_keyword(self, kw, count=1):
        # Note: Current implementation doesn't store count, just presence
        add_keyword(kw)
    def remove_keyword(self, kw):
        remove_keyword(kw)
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
            # Additional check to ensure database is properly initialized
            from flask import current_app
            if hasattr(current_app, 'extensions') and 'sqlalchemy' in current_app.extensions:
                return WhitelistedIP.query.filter_by(ip=ip).first() is not None
            else:
                storage_mode = 'csv'
        except Exception:
            # Fallback to CSV on any database error
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

def remove_ip_whitelist(ip):
    """Remove IP from whitelist."""
    storage_mode = _get_storage_mode()
    
    if storage_mode == 'database':
        try:
            entry = WhitelistedIP.query.filter_by(ip=ip).first()
            if entry:
                db.session.delete(entry)
                db.session.commit()
        except Exception:
            # Fallback to memory
            _memory_whitelist.discard(ip)
    elif storage_mode == 'csv':
        # For CSV, we need to rewrite the file without the IP
        whitelist = _read_csv_whitelist()
        whitelist.discard(ip)
        _rewrite_csv_whitelist(whitelist)
    else:
        _memory_whitelist.discard(ip)

def _rewrite_csv_whitelist(whitelist):
    """Rewrite whitelist CSV file."""
    _ensure_csv_files()
    csv_file = Path(_get_data_dir()) / WHITELIST_CSV
    
    try:
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['ip', 'added_date'])
            for ip in whitelist:
                writer.writerow([ip, datetime.now().isoformat()])
    except Exception:
        pass

def is_ip_blacklisted(ip):
    """Check if IP is blacklisted."""
    storage_mode = _get_storage_mode()
    
    if storage_mode == 'database':
        try:
            # Additional check to ensure database is properly initialized
            from flask import current_app
            if hasattr(current_app, 'extensions') and 'sqlalchemy' in current_app.extensions:
                return BlacklistedIP.query.filter_by(ip=ip).first() is not None
            else:
                storage_mode = 'csv'
        except Exception:
            # Fallback to CSV on any database error
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

def _normalize_country_code(country_code):
    if not country_code:
        return None
    normalized = str(country_code).strip().upper()
    return normalized or None

def get_geo_blocked_countries():
    """Get all geo blocked countries."""
    storage_mode = _get_storage_mode()

    if storage_mode == 'database':
        try:
            from flask import current_app
            if hasattr(current_app, 'extensions') and 'sqlalchemy' in current_app.extensions:
                return {c.country_code for c in GeoBlockedCountry.query.all()}
            storage_mode = 'csv'
        except Exception:
            storage_mode = 'csv'

    if storage_mode == 'csv':
        return _read_csv_geo_blocked_countries()
    return set(_memory_geo_blocked_countries)

def is_country_geo_blocked(country_code):
    """Check if a country is geo blocked."""
    normalized = _normalize_country_code(country_code)
    if not normalized:
        return False

    storage_mode = _get_storage_mode()

    if storage_mode == 'database':
        try:
            from flask import current_app
            if hasattr(current_app, 'extensions') and 'sqlalchemy' in current_app.extensions:
                return GeoBlockedCountry.query.filter_by(country_code=normalized).first() is not None
            storage_mode = 'csv'
        except Exception:
            storage_mode = 'csv'

    if storage_mode == 'csv':
        countries = _read_csv_geo_blocked_countries()
        return normalized in countries
    return normalized in _memory_geo_blocked_countries

def add_geo_blocked_country(country_code):
    """Add a country to geo blocked list."""
    normalized = _normalize_country_code(country_code)
    if not normalized or is_country_geo_blocked(normalized):
        return

    storage_mode = _get_storage_mode()

    if storage_mode == 'database':
        try:
            db.session.add(GeoBlockedCountry(country_code=normalized))
            db.session.commit()
            return
        except Exception:
            storage_mode = 'csv'

    if storage_mode == 'csv':
        _append_csv_geo_blocked_country(normalized)
    else:
        _memory_geo_blocked_countries.add(normalized)

def remove_geo_blocked_country(country_code):
    """Remove a country from geo blocked list."""
    normalized = _normalize_country_code(country_code)
    if not normalized:
        return

    storage_mode = _get_storage_mode()

    if storage_mode == 'database':
        try:
            entry = GeoBlockedCountry.query.filter_by(country_code=normalized).first()
            if entry:
                db.session.delete(entry)
                db.session.commit()
            return
        except Exception:
            storage_mode = 'csv'

    if storage_mode == 'csv':
        countries = _read_csv_geo_blocked_countries()
        if normalized in countries:
            countries.discard(normalized)
            _rewrite_csv_geo_blocked_countries(countries)
    else:
        _memory_geo_blocked_countries.discard(normalized)


def get_path_exemptions():
    """Get all path exemptions."""
    storage_mode = _get_storage_mode()

    if storage_mode == 'database':
        return set(_memory_path_exemptions.keys())

    if storage_mode == 'csv':
        return set(_read_csv_path_exemptions().keys())
    return set(_memory_path_exemptions.keys())


def add_path_exemption(path, reason=None):
    """Add a path exemption."""
    if not path:
        return
    normalized = str(path).strip()
    if not normalized:
        return
    key = normalized.lower()
    if key in get_path_exemptions():
        return

    storage_mode = _get_storage_mode()

    if storage_mode == 'database':
        _memory_path_exemptions[key] = reason or ""
        return

    if storage_mode == 'csv':
        _append_csv_path_exemption(normalized, reason)
    else:
        _memory_path_exemptions[key] = reason or ""


def remove_path_exemption(path):
    """Remove a path exemption."""
    if not path:
        return
    normalized = str(path).strip()
    if not normalized:
        return
    key = normalized.lower()

    storage_mode = _get_storage_mode()

    if storage_mode == 'database':
        _memory_path_exemptions.pop(key, None)
        return

    if storage_mode == 'csv':
        exemptions = _read_csv_path_exemptions()
        if key in exemptions:
            exemptions.pop(key, None)
            _rewrite_csv_path_exemptions(exemptions)
    else:
        _memory_path_exemptions.pop(key, None)

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

def remove_keyword(keyword):
    """Remove keyword from blocked list."""
    storage_mode = _get_storage_mode()
    
    if storage_mode == 'database':
        try:
            entry = Keyword.query.filter_by(keyword=keyword).first()
            if entry:
                db.session.delete(entry)
                db.session.commit()
        except Exception:
            # Fallback to memory
            _memory_keywords.discard(keyword)
    elif storage_mode == 'csv':
        # For CSV, we need to rewrite the file without the keyword
        keywords = _read_csv_keywords()
        keywords.discard(keyword)
        _rewrite_csv_keywords(keywords)
    else:
        _memory_keywords.discard(keyword)

def _rewrite_csv_keywords(keywords):
    """Rewrite keywords CSV file."""
    _ensure_csv_files()
    csv_file = Path(_get_data_dir()) / KEYWORDS_CSV
    
    try:
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['keyword', 'added_date'])
            for keyword in keywords:
                writer.writerow([keyword, datetime.now().isoformat()])
    except Exception:
        pass

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
