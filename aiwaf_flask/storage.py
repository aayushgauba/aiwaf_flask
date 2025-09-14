"""Storage functions for AIWAF Flask with CSV, database, and in-memory fallback."""

import csv
import os
import threading
import time
import logging
import random
import tempfile
import shutil
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

# Retry configuration for Windows file operations
MAX_RETRIES = 3
RETRY_DELAY = 0.1  # seconds
TIMEOUT_SECONDS = 5  # Maximum time to wait for file access

# In-memory fallback storage
_memory_whitelist = set()
_memory_blacklist = {}
_memory_keywords = set()

# Thread locks for process-level synchronization
_thread_locks = {
    WHITELIST_CSV: threading.RLock(),
    BLACKLIST_CSV: threading.RLock(),
    KEYWORDS_CSV: threading.RLock()
}

# Configure logging
logger = logging.getLogger(__name__)

@contextmanager
def _file_lock(file_path, mode='r'):
    """Cross-platform file locking context manager with improved Windows support."""
    file_obj = None
    lock_acquired = False
    
    try:
        # Ensure directory exists
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        
        # For Windows, use atomic operations with temporary files for writes
        if MSVCRT_AVAILABLE and ('w' in mode or 'a' in mode):
            # Use atomic write pattern for Windows
            temp_file = None
            try:
                if 'w' in mode:
                    # Atomic write: write to temp file, then rename
                    temp_fd, temp_path = tempfile.mkstemp(dir=Path(file_path).parent, suffix='.tmp')
                    temp_file = os.fdopen(temp_fd, mode, newline='' if 'b' not in mode else None)
                    yield temp_file
                    temp_file.close()
                    
                    # Atomic rename
                    if os.path.exists(temp_path):
                        shutil.move(temp_path, file_path)
                    return
                else:
                    # For append mode, use regular file with retries
                    file_obj = open(file_path, mode, newline='' if 'b' not in mode else None)
            except Exception:
                if temp_file:
                    try:
                        temp_file.close()
                        if 'temp_path' in locals() and os.path.exists(temp_path):
                            os.unlink(temp_path)
                    except:
                        pass
                # Fallback to regular file
                if not file_obj:
                    file_obj = open(file_path, mode, newline='' if 'b' not in mode else None)
        else:
            # Regular file opening for read mode or Unix systems
            file_obj = open(file_path, mode, newline='' if 'b' not in mode else None)
        
        # Apply file lock based on platform
        if FCNTL_AVAILABLE and file_obj:
            # Unix/Linux/macOS
            try:
                if 'w' in mode or 'a' in mode:
                    fcntl.flock(file_obj.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)  # Non-blocking exclusive
                else:
                    fcntl.flock(file_obj.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)  # Non-blocking shared
                lock_acquired = True
            except (IOError, OSError):
                # Lock failed, continue without lock
                logger.debug(f"Could not acquire file lock for {file_path}")
        elif MSVCRT_AVAILABLE and file_obj:
            # Windows - minimal locking for read operations only
            if 'r' in mode:
                try:
                    # Try to lock just 1 byte at the beginning of the file
                    file_obj.seek(0)
                    msvcrt.locking(file_obj.fileno(), msvcrt.LK_NBLCK, 1)
                    lock_acquired = True
                except (OSError, IOError):
                    # Lock failed, continue without lock (Windows can be problematic)
                    logger.debug(f"Could not acquire Windows file lock for {file_path}")
        
        if file_obj:
            yield file_obj
        
    except PermissionError:
        # Handle Windows permission errors gracefully
        logger.warning(f"Permission denied for file {file_path}, attempting fallback")
        if file_obj:
            try:
                file_obj.close()
            except:
                pass
        # Try opening in a simpler mode
        try:
            file_obj = open(file_path, mode.replace('x', 'w'), newline='' if 'b' not in mode else None)
            yield file_obj
        except Exception as e:
            logger.error(f"Failed to open file {file_path} even with fallback: {e}")
            raise
    except Exception as e:
        logger.warning(f"File operation failed for {file_path}: {e}")
        # Fallback to non-locked file access
        if file_obj is None:
            try:
                file_obj = open(file_path, mode, newline='' if 'b' not in mode else None)
            except Exception:
                # If we can't even open the file, create it if needed
                if 'w' in mode or 'a' in mode:
                    Path(file_path).touch()
                    file_obj = open(file_path, mode, newline='' if 'b' not in mode else None)
                else:
                    raise
        if file_obj:
            yield file_obj
    finally:
        if file_obj:
            try:
                # Release lock if acquired
                if lock_acquired:
                    if FCNTL_AVAILABLE:
                        fcntl.flock(file_obj.fileno(), fcntl.LOCK_UN)
                    elif MSVCRT_AVAILABLE:
                        try:
                            file_obj.seek(0)
                            msvcrt.locking(file_obj.fileno(), msvcrt.LK_UNLCK, 1)
                        except:
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
            (data_dir / KEYWORDS_CSV, ['keyword', 'added_date'])
        ]
        
        for file_path, headers in files_to_create:
            if not file_path.exists():
                try:
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