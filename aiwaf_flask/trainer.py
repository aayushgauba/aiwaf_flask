#!/usr/bin/env python3
"""
AI Training Module for AIWAF Flask

Replicates the Django training functionality for Flask applications.
Trains machine learning models and learns keywords from access logs.
"""

import os
import glob
import gzip
import re
import csv
import json
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path
from typing import List, Dict, Optional, Set, Any

# Try to import AI dependencies
try:
    import pandas as pd
    import joblib
    from sklearn.ensemble import IsolationForest
    import sklearn
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    pd = None
    joblib = None
    IsolationForest = None
    sklearn = None

# Flask imports
from flask import Flask, current_app

# AIWAF imports
from .storage import get_exemption_store, get_keyword_store
from .blacklist_manager import BlacklistManager
from .utils import is_exempt, is_path_exempt

# ─────────── Configuration ───────────
DEFAULT_LOG_DIR = 'aiwaf_logs'

def get_default_model_path():
    """Get the default model path relative to the package."""
    import os
    from pathlib import Path
    
    # Get the directory where this trainer.py file is located
    trainer_dir = Path(__file__).parent
    resources_dir = trainer_dir / 'resources'
    
    # Ensure resources directory exists
    resources_dir.mkdir(exist_ok=True)
    
    return str(resources_dir / 'model.pkl')

DEFAULT_MODEL_PATH = get_default_model_path()

STATIC_KW = [".php", "xmlrpc", "wp-", ".env", ".git", ".bak", "config", "shell", "filemanager"]
STATUS_IDX = ["200", "403", "404", "500"]

# Enhanced log regex pattern for different formats
_LOG_RX_PATTERNS = [
    # Combined log format with response time
    re.compile(
        r'(\d+\.\d+\.\d+\.\d+).*\[(.*?)\].*"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS) (.*?) HTTP/.*?" '
        r'(\d{3}).*?"(.*?)" "(.*?)".*?response-time=(\d+\.\d+)'
    ),
    # Standard combined log format
    re.compile(
        r'(\d+\.\d+\.\d+\.\d+).*\[(.*?)\].*"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS) (.*?) HTTP/.*?" '
        r'(\d{3}) (\d+) "(.*?)" "(.*?)"'
    ),
    # Common log format
    re.compile(
        r'(\d+\.\d+\.\d+\.\d+).*\[(.*?)\].*"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS) (.*?) HTTP/.*?" '
        r'(\d{3}) (\d+)'
    ),
]

class FlaskAITrainer:
    """AI Trainer for Flask AIWAF"""
    
    def __init__(self, app: Optional[Flask] = None):
        self.app = app
        self._route_keywords: Optional[Set[str]] = None
        
    def init_app(self, app: Flask):
        """Initialize with Flask app"""
        self.app = app
        
    def get_config(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        if self.app:
            return self.app.config.get(key, default)
        return default
    
    def path_exists_in_flask(self, path: str) -> bool:
        """Check if a path exists in Flask URL routes"""
        if not self.app:
            return False
        
        # Remove query params and normalize
        candidate = path.split("?")[0].strip("/")
        
        # Try exact resolution first
        try:
            with self.app.test_request_context(f"/{candidate}"):
                self.app.url_map.match(f"/{candidate}", method='GET')
                return True
        except:
            pass
        
        # Try with trailing slash
        if not candidate.endswith("/"):
            try:
                with self.app.test_request_context(f"/{candidate}/"):
                    self.app.url_map.match(f"/{candidate}/", method='GET')
                    return True
            except:
                pass
        
        # Try without trailing slash
        if candidate.endswith("/"):
            try:
                with self.app.test_request_context(f"/{candidate.rstrip('/')}"):
                    self.app.url_map.match(f"/{candidate.rstrip('/')}", method='GET')
                    return True
            except:
                pass
        
        return False
    
    def remove_exempt_keywords(self) -> None:
        """Remove exempt keywords from dynamic keyword storage"""
        keyword_store = get_keyword_store()
        exempt_tokens = set()
        
        # Extract tokens from exempt paths
        exempt_paths = self.get_config("AIWAF_EXEMPT_PATHS", set())
        for path in exempt_paths:
            for seg in re.split(r"\W+", str(path).strip("/").lower()):
                if len(seg) > 3:
                    exempt_tokens.add(seg)
        
        # Add explicit exempt keywords from settings
        explicit_exempt = self.get_config("AIWAF_EXEMPT_KEYWORDS", [])
        exempt_tokens.update(explicit_exempt)
        
        # Add legitimate path keywords
        allowed_path_keywords = self.get_config("AIWAF_ALLOWED_PATH_KEYWORDS", [])
        exempt_tokens.update(allowed_path_keywords)
        
        # Remove exempt tokens from keyword storage
        for token in exempt_tokens:
            keyword_store.remove_keyword(token)
        
        if exempt_tokens:
            print(f"🧹 Removed {len(exempt_tokens)} exempt keywords from learning: {list(exempt_tokens)[:10]}")
    
    def get_legitimate_keywords(self) -> Set[str]:
        """Get all legitimate keywords that shouldn't be learned as suspicious"""
        legitimate = set()
        
        # Common legitimate path segments - expanded set
        default_legitimate = {
            "profile", "user", "users", "account", "accounts", "settings", "dashboard", 
            "home", "about", "contact", "help", "search", "list", "lists",
            "view", "views", "edit", "create", "update", "delete", "detail", "details",
            "api", "auth", "login", "logout", "register", "signup", "signin",
            "reset", "confirm", "activate", "verify", "page", "pages",
            "category", "categories", "tag", "tags", "post", "posts",
            "article", "articles", "blog", "blogs", "news", "item", "items",
            "admin", "administration", "manage", "manager", "control", "panel",
            "config", "configuration", "option", "options", "preference", "preferences",
            
            # Flask common keywords
            "static", "favicon", "robots", "sitemap", "manifest", "health", "ping",
            "status", "metrics", "debug", "test", "docs", "documentation",
            
            # Common web development terms
            "endpoint", "endpoints", "resource", "resources", "data", "export",
            "import", "upload", "download", "file", "files", "media", "images",
            "documents", "reports", "analytics", "stats", "statistics",
            
            # Common business/application terms
            "customer", "customers", "client", "clients", "company", "companies",
            "department", "departments", "employee", "employees", "team", "teams",
            "project", "projects", "task", "tasks", "event", "events",
            "notification", "notifications", "alert", "alerts",
            
            # Language/localization
            "language", "languages", "locale", "locales", "translation", "translations",
            "en", "fr", "de", "es", "it", "pt", "ru", "ja", "zh", "ko"
        }
        legitimate.update(default_legitimate)
        
        # Extract keywords from Flask routes
        legitimate.update(self._extract_flask_route_keywords())
        
        # Add from Flask config
        allowed_path_keywords = self.get_config("AIWAF_ALLOWED_PATH_KEYWORDS", [])
        legitimate.update(allowed_path_keywords)
        
        # Add exempt keywords
        exempt_keywords = self.get_config("AIWAF_EXEMPT_KEYWORDS", [])
        legitimate.update(exempt_keywords)
        
        return legitimate
    
    def _extract_flask_route_keywords(self) -> Set[str]:
        """Extract legitimate keywords from Flask URL patterns and blueprints"""
        if self._route_keywords is not None:
            return self._route_keywords
            
        keywords = set()
        
        if not self.app:
            self._route_keywords = keywords
            return keywords
        
        try:
            # Extract from URL rules
            for rule in self.app.url_map.iter_rules():
                # Extract from rule pattern
                rule_str = str(rule.rule)
                # Get literal path segments (not Flask variables)
                literal_parts = re.findall(r'/([a-zA-Z][a-zA-Z0-9_-]*)', rule_str)
                
                for part in literal_parts:
                    if len(part) > 2:
                        part_lower = part.lower()
                        keywords.add(part_lower)
                
                # Extract from endpoint name
                if rule.endpoint:
                    endpoint_parts = rule.endpoint.split('.')
                    for part in endpoint_parts:
                        for segment in re.split(r'[._-]', part.lower()):
                            if len(segment) > 2 and segment not in ['view', 'function']:
                                keywords.add(segment)
            
            # Extract from blueprint names
            for blueprint_name in self.app.blueprints:
                for segment in re.split(r'[._-]', blueprint_name.lower()):
                    if len(segment) > 2:
                        keywords.add(segment)
            
        except Exception as e:
            print(f"Warning: Could not extract Flask route keywords: {e}")
        
        # Filter out common/generic words
        exclude_words = {
            'www', 'com', 'org', 'net', 'int', 'str', 'obj', 'get', 'set', 'put', 'del',
            'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had', 'her',
            'was', 'one', 'our', 'out', 'day', 'had', 'has', 'his', 'how', 'man', 'new',
            'now', 'old', 'see', 'two', 'who', 'boy', 'did', 'its', 'let', 'put', 'say',
            'she', 'too', 'use', 'var', 'way', 'may', 'end', 'why', 'any', 'app', 'run'
        }
        
        filtered_keywords = set()
        for keyword in keywords:
            if (len(keyword) >= 3 and 
                keyword not in exclude_words and
                not keyword.isdigit()):
                filtered_keywords.add(keyword)
        
        if filtered_keywords:
            print(f"🔗 Extracted {len(filtered_keywords)} legitimate keywords from Flask routes")
        
        self._route_keywords = filtered_keywords
        return filtered_keywords
    
    def _read_all_logs(self) -> List[str]:
        """Read log lines from various sources"""
        lines = []
        
        # Try log files first
        log_dir = self.get_config('AIWAF_LOG_DIR', DEFAULT_LOG_DIR)
        
        # Look for access log files
        access_log_files = [
            os.path.join(log_dir, 'access.log'),
            os.path.join(log_dir, 'aiwaf.log'),
            'access.log',
            'aiwaf.log'
        ]
        
        for log_path in access_log_files:
            if os.path.exists(log_path):
                print(f"📁 Reading logs from: {log_path}")
                with open(log_path, "r", errors="ignore") as f:
                    lines.extend(f.readlines())
                
                # Also check for rotated logs
                for p in sorted(glob.glob(f"{log_path}.*")):
                    opener = gzip.open if p.endswith(".gz") else open
                    try:
                        with opener(p, "rt", errors="ignore") as f:
                            lines.extend(f.readlines())
                    except OSError:
                        continue
                break
        
        # If no log files found, try CSV logs
        if not lines:
            lines = self._get_logs_from_csv()
        
        # If still no logs, try JSON logs
        if not lines:
            lines = self._get_logs_from_json()
        
        print(f"📊 Total log lines found: {len(lines)}")
        return lines
    
    def _get_logs_from_csv(self) -> List[str]:
        """Get log data from CSV files"""
        lines = []
        log_dir = self.get_config('AIWAF_LOG_DIR', DEFAULT_LOG_DIR)
        csv_files = glob.glob(os.path.join(log_dir, '*.csv'))
        
        for csv_file in csv_files:
            if 'access' in os.path.basename(csv_file) or 'aiwaf' in os.path.basename(csv_file):
                try:
                    with open(csv_file, 'r', newline='', errors='ignore') as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            # Convert CSV to log format
                            if all(key in row for key in ['timestamp', 'ip', 'method', 'path', 'status_code']):
                                timestamp = row['timestamp']
                                ip = row['ip']
                                method = row.get('method', 'GET')
                                path = row['path']
                                status = row['status_code']
                                response_time = row.get('response_time_ms', '0')
                                user_agent = row.get('user_agent', '-')
                                referer = row.get('referer', '-')
                                
                                # Convert to Apache log format
                                log_line = (f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" '
                                          f'{status} 0 "{referer}" "{user_agent}" '
                                          f'response-time={float(response_time)/1000}\n')
                                lines.append(log_line)
                    
                    print(f"📂 Loaded {len(lines)} entries from CSV: {csv_file}")
                except Exception as e:
                    print(f"Warning: Could not read CSV file {csv_file}: {e}")
        
        return lines
    
    def _get_logs_from_json(self) -> List[str]:
        """Get log data from JSON log files"""
        lines = []
        log_dir = self.get_config('AIWAF_LOG_DIR', DEFAULT_LOG_DIR)
        json_files = glob.glob(os.path.join(log_dir, '*.json')) + glob.glob(os.path.join(log_dir, '*.jsonl'))
        
        for json_file in json_files:
            try:
                with open(json_file, 'r', errors='ignore') as f:
                    for line in f:
                        try:
                            record = json.loads(line.strip())
                            
                            # Convert JSON to log format
                            if all(key in record for key in ['timestamp', 'ip', 'method', 'path', 'status_code']):
                                timestamp = record['timestamp']
                                ip = record['ip']
                                method = record.get('method', 'GET')
                                path = record['path']
                                status = record['status_code']
                                response_time = record.get('response_time', 0)
                                user_agent = record.get('user_agent', '-')
                                referer = record.get('referer', '-')
                                
                                # Convert to Apache log format
                                log_line = (f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" '
                                          f'{status} 0 "{referer}" "{user_agent}" '
                                          f'response-time={response_time}\n')
                                lines.append(log_line)
                        except json.JSONDecodeError:
                            continue
                
                print(f"📄 Loaded entries from JSON: {json_file}")
            except Exception as e:
                print(f"Warning: Could not read JSON file {json_file}: {e}")
        
        return lines
    
    def _parse(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a log line using multiple regex patterns"""
        for pattern in _LOG_RX_PATTERNS:
            m = pattern.search(line)
            if m:
                groups = m.groups()
                ip = groups[0]
                ts_str = groups[1]
                path = groups[2]
                status = groups[3]
                
                # Response time might be in different positions
                rt = 0.0
                for group in groups[4:]:
                    try:
                        if '.' in str(group):
                            rt = float(group)
                            break
                    except (ValueError, TypeError):
                        continue
                
                try:
                    ts = datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S")
                except ValueError:
                    try:
                        # Try different timestamp formats
                        ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                    except ValueError:
                        continue
                
                return {
                    "ip": ip,
                    "timestamp": ts,
                    "path": path,
                    "status": status,
                    "response_time": rt,
                }
        
        return None
    
    def _is_malicious_context_trainer(self, path: str, keyword: str, status: str = "404") -> bool:
        """Determine if a keyword appears in a malicious context (trainer version)"""
        # Don't learn from valid Flask paths
        if self.path_exists_in_flask(path):
            return False
        
        # Strong malicious indicators for log analysis
        malicious_indicators = [
            # Multiple suspicious segments in path
            len([seg for seg in re.split(r"\W+", path) if seg in STATIC_KW]) > 1,
            
            # Common attack patterns
            any(pattern in path.lower() for pattern in [
                '../', '..\\', '.env', 'wp-admin', 'phpmyadmin', 'config',
                'backup', 'database', 'mysql', 'passwd', 'shadow', 'xmlrpc',
                'shell', 'cmd', 'exec', 'eval', 'system'
            ]),
            
            # Path indicates obvious attack attempt
            any(attack in path.lower() for attack in [
                'union+select', 'drop+table', '<script', 'javascript:',
                '${', '{{', 'onload=', 'onerror=', 'file://', 'http://'
            ]),
            
            # Multiple directory traversal attempts
            path.count('../') > 1 or path.count('..\\') > 1,
            
            # Encoded attack patterns
            any(encoded in path for encoded in ['%2e%2e', '%252e', '%c0%ae', '%3c%73%63%72%69%70%74']),
            
            # 404 status with suspicious characteristics
            status == "404" and (
                len(path) > 50 or  # Very long paths are often attacks
                path.count('/') > 10 or  # Too many directory levels
                any(c in path for c in ['<', '>', '{', '}', '$', '`'])  # Special characters
            ),
        ]
        
        return any(malicious_indicators)
    
    def train(self, disable_ai: bool = False) -> None:
        """Enhanced training with improved keyword filtering and exemption handling"""
        print("🚀 Starting AIWAF Flask enhanced training...")
        
        if not AI_AVAILABLE and not disable_ai:
            print("⚠️  AI dependencies not available - switching to keyword-only mode")
            print("   Install with: pip install aiwaf-flask[ai]")
            disable_ai = True
        
        if disable_ai:
            print("🔤 AI model training disabled - keyword learning only")
        
        # Remove exempt keywords first
        self.remove_exempt_keywords()
        
        # Remove any IPs in exemption from the blacklist
        # Note: Current storage system uses in-memory exemptions only
        exemption_store = get_exemption_store()
        # For now, we'll rely on the existing exemption system during blocking
        exempted_count = 0  # Since we can't easily get all exempted IPs
        
        raw_lines = self._read_all_logs()
        if not raw_lines:
            print("❌ No log lines found – check AIWAF_LOG_DIR setting or log files.")
            return
        
        # Skip processing if we have too few entries
        if len(raw_lines) < 10:
            print(f"⚠️  Only {len(raw_lines)} log entries found - need at least 10 for training")
            return
        
        # Check if we have enough data for AI training
        min_ai_threshold = current_app.config.get('AIWAF_MIN_AI_LOGS', 10000)
        force_ai = current_app.config.get('AIWAF_FORCE_AI', False)
        
        if not disable_ai and not force_ai and len(raw_lines) < min_ai_threshold:
            print(f"⚠️  Only {len(raw_lines)} log entries found - need at least {min_ai_threshold} for AI training")
            print("   Switching to keyword-only mode (use --force-ai to override or --disable-ai to suppress this warning)")
            disable_ai = True
        elif not disable_ai and force_ai and len(raw_lines) < min_ai_threshold:
            print(f"⚠️  Only {len(raw_lines)} log entries found (recommended: {min_ai_threshold}+) but forcing AI training")
        
        parsed = []
        ip_404 = defaultdict(int)
        ip_404_login = defaultdict(int)
        ip_times = defaultdict(list)
        
        print(f"📋 Parsing {len(raw_lines)} log entries...")
        for line in raw_lines:
            rec = self._parse(line)
            if not rec:
                continue
            parsed.append(rec)
            ip_times[rec["ip"]].append(rec["timestamp"])
            if rec["status"] == "404":
                if is_path_exempt(rec["path"]):
                    ip_404_login[rec["ip"]] += 1
                else:
                    ip_404[rec["ip"]] += 1
        
        print(f"✅ Successfully parsed {len(parsed)} log entries")
        
        # Check if we have enough data
        if len(parsed) < 10:
            print(f"⚠️  Only {len(parsed)} valid entries parsed - need at least 10 for training")
            return
        
        # 404 flood blocking (only for non-login paths)
        blocked_404_count = 0
        for ip, count in ip_404.items():
            if count >= 6:
                login_404s = ip_404_login.get(ip, 0)
                total_404s = count + login_404s
                
                if count > login_404s:
                    BlacklistManager.block(ip, f"Excessive 404s (>=6 non-login, {count}/{total_404s})")
                    blocked_404_count += 1
        
        if blocked_404_count > 0:
            print(f"🚫 Blocked {blocked_404_count} IPs for excessive 404 errors")
        
        # Prepare feature data
        feature_dicts = []
        for r in parsed:
            ip = r["ip"]
            burst = sum(
                1 for t in ip_times[ip]
                if (r["timestamp"] - t).total_seconds() <= 10
            )
            total404 = ip_404[ip]
            known_path = self.path_exists_in_flask(r["path"])
            kw_hits = 0
            if not known_path and not is_path_exempt(r["path"]):
                kw_hits = sum(k in r["path"].lower() for k in STATIC_KW)
            
            status_idx = STATUS_IDX.index(r["status"]) if r["status"] in STATUS_IDX else -1
            
            feature_dicts.append({
                "ip": ip,
                "path_len": len(r["path"]),
                "kw_hits": kw_hits,
                "resp_time": r["response_time"],
                "status_idx": status_idx,
                "burst_count": burst,
                "total_404": total404,
            })
        
        if not feature_dicts:
            print("❌ Nothing to train on – no valid log entries.")
            return
        
        print(f"🔢 Generated {len(feature_dicts)} feature vectors for training")
        
        # AI Model Training (optional)
        blocked_count = 0
        if not disable_ai and AI_AVAILABLE:
            print("🤖 Training AI anomaly detection model...")
            
            try:
                df = pd.DataFrame(feature_dicts)
                feature_cols = [c for c in df.columns if c != "ip"]
                X = df[feature_cols].astype(float).values
                
                contamination = self.get_config("AIWAF_AI_CONTAMINATION", 0.05)
                model = IsolationForest(contamination=contamination, random_state=42)
                
                # Suppress sklearn warnings during training
                import warnings
                with warnings.catch_warnings():
                    warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
                    model.fit(X)
                
                # Ensure model directory exists
                model_path = self.get_config("AIWAF_MODEL_PATH", DEFAULT_MODEL_PATH)
                os.makedirs(os.path.dirname(model_path), exist_ok=True)
                
                # Save model with metadata
                model_data = {
                    'model': model,
                    'sklearn_version': sklearn.__version__,
                    'created_at': str(datetime.now()),
                    'feature_count': len(feature_cols),
                    'samples_count': len(X),
                    'framework': 'flask'
                }
                joblib.dump(model_data, model_path)
                print(f"💾 Model saved: {model_path}")
                print(f"📊 Trained on {len(X)} samples with scikit-learn v{sklearn.__version__}")
                
                # Check for anomalies and intelligently decide which IPs to block
                preds = model.predict(X)
                anomalous_ips = set(df.loc[preds == -1, "ip"])
                
                if anomalous_ips:
                    print(f"🔍 Detected {len(anomalous_ips)} potentially anomalous IPs")
                    
                    exemption_store = get_exemption_store()
                    
                    for ip in anomalous_ips:
                        # Skip if IP is exempted
                        if exemption_store.is_exempted(ip):
                            continue
                        
                        # Get this IP's behavior from the data
                        ip_data = df[df["ip"] == ip]
                        
                        # Criteria to determine if this is likely legitimate vs threat
                        avg_kw_hits = ip_data["kw_hits"].mean()
                        max_404s = ip_data["total_404"].max()
                        avg_burst = ip_data["burst_count"].mean()
                        total_requests = len(ip_data)
                        
                        # Don't block if it looks like legitimate behavior
                        if (
                            avg_kw_hits < 2 and           # Not hitting many malicious keywords
                            max_404s < 10 and            # Not excessive 404s
                            avg_burst < 15 and           # Not excessive burst activity
                            total_requests < 100         # Not excessive total requests
                        ):
                            print(f"   ✅ {ip}: Anomalous but looks legitimate - NOT blocking")
                            continue
                        
                        # Block if it shows clear signs of malicious behavior
                        BlacklistManager.block(ip, f"AI anomaly + suspicious patterns (kw:{avg_kw_hits:.1f}, 404s:{max_404s}, burst:{avg_burst:.1f})")
                        blocked_count += 1
                        print(f"   🚫 {ip}: Blocked for suspicious behavior")
                    
                    print(f"🎯 Blocked {blocked_count}/{len(anomalous_ips)} anomalous IPs")
            
            except Exception as e:
                print(f"❌ AI model training failed: {e}")
                print("   Continuing with keyword learning only...")
                disable_ai = True
        else:
            print("🔤 AI model training skipped")
            if not disable_ai:
                df = pd.DataFrame(feature_dicts)  # Still need df for some operations
        
        # Keyword Learning
        print("📚 Learning suspicious keywords from logs...")
        
        tokens = Counter()
        legitimate_keywords = self.get_legitimate_keywords()
        
        for r in parsed:
            # Only learn from suspicious requests (errors on non-existent paths)
            if (r["status"].startswith(("4", "5")) and 
                not self.path_exists_in_flask(r["path"]) and 
                not is_path_exempt(r["path"])):
                
                for seg in re.split(r"\W+", r["path"].lower()):
                    if (len(seg) > 3 and 
                        seg not in STATIC_KW and 
                        seg not in legitimate_keywords and
                        self._is_malicious_context_trainer(r["path"], seg, r["status"])):
                        tokens[seg] += 1
        
        keyword_store = get_keyword_store()
        top_n = self.get_config("AIWAF_DYNAMIC_TOP_N", 10)
        top_tokens = tokens.most_common(top_n)
        
        # Filter tokens with malicious context validation
        filtered_tokens = []
        learned_from_paths = []
        
        for kw, cnt in top_tokens:
            # Find example paths where this keyword appeared
            example_paths = [r["path"] for r in parsed 
                            if kw in r["path"].lower() and 
                            r["status"].startswith(("4", "5")) and
                            not self.path_exists_in_flask(r["path"])]
            
            # Only add if keyword appears in malicious contexts
            if (cnt >= 2 and
                len(kw) >= 4 and
                kw not in legitimate_keywords and
                example_paths and
                any(self._is_malicious_context_trainer(path, kw) for path in example_paths[:3])):
                
                filtered_tokens.append((kw, cnt))
                keyword_store.add_keyword(kw, cnt)
                learned_from_paths.extend(example_paths[:2])
        
        # Training summary
        print("\n" + "="*60)
        if disable_ai:
            print("🔤 AIWAF FLASK KEYWORD-ONLY TRAINING COMPLETE")
        else:
            print("🤖 AIWAF FLASK ENHANCED TRAINING COMPLETE")
        print("="*60)
        print(f"📊 Training Data: {len(parsed)} log entries processed")
        
        if not disable_ai and AI_AVAILABLE:
            print(f"🤖 AI Model: Trained with {len(feature_cols) if 'feature_cols' in locals() else 'N/A'} features")
            print(f"🚫 AI Blocked IPs: {blocked_count} suspicious IPs blocked")
        else:
            print(f"🔤 AI Model: Disabled (keyword learning only)")
            print(f"🚫 AI Blocked IPs: 0 (AI blocking disabled)")
        
        print(f"📚 Keywords: {len(filtered_tokens)} new suspicious keywords learned")
        if filtered_tokens:
            print(f"   📝 Keywords: {[kw for kw, _ in filtered_tokens]}")
        
        print(f"🛡️  Exemptions: {exempted_count} IPs protected from blocking")
        print(f"🚫 404 Blocking: {blocked_404_count} IPs blocked for excessive 404s")
        
        if disable_ai:
            print("✅ Keyword-based protection now active with context-aware filtering!")
        else:
            print("✅ Enhanced AI protection now active with context-aware filtering!")
        print("="*60)

# Global trainer instance
_trainer = FlaskAITrainer()

def init_trainer(app: Flask):
    """Initialize the trainer with Flask app"""
    _trainer.init_app(app)

def train_from_logs(app: Optional[Flask] = None, disable_ai: bool = False):
    """Train AIWAF from logs
    
    Args:
        app: Flask application instance (optional if already initialized)
        disable_ai: If True, skip AI model training and only do keyword learning
    """
    if app:
        _trainer.init_app(app)
    
    _trainer.train(disable_ai=disable_ai)

# Convenience function for backward compatibility
def train(disable_ai: bool = False):
    """Train AIWAF from logs (requires app to be initialized first)"""
    _trainer.train(disable_ai=disable_ai)

# Legacy function for compatibility
def get_legitimate_keywords():
    """Return a set of legitimate keywords for Flask routes (legacy function)"""
    return _trainer.get_legitimate_keywords() if _trainer.app else {
        "profile", "user", "account", "settings", "dashboard", "home", "about", "contact", "help", "search", "list", "view", "edit", "create", "update", "delete", "detail", "api", "auth", "login", "logout", "register", "signup", "reset", "confirm", "activate", "verify", "page", "category", "tag", "post", "article", "blog", "news", "item", "admin", "manage", "config", "option", "preference"
    }
