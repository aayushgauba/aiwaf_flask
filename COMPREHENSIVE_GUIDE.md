# AIWAF Flask - Comprehensive Guide

## Table of Contents
1. [Overview](#overview)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Configuration](#configuration)
5. [CLI Commands](#cli-commands)
6. [Auto-Configuration System](#auto-configuration-system)
7. [Protection Features](#protection-features)
8. [Training System](#training-system)
9. [Storage Options](#storage-options)
10. [Logging and Monitoring](#logging-and-monitoring)
11. [Advanced Usage](#advanced-usage)
12. [Troubleshooting](#troubleshooting)
13. [API Reference](#api-reference)

---

## Overview

AIWAF (AI Web Application Firewall) Flask is an advanced, self-learning security middleware for Flask applications. It provides comprehensive protection through multiple layers of security, including AI-powered anomaly detection, rate limiting, IP/keyword blocking, and more.

### Key Features
- **AI-Powered Anomaly Detection** - Machine learning models that learn from your traffic patterns
- **Multi-Layer Protection** - IP blocking, keyword filtering, rate limiting, honeypot timing
- **Auto-Configuration** - Intelligent directory detection and configuration management
- **Flexible Storage** - Database, CSV files, or in-memory storage options
- **Comprehensive CLI** - Complete command-line interface for management
- **Real-time Monitoring** - Detailed logging and analytics
- **Zero Dependencies** - Works without database setup

---

## Installation

### Basic Installation
```bash
# Basic installation (without AI features)
pip install aiwaf-flask

# With AI anomaly detection features
pip install aiwaf-flask[ai]

# Full installation (AI + development tools)
pip install aiwaf-flask[all]
```

### Requirements
- **Python 3.7+**
- **Flask 2.0+**
- **For AI Features**: scikit-learn, numpy

---

## Quick Start

### 1. Basic Flask Integration
```python
from flask import Flask
from aiwaf_flask import register_aiwaf_middlewares

app = Flask(__name__)

# Basic configuration
app.config.update({
    'AIWAF_USE_CSV': True,              # Enable CSV storage
    'AIWAF_ENABLE_LOGGING': True,       # Enable access logging
    'AIWAF_DATA_DIR': 'aiwaf_data',     # Data directory
    'AIWAF_LOG_DIR': 'logs',            # Log directory
})

# Register AIWAF protection
register_aiwaf_middlewares(app)

@app.route('/')
def home():
    return "Protected by AIWAF!"

if __name__ == '__main__':
    app.run(debug=True)
```

### 2. Database Integration
```python
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from aiwaf_flask import register_aiwaf_middlewares

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['AIWAF_USE_CSV'] = False  # Use database storage

db = SQLAlchemy(app)
register_aiwaf_middlewares(app)
```

### 3. CLI Management
```bash
# List all protection data
python -m aiwaf_flask.cli list all

# Add IP to blacklist
python -m aiwaf_flask.cli add blacklist 192.168.1.100 --reason "Suspicious activity"

# Train AI model from logs
python -m aiwaf_flask.cli train --verbose

# Analyze request logs
python -m aiwaf_flask.cli logs --format combined
```

---

## Configuration

### Complete Configuration Options

```python
app.config.update({
    # === Core Settings ===
    'AIWAF_USE_CSV': True,                    # Storage: True=CSV, False=Database
    'AIWAF_DATA_DIR': 'aiwaf_data',          # Data directory (auto-detected)
    'AIWAF_LOG_DIR': 'logs',                 # Log directory (auto-detected)
    
    # === Protection Settings ===
    'AIWAF_ENABLE_PROTECTION': True,         # Master protection switch
    'AIWAF_RATE_LIMIT': 10,                  # Requests per window
    'AIWAF_WINDOW_SECONDS': 60,             # Rate limiting window
    'AIWAF_RATE_FLOOD': 200,                # Auto-block threshold
    'AIWAF_HONEYPOT_DELAY': 0.5,            # Honeypot timing sensitivity
    'AIWAF_MIN_FORM_TIME': 1.0,             # Minimum form submission time
    
    # === AI Training Settings ===
    'AIWAF_MIN_AI_LOGS': 10000,             # Minimum logs for AI training
    'AIWAF_FORCE_AI': False,                # Force AI training
    'AIWAF_DYNAMIC_TOP_N': 10,              # Keywords to learn
    'AIWAF_AI_CONTAMINATION': 0.05,         # AI sensitivity (5%)
    
    # === Logging Settings ===
    'AIWAF_ENABLE_LOGGING': True,           # Enable request logging
    'AIWAF_LOG_FORMAT': 'combined',         # Log format: combined, common, csv, json
    
    # === Path Exemptions ===
    'AIWAF_EXEMPT_PATHS': [                 # Paths to skip protection
        '/health', '/status', '/favicon.ico'
    ],
    'AIWAF_EXEMPT_KEYWORDS': [              # Keywords exempt from learning
        'health', 'check', 'status', 'ping', 'favicon'
    ],
    'AIWAF_ALLOWED_PATH_KEYWORDS': [        # Legitimate path keywords
        'dashboard', 'profile', 'settings'
    ],
})
```

---

## CLI Commands

### List Commands
```bash
# List all data
python -m aiwaf_flask.cli list all

# List specific data types
python -m aiwaf_flask.cli list whitelist
python -m aiwaf_flask.cli list blacklist
python -m aiwaf_flask.cli list keywords

# Show statistics
python -m aiwaf_flask.cli stats
```

### Management Commands
```bash
# Add items
python -m aiwaf_flask.cli add whitelist 192.168.1.10
python -m aiwaf_flask.cli add blacklist 10.0.0.50 --reason "Malicious scan"
python -m aiwaf_flask.cli add keyword "malicious-pattern"

# Remove items
python -m aiwaf_flask.cli remove whitelist 192.168.1.10
python -m aiwaf_flask.cli remove blacklist 10.0.0.50
python -m aiwaf_flask.cli remove keyword "old-pattern"
```

### Training Commands
```bash
# Basic training (keyword learning only)
python -m aiwaf_flask.cli train --disable-ai

# Full AI training (requires 10k+ log entries)
python -m aiwaf_flask.cli train --verbose

# Force AI training with insufficient data
python -m aiwaf_flask.cli train --force-ai --min-ai-logs 1000

# Custom log directory
python -m aiwaf_flask.cli train --log-dir /path/to/logs --verbose
```

### Log Analysis Commands
```bash
# Analyze logs with detailed statistics
python -m aiwaf_flask.cli logs --format combined

# Analyze different log formats
python -m aiwaf_flask.cli logs --format csv
python -m aiwaf_flask.cli logs --format json

# Custom log directory
python -m aiwaf_flask.cli logs --log-dir /custom/logs --format combined
```

### Model Management Commands
```bash
# Check model status and compatibility
python -m aiwaf_flask.cli model --check

# Show detailed model information
python -m aiwaf_flask.cli model --info

# Force retrain model with current dependencies
python -m aiwaf_flask.cli model --retrain
```

### Export/Import Commands
```bash
# Export current configuration
python -m aiwaf_flask.cli export --output aiwaf_backup.json

# Import configuration
python -m aiwaf_flask.cli import --file aiwaf_backup.json
```

---

## Auto-Configuration System

AIWAF Flask includes an intelligent auto-configuration system that automatically detects and manages data and log directories.

### How Auto-Detection Works

1. **Environment Variables**: Checks `AIWAF_DATA_DIR` and `AIWAF_LOG_DIR`
2. **Existing Directories**: Scans for directories with actual data/logs
3. **Scoring Algorithm**: Ranks directories by content and suitability
4. **Fallback Creation**: Creates directories in consistent locations

### Directory Detection Order

**Data Directories:**
1. Environment variable `AIWAF_DATA_DIR`
2. Existing directories with most data (scored)
3. `~/.aiwaf/data`
4. `~/aiwaf_data`
5. Relative `./aiwaf_data`

**Log Directories:**
1. Environment variable `AIWAF_LOG_DIR`
2. Existing directories with most logs (scored)
3. `~/.aiwaf/logs`
4. `~/logs`
5. Relative `./logs`

### Auto-Configuration Benefits

- **Working Directory Independence**: Commands work from anywhere
- **Intelligent Path Resolution**: Finds existing data automatically
- **Consistent Behavior**: Same results regardless of execution location
- **User-Friendly**: No manual path configuration needed

### Verbose Output Example
```bash
$ python -m aiwaf_flask.cli list all
📁 Auto-configured data directory: C:\Users\username\aiwaf_data
🔍 Detection method: Selected data directory with most existing data
📍 Selected from 2 candidates
📊 Data score: 506
```

---

## Protection Features

### 1. IP-Based Protection

**Whitelist Protection**
- IPs on whitelist bypass all protection
- Permanent exemption from blocking
- Highest priority in filtering

**Blacklist Protection**
- Immediate blocking of flagged IPs
- Configurable block reasons
- Persistent across restarts

```python
# Programmatic IP management
from aiwaf_flask.middleware import AIWAFMiddleware

# Add to whitelist
middleware.storage['add_to_whitelist']('192.168.1.100')

# Add to blacklist with reason
middleware.storage['add_to_blacklist']('10.0.0.50', 'Malicious scan detected')
```

### 2. Rate Limiting

**Adaptive Rate Limiting**
- Per-IP request counting
- Configurable time windows
- Burst detection and blocking

**Configuration**
```python
app.config.update({
    'AIWAF_RATE_LIMIT': 10,        # Requests per window
    'AIWAF_WINDOW_SECONDS': 60,    # 60-second windows
    'AIWAF_RATE_FLOOD': 200,       # Auto-block threshold
})
```

### 3. Keyword Protection

**Dynamic Keyword Learning**
- Learns suspicious patterns from logs
- Context-aware filtering
- Route-specific exemptions

**Manual Keyword Management**
```bash
# Add suspicious keywords
python -m aiwaf_flask.cli add keyword "wp-admin"
python -m aiwaf_flask.cli add keyword "../"

# Remove false positives
python -m aiwaf_flask.cli remove keyword "dashboard"
```

### 4. Honeypot Timing Protection

**Form Submission Timing**
- Detects automated form submissions
- Configurable minimum submission time
- Bot detection through timing analysis

```python
app.config.update({
    'AIWAF_HONEYPOT_DELAY': 0.5,   # Sensitivity threshold
    'AIWAF_MIN_FORM_TIME': 1.0,    # Minimum human time
})
```

### 5. Header Validation

**HTTP Header Analysis**
- User-Agent validation
- Suspicious header detection
- Bot identification patterns

### 6. Geo-Blocking

**Rule-Based Geo-Blocking**
- Uses an MMDB lookup (default: `ipinfo_lite.mmdb`) to resolve country
- No trainer integration; enforcement is purely rule-based

**Flow**
1. `GeoBlockMiddleware` runs early in the request pipeline (`middleware.py`).
2. It checks:
   - `AIWAF_GEO_BLOCK_ENABLED` is `True`.
   - `AIWAF_GEO_ALLOW_COUNTRIES` or `AIWAF_GEO_BLOCK_COUNTRIES` is set.
3. It gets the client IP with `get_ip()` and resolves country via `lookup_country()` in `geoip.py`, using the MMDB at `AIWAF_GEOIP_DB_PATH`.
4. Country results are cached using `AIWAF_GEO_CACHE_PREFIX` and `AIWAF_GEO_CACHE_SECONDS`.
5. Decision logic:
   - If `AIWAF_GEO_ALLOW_COUNTRIES` is non-empty, block everything not in that list.
   - Otherwise, block anything in `AIWAF_GEO_BLOCK_COUNTRIES` or dynamically blocked countries stored in the `GeoBlockedCountry` model.
6. If blocked, it adds the IP to the blacklist and returns `403`.

**Dynamic Admin Control**
- Managed with `python manage.py geo_block_country add|remove|list`, which updates `GeoBlockedCountry` (see `geo_block_country.py` and `models.py`).

**Trainer**
- The trainer does not add or remove geo blocks. It only prints GeoIP summaries for blocked/anomalous IPs via `_print_geoip_summary()` in `trainer.py`.

**Key Settings**
- `AIWAF_GEO_BLOCK_ENABLED`
- `AIWAF_GEO_BLOCK_COUNTRIES`
- `AIWAF_GEO_ALLOW_COUNTRIES`
- `AIWAF_GEOIP_DB_PATH`
- `AIWAF_GEO_CACHE_SECONDS`
- `AIWAF_GEO_CACHE_PREFIX`

### 7. AI Anomaly Detection

**Machine Learning Protection**
- Learns normal traffic patterns
- Detects statistical anomalies
- Requires 10,000+ log entries for training

**AI Training Process**
1. **Log Collection**: Gathers request patterns
2. **Feature Extraction**: Analyzes request characteristics
3. **Model Training**: Builds anomaly detection model
4. **Real-time Detection**: Flags unusual requests

---

## Training System

### Training Requirements

**Basic Training (Keyword Learning)**
- Minimum: 50 log entries
- Functionality: Keyword pattern learning
- Storage: Updates keyword blacklist

**AI Training (Anomaly Detection)**
- Minimum: 10,000 log entries
- Functionality: Machine learning model training
- Storage: Creates/updates ML model

### Training Process

1. **Log Reading**: Scans access logs in multiple formats
2. **Parsing**: Extracts request features (IP, path, method, etc.)
3. **Feature Engineering**: Creates ML-ready feature vectors
4. **Model Training**: Fits isolation forest anomaly detector
5. **Keyword Learning**: Identifies suspicious path patterns
6. **Storage**: Saves model and updated keywords

### Supported Log Formats

**Apache/Nginx Combined Format**
```
127.0.0.1 - - [16/Sep/2025:10:30:45 +0000] "GET /api/data HTTP/1.1" 200 1234 "http://example.com" "Mozilla/5.0..."
```

**CSV Format**
```csv
timestamp,ip,method,path,status_code,user_agent,size
2025-09-16T10:30:45,127.0.0.1,GET,/api/data,200,Mozilla/5.0...,1234
```

**JSON/JSONL Format**
```json
{"timestamp": "2025-09-16T10:30:45", "ip": "127.0.0.1", "method": "GET", "path": "/api/data", "status": 200}
```

### Training Examples

```bash
# Keyword-only training (fast)
python -m aiwaf_flask.cli train --disable-ai --verbose

# Full AI training (requires sufficient data)
python -m aiwaf_flask.cli train --verbose

# Force AI training with minimal data (not recommended)
python -m aiwaf_flask.cli train --force-ai --min-ai-logs 100

# Training output example:
🚀 AIWAF Flask Training Tool
========================================
Log directory: /app/logs
AI training: enabled
Min AI logs threshold: 10000
========================================

📁 Reading logs from: /app/logs/access.log
📊 Total log lines found: 15,247
📋 Parsing 15,247 log entries...
✅ Successfully parsed 14,892 log entries
🔢 Generated 14,892 feature vectors for training
🤖 Training AI anomaly detection model...
📚 Learning suspicious keywords from logs...

============================================================
🤖 AIWAF FLASK TRAINING COMPLETE
============================================================
📊 Training Data: 14,892 log entries processed
🤖 AI Model: Successfully trained with 99.7% feature retention
🚫 AI Blocked IPs: 0 (training mode)
📚 Keywords: 23 new suspicious keywords learned
🛡️  Exemptions: 5 IPs protected from blocking
🚫 404 Blocking: 3 IPs blocked for excessive 404s
✅ Enhanced protection is now active!
```

---

## Storage Options

### 1. CSV Storage (Recommended)

**Benefits**
- No database required
- Human-readable
- Easy backup/migration
- Fast setup

**Files Created**
```
aiwaf_data/
├── whitelist.csv      # Whitelisted IPs
├── blacklist.csv      # Blacklisted IPs with reasons
├── keywords.csv       # Blocked keywords
├── rate_limit.csv     # Rate limiting data
└── model.pkl          # AI model (if trained)
```

**Configuration**
```python
app.config['AIWAF_USE_CSV'] = True
app.config['AIWAF_DATA_DIR'] = 'aiwaf_data'  # Auto-detected
```

### 2. Database Storage

**Benefits**
- Concurrent access
- Transactional safety
- Better performance at scale
- Integration with existing DB

**Required Models**
```python
from aiwaf_flask.models import (
    AIWAFWhitelist,
    AIWAFBlacklist, 
    AIWAFKeyword,
    AIWAFRateLimit
)
```

**Configuration**
```python
app.config['AIWAF_USE_CSV'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'

# Initialize database
with app.app_context():
    db.create_all()
```

### 3. In-Memory Storage

**Benefits**
- Ultra-fast access
- No persistence overhead
- Testing and development

**Limitations**
- Data lost on restart
- No backup capability
- Not suitable for production

---

## Logging and Monitoring

### Access Logging

AIWAF generates comprehensive access logs compatible with standard web server log analyzers.

**Log Files Generated**
```
logs/
├── access.log     # All HTTP requests
├── error.log      # HTTP errors (4xx, 5xx)
└── aiwaf.log      # AIWAF security events
```

**Log Formats**

**Combined Format (Default)**
```
127.0.0.1 - - [16/Sep/2025:10:30:45 +0000] "GET /api/data HTTP/1.1" 200 1234 "http://example.com" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

**CSV Format**
```csv
timestamp,ip,method,path,status_code,user_agent,size,referer
2025-09-16T10:30:45.123456,127.0.0.1,GET,/api/data,200,"Mozilla/5.0...",1234,"http://example.com"
```

**JSON Format**
```json
{
  "timestamp": "2025-09-16T10:30:45.123456",
  "ip": "127.0.0.1",
  "method": "GET", 
  "path": "/api/data",
  "status_code": 200,
  "user_agent": "Mozilla/5.0...",
  "size": 1234,
  "referer": "http://example.com"
}
```

### Security Event Logging

**AIWAF Security Log Example**
```
2025-09-16 10:30:45,123 [INFO] IP 192.168.1.100 added to whitelist
2025-09-16 10:31:12,456 [WARNING] Rate limit exceeded for IP 10.0.0.50 (15 requests in 60s)
2025-09-16 10:31:45,789 [CRITICAL] IP 203.0.113.10 blocked - keyword match: "wp-admin"
2025-09-16 10:32:30,012 [INFO] AI anomaly detected for request from 172.16.0.10 to /api/unusual
```

### Log Analysis

**Built-in Analytics**
```bash
$ python -m aiwaf_flask.cli logs --format combined

📊 AIWAF Access Log Analysis
==================================================
Total Requests: 15,247
Blocked Requests: 423
Unique IPs: 1,892
Block Rate: 2.8%

📈 Status Code Distribution:
  • 200: 12,456 (81.7%)
  • 403: 423 (2.8%) 
  • 404: 1,234 (8.1%)
  • 429: 892 (5.9%)
  • 500: 242 (1.6%)

🌐 Top Client IPs:
  • 192.168.1.100: 2,345 requests (15.4%)
  • 10.0.0.25: 1,234 requests (8.1%)
  • 172.16.0.50: 987 requests (6.5%)

📊 Most Requested Paths:
  • /api/data: 3,456 requests
  • /health: 2,134 requests  
  • /dashboard: 1,876 requests
  • /api/users: 1,234 requests

🚫 Block Reasons:
  • Rate limit exceeded: 234 blocks
  • IP blacklisted: 123 blocks
  • Malicious keyword: 45 blocks
  • AI anomaly detected: 21 blocks
```

---

## Advanced Usage

### Route-Level Protection Control

**Exemption Decorators**
```python
from aiwaf_flask.decorators import exempt_from_aiwaf, aiwaf_config

@app.route('/public-api')
@exempt_from_aiwaf  # Skip all AIWAF protection
def public_endpoint():
    return {"status": "public"}

@app.route('/special-endpoint')
@aiwaf_config(rate_limit=100, honeypot_delay=0.1)  # Custom settings
def special_endpoint():
    return {"status": "special"}
```

**Path Exemptions**
```python
app.config['AIWAF_EXEMPT_PATHS'] = [
    '/health',           # Health checks
    '/metrics',          # Monitoring
    '/static/*',         # Static files
    '/api/webhook/*',    # Webhook endpoints
]
```

**Path-Specific Rules**
```python
app.config['AIWAF_PATH_RULES'] = [
    {
        'PREFIX': '/myapp/api/',
        'DISABLE': ['HeaderValidationMiddleware'],
        'RATE_LIMIT': {'WINDOW': 60, 'MAX': 2000},
    },
    {
        'PREFIX': '/myapp/',
        'RATE_LIMIT': {'WINDOW': 60, 'MAX': 200},
    },
]
```

Notes:
- `PREFIX` is a startswith match; longest prefix wins.
- `DISABLE` accepts middleware keys (e.g., `header_validation`) or class names.
- `RATE_LIMIT` supports `WINDOW`, `MAX`, and `FLOOD` overrides.

### Custom Storage Backend

```python
from aiwaf_flask.storage import BaseStorage

class CustomStorage(BaseStorage):
    def read_whitelist(self):
        # Custom whitelist logic
        return set()
    
    def add_to_whitelist(self, ip):
        # Custom add logic
        pass

# Use custom storage
app.config['AIWAF_CUSTOM_STORAGE'] = CustomStorage()
```

### Integration with Flask-Login

```python
from flask_login import current_user
from aiwaf_flask import register_aiwaf_middlewares

@app.before_request
def aiwaf_user_context():
    # Skip protection for authenticated admin users
    if current_user.is_authenticated and current_user.is_admin:
        request.aiwaf_exempt = True

register_aiwaf_middlewares(app)
```

### Webhook Protection

```python
from aiwaf_flask.decorators import aiwaf_config

@app.route('/webhooks/github', methods=['POST'])
@aiwaf_config(rate_limit=1000, skip_ai=True)  # High rate limit, no AI
def github_webhook():
    # Process webhook
    return {"status": "received"}
```

---

## Troubleshooting

### Common Issues

**1. "No log lines found" Error**
```bash
# Check log directory
python -m aiwaf_flask.cli logs --log-dir /path/to/logs

# Verify auto-detection
python -m aiwaf_flask.cli train --verbose
# Look for: "📁 Auto-configured log directory: ..."
```

**2. "Need at least 10000 for AI training"**
```bash
# Use keyword-only training
python -m aiwaf_flask.cli train --disable-ai

# Or force AI training (not recommended)
python -m aiwaf_flask.cli train --force-ai --min-ai-logs 100
```

**3. Directory Inconsistency**
```bash
# Check auto-configuration
python -m aiwaf_flask.cli list all
# Should show same data directory regardless of working directory

# Set explicit paths if needed
export AIWAF_DATA_DIR=/app/data
export AIWAF_LOG_DIR=/app/logs
```

**4. Model Compatibility Issues**
```bash
# Check model status
python -m aiwaf_flask.cli model --check

# Retrain with current dependencies
python -m aiwaf_flask.cli model --retrain
```

**5. Permission Errors**
```bash
# Check directory permissions
ls -la aiwaf_data/
ls -la logs/

# Fix permissions (Linux/Mac)
chmod 755 aiwaf_data/ logs/
chmod 644 aiwaf_data/*.csv logs/*.log
```

### Debug Mode

**Enable Verbose Output**
```python
import logging
logging.basicConfig(level=logging.DEBUG)

app.config['AIWAF_DEBUG'] = True
```

**CLI Debug Information**
```bash
# All CLI commands support verbose output
python -m aiwaf_flask.cli train --verbose
python -m aiwaf_flask.cli list all --verbose
```

### Performance Optimization

**For High-Traffic Applications**
```python
app.config.update({
    'AIWAF_USE_CSV': False,              # Use database for better performance
    'AIWAF_RATE_LIMIT': 1000,           # Higher rate limits
    'AIWAF_WINDOW_SECONDS': 300,        # Longer windows
    'AIWAF_DISABLE_AI_REALTIME': True,  # Disable real-time AI (train separately)
})
```

**Memory Usage Optimization**
```python
app.config.update({
    'AIWAF_MAX_RATE_ENTRIES': 10000,    # Limit rate limiting entries
    'AIWAF_CLEANUP_INTERVAL': 3600,     # Cleanup old entries hourly
})
```

---

## API Reference

### Core Functions

**register_aiwaf_middlewares(app)**
```python
"""Register AIWAF protection middleware with Flask app.

Args:
    app (Flask): Flask application instance

Returns:
    AIWAFMiddleware: Configured middleware instance
"""
```

**register_aiwaf_protection(app)**
```python
"""Backward compatibility alias for register_aiwaf_middlewares.

Args:
    app (Flask): Flask application instance

Returns:
    AIWAFMiddleware: Configured middleware instance
"""
```

### Decorators

**@exempt_from_aiwaf**
```python
"""Completely bypass AIWAF protection for a route.

Usage:
    @app.route('/public')
    @exempt_from_aiwaf
    def public_route():
        return "No protection"
"""
```

**@aiwaf_config(**kwargs)**
```python
"""Configure AIWAF settings for specific route.

Args:
    rate_limit (int): Custom rate limit
    honeypot_delay (float): Custom honeypot sensitivity
    skip_ai (bool): Skip AI anomaly detection
    skip_keywords (bool): Skip keyword filtering

Usage:
    @app.route('/api')
    @aiwaf_config(rate_limit=100, skip_ai=True)
    def api_route():
        return {"data": "value"}
"""
```

### Storage Interface

**BaseStorage Methods**
```python
class BaseStorage:
    def read_whitelist(self) -> Set[str]: ...
    def read_blacklist(self) -> Dict[str, str]: ...
    def read_keywords(self) -> Set[str]: ...
    def add_to_whitelist(self, ip: str) -> bool: ...
    def add_to_blacklist(self, ip: str, reason: str = "") -> bool: ...
    def add_keyword(self, keyword: str) -> bool: ...
    def remove_from_whitelist(self, ip: str) -> bool: ...
    def remove_from_blacklist(self, ip: str) -> bool: ...
    def remove_keyword(self, keyword: str) -> bool: ...
```

### Training Interface

**train_from_logs(app, disable_ai=False)**
```python
"""Train AIWAF from application logs.

Args:
    app (Flask): Flask application with AIWAF configured
    disable_ai (bool): Skip AI training, do keyword learning only

Returns:
    bool: True if training successful
"""
```

### CLI Manager

**AIWAFCLIManager**
```python
class AIWAFCLIManager:
    def list_data(self, data_type: str) -> None: ...
    def add_item(self, list_type: str, value: str, reason: str = "") -> None: ...
    def remove_item(self, list_type: str, value: str) -> None: ...
    def show_stats(self) -> None: ...
    def analyze_logs(self, log_dir: str, log_format: str) -> None: ...
    def train_model(self, log_dir: str, disable_ai: bool, 
                   min_ai_logs: int, force_ai: bool, verbose: bool) -> None: ...
```

---

## Conclusion

AIWAF Flask provides enterprise-grade security for Flask applications with minimal setup requirements. The auto-configuration system ensures consistent behavior across different environments, while the comprehensive CLI enables easy management and monitoring.

For additional support, feature requests, or bug reports, please visit the project repository or consult the API documentation.

### Quick Reference Commands

```bash
# Setup and basic usage
pip install aiwaf-flask[ai]
python -m aiwaf_flask.cli list all
python -m aiwaf_flask.cli train --verbose

# Management
python -m aiwaf_flask.cli add blacklist 10.0.0.1 --reason "Malicious"
python -m aiwaf_flask.cli logs --format combined
python -m aiwaf_flask.cli model --check

# Monitoring
python -m aiwaf_flask.cli stats
python -m aiwaf_flask.cli export --output backup.json
```

**Remember**: AIWAF learns and adapts to your application's traffic patterns. Regular training with fresh log data improves protection effectiveness.
