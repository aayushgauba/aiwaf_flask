# AIWAF Flask

AIWAF (AI Web Application Firewall) for Flask provides advanced, self-learning protection for your Flask web applications. It supports IP/keyword blocking, rate limiting, honeypot timing, header validation, anomaly detection, and UUID tampering, with flexible storage options: **database**, **CSV files**, or **in-memory**.

## Features
- IP and keyword blocking
- Rate limiting with burst detection
- Honeypot timing protection
- Header validation
- Anomaly detection (extensible)
- UUID tampering detection
- **Path exemptions** - Prevent false positives for legitimate resources
- **Flexible storage**: Database, CSV files, or in-memory
- Zero-dependency protection (works without database)

## Function Names

AIWAF Flask provides two function names for registering middleware:

- **`register_aiwaf_middlewares(app)`** - Current recommended name
- **`register_aiwaf_protection(app)`** - Backward compatibility alias

Both functions work identically and provide the same protection features.

```python
from flask import Flask
from aiwaf_flask import register_aiwaf_middlewares
# OR: from aiwaf_flask import register_aiwaf_protection

app = Flask(__name__)
app.config['AIWAF_USE_CSV'] = True

# Both of these work the same way:
register_aiwaf_middlewares(app)
# register_aiwaf_protection(app)  # Alternative
```

## Installation

```bash
pip install flask flask-sqlalchemy  # For database storage
# OR
pip install flask  # For CSV/in-memory storage only
```

## Storage Options

### 1. **CSV Storage (Recommended for small apps)**
```python
from flask import Flask
from aiwaf_flask import register_aiwaf_middlewares

app = Flask(__name__)

# CSV Configuration (no database needed!)
app.config['AIWAF_USE_CSV'] = True
app.config['AIWAF_DATA_DIR'] = 'aiwaf_data'  # Optional: custom directory

# AIWAF Settings
app.config['AIWAF_RATE_WINDOW'] = 60
app.config['AIWAF_RATE_MAX'] = 100

register_aiwaf_middlewares(app)
```

### 2. **Database Storage (Recommended for production)**
```python
from flask import Flask
from aiwaf_flask.db_models import db
from aiwaf_flask import register_aiwaf_middlewares

app = Flask(__name__)

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///aiwaf.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# AIWAF Settings
app.config['AIWAF_RATE_WINDOW'] = 60
app.config['AIWAF_RATE_MAX'] = 100

db.init_app(app)
with app.app_context():
    db.create_all()

register_aiwaf_middlewares(app)
```

### 3. **In-Memory Storage (For testing)**
```python
from flask import Flask
from aiwaf_flask import register_aiwaf_middlewares

app = Flask(__name__)

# Force in-memory storage
app.config['AIWAF_USE_CSV'] = False

register_aiwaf_middlewares(app, use_database=False)
```

## Configuration Options

```python
# Rate Limiting
app.config['AIWAF_RATE_WINDOW'] = 60      # Time window in seconds
app.config['AIWAF_RATE_MAX'] = 100        # Max requests per window
app.config['AIWAF_RATE_FLOOD'] = 200      # Auto-block threshold

# Honeypot Protection
app.config['AIWAF_MIN_FORM_TIME'] = 2.0   # Minimum form submission time

# CSV Storage (if enabled)
app.config['AIWAF_USE_CSV'] = True        # Enable CSV storage
app.config['AIWAF_DATA_DIR'] = 'aiwaf_data'  # CSV files directory

# Logging Configuration
app.config['AIWAF_ENABLE_LOGGING'] = True    # Enable request logging
app.config['AIWAF_LOG_DIR'] = 'aiwaf_logs'   # Log files directory
app.config['AIWAF_LOG_FORMAT'] = 'combined'  # Log format: combined, common, csv, json

# Path Exemptions
app.config['AIWAF_EXEMPT_PATHS'] = {      # Paths exempt from AIWAF protection
    '/favicon.ico',
    '/robots.txt', 
    '*.css',        # Wildcard patterns
    '/static/',     # Directory patterns
}
```

## Path Exemptions (Prevent False Positives)

AIWAF supports **path-based exemptions** to prevent false positives for legitimate resources that might return 404s or should not be subject to security filtering.

### Default Exempt Paths

AIWAF includes sensible defaults for common legitimate resources:

```python
# SEO and crawlers
'/favicon.ico', '/robots.txt', '/sitemap.xml', '/ads.txt'

# Apple and mobile devices  
'/apple-touch-icon.png', '/manifest.json', '/browserconfig.xml'

# Health checks and monitoring
'/health', '/healthcheck', '/ping', '/status'

# Well-known URIs (SSL certificates, security policies)
'/.well-known/'

# Static file extensions (wildcards)
'*.css', '*.js', '*.png', '*.jpg', '*.ico', '*.woff2'

# Static directories
'/static/', '/assets/', '/css/', '/js/', '/images/', '/fonts/'
```

### Custom Path Exemptions

Configure custom exempt paths for your application:

```python
# Override defaults with custom paths
app.config['AIWAF_EXEMPT_PATHS'] = {
    # Essential SEO files
    '/favicon.ico',
    '/robots.txt',
    '/sitemap.xml',
    
    # Health monitoring  
    '/health',
    '/api/health',
    
    # Public APIs
    '/api/public/',
    '/webhook/github',
    
    # Static assets
    '*.css', '*.js', '*.png', '*.pdf',
    '/static/', '/assets/',
    
    # Custom application paths
    '/special-public-endpoint',
    '/custom-health-check',
}
```

### Pattern Types

- **Exact paths**: `/favicon.ico` (matches exactly)
- **Wildcard patterns**: `*.css` (matches any .css file)  
- **Directory patterns**: `/static/` (matches anything under /static/)
- **Case insensitive**: `/FAVICON.ICO` also matches

### Why Use Path Exemptions?

- **Prevent SEO issues**: Search engines can safely crawl `/robots.txt`, `/sitemap.xml`
- **Avoid blocking legitimate 404s**: `favicon.ico` requests won't trigger blocking
- **Load balancer compatibility**: Health checks always work (`/health`, `/ping`)
- **Static asset safety**: CSS/JS/images load without interference
- **SSL certificate support**: `/.well-known/` URIs for ACME challenges

## Web Server Logging

AIWAF Flask includes comprehensive logging that generates **standard web server logs** compatible with tools like Gunicorn, Nginx, and Apache log analyzers.

### Log Formats

#### **Combined Log Format (Default)**
```
127.0.0.1 - - [14/Sep/2025:15:02:41 +0000] "GET /api/data HTTP/1.1" 200 1234 "http://example.com" "Mozilla/5.0" 50ms - "-"
203.0.113.10 - - [14/Sep/2025:15:02:42 +0000] "GET /admin.php HTTP/1.1" 403 0 "-" "BadBot/1.0" 10ms BLOCKED "Malicious keyword: .php"
```

#### **CSV Format (Easy Analysis)**
```csv
timestamp,ip,method,path,status_code,response_time_ms,blocked,block_reason
2025-09-14T15:02:41,127.0.0.1,GET,/api/data,200,50,False,
2025-09-14T15:02:42,203.0.113.10,GET,/admin.php,403,10,True,Malicious keyword: .php
```

#### **JSON Format (Structured)**
```json
{"timestamp": "2025-09-14T15:02:41", "ip": "127.0.0.1", "method": "GET", "path": "/api/data", "status_code": 200, "blocked": false}
{"timestamp": "2025-09-14T15:02:42", "ip": "203.0.113.10", "method": "GET", "path": "/admin.php", "status_code": 403, "blocked": true, "block_reason": "Malicious keyword: .php"}
```

### Log Configuration

```python
app.config['AIWAF_ENABLE_LOGGING'] = True       # Enable logging
app.config['AIWAF_LOG_DIR'] = 'logs'            # Log directory
app.config['AIWAF_LOG_FORMAT'] = 'combined'     # Format: combined, common, csv, json
```

### Generated Log Files

- **`access.log`** - All HTTP requests (main access log)
- **`error.log`** - HTTP errors (4xx, 5xx status codes)
- **`aiwaf.log`** - AIWAF security events and blocks

### Log Analysis

```bash
# Analyze logs with detailed statistics
aiwaf logs --log-dir logs --format combined

# Sample output:
# 📊 AIWAF Access Log Analysis
# Total Requests: 1,250
# Blocked Requests: 45 (3.6%)
# Average Response Time: 85ms
# Top IPs, paths, block reasons, hourly patterns, etc.
```

## Usage Examples

Your routes are automatically protected:

```python
@app.route('/')
def home():
    return render_template('home.html')  # Protected by AIWAF

@app.route('/api/data')
def api_data():
    return jsonify({'data': 'protected'})  # Rate limited & validated
```

## Managing Protection Lists

```python
from aiwaf_flask.storage import add_ip_whitelist, add_ip_blacklist, add_keyword

# Add IPs to whitelist (bypass all protection)
add_ip_whitelist('192.168.1.100')

# Add IPs to blacklist (block completely)
add_ip_blacklist('10.0.0.1', reason='Suspicious activity')

# Add malicious keywords to block
add_keyword('wp-admin')
add_keyword('.env')
```

## CSV Files Structure

When using CSV storage, AIWAF creates these files in your data directory:

- `whitelist.csv` - Whitelisted IP addresses
- `blacklist.csv` - Blacklisted IP addresses with reasons
- `keywords.csv` - Blocked keywords

Example `blacklist.csv`:
```csv
ip,reason,added_date
10.0.0.1,Suspicious activity,2025-09-14T10:30:00
192.168.1.50,Rate limit exceeded,2025-09-14T11:15:00
```

## Command Line Management

AIWAF Flask includes a powerful CLI tool for managing IP exemptions, blacklists, and blocked keywords from the command line. After installation, the CLI is available globally as `aiwaf` or `aiwaf-console`.

### Installation & CLI Access

```bash
# Install AIWAF Flask
pip install aiwaf-flask

# CLI is now available globally - no need to be in project directory!
aiwaf --help
aiwaf-console --help  # Alternative command name

# If developing locally:
pip install -e .      # Makes CLI available globally
```

### Basic Usage

```bash
# Show help (works from any directory after installation)
aiwaf --help

# Show current statistics
aiwaf stats

# List all data
aiwaf list all
```

### IP Management

```bash
# Add IP to whitelist
aiwaf add whitelist 192.168.1.100

# Add IP to blacklist with reason
aiwaf add blacklist 10.0.0.5 --reason "Brute force attack"

# Remove IP from whitelist
aiwaf remove whitelist 192.168.1.100

# Remove IP from blacklist
aiwaf remove blacklist 10.0.0.5

# List specific data types
aiwaf list whitelist
aiwaf list blacklist
```

### Keyword Management

```bash
# Add blocked keyword
aiwaf add keyword "sql injection"
aiwaf add keyword "script"

# List blocked keywords
aiwaf list keywords
```

### Configuration Backup/Restore

```bash
# Export current configuration
aiwaf export backup.json

# Import configuration from backup
aiwaf import backup.json
```

### Log Analysis

```bash
# Analyze logs with detailed statistics
aiwaf logs --log-dir logs --format combined
```

### Custom Data Directory

```bash
# Use custom data directory
aiwaf --data-dir /path/to/custom/aiwaf_data stats
```

### Example CLI Session

```bash
# Check current status (works from any directory!)
aiwaf stats

# Add some IPs to whitelist
aiwaf add whitelist 192.168.1.100
aiwaf add whitelist 10.0.0.50

# Block a malicious IP
aiwaf add blacklist 203.0.113.10 --reason "SQL injection attempts"

# Add dangerous keywords
aiwaf add keyword "union select"
aiwaf add keyword "drop table"

# Review all settings
aiwaf list all

# Create backup
aiwaf export production_backup.json
```

### Programmatic Management

You can also use the CLI functionality in your Python code:

```python
from aiwaf_flask.cli import AIWAFManager

# Initialize manager
manager = AIWAFManager()

# Add IPs programmatically
manager.add_to_whitelist("192.168.1.100")
manager.add_to_blacklist("10.0.0.5", "Suspicious activity")

# Get current lists
whitelist = manager.list_whitelist()
blacklist = manager.list_blacklist()
keywords = manager.list_keywords()

# Export configuration
manager.export_config("backup.json")
```

## CLI Features & Real-World Examples

AIWAF Flask includes powerful command-line tools for production management. The CLI works independently without requiring Flask to be installed, making it perfect for system administration and automation.

### Quick Setup

```bash
# Show CLI status and help
python aiwaf_setup.py

# Install Flask if needed (optional for CLI-only usage)
python aiwaf_setup.py install-flask

# Run interactive demo
python aiwaf_setup.py demo
```

### Production Management Examples

#### **Emergency IP Blocking**
```bash
# Block attacking IPs immediately (works from any directory!)
aiwaf add blacklist 203.0.113.10 --reason "SQL injection attack detected"
aiwaf add blacklist 198.51.100.5 --reason "Brute force login attempts"
aiwaf add blacklist 10.0.0.1 --reason "Suspicious port scanning"

# Verify blocks are active
aiwaf list blacklist
```

#### **Whitelist Management**
```bash
# Add trusted networks
aiwaf add whitelist 192.168.1.0/24
aiwaf add whitelist 10.0.0.0/8
aiwaf add whitelist 172.16.0.0/12

# Add specific trusted IPs
aiwaf add whitelist 203.0.113.100  # Office IP
aiwaf add whitelist 198.51.100.200 # API partner
```

#### **Security Keywords**
```bash
# Block common attack patterns
aiwaf add keyword "union select"
aiwaf add keyword "drop table"
aiwaf add keyword "<script>"
aiwaf add keyword "javascript:"
aiwaf add keyword "eval("
aiwaf add keyword "base64_decode"

# Review blocked keywords
aiwaf list keywords
```

#### **Daily Operations**
```bash
# Morning security check
aiwaf stats

# Review recent blocks
aiwaf list blacklist

# Create daily backup
aiwaf export "backup-$(date +%Y%m%d).json"

# Clean up test entries
aiwaf remove whitelist 192.168.1.99
aiwaf remove blacklist 10.0.0.99
```

### Automation Scripts

#### **Security Incident Response**
```bash
#!/bin/bash
# incident_response.sh - Block multiple IPs from security incident

MALICIOUS_IPS=(
    "203.0.113.10"
    "198.51.100.5" 
    "192.0.2.15"
    "198.51.100.25"
)

for ip in "${MALICIOUS_IPS[@]}"; do
    aiwaf add blacklist "$ip" --reason "Security incident #2025-001"
done

# Create incident backup
aiwaf export "incident-2025-001-backup.json"
echo "Blocked ${#MALICIOUS_IPS[@]} IPs from security incident"
```

#### **Configuration Deployment**
```bash
#!/bin/bash
# deploy_config.sh - Deploy AIWAF configuration to production

# Backup current config
aiwaf export "backup-before-deploy-$(date +%Y%m%d-%H%M).json"

# Deploy new configuration
aiwaf import "production-config.json"

# Verify deployment
aiwaf stats
aiwaf list all
```

### Real CLI Session Output

```bash
$ aiwaf stats
📁 Using CSV storage: aiwaf_data

📊 AIWAF Statistics
==================================================
Whitelisted IPs: 5
Blacklisted IPs: 3
Blocked Keywords: 8
Storage Mode: CSV
Data Directory: aiwaf_data

$ aiwaf list all
📁 Using CSV storage: aiwaf_data

🟢 Whitelisted IPs (5):
  • 192.168.1.100
  • 192.168.1.200
  • 10.0.0.50
  • 203.0.113.100
  • 198.51.100.200

🔴 Blacklisted IPs (3):
  • 203.0.113.10 - SQL injection attack detected (2025-09-14T09:15:30)
  • 198.51.100.5 - Brute force login attempts (2025-09-14T10:22:15)
  • 10.0.0.1 - Suspicious port scanning (2025-09-14T11:45:22)

🚫 Blocked Keywords (8):
  • union select
  • drop table
  • <script>
  • javascript:
  • eval(
  • base64_decode
  • onload=
  • document.cookie

$ aiwaf export production-backup.json
📁 Using CSV storage: aiwaf_data
✅ Configuration exported to production-backup.json
```

### Configuration Format

The exported JSON configuration contains all security settings:

```json
{
  "whitelist": [
    "192.168.1.100",
    "192.168.1.200",
    "10.0.0.50"
  ],
  "blacklist": {
    "203.0.113.10": {
      "timestamp": "2025-09-14T09:15:30.123456",
      "reason": "SQL injection attack detected"
    },
    "198.51.100.5": {
      "timestamp": "2025-09-14T10:22:15.789012", 
      "reason": "Brute force login attempts"
    }
  },
  "keywords": [
    "union select",
    "drop table",
    "<script>",
    "eval("
  ],
  "exported_at": "2025-09-14T14:30:00.000000",
  "storage_mode": "CSV"
}
```

### Integration with Monitoring

```bash
# Add to crontab for daily reports
0 9 * * * /path/to/aiwaf stats >> /var/log/aiwaf-daily.log

# Add to monitoring script
aiwaf stats | grep -E "(Blacklisted|Keywords)" | \
  awk '{if($3 > 100) print "ALERT: High security blocks detected"}'
```

## Production Deployment

```python
# config.py
import os

class ProductionConfig:
    # Use PostgreSQL in production
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    
    # Stricter limits for production
    AIWAF_RATE_MAX = 50
    AIWAF_RATE_FLOOD = 100
    AIWAF_MIN_FORM_TIME = 3.0

# app.py
app.config.from_object(ProductionConfig)
```

## License
MIT
