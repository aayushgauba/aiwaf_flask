# AIWAF Flask

AIWAF (AI Web Application Firewall) for Flask provides advanced, self-learning protection for your Flask web applications. It supports IP/keyword blocking, rate limiting, honeypot timing, header validation, anomaly detection, and UUID tampering, with flexible storage options: **database**, **CSV files**, or **in-memory**.

## Features
- IP and keyword blocking
- Rate limiting with burst detection
- Honeypot timing protection
- Header validation
- **AI-powered anomaly detection** - Machine learning to detect suspicious patterns
- UUID tampering detection
- **Route-level exemption decorators** - Fine-grained control over middleware protection
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
# Basic installation (without AI features)
pip install aiwaf-flask

# With AI anomaly detection features
pip install aiwaf-flask[ai]

# Full installation (AI + development tools)
pip install aiwaf-flask[all]
```

### AI Dependencies

The AI anomaly detection middleware requires additional dependencies:
- **NumPy** (`>=1.20.0`) - For numerical computations and feature analysis
- **Scikit-learn** (`>=1.0.0`) - For machine learning model training and prediction

```bash
# Install AI dependencies separately if needed
pip install numpy>=1.20.0 scikit-learn>=1.0.0
```

## Quick Start

### Basic Setup (All Middlewares)

```python
from flask import Flask
from aiwaf_flask import AIWAF

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

# Enable all AIWAF protections (default behavior)
aiwaf = AIWAF(app)  # ← Automatically enables ALL 7 middlewares

@app.route('/')
def home():
    return 'Hello, AIWAF!'

# Optional: Use exemption decorators for fine-grained control
from aiwaf_flask import aiwaf_exempt

@app.route('/health')
@aiwaf_exempt  # Bypass all protection for health checks
def health():
    return {'status': 'ok'}

if __name__ == '__main__':
    app.run(debug=True)
```

### Default Behavior

**When you don't specify any middlewares, AIWAF automatically enables ALL available middlewares:**

```python
# These are all equivalent - they all enable ALL middlewares:
aiwaf = AIWAF(app)                    # ← Default: enables all 7 middlewares
aiwaf = AIWAF(app, middlewares=None)  # ← Same as above
aiwaf = AIWAF()                       # ← Then call aiwaf.init_app(app)
aiwaf.init_app(app)                   # ← Also enables all middlewares
```

### Customized Middleware Selection

If you want **specific control**, you can selectively enable or disable middlewares:

```python
from flask import Flask
from aiwaf_flask import AIWAF

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

# Option 1: Enable ONLY specific middlewares
aiwaf = AIWAF(app, middlewares=[
    'rate_limit',           # Rate limiting protection
    'header_validation',    # HTTP header validation  
    'ai_anomaly',          # AI-powered anomaly detection
    'logging'              # Request/response logging
])

# Option 2: Enable ALL middlewares EXCEPT specified ones
aiwaf = AIWAF(app, disable_middlewares=[
    'honeypot',            # Disable honeypot timing
    'uuid_tamper'          # Disable UUID tampering protection
])
# ↑ Enables 5 out of 7 middlewares (all except the 2 disabled)

# Option 3: Minimal security setup (essentials only)
aiwaf = AIWAF(app, middlewares=[
    'ip_keyword_block',    # Core IP/keyword blocking
    'rate_limit',          # Rate limiting
    'logging'              # Activity logging
])
# ↑ Enables only 3 specific middlewares
```

### Available Middlewares

| Middleware | Name | Description |
|------------|------|-------------|
| **IP & Keyword Block** | `ip_keyword_block` | Blocks malicious IPs and detects attack keywords |
| **Rate Limiting** | `rate_limit` | Protects against brute force and DDoS attacks |
| **Honeypot Timing** | `honeypot` | Detects automated form submissions |
| **Header Validation** | `header_validation` | Validates HTTP headers for security threats |
| **AI Anomaly Detection** | `ai_anomaly` | Machine learning-based pattern analysis |
| **UUID Tampering** | `uuid_tamper` | Protects against UUID manipulation attacks |
| **Request Logging** | `logging` | Comprehensive request/response logging |

### Initialization Patterns

| Pattern | Result | Use Case |
|---------|--------|----------|
| `AIWAF(app)` | **Enables ALL 7 middlewares** | Default - maximum protection |
| `AIWAF(app, middlewares=[...])` | Enables only specified | Custom selection |
| `AIWAF(app, disable_middlewares=[...])` | Enables all except specified | Mostly default with exceptions |
| `AIWAF()` then `init_app(app)` | **Enables ALL 7 middlewares** | Factory pattern |

### Middleware Management

```python
# Check which middlewares are enabled
enabled = aiwaf.get_enabled_middlewares()
print(f"Active protections: {enabled}")

# Check if specific middleware is enabled
if aiwaf.is_middleware_enabled('ai_anomaly'):
    print("AI protection is active")

# Get middleware instance for advanced configuration
rate_limiter = aiwaf.get_middleware_instance('rate_limit')

# List all available middlewares
available = AIWAF.list_available_middlewares()
print(f"Available: {available}")
```

## Route-Level Exemption Decorators

AIWAF Flask provides powerful decorators for fine-grained control over which middlewares apply to specific routes. This allows you to create precise security policies that balance protection with functionality.

### Complete Exemption

Use `@aiwaf_exempt` to completely bypass ALL AIWAF protection for a route:

```python
from aiwaf_flask import aiwaf_exempt

@app.route('/health')
@aiwaf_exempt
def health_check():
    """Health check endpoint - no security needed"""
    return {'status': 'ok'}

@app.route('/metrics')
@aiwaf_exempt
def metrics():
    """Metrics endpoint for monitoring systems"""
    return "# Prometheus metrics\napp_requests_total 1234\n"
```

### Selective Exemption

Use `@aiwaf_exempt_from()` to exempt from specific middlewares while keeping others:

```python
from aiwaf_flask import aiwaf_exempt_from

@app.route('/api/webhook')
@aiwaf_exempt_from('rate_limit', 'ai_anomaly')
def github_webhook():
    """Webhook endpoint - bypasses rate limiting and AI detection"""
    return {'received': True}

@app.route('/api/upload')
@aiwaf_exempt_from('ai_anomaly', 'honeypot')
def file_upload():
    """File upload - large files may trigger false positives"""
    return {'uploaded': True}
```

### Apply Only Specific Middlewares

Use `@aiwaf_only()` to apply ONLY specific middlewares:

```python
from aiwaf_flask import aiwaf_only

@app.route('/api/public')
@aiwaf_only('rate_limit')
def public_api():
    """Public API - only needs rate limiting"""
    return {'data': get_public_data()}

@app.route('/api/sensitive')
@aiwaf_only('ip_keyword_block', 'rate_limit', 'ai_anomaly')
def sensitive_api():
    """High-security endpoint with critical protection only"""
    return {'sensitive_data': get_sensitive_data()}
```

### Force Required Protection

Use `@aiwaf_require_protection()` to force specific middlewares even if exempted elsewhere:

```python
from aiwaf_flask import aiwaf_require_protection

@app.route('/admin/critical')
@aiwaf_exempt_from('rate_limit')  # Try to exempt rate limiting
@aiwaf_require_protection('rate_limit', 'ai_anomaly')  # But force it anyway
def critical_admin():
    """Critical admin function - always needs full protection"""
    return {'status': 'executed'}
```

### Available Middleware Names

When using exemption decorators, these are the middleware names you can specify:

- `'ip_keyword_block'` - IP blocking and keyword detection
- `'rate_limit'` - Rate limiting protection
- `'honeypot'` - Honeypot timing detection
- `'header_validation'` - HTTP header validation
- `'ai_anomaly'` - AI-based anomaly detection
- `'uuid_tamper'` - UUID tampering protection
- `'logging'` - Security event logging

### Practical Examples

```python
from flask import Flask
from aiwaf_flask import AIWAF, aiwaf_exempt, aiwaf_exempt_from, aiwaf_only

app = Flask(__name__)
aiwaf = AIWAF(app)

# Monitoring endpoints (no protection needed)
@app.route('/health')
@aiwaf_exempt
def health(): return {'status': 'healthy'}

# Webhook endpoints (selective protection)
@app.route('/webhooks/github')
@aiwaf_exempt_from('rate_limit', 'honeypot')
def github_webhook(): return {'received': True}

# Public API (minimal protection)
@app.route('/api/public/data')
@aiwaf_only('rate_limit')
def public_data(): return {'data': 'public'}

# Admin endpoints (always protected)
@app.route('/admin/users')
@aiwaf_require_protection('ip_keyword_block', 'rate_limit', 'ai_anomaly')
def admin_users(): return {'users': get_users()}
```

For comprehensive documentation and advanced use cases, see [EXEMPTION_DECORATORS_GUIDE.md](EXEMPTION_DECORATORS_GUIDE.md).

## Legacy Compatibility

The old registration method still works with new customization options:

```python
from aiwaf_flask import register_aiwaf_middlewares

# Legacy method with new features
register_aiwaf_middlewares(
    app, 
    middlewares=['rate_limit', 'ai_anomaly'],
    disable_middlewares=['honeypot']
)
```

## Storage Options

### 1. **CSV Storage (Recommended for small apps)**
```python
from flask import Flask
from aiwaf_flask import AIWAF

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

# CSV Configuration (no database needed!)
app.config['AIWAF_USE_CSV'] = True
app.config['AIWAF_DATA_DIR'] = 'aiwaf_data'  # Optional: custom directory

# AIWAF Settings
app.config['AIWAF_RATE_WINDOW'] = 60
app.config['AIWAF_RATE_MAX'] = 100

# Initialize with custom middleware selection
aiwaf = AIWAF(app, middlewares=['rate_limit', 'ip_keyword_block', 'logging'])
```

### 2. **Database Storage (Recommended for production)**
```python
from flask import Flask
from aiwaf_flask.db_models import db
from aiwaf_flask import AIWAF

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///aiwaf.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['AIWAF_USE_CSV'] = False  # Force database usage

# AIWAF Settings
app.config['AIWAF_RATE_WINDOW'] = 60
app.config['AIWAF_RATE_MAX'] = 100

# Initialize with all middlewares
aiwaf = AIWAF(app, use_database=True)
```
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

## Middleware Selection Guide

### 🛡️ **Minimal Security (Essential Protection)**
Best for: Small applications, development environments, minimal overhead

```python
aiwaf = AIWAF(app, middlewares=[
    'ip_keyword_block',  # Core attack prevention
    'rate_limit',        # Basic DDoS protection  
    'logging'            # Security monitoring
])
```

### 🚀 **Standard Security (Recommended)**
Best for: Most production applications, balanced protection

```python
aiwaf = AIWAF(app, middlewares=[
    'ip_keyword_block',   # Core attack prevention
    'rate_limit',         # DDoS protection
    'header_validation',  # HTTP security
    'ai_anomaly',        # Smart threat detection
    'logging'            # Security monitoring
])
```

### 🔥 **Maximum Security (Full Protection)**
Best for: High-security applications, sensitive data handling

```python
# Enable all middlewares (default)
aiwaf = AIWAF(app)
```

### 🤖 **AI-Focused Security (Modern Protection)**
Best for: Applications with complex user patterns, advanced threat detection

```python
aiwaf = AIWAF(app, middlewares=[
    'ai_anomaly',         # Machine learning detection
    'rate_limit',         # Intelligent rate limiting
    'header_validation',  # Advanced header analysis
    'logging'            # ML-enhanced logging
])
```

### 🎯 **Custom Security (Selective Protection)**
Best for: Specific requirements, performance optimization

```python
# Disable specific middlewares you don't need
aiwaf = AIWAF(app, disable_middlewares=[
    'honeypot',          # If no forms in your app
    'uuid_tamper'        # If not using UUIDs
])
```

### Performance Impact Guide

| Middleware | Performance Impact | Use Case |
|------------|-------------------|----------|
| `ip_keyword_block` | **Low** | Essential for all apps |
| `rate_limit` | **Low** | Essential for public apps |
| `logging` | **Medium** | Important for monitoring |
| `header_validation` | **Low** | Good for web APIs |
| `ai_anomaly` | **Medium** | Advanced threat detection |
| `honeypot` | **Low** | Only useful with forms |
| `uuid_tamper` | **Very Low** | Only if using UUIDs |

## Configuration Options

```python
# Rate Limiting
app.config['AIWAF_RATE_WINDOW'] = 60      # Time window in seconds
app.config['AIWAF_RATE_MAX'] = 100        # Max requests per window
app.config['AIWAF_RATE_FLOOD'] = 200      # Auto-block threshold

# Honeypot Protection
app.config['AIWAF_MIN_FORM_TIME'] = 2.0   # Minimum form submission time

# AI Anomaly Detection
app.config['AIWAF_WINDOW_SECONDS'] = 60   # Analysis window for behavior patterns
app.config['AIWAF_DYNAMIC_TOP_N'] = 10    # Top N patterns to track
app.config['AIWAF_MODEL_PATH'] = 'aiwaf_flask/resources/model.pkl'  # ML model path

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

## AI-Powered Anomaly Detection

AIWAF Flask includes advanced **machine learning-based anomaly detection** that analyzes request patterns and automatically identifies malicious behavior.

### How It Works

The AI anomaly detection middleware:

1. **Analyzes Request Patterns**: Tracks path length, keyword hits, response times, status codes, and burst patterns
2. **Uses Machine Learning**: Employs a trained model to detect anomalous behavior (requires NumPy)
3. **Intelligent Blocking**: Only blocks after analyzing multiple indicators to avoid false positives
4. **Dynamic Learning**: Learns new malicious keywords from scanning attempts

### Key Features

- **Multi-factor Analysis**: Combines ML predictions with behavioral analysis
- **Smart Thresholds**: Distinguishes between legitimate 404s and malicious scanning
- **Contextual Learning**: Only learns keywords from confirmed malicious contexts
- **Pattern Recognition**: Detects common attack patterns (SQLi, XSS, directory traversal)

### Configuration

```python
# AI Anomaly Detection Settings
app.config['AIWAF_WINDOW_SECONDS'] = 60       # Analysis window (seconds)
app.config['AIWAF_DYNAMIC_TOP_N'] = 10        # Top patterns to track  
app.config['AIWAF_MODEL_PATH'] = 'path/to/model.pkl'  # ML model location
app.config['AIWAF_MIN_AI_LOGS'] = 10000       # Minimum logs for AI training (NEW)
app.config['AIWAF_FORCE_AI'] = False          # Force AI regardless of data amount (NEW)
app.config['AIWAF_AI_CHECK_INTERVAL'] = 3600  # AI status re-evaluation interval (NEW)

# Install AI dependencies for full functionality
# pip install aiwaf-flask[ai]
# or: pip install numpy>=1.20.0 scikit-learn>=1.0.0
```

**Note**: AI anomaly detection requires NumPy and Scikit-learn. Install with `pip install aiwaf-flask[ai]` for full ML capabilities.

**New in v0.1.8**: 
- AI training automatically disables when there are fewer than 10,000 log entries to prevent poor model performance
- Middleware dynamically re-evaluates AI status during runtime based on current log data
- Use `AIWAF_FORCE_AI=True` to override or adjust `AIWAF_MIN_AI_LOGS` threshold
- **Route-level exemption decorators** - `@aiwaf_exempt`, `@aiwaf_exempt_from()`, `@aiwaf_only()`, and `@aiwaf_require_protection()` for fine-grained middleware control

### Detection Criteria

The AI system analyzes multiple factors before blocking:

- **Keyword Density**: Number of malicious keywords in requests
- **Scanning Patterns**: Attempts to access non-existent admin/config files
- **404 Analysis**: Distinguishes scanning vs. legitimate missing pages
- **Burst Behavior**: Rapid successive requests indicating automation
- **Response Time Patterns**: Unusual timing that may indicate probing

### Examples of Detected Patterns

```python
# These patterns trigger AI analysis:
GET /wp-admin/             # WordPress scanning
GET /phpmyadmin/           # Database admin access attempts
GET /.env                  # Environment file probing
GET /config.php            # Configuration file access
GET /backup.sql            # Backup file attempts
GET /?cmd=whoami           # Command injection attempts
GET /test?union=select     # SQL injection patterns
```

### Intelligent Blocking Logic

The AI doesn't block on single suspicious requests. Instead, it analyzes:

- **Recent behavior** (last 5 minutes)
- **Total vs. scanning 404s**
- **Average keyword hits**
- **Burst patterns**
- **Request volume**

Only blocks when multiple indicators suggest malicious intent, preventing false positives for legitimate users.

### AI Dependencies Troubleshooting

#### **Checking AI Dependencies**

```bash
# Check if AI dependencies are available
python -c "
try:
    import numpy, sklearn
    print('✅ AI dependencies available')
except ImportError as e:
    print(f'❌ Missing: {e}')
    print('Install with: pip install aiwaf-flask[ai]')
"
```

## 📚 Training the AI Model

AIWAF Flask includes a comprehensive training system that replicates Django's functionality, supporting multiple log formats and intelligent learning from thousands of log entries.

### Basic Training

```python
from aiwaf_flask.trainer import train_from_logs

# Train with your Flask app
train_from_logs(app)

# Or disable AI and use keyword learning only
train_from_logs(app, disable_ai=True)
```

### Standalone Training Script

Use the included training script for easy command-line training:

```bash
# Train with AI model (requires AI dependencies)
python train_aiwaf.py --log-dir /path/to/logs

# Train with keyword learning only (no AI dependencies needed)
python train_aiwaf.py --disable-ai --log-dir /path/to/logs

# Verbose output
python train_aiwaf.py --verbose
```

### CLI Training Command

The easiest way to train is using the built-in CLI command:

```bash
# Simple training with AI (auto-detects log format)
aiwaf train

# Train with keyword learning only
aiwaf train --disable-ai

# Train from custom log directory with verbose output
aiwaf train --log-dir /path/to/logs --verbose

# Show training options
aiwaf train --help
```

### Supported Log Formats

The trainer automatically detects and processes multiple log formats:

1. **Apache/Nginx Access Logs** - Standard combined log format
2. **CSV Logs** - With columns: timestamp, ip, method, path, status_code, user_agent, etc.
3. **JSON/JSONL Logs** - Structured log files with request data

### Training Features

The comprehensive training system includes:

- **Smart Keyword Learning**: Learns suspicious patterns from 404s and errors
- **Context-Aware Filtering**: Distinguishes legitimate vs malicious keywords
- **Flask Route Analysis**: Extracts legitimate keywords from your app's routes
- **AI Anomaly Detection**: Machine learning model for behavior analysis
- **Intelligent IP Blocking**: Blocks based on combined indicators
- **Exemption Handling**: Respects IP exemptions and allowed keywords

### Log Processing

The trainer can handle large datasets efficiently:

```python
# Process 1000+ log entries with intelligent filtering
train_from_logs(app)
```

Training analyzes:
- Request patterns and frequencies
- 404 error clustering
- Response time anomalies  
- Burst activity detection
- Keyword context analysis
- Path existence validation

### Configuration

Customize training behavior in your Flask app:

```python
app.config.update({
    'AIWAF_LOG_DIR': 'logs/',
    'AIWAF_DYNAMIC_TOP_N': 15,  # Top keywords to learn
    'AIWAF_AI_CONTAMINATION': 0.05,  # AI sensitivity
    'AIWAF_EXEMPT_KEYWORDS': ['api', 'health'],
    'AIWAF_ALLOWED_PATH_KEYWORDS': ['dashboard', 'profile']
})
```

### Training Output Example

```
🚀 Starting AIWAF Flask enhanced training...
📁 Reading logs from: access.log
📊 Total log lines found: 1247
📋 Parsing 1247 log entries...
✅ Successfully parsed 1205 log entries
🚫 Blocked 3 IPs for excessive 404 errors
🤖 Training AI anomaly detection model...
💾 Model saved: aiwaf_flask/resources/model.pkl
📊 Trained on 1205 samples with scikit-learn v1.3.0
🔍 Detected 7 potentially anomalous IPs
   🚫 203.0.113.10: Blocked for suspicious behavior
📚 Learning suspicious keywords from logs...

============================================================
🤖 AIWAF FLASK ENHANCED TRAINING COMPLETE
============================================================
📊 Training Data: 1205 log entries processed
🤖 AI Model: Trained with 7 features
🚫 AI Blocked IPs: 1 suspicious IPs blocked
📚 Keywords: 5 new suspicious keywords learned
   📝 Keywords: ['xmlrpc', 'wp-config', 'phpmyadmin', 'backup', 'shell']
🛡️  Exemptions: 2 IPs protected from blocking
🚫 404 Blocking: 3 IPs blocked for excessive 404s
✅ Enhanced AI protection now active with context-aware filtering!
============================================================
```

#### **Checking AI Dependencies**

```python
# Check if AI dependencies are available
def check_ai_dependencies():
    try:
        import numpy as np
        import sklearn
        print(f"✅ AI Ready: NumPy {np.__version__}, Scikit-learn {sklearn.__version__}")
        return True
    except ImportError as e:
        print(f"❌ AI Missing: {e}")
        print("Install with: pip install aiwaf-flask[ai]")
        return False

# Use in your application
if check_ai_dependencies():
    # Enable AI middleware
    aiwaf = AIWAF(app, middlewares=['ai_anomaly', 'rate_limit', 'logging'])
else:
    # Fallback to non-AI middlewares
    aiwaf = AIWAF(app, middlewares=['rate_limit', 'ip_keyword_block', 'logging'])
```

#### **Installation Options**

| Installation | Command | Features |
|--------------|---------|----------|
| **Basic** | `pip install aiwaf-flask` | Core security (no AI) |
| **AI Enabled** | `pip install aiwaf-flask[ai]` | Full AI capabilities |
| **Development** | `pip install aiwaf-flask[all]` | AI + testing tools |
| **Manual AI** | `pip install numpy scikit-learn` | Add AI to existing install |

#### **Common Issues**

- **"NumPy not available"** → Install with `pip install aiwaf-flask[ai]`
- **"AI anomaly detection disabled"** → Normal when NumPy is missing
- **Slow startup** → Consider disabling AI: `disable_middlewares=['ai_anomaly']`
- **Memory usage** → AI uses ~50MB for ML models, disable if needed

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

### AI Model Training

```bash
# Train AI model from access logs (auto-detects log format)
aiwaf train

# Train with keyword learning only (no AI dependencies)
aiwaf train --disable-ai

# Train from custom log directory with verbose output
aiwaf train --log-dir /path/to/logs --verbose

# Train with specific options
aiwaf train --log-dir logs --disable-ai --verbose
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

## Dependencies Summary

### Core Dependencies (Always Required)
- **Flask** (`>=2.0.0`) - Web framework
- **Flask-SQLAlchemy** (`>=3.0.0`) - Database ORM (optional for CSV mode)

### AI Dependencies (Optional for Enhanced Security)
- **NumPy** (`>=1.20.0`) - Numerical computations for ML features
- **Scikit-learn** (`>=1.0.0`) - Machine learning model training and prediction

### Installation Matrix

| Feature Set | Command | Dependencies Installed |
|-------------|---------|----------------------|
| **Basic Security** | `pip install aiwaf-flask` | Flask, Flask-SQLAlchemy |
| **AI Enhanced** | `pip install aiwaf-flask[ai]` | Basic + NumPy, Scikit-learn |
| **Development** | `pip install aiwaf-flask[all]` | AI + pytest, coverage tools |

### Middleware Dependency Requirements

| Middleware | Dependencies | Notes |
|------------|-------------|-------|
| `ip_keyword_block` | Core only | Always available |
| `rate_limit` | Core only | Always available |
| `header_validation` | Core only | Always available |
| `honeypot` | Core only | Always available |
| `uuid_tamper` | Core only | Always available |
| `logging` | Core only | Always available |
| **`ai_anomaly`** | **NumPy + Scikit-learn** | **Requires AI dependencies** |

## License
MIT
