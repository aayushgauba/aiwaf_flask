# AIWAF Flask

AIWAF (AI Web Application Firewall) for Flask provides advanced, self-learning protection for your Flask web applications. It supports IP/keyword blocking, rate limiting, honeypot timing, header validation, anomaly detection, and UUID tampering, with flexible storage options: **database**, **CSV files**, or **in-memory**.

## Features
- IP and keyword blocking
- Rate limiting with burst detection
- Honeypot timing protection
- Header validation
- Anomaly detection (extensible)
- UUID tampering detection
- **Flexible storage**: Database, CSV files, or in-memory
- Zero-dependency protection (works without database)

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
from aiwaf_flask.middleware import register_aiwaf_middlewares

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
from aiwaf_flask.middleware import register_aiwaf_middlewares

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
from aiwaf_flask.middleware import register_aiwaf_middlewares

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
