# AIWAF Flask

AIWAF (AI Web Application Firewall) for Flask provides advanced, self-learning protection for your Flask web applications. It supports IP/keyword blocking, rate limiting, honeypot timing, header validation, anomaly detection, and UUID tampering, with database-backed storage for whitelisted/blacklisted IPs and keywords.

## Features
- IP and keyword blocking
- Rate limiting
- Honeypot timing
- Header validation
- Anomaly detection (stub)
- UUID tampering
- Database-backed whitelist/blacklist/keywords

## Installation

```
pip install flask flask_sqlalchemy
```

## Quick Start

1. **Add AIWAF to your Flask app:**

```python
from flask import Flask
from aiwaf_flask.db_models import db
from aiwaf_flask.middleware import register_aiwaf_middlewares

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///aiwaf.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['AIWAF_RATE_WINDOW'] = 10
app.config['AIWAF_RATE_MAX'] = 20
app.config['AIWAF_RATE_FLOOD'] = 40
app.config['AIWAF_MIN_FORM_TIME'] = 1.0

db.init_app(app)
with app.app_context():
    db.create_all()

register_aiwaf_middlewares(app)
```

2. **Run your app:**

```
python your_app.py
```

3. **Manage whitelist/blacklist/keywords:**

```python
from aiwaf_flask.storage import add_ip_whitelist, add_ip_blacklist, add_keyword

add_ip_whitelist('1.2.3.4')
add_ip_blacklist('5.6.7.8', reason='manual')
add_keyword('malicious')
```

## Endpoints Example

- `/whitelist/<ip>` — Add IP to whitelist
- `/blacklist/<ip>` — Add IP to blacklist
- `/add_keyword/<kw>` — Add keyword to blocklist

## Customization
- Configure rate limits and timing in your Flask config.
- Extend models and middleware for advanced logic.

## License
MIT
