import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from flask import Flask
from flask.testing import FlaskClient
from aiwaf_flask.db_models import db

@pytest.fixture
def app():
    """Create and configure a test Flask app."""
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['AIWAF_RATE_WINDOW'] = 10
    app.config['AIWAF_RATE_MAX'] = 20
    app.config['AIWAF_RATE_FLOOD'] = 40
    app.config['AIWAF_MIN_FORM_TIME'] = 1.0
    
    # Force database mode for tests (disable CSV to test database functionality)
    app.config['AIWAF_USE_CSV'] = False
    
    # Disable path exemptions for tests to ensure middleware blocking works
    app.config['AIWAF_EXEMPT_PATHS'] = set()
    
    db.init_app(app)
    
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()

@pytest.fixture
def client(app):
    """Create a test client for the Flask app."""
    return app.test_client()

@pytest.fixture
def app_context(app):
    """Create an application context."""
    with app.app_context():
        yield app


@pytest.fixture(autouse=True)
def _default_header_injection(monkeypatch):
    """Inject browser-like headers so header validation doesn't block tests."""
    default_headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }
    original_open = FlaskClient.open

    def open_with_defaults(self, *args, **kwargs):
        headers = kwargs.pop("headers", {})
        merged = {**default_headers, **headers}
        kwargs["headers"] = merged
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(FlaskClient, "open", open_with_defaults)
    yield
