import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from flask import Flask
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