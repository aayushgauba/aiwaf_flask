from pathlib import Path

import pytest
from flask import Flask

from aiwaf_flask import AIWAF
from aiwaf_flask import rust_backend


def _make_app(tmp_path: Path) -> Flask:
    app = Flask(__name__)
    app.config["AIWAF_ENABLE_LOGGING"] = True
    app.config["AIWAF_LOG_FORMAT"] = "csv"
    app.config["AIWAF_LOG_DIR"] = str(tmp_path)
    app.config["AIWAF_DATA_DIR"] = str(tmp_path)
    app.config["AIWAF_USE_RUST"] = True
    app.config["AIWAF_USE_CSV"] = True

    @app.route("/")
    def index():
        return "ok"

    AIWAF(app)
    return app


def test_header_validation_uses_rust_when_enabled(monkeypatch, tmp_path):
    called = {"value": False}

    def fake_validate(headers):
        called["value"] = True
        return None

    monkeypatch.setattr(rust_backend, "rust_available", lambda: True)
    monkeypatch.setattr(rust_backend, "validate_headers", fake_validate)

    app = _make_app(tmp_path)
    with app.test_client() as client:
        client.get("/", headers={"User-Agent": "Mozilla/5.0", "Accept": "text/html"})

    assert called["value"] is True


def test_header_validation_skips_rust_when_csv_disabled(monkeypatch, tmp_path):
    called = {"value": False}

    def fake_validate(headers):
        called["value"] = True
        return None

    monkeypatch.setattr(rust_backend, "rust_available", lambda: True)
    monkeypatch.setattr(rust_backend, "validate_headers", fake_validate)

    app = _make_app(tmp_path)
    app.config["AIWAF_USE_CSV"] = False
    with app.test_client() as client:
        client.get("/", headers={"User-Agent": "Mozilla/5.0", "Accept": "text/html"})

    assert called["value"] is False
