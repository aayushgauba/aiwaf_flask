import os
import tempfile
from pathlib import Path

import pytest

from aiwaf_flask import rust_backend
from aiwaf_flask.header_validation_middleware import validate_headers_python


def test_python_header_validation_blocks_missing():
    environ = {"HTTP_USER_AGENT": "Mozilla/5.0"}
    reason = validate_headers_python(environ)
    assert reason and "Missing required headers" in reason


@pytest.mark.skipif(not rust_backend.rust_available(), reason="Rust extension not available")
def test_rust_validate_headers_blocks_missing():
    environ = {"HTTP_USER_AGENT": "Mozilla/5.0"}
    reason = rust_backend.validate_headers(environ)
    assert reason and "Missing required headers" in reason


@pytest.mark.skipif(not rust_backend.rust_available(), reason="Rust extension not available")
def test_rust_extract_features_basic():
    records = [
        {
            "ip": "1.2.3.4",
            "path_lower": "/wp-admin",
            "path_len": 9,
            "timestamp": 1000.0,
            "response_time": 0.1,
            "status_idx": 0,
            "kw_check": True,
            "total_404": 2,
        },
        {
            "ip": "1.2.3.4",
            "path_lower": "/home",
            "path_len": 5,
            "timestamp": 1005.0,
            "response_time": 0.2,
            "status_idx": 1,
            "kw_check": False,
            "total_404": 2,
        },
    ]
    features = rust_backend.extract_features(records, ["wp-admin", "sql"])
    assert features is not None
    assert len(features) == 2

    first = features[0]
    assert first["ip"] == "1.2.3.4"
    assert first["path_len"] == 9
    assert first["kw_hits"] >= 1
    assert first["burst_count"] >= 1
    assert first["total_404"] == 2

    second = features[1]
    assert second["path_len"] == 5
    assert second["kw_hits"] == 0


@pytest.mark.skipif(not rust_backend.rust_available(), reason="Rust extension not available")
def test_rust_analyze_recent_behavior_basic():
    entries = [
        {"path_lower": "/wp-admin", "timestamp": 1000.0, "status": 404, "kw_check": True},
        {"path_lower": "/wp-content", "timestamp": 1003.0, "status": 404, "kw_check": True},
        {"path_lower": "/home", "timestamp": 1006.0, "status": 200, "kw_check": False},
    ]
    result = rust_backend.analyze_recent_behavior(entries, ["wp-admin", "wp-content", "sql"])
    assert result is not None
    assert result["total_requests"] == 3
    assert result["max_404s"] == 2
    assert result["scanning_404s"] >= 1
    assert isinstance(result["should_block"], bool)


@pytest.mark.skipif(not rust_backend.rust_available(), reason="Rust extension not available")
def test_rust_write_csv_log_deprecated():
    temp_dir = Path(tempfile.mkdtemp(prefix="aiwaf_rust_test_"))
    path = temp_dir / "access.csv"
    headers = ["timestamp", "ip"]
    row = {"timestamp": "t", "ip": "127.0.0.1"}

    ok = rust_backend.write_csv_log(str(path), headers, row)
    assert not ok
    assert not path.exists()

    lock_path = path.with_suffix(".csv.lock")
    if lock_path.exists():
        os.remove(lock_path)
    if path.exists():
        os.remove(path)
    os.rmdir(temp_dir)
