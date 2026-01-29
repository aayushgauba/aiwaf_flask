"""Benchmark Rust vs Python for header validation and CSV logging."""

from __future__ import annotations

import csv
import os
import tempfile
import time
from pathlib import Path

from aiwaf_flask import rust_backend
from aiwaf_flask.header_validation_middleware import validate_headers_python


SAMPLE_ENVIRON = {
    "HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "HTTP_ACCEPT": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "HTTP_ACCEPT_LANGUAGE": "en-US,en;q=0.5",
    "HTTP_ACCEPT_ENCODING": "gzip, deflate",
    "HTTP_CONNECTION": "keep-alive",
    "SERVER_PROTOCOL": "HTTP/1.1",
}

CSV_HEADERS = [
    "timestamp",
    "ip",
    "method",
    "path",
    "query_string",
    "protocol",
    "status_code",
    "content_length",
    "response_time_ms",
    "referer",
    "user_agent",
    "blocked",
    "block_reason",
]


def _python_csv_write(path: Path, headers: list[str], row: dict) -> None:
    if not path.exists():
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([row.get(key, "") for key in headers])


def _benchmark(name, fn, iterations: int) -> float:
    start = time.perf_counter()
    for _ in range(iterations):
        fn()
    elapsed = time.perf_counter() - start
    ops = iterations / elapsed if elapsed > 0 else 0.0
    print(f"{name}: {ops:,.0f} ops/sec ({iterations} iters, {elapsed:.3f}s)")
    return ops


def benchmark_header_validation(iterations: int) -> None:
    print("Header validation")
    _benchmark("Python", lambda: validate_headers_python(SAMPLE_ENVIRON), iterations)
    if rust_backend.rust_available():
        _benchmark("Rust", lambda: rust_backend.validate_headers(SAMPLE_ENVIRON), iterations)
    else:
        print("Rust: unavailable")


def benchmark_csv_logging(iterations: int) -> None:
    print("CSV logging")
    row = {
        "timestamp": "t",
        "ip": "127.0.0.1",
        "method": "GET",
        "path": "/",
        "query_string": "",
        "protocol": "HTTP/1.1",
        "status_code": 200,
        "content_length": 123,
        "response_time_ms": 10,
        "referer": "",
        "user_agent": "Mozilla/5.0",
        "blocked": False,
        "block_reason": "",
    }

    temp_dir = Path(tempfile.mkdtemp(prefix="aiwaf_bench_"))
    py_path = temp_dir / "py.csv"
    rs_path = temp_dir / "rs.csv"

    _benchmark("Python", lambda: _python_csv_write(py_path, CSV_HEADERS, row), iterations)
    if rust_backend.rust_available():
        _benchmark("Rust", lambda: rust_backend.write_csv_log(str(rs_path), CSV_HEADERS, row), iterations)
    else:
        print("Rust: unavailable")

    for p in [py_path, rs_path, rs_path.with_suffix(".csv.lock")]:
        if p.exists():
            try:
                os.remove(p)
            except OSError:
                pass
    try:
        os.rmdir(temp_dir)
    except OSError:
        pass


if __name__ == "__main__":
    iterations = 10000
    benchmark_header_validation(iterations)
    print()
    benchmark_csv_logging(iterations)
