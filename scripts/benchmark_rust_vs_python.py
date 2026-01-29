#!/usr/bin/env python3
"""
Quick benchmark: Rust vs Python header validation + CSV logging.
Run from repo root: python scripts/benchmark_rust_vs_python.py
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aiwaf_flask import rust_backend
from aiwaf_flask.header_validation_middleware import validate_headers_python


def python_validate_headers(headers: dict) -> str | None:
    return validate_headers_python(headers)


def bench(fn, iterations: int) -> float:
    start = time.perf_counter()
    for _ in range(iterations):
        fn()
    end = time.perf_counter()
    return end - start


def _python_csv_write(path: Path, headers: list[str], row: dict) -> None:
    if not path.exists():
        with open(path, "w", newline="", encoding="utf-8") as f:
            f.write(",".join(headers) + "\n")
    with open(path, "a", newline="", encoding="utf-8") as f:
        f.write(",".join(str(row.get(h, "")) for h in headers) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iters", type=int, default=10000)
    parser.add_argument("--csv-iters", type=int, default=1000)
    args = parser.parse_args()

    headers = {
        "HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "HTTP_ACCEPT": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "HTTP_ACCEPT_LANGUAGE": "en-US,en;q=0.5",
        "HTTP_ACCEPT_ENCODING": "gzip, deflate",
        "HTTP_CONNECTION": "keep-alive",
        "SERVER_PROTOCOL": "HTTP/1.1",
    }

    py_time = bench(lambda: python_validate_headers(headers), args.iters)
    print(f"Python header validation: {args.iters / py_time:.2f} ops/sec")

    if rust_backend.rust_available():
        rust_time = bench(lambda: rust_backend.validate_headers(headers), args.iters)
        print(f"Rust header validation:   {args.iters / rust_time:.2f} ops/sec")
    else:
        print("Rust header validation:   skipped (aiwaf_rust not available)")

    # CSV logging benchmark
    tmpdir = tempfile.TemporaryDirectory()
    csv_path = Path(tmpdir.name) / "bench.csv"

    row_headers = [
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
    row = {
        "timestamp": "t",
        "ip": "127.0.0.1",
        "method": "GET",
        "path": "/bench",
        "query_string": "",
        "protocol": "HTTP/1.1",
        "status_code": 200,
        "content_length": 123,
        "response_time_ms": 1,
        "referer": "",
        "user_agent": headers["HTTP_USER_AGENT"],
        "blocked": False,
        "block_reason": "",
    }

    py_csv_time = bench(lambda: _python_csv_write(csv_path, row_headers, row), args.csv_iters)
    print(f"Python CSV logging:       {args.csv_iters / py_csv_time:.2f} ops/sec")

    if rust_backend.rust_available():
        rust_csv_time = bench(
            lambda: rust_backend.write_csv_log(str(csv_path), row_headers, row),
            args.csv_iters,
        )
        print(f"Rust CSV logging:         {args.csv_iters / rust_csv_time:.2f} ops/sec")
    else:
        print("Rust CSV logging:         skipped (aiwaf_rust not available)")

    tmpdir.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
