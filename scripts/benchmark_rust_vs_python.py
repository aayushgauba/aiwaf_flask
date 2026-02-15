#!/usr/bin/env python3
"""Quick benchmark: Rust vs Python header validation + AI analysis helpers."""

from __future__ import annotations

import argparse
import os
import sys
import time

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


def extract_features_python(records: list[dict], static_keywords: list[str]) -> list[dict]:
    features: list[dict] = []
    for rec in records:
        path_lower = rec.get("path_lower", "")
        kw_check = bool(rec.get("kw_check", True))
        kw_hits = 0
        if kw_check:
            kw_hits = sum(1 for kw in static_keywords if kw in path_lower)
        features.append(
            {
                "ip": rec.get("ip"),
                "path_len": int(rec.get("path_len", 0)),
                "kw_hits": kw_hits,
                "response_time": float(rec.get("response_time", 0.0)),
                "status_idx": int(rec.get("status_idx", -1)),
                "burst_count": 1,
                "total_404": int(rec.get("total_404", 0)),
            }
        )
    return features


def analyze_recent_behavior_python(entries: list[dict], static_keywords: list[str]) -> dict:
    recent_kw_hits = []
    recent_404s = 0
    recent_burst_counts = []
    scanning_404s = 0

    for i, entry in enumerate(entries):
        path_lower = entry.get("path_lower", "")
        timestamp = float(entry.get("timestamp", 0.0))
        status = int(entry.get("status", 0))
        kw_check = bool(entry.get("kw_check", True))

        kw_hits = 0
        if kw_check:
            kw_hits = sum(1 for kw in static_keywords if kw in path_lower)
        recent_kw_hits.append(kw_hits)

        if status == 404:
            recent_404s += 1
            if any(p in path_lower for p in ("wp-admin", "wp-content", "phpmyadmin", ".env", ".git", "xmlrpc", "sql")):
                scanning_404s += 1

        entry_burst = 0
        for j, other in enumerate(entries):
            if i == j:
                continue
            if abs(timestamp - float(other.get("timestamp", 0.0))) <= 10:
                entry_burst += 1
        recent_burst_counts.append(entry_burst)

    avg_kw_hits = sum(recent_kw_hits) / len(recent_kw_hits) if recent_kw_hits else 0.0
    max_404s = recent_404s
    avg_burst = sum(recent_burst_counts) / len(recent_burst_counts) if recent_burst_counts else 0.0
    total_requests = len(entries)
    legitimate_404s = max_404s - scanning_404s

    should_block = not (
        avg_kw_hits < 3
        and scanning_404s < 5
        and legitimate_404s < 20
        and avg_burst < 25
        and total_requests < 150
    )
    if avg_kw_hits == 0 and max_404s == 0:
        should_block = False

    return {
        "avg_kw_hits": avg_kw_hits,
        "max_404s": max_404s,
        "avg_burst": avg_burst,
        "total_requests": total_requests,
        "scanning_404s": scanning_404s,
        "legitimate_404s": legitimate_404s,
        "should_block": should_block,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iters", type=int, default=10000)
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

    static_keywords = ["wp-admin", "sql", "select", "union"]
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
            "timestamp": 1001.0,
            "response_time": 0.2,
            "status_idx": 1,
            "kw_check": False,
            "total_404": 2,
        },
    ]
    entries = [
        {"path_lower": "/wp-admin", "timestamp": 1000.0, "status": 404, "kw_check": True},
        {"path_lower": "/home", "timestamp": 1001.0, "status": 200, "kw_check": False},
    ]

    py_extract_time = bench(lambda: extract_features_python(records, static_keywords), args.iters)
    print(f"Python extract_features:  {args.iters / py_extract_time:.2f} ops/sec")
    py_recent_time = bench(lambda: analyze_recent_behavior_python(entries, static_keywords), args.iters)
    print(f"Python analyze_recent:    {args.iters / py_recent_time:.2f} ops/sec")

    if rust_backend.rust_available():
        rust_extract_time = bench(
            lambda: rust_backend.extract_features(records, static_keywords),
            args.iters,
        )
        print(f"Rust extract_features:    {args.iters / rust_extract_time:.2f} ops/sec")
        rust_recent_time = bench(
            lambda: rust_backend.analyze_recent_behavior(entries, static_keywords),
            args.iters,
        )
        print(f"Rust analyze_recent:      {args.iters / rust_recent_time:.2f} ops/sec")
    else:
        print("Rust analysis helpers:    skipped (aiwaf_rust not available)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
