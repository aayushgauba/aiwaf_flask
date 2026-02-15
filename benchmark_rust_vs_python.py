"""Benchmark Rust vs Python for header validation and AI analysis helpers."""

from __future__ import annotations

import time

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

STATIC_KEYWORDS = ["wp-admin", "sql", "select", "union"]


def _benchmark(name, fn, iterations: int) -> float:
    start = time.perf_counter()
    for _ in range(iterations):
        fn()
    elapsed = time.perf_counter() - start
    ops = iterations / elapsed if elapsed > 0 else 0.0
    print(f"{name}: {ops:,.0f} ops/sec ({iterations} iters, {elapsed:.3f}s)")
    return ops


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


def benchmark_header_validation(iterations: int) -> None:
    print("Header validation")
    _benchmark("Python", lambda: validate_headers_python(SAMPLE_ENVIRON), iterations)
    if rust_backend.rust_available():
        _benchmark("Rust", lambda: rust_backend.validate_headers(SAMPLE_ENVIRON), iterations)
    else:
        print("Rust: unavailable")


def benchmark_analysis_helpers(iterations: int) -> None:
    print("AI analysis helpers")
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

    _benchmark("Python extract_features", lambda: extract_features_python(records, STATIC_KEYWORDS), iterations)
    _benchmark(
        "Python analyze_recent",
        lambda: analyze_recent_behavior_python(entries, STATIC_KEYWORDS),
        iterations,
    )
    if rust_backend.rust_available():
        _benchmark("Rust extract_features", lambda: rust_backend.extract_features(records, STATIC_KEYWORDS), iterations)
        _benchmark(
            "Rust analyze_recent",
            lambda: rust_backend.analyze_recent_behavior(entries, STATIC_KEYWORDS),
            iterations,
        )
    else:
        print("Rust: unavailable")


if __name__ == "__main__":
    iterations = 10000
    benchmark_header_validation(iterations)
    print()
    benchmark_analysis_helpers(iterations)
