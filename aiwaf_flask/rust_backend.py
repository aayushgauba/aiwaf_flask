"""Optional Rust acceleration for header validation and log analysis."""

from __future__ import annotations

from typing import Any, Dict, Optional

_rust_module = None
_rust_failed = False

try:
    import aiwaf_rust as _aiwaf_rust  # type: ignore
    _rust_module = _aiwaf_rust
except Exception:
    _rust_module = None


def rust_available() -> bool:
    """Return True if the Rust extension is loaded and healthy."""
    return _rust_module is not None and not _rust_failed


def _mark_rust_failed() -> None:
    global _rust_failed
    _rust_failed = True


def _get_rust_attr(name: str):
    if _rust_module is None or _rust_failed:
        return None
    return getattr(_rust_module, name, None)


def validate_headers(headers: Dict[str, str]) -> Optional[str]:
    """Validate headers using Rust. Returns reason string or None if allowed."""
    func = _get_rust_attr("validate_headers")
    if func is None:
        return None
    try:
        return func(headers)
    except Exception:
        _mark_rust_failed()
        return None


def write_csv_log(csv_file: str, headers: list[str], row: Dict[str, str]) -> bool:
    """Rust CSV logging is deprecated; always use Python fallback."""
    return False


def extract_features(records: list[Dict[str, Any]], static_keywords: list[str]) -> Optional[list[Dict[str, Any]]]:
    """Extract feature dictionaries using Rust. Returns list or None on failure."""
    func = _get_rust_attr("extract_features")
    if func is None:
        return None
    try:
        return func(records, static_keywords)
    except Exception:
        _mark_rust_failed()
        return None


def analyze_recent_behavior(entries: list[Dict[str, Any]], static_keywords: list[str]) -> Optional[Dict[str, Any]]:
    """Analyze recent behavior using Rust. Returns dict or None on failure."""
    func = _get_rust_attr("analyze_recent_behavior")
    if func is None:
        return None
    try:
        return func(entries, static_keywords)
    except Exception:
        _mark_rust_failed()
        return None
