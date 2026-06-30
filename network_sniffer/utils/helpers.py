"""Reusable helper utilities."""

from __future__ import annotations

import datetime
import socket


def current_time_string() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")


def runtime_string(start_time: datetime.datetime) -> str:
    delta = datetime.datetime.now() - start_time
    seconds = int(delta.total_seconds())
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def human_bytes(size: float) -> str:
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    for unit in units:
        if value < 1024.0:
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} TB"


def safe_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def get_capture_ip() -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 80))
        return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()


def packet_matches_query(record: dict[str, object], query: str) -> bool:
    if not query.strip():
        return True
    haystack = " ".join(
        str(record.get(key, ""))
        for key in ("count", "timestamp", "protocol", "source", "destination", "summary", "details", "preview", "payload_hex")
    ).lower()
    return query.lower() in haystack
