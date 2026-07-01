"""
models.py — Typed data schema for DLP scan findings.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class Finding:
    """Represents a single PII/sensitive-data detection event."""

    timestamp: str        # ISO 8601 UTC string
    file_path: str        # Absolute or relative path to the scanned file
    line_number: int      # 1-based line number of the match
    data_type: str        # Human-readable category, e.g. "Credit Card"
    masked_value: str     # Redacted representation — never the raw match

    @staticmethod
    def now_utc() -> str:
        """Return the current UTC time as an ISO 8601 string."""
        return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    def to_dict(self) -> dict:
        return asdict(self)
