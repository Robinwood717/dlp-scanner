"""
reporter.py — Audit report generation in JSON and CSV formats.

Security note: findings contain only masked_value; raw PII is never written.
"""
from __future__ import annotations

import csv
import json
import logging
from collections import Counter
from pathlib import Path
from typing import List

from dlp_scanner.models import Finding

logger = logging.getLogger(__name__)

# Field order for CSV header
_CSV_FIELDS = ["timestamp", "file_path", "line_number", "data_type", "masked_value"]


class Reporter:
    """Serialises a list of Finding objects to JSON or CSV audit reports."""

    def export_json(self, findings: List[Finding], output_path: Path) -> None:
        """Write findings as a pretty-printed JSON array."""
        payload = [f.to_dict() for f in findings]
        output_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info("JSON report written: %s", output_path)

    def export_csv(self, findings: List[Finding], output_path: Path) -> None:
        """Write findings as a RFC 4180 CSV file with a header row."""
        with output_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=_CSV_FIELDS)
            writer.writeheader()
            for f in findings:
                writer.writerow(f.to_dict())
        logger.info("CSV report written: %s", output_path)

    def print_summary(
        self,
        findings: List[Finding],
        files_scanned: int,
        files_skipped: int,
    ) -> None:
        """Print a human-readable summary to stdout."""
        total = len(findings)
        by_type = Counter(f.data_type for f in findings)

        print("\n" + "=" * 60)
        print("  DLP SCAN SUMMARY")
        print("=" * 60)
        print(f"  Files scanned : {files_scanned}")
        print(f"  Files skipped : {files_skipped}")
        print(f"  Total findings: {total}")
        if by_type:
            print("\n  Breakdown by data type:")
            for dtype, count in sorted(by_type.items()):
                print(f"    {dtype:<20} {count}")
        else:
            print("\n  No sensitive data detected.")
        print("=" * 60 + "\n")
