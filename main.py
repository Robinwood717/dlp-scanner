"""
main.py — CLI entry point for the DLP Scanner / Auditor.

Usage:
    python main.py --target <directory> --format [json|csv|both] --output <base_name>

Examples:
    python main.py --target sample_data --format both --output dlp_report
    python main.py --target C:/Users/data --format json
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from dlp_scanner.detectors import DEFAULT_DETECTORS
from dlp_scanner.reporter import Reporter
from dlp_scanner.scanner import FileScanner


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dlp_scanner",
        description=(
            "Data Loss Prevention (DLP) Scanner — detects PII and sensitive "
            "financial data in .txt/.csv files and generates masked audit reports."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--target",
        type=Path,
        default=Path("."),
        metavar="DIR",
        help="Directory to scan recursively (default: current directory).",
    )
    parser.add_argument(
        "--format",
        choices=["json", "csv", "both"],
        default="json",
        help="Output report format (default: json).",
    )
    parser.add_argument(
        "--output",
        default="dlp_report",
        metavar="BASENAME",
        help="Base name for the report file(s), without extension (default: dlp_report).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug-level logging.",
    )
    return parser


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def main() -> int:
    parser = _build_arg_parser()
    args = parser.parse_args()
    _configure_logging(args.verbose)

    target: Path = args.target
    if not target.exists():
        print(f"ERROR: Target directory does not exist: {target}", file=sys.stderr)
        return 1
    if not target.is_dir():
        print(f"ERROR: Target is not a directory: {target}", file=sys.stderr)
        return 1

    print(f"[DLP Scanner] Starting scan on: {target.resolve()}")
    print(f"[DLP Scanner] Active detectors: {[d.name for d in DEFAULT_DETECTORS]}")

    scanner = FileScanner(target_dir=target, detectors=DEFAULT_DETECTORS)
    findings = scanner.scan()

    reporter = Reporter()
    reporter.print_summary(
        findings,
        files_scanned=scanner.files_scanned,
        files_skipped=scanner.files_skipped,
    )

    if not findings:
        print("[DLP Scanner] No findings — no report file generated.")
        return 0

    output_base = Path(args.output)
    fmt: str = args.format

    if fmt in ("json", "both"):
        reporter.export_json(findings, output_base.with_suffix(".json"))
        print(f"[DLP Scanner] Report: {output_base.with_suffix('.json')}")

    if fmt in ("csv", "both"):
        reporter.export_csv(findings, output_base.with_suffix(".csv"))
        print(f"[DLP Scanner] Report: {output_base.with_suffix('.csv')}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
