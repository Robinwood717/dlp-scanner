"""
scanner.py — Recursive file traversal and orchestration of the detection engine.

Scans .txt and .csv files under a target directory.
Handles encoding failures gracefully and logs all I/O errors without aborting.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Tuple

from dlp_scanner.detectors import BaseDetector, DEFAULT_DETECTORS
from dlp_scanner.models import Finding

logger = logging.getLogger(__name__)

# Supported file extensions (lowercase)
_TARGET_EXTENSIONS = {".txt", ".csv"}

# Encoding fallback chain: try UTF-8 first, then Latin-1 (covers most Western charsets)
_ENCODINGS = ("utf-8", "latin-1")


class FileScanner:
    """
    Orchestrates recursive directory scanning and PII detection.

    Args:
        target_dir: Root directory to scan recursively.
        detectors:  List of BaseDetector instances to apply to each line.
                    Defaults to DEFAULT_DETECTORS (CC, AFM, Email).
    """

    def __init__(
        self,
        target_dir: Path,
        detectors: List[BaseDetector] | None = None,
    ) -> None:
        self._target_dir = target_dir.resolve()
        self._detectors = detectors if detectors is not None else DEFAULT_DETECTORS
        self._files_scanned = 0
        self._files_skipped = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self) -> List[Finding]:
        """
        Traverse the target directory and return all PII findings.

        Returns:
            Ordered list of Finding objects (sorted by file path then line).
        """
        findings: List[Finding] = []
        for file_path in self._collect_files():
            file_findings = self._scan_file(file_path)
            findings.extend(file_findings)
        return findings

    @property
    def files_scanned(self) -> int:
        return self._files_scanned

    @property
    def files_skipped(self) -> int:
        return self._files_skipped

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _collect_files(self) -> List[Path]:
        """Collect all .txt and .csv files under the target directory."""
        collected: List[Path] = []
        for ext in _TARGET_EXTENSIONS:
            collected.extend(self._target_dir.rglob(f"*{ext}"))
        # Sort for deterministic output order
        return sorted(collected)

    def _read_lines(self, file_path: Path) -> Tuple[List[str], str] | None:
        """
        Read all lines from a file, trying each encoding in _ENCODINGS.

        Returns:
            (lines, encoding_used) on success, or None if all encodings fail
            or a permission/OS error occurs.
        """
        for encoding in _ENCODINGS:
            try:
                lines = file_path.read_text(encoding=encoding).splitlines()
                return lines, encoding
            except UnicodeDecodeError:
                continue
            except PermissionError:
                logger.warning("Permission denied — skipping: %s", file_path)
                return None
            except OSError as exc:
                logger.warning("OS error reading %s: %s", file_path, exc)
                return None
        logger.warning(
            "Unable to decode %s with any known encoding — skipping.", file_path
        )
        return None

    def _scan_file(self, file_path: Path) -> List[Finding]:
        """Run all detectors over every line of a single file."""
        result = self._read_lines(file_path)
        if result is None:
            self._files_skipped += 1
            return []

        lines, encoding = result
        logger.debug("Scanning %s (%s, %d lines)", file_path, encoding, len(lines))
        self._files_scanned += 1

        findings: List[Finding] = []
        timestamp = Finding.now_utc()

        for line_no, line in enumerate(lines, start=1):
            for detector in self._detectors:
                for _raw, masked in detector.find_all(line):
                    findings.append(
                        Finding(
                            timestamp=timestamp,
                            file_path=str(file_path),
                            line_number=line_no,
                            data_type=detector.name,
                            masked_value=masked,
                        )
                    )

        return findings
