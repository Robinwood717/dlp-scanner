"""
detectors.py — Detection engine for PII and sensitive financial data.

Each detector implements BaseDetector and is responsible for:
  1. Finding regex matches in a line of text.
  2. Validating the match (e.g., Luhn check for credit cards).
  3. Returning a MASKED representation — never the raw value.
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import List, Tuple


# ---------------------------------------------------------------------------
# Base interface
# ---------------------------------------------------------------------------

class BaseDetector(ABC):
    """Abstract base class for all PII/sensitive-data detectors."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable category name used in the report's data_type field."""
        ...

    @abstractmethod
    def find_all(self, line: str) -> List[Tuple[str, str]]:
        """
        Scan a single line and return every confirmed match.

        Returns:
            List of (raw_match, masked_value) tuples.
            The caller must only store masked_value — raw_match is used
            solely for internal validation before being discarded.
        """
        ...


# ---------------------------------------------------------------------------
# Helper: Luhn algorithm
# ---------------------------------------------------------------------------

def _luhn_check(digits_only: str) -> bool:
    """
    Validate a digit string against the Luhn algorithm (ISO/IEC 7812-1).

    Eliminates structurally plausible but arithmetically invalid card numbers,
    dramatically reducing false positives from the regex stage.
    """
    total = 0
    for i, ch in enumerate(reversed(digits_only)):
        n = int(ch)
        # Double every second digit from the right (odd positions in 0-based reverse)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# ---------------------------------------------------------------------------
# Detector 1: Credit Card Numbers
# ---------------------------------------------------------------------------

class CreditCardDetector(BaseDetector):
    """
    Detects major credit/debit card numbers (Visa, Mastercard, Amex, Discover,
    Maestro/Mastercard 2-series) with optional space or dash separators.

    Regex strategy:
      - Strip separators first, then match against pure-digit IIN prefixes.
      - Visa:        starts with 4, 13 or 16 digits.
      - Mastercard:  starts with 51-55 or 2221-2720, 16 digits.
      - Amex:        starts with 34 or 37, 15 digits.
      - Discover:    starts with 6011 / 65 / 644-649, 16 digits.
      - Maestro:     starts with 6304/6759/676[1-3], 12-19 digits.
    After regex match, Luhn validation is applied to reject false positives.
    """

    name = "Credit Card"

    # Matches sequences of digits separated by spaces or dashes (13-19 chars of digits)
    # The outer pattern is intentionally broad; IIN prefix filtering happens via Luhn + prefix check.
    _SEPARATOR_PATTERN = re.compile(
        r'\b(?:\d[ -]?){12,18}\d\b'
    )

    # IIN prefix checks (applied to stripped digit string)
    _VISA_RE         = re.compile(r'^4\d{12}(?:\d{3})?$')
    _MC_RE           = re.compile(r'^(?:5[1-5]\d{14}|2(?:2[2-9][1-9]|[3-6]\d\d|7[01]\d|720)\d{12})$')
    _AMEX_RE         = re.compile(r'^3[47]\d{13}$')
    _DISCOVER_RE     = re.compile(r'^(?:6011|65\d{2}|64[4-9]\d)\d{12}$')
    _MAESTRO_RE      = re.compile(r'^(?:6304|6759|676[1-3])\d{8,15}$')

    _BRAND_PATTERNS  = [_VISA_RE, _MC_RE, _AMEX_RE, _DISCOVER_RE, _MAESTRO_RE]

    def _is_known_brand(self, digits: str) -> bool:
        return any(p.match(digits) for p in self._BRAND_PATTERNS)

    @staticmethod
    def _mask(digits: str) -> str:
        """Reveal only the last 4 digits; mask the rest in groups of 4."""
        last4 = digits[-4:]
        groups = (len(digits) - 4) // 4
        hidden = "-".join(["****"] * groups)
        return f"{hidden}-{last4}"

    def find_all(self, line: str) -> List[Tuple[str, str]]:
        results: List[Tuple[str, str]] = []
        for m in self._SEPARATOR_PATTERN.finditer(line):
            raw = m.group(0)
            digits = re.sub(r'[ -]', '', raw)
            if self._is_known_brand(digits) and _luhn_check(digits):
                results.append((raw, self._mask(digits)))
        return results


# ---------------------------------------------------------------------------
# Detector 2: Greek Tax Identification Number (AFM / ΑΦΜ)
# ---------------------------------------------------------------------------

class GreekAFMDetector(BaseDetector):
    """
    Detects Greek Tax Identification Numbers (Αριθμός Φορολογικού Μητρώου).

    Format: exactly 9 digits, first digit non-zero, isolated by word boundaries.
    The 9th digit is a check digit computed via a weighted modulo algorithm,
    which is validated here to reduce false positives from plain 9-digit numbers.

    Regex: \\b[1-9][0-9]{8}\\b
    """

    name = "Greek AFM"

    _PATTERN = re.compile(r'\b([1-9][0-9]{8})\b')

    @staticmethod
    def _afm_check(digits: str) -> bool:
        """
        Validate an AFM using GSIS's published weighted-sum algorithm.
        Weights for digits 1-8 are powers of 2 (128, 64, 32, 16, 8, 4, 2, 1).
        The sum mod 11 mod 10 must equal the 9th (check) digit.
        """
        weights = [128, 64, 32, 16, 8, 4, 2, 1]
        total = sum(int(digits[i]) * weights[i] for i in range(8))
        return (total % 11) % 10 == int(digits[8])

    @staticmethod
    def _mask(digits: str) -> str:
        """Reveal last 3 digits; mask the first 6 with X."""
        return f"XXXXXX{digits[-3:]}"

    def find_all(self, line: str) -> List[Tuple[str, str]]:
        results: List[Tuple[str, str]] = []
        for m in self._PATTERN.finditer(line):
            raw = m.group(0)
            if self._afm_check(raw):
                results.append((raw, self._mask(raw)))
        return results


# ---------------------------------------------------------------------------
# Detector 3: Email Addresses
# ---------------------------------------------------------------------------

class EmailDetector(BaseDetector):
    """
    Detects email addresses using a practical RFC 5322–compliant subset.

    Pattern breakdown:
      Local part:  [a-zA-Z0-9._%+\\-]+   (alphanumeric + safe special chars)
      @
      Domain:      [a-zA-Z0-9.\\-]+       (subdomains allowed)
      TLD:         \\.[a-zA-Z]{2,}        (at least 2-char TLD)

    Word boundaries ensure we don't match partial addresses embedded in URLs
    or other strings.
    """

    name = "Email"

    _PATTERN = re.compile(
        r'\b([a-zA-Z0-9._%+\-]+)@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b'
    )

    @staticmethod
    def _mask(local: str, domain: str) -> str:
        """Mask the local part; preserve the domain for triage context."""
        return f"****@{domain}"

    def find_all(self, line: str) -> List[Tuple[str, str]]:
        results: List[Tuple[str, str]] = []
        for m in self._PATTERN.finditer(line):
            raw = m.group(0)
            local, domain = m.group(1), m.group(2)
            results.append((raw, self._mask(local, domain)))
        return results


# ---------------------------------------------------------------------------
# Default detector set (imported by scanner)
# ---------------------------------------------------------------------------

DEFAULT_DETECTORS: List[BaseDetector] = [
    CreditCardDetector(),
    GreekAFMDetector(),
    EmailDetector(),
]
