"""
Indicator validation, classification, and sanitation module.

Strictly validates IP addresses (IPv4 & IPv6) and cryptographic hashes (MD5, SHA-1, SHA-256).
Differentiates public routable IPs from internal/private/reserved ranges to prevent
inadvertent disclosure of internal network topologies to external threat intelligence providers.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Optional, Tuple, Set


class IndicatorType(str, Enum):
    """Supported indicator types."""
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    UNKNOWN = "unknown"


# Strict regex patterns for cryptographic hashes (case-insensitive hexadecimal)
MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")


@dataclass(frozen=True)
class ValidatedIndicator:
    """Represents a sanitized, validated indicator of compromise (IOC)."""
    raw_value: str
    normalized_value: str
    indicator_type: IndicatorType
    is_public: bool = True
    scope_note: Optional[str] = None


def classify_ip_address(ip_str: str) -> Tuple[bool, Optional[IndicatorType], Optional[bool], Optional[str]]:
    """
    Validate and classify an IP address string.

    Returns:
        (is_valid, indicator_type, is_public, scope_note)
    """
    clean_ip = ip_str.strip()
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        return False, None, None, "Invalid IP address syntax"

    itype = IndicatorType.IPV4 if isinstance(ip_obj, ipaddress.IPv4Address) else IndicatorType.IPV6

    # Determine scope
    is_public = True
    scope_notes = []

    if ip_obj.is_private:
        is_public = False
        scope_notes.append("Private network (RFC 1918 / RFC 4193)")
    if ip_obj.is_loopback:
        is_public = False
        scope_notes.append("Loopback address")
    if ip_obj.is_link_local:
        is_public = False
        scope_notes.append("Link-local address")
    if ip_obj.is_multicast:
        is_public = False
        scope_notes.append("Multicast address")
    if ip_obj.is_reserved:
        is_public = False
        scope_notes.append("Reserved address")
    if ip_obj.is_unspecified:
        is_public = False
        scope_notes.append("Unspecified address (0.0.0.0 / ::)")

    # Special IPv4 documentation ranges (e.g. 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
    if isinstance(ip_obj, ipaddress.IPv4Address):
        doc_subnets = [
            ipaddress.IPv4Network("192.0.2.0/24"),
            ipaddress.IPv4Network("198.51.100.0/24"),
            ipaddress.IPv4Network("203.0.113.0/24"),
        ]
        if any(ip_obj in net for net in doc_subnets):
            is_public = False
            scope_notes.append("TEST-NET documentation range (RFC 5737)")

    scope_str = ", ".join(scope_notes) if scope_notes else "Public routable address"
    return True, itype, is_public, scope_str


def classify_hash(hash_str: str) -> Tuple[bool, Optional[IndicatorType], Optional[str]]:
    """
    Validate and classify a cryptographic hash string.

    Returns:
        (is_valid, indicator_type, error_reason)
    """
    clean_hash = hash_str.strip().lower()
    length = len(clean_hash)

    if length == 32:
        if MD5_REGEX.match(clean_hash):
            return True, IndicatorType.MD5, None
        return False, None, "32-character string contains non-hexadecimal characters"
    elif length == 40:
        if SHA1_REGEX.match(clean_hash):
            return True, IndicatorType.SHA1, None
        return False, None, "40-character string contains non-hexadecimal characters"
    elif length == 64:
        if SHA256_REGEX.match(clean_hash):
            return True, IndicatorType.SHA256, None
        return False, None, "64-character string contains non-hexadecimal characters"
    else:
        return False, None, f"Unsupported hash length ({length} chars). Expected MD5 (32), SHA-1 (40), or SHA-256 (64)"


def validate_single_indicator(value: str, allow_private: bool = False) -> ValidatedIndicator:
    """
    Validate a single indicator string (auto-detects IP or hash).

    Raises:
        ValueError: If indicator is malformed or unroutable without allow_private.
    """
    clean_val = value.strip()
    if not clean_val:
        raise ValueError("Indicator string cannot be empty")

    # Try IP classification
    is_ip_valid, ip_type, is_public, scope_note = classify_ip_address(clean_val)
    if is_ip_valid and ip_type is not None:
        if not is_public and not allow_private:
            raise ValueError(
                f"Indicator '{clean_val}' is an internal/non-routable IP ({scope_note}). "
                "Will not query external intelligence providers unless explicitly allowed."
            )
        return ValidatedIndicator(
            raw_value=value,
            normalized_value=clean_val,
            indicator_type=ip_type,
            is_public=bool(is_public),
            scope_note=scope_note,
        )

    # Try Hash classification
    is_hash_valid, hash_type, hash_error = classify_hash(clean_val)
    if is_hash_valid and hash_type is not None:
        return ValidatedIndicator(
            raw_value=value,
            normalized_value=clean_val.lower(),
            indicator_type=hash_type,
            is_public=True,
            scope_note="Cryptographic file hash",
        )

    # Invalid for both
    raise ValueError(f"Indicator '{clean_val}' is neither a valid IP address nor a supported hash (MD5, SHA-1, SHA-256): {hash_error}")


def parse_indicator_file(file_path: Path, allow_private: bool = False) -> Tuple[List[ValidatedIndicator], List[str]]:
    """
    Parse indicators from a line-delimited text file or JSON list.
    Deduplicates indicators while preserving order.

    Returns:
        (valid_indicators, errors)
    """
    if not file_path.exists():
        raise FileNotFoundError(f"Input file not found: {file_path}")
    if not file_path.is_file():
        raise ValueError(f"Path is not a regular file: {file_path}")

    content = file_path.read_text(encoding="utf-8").strip()
    if not content:
        return [], ["File is empty"]

    raw_candidates: List[str] = []

    # Check if content is JSON
    if content.startswith("[") or content.startswith("{"):
        import json
        try:
            data = json.loads(content)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, str):
                        raw_candidates.append(item)
                    elif isinstance(item, dict) and "indicator" in item:
                        raw_candidates.append(str(item["indicator"]))
            elif isinstance(data, dict) and "indicators" in data and isinstance(data["indicators"], list):
                for item in data["indicators"]:
                    if isinstance(item, str):
                        raw_candidates.append(item)
                    elif isinstance(item, dict) and "indicator" in item:
                        raw_candidates.append(str(item["indicator"]))
            else:
                return [], ["JSON must be a list of strings or an object with an 'indicators' list."]
        except json.JSONDecodeError as err:
            return [], [f"Malformed JSON file: {err}"]
    else:
        # Plain text: line delimited
        for line in content.splitlines():
            line_str = line.strip()
            # Skip comments and empty lines
            if line_str and not line_str.startswith("#"):
                raw_candidates.append(line_str)

    valid_results: List[ValidatedIndicator] = []
    errors: List[str] = []
    seen: Set[str] = set()

    for item in raw_candidates:
        cleaned = item.strip()
        if not cleaned:
            continue

        try:
            val_obj = validate_single_indicator(cleaned, allow_private=allow_private)
            dedup_key = f"{val_obj.indicator_type.value}:{val_obj.normalized_value}"
            if dedup_key not in seen:
                seen.add(dedup_key)
                valid_results.append(val_obj)
        except ValueError as exc:
            errors.append(str(exc))

    return valid_results, errors
