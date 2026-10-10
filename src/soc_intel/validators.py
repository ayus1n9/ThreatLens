"""
Indicator validation, classification, and sanitation module.

Strictly validates IP addresses (IPv4 & IPv6) and cryptographic hashes (MD5, SHA-1, SHA-256).
Enforces global routability standards across all RFC special-purpose registers
(RFC 1918, RFC 6598 Carrier-Grade NAT / Shared Address space, RFC 3927 link-local,
RFC 5737 documentation, RFC 3849 IPv6 documentation, RFC 4193 unique local, etc.)
to prevent inadvertent disclosure of internal network topologies to external threat intelligence providers.
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

# Comprehensive non-global IPv4 subnets (RFC 6890 / IANA Special-Purpose Address Registry)
SPECIAL_IPV4_NETWORKS = [
    (ipaddress.IPv4Network("0.0.0.0/8"), "Current network / 'this host' (RFC 1122)"),
    (ipaddress.IPv4Network("10.0.0.0/8"), "Private network (RFC 1918)"),
    (ipaddress.IPv4Network("100.64.0.0/10"), "Shared Address Space / CGNAT (RFC 6598)"),
    (ipaddress.IPv4Network("127.0.0.0/8"), "Loopback network (RFC 1122)"),
    (ipaddress.IPv4Network("169.254.0.0/16"), "Link-local address (RFC 3927)"),
    (ipaddress.IPv4Network("172.16.0.0/12"), "Private network (RFC 1918)"),
    (ipaddress.IPv4Network("192.0.0.0/24"), "IETF Protocol Assignments (RFC 6890)"),
    (ipaddress.IPv4Network("192.0.2.0/24"), "TEST-NET-1 documentation (RFC 5737)"),
    (ipaddress.IPv4Network("192.88.99.0/24"), "6to4 Relay Anycast (RFC 7526)"),
    (ipaddress.IPv4Network("192.168.0.0/16"), "Private network (RFC 1918)"),
    (ipaddress.IPv4Network("198.18.0.0/15"), "Benchmarking (RFC 2544)"),
    (ipaddress.IPv4Network("198.51.100.0/24"), "TEST-NET-2 documentation (RFC 5737)"),
    (ipaddress.IPv4Network("203.0.113.0/24"), "TEST-NET-3 documentation (RFC 5737)"),
    (ipaddress.IPv4Network("224.0.0.0/4"), "Multicast (RFC 5771)"),
    (ipaddress.IPv4Network("240.0.0.0/4"), "Reserved for future use (RFC 1112)"),
    (ipaddress.IPv4Network("255.255.255.255/32"), "Limited Broadcast (RFC 919)"),
]

# Comprehensive non-global IPv6 subnets (RFC 6890 / IANA Special-Purpose Address Registry)
SPECIAL_IPV6_NETWORKS = [
    (ipaddress.IPv6Network("::1/128"), "Loopback address (RFC 4291)"),
    (ipaddress.IPv6Network("::/128"), "Unspecified address (RFC 4291)"),
    (ipaddress.IPv6Network("::ffff:0:0/96"), "IPv4-mapped address (RFC 4291)"),
    (ipaddress.IPv6Network("64:ff9b::/96"), "IPv4-IPv6 Translation (RFC 6052)"),
    (ipaddress.IPv6Network("100::/64"), "Discard-Only Address Block (RFC 6666)"),
    (ipaddress.IPv6Network("2001::/23"), "IETF Protocol Assignments (RFC 2928)"),
    (ipaddress.IPv6Network("2001:db8::/32"), "Documentation prefix (RFC 3849)"),
    (ipaddress.IPv6Network("2002::/16"), "6to4 prefix (RFC 3056)"),
    (ipaddress.IPv6Network("fc00::/7"), "Unique Local Address (ULA) (RFC 4193)"),
    (ipaddress.IPv6Network("fe80::/10"), "Link-Local Unicast (RFC 4291)"),
    (ipaddress.IPv6Network("ff00::/8"), "Multicast (RFC 4291)"),
]


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
    Validate and classify an IP address string against global routability standards.

    Returns:
        (is_valid, indicator_type, is_public, scope_note)
    """
    clean_ip = ip_str.strip()
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        return False, None, None, "Invalid IP address syntax"

    is_v4 = isinstance(ip_obj, ipaddress.IPv4Address)
    itype = IndicatorType.IPV4 if is_v4 else IndicatorType.IPV6

    # 1. Primary check: Python ipaddress is_global attribute
    # Note: is_global handles private, loopback, link_local, multicast, reserved
    is_globally_routable = getattr(ip_obj, "is_global", False)

    # 2. Secondary explicit sweep against special registers (e.g. CGNAT, doc ranges, IPv4-mapped)
    reasons = []
    if is_v4:
        for net, desc in SPECIAL_IPV4_NETWORKS:
            if ip_obj in net:
                is_globally_routable = False
                reasons.append(desc)
                break
    else:
        for net, desc in SPECIAL_IPV6_NETWORKS:
            if ip_obj in net:
                is_globally_routable = False
                reasons.append(desc)
                break

    # If is_global was False but not caught in the list (e.g., standard is_private or loopback)
    if not is_globally_routable and not reasons:
        if ip_obj.is_private:
            reasons.append("Private network (RFC 1918 / RFC 4193)")
        elif ip_obj.is_loopback:
            reasons.append("Loopback address")
        elif ip_obj.is_link_local:
            reasons.append("Link-local address")
        elif ip_obj.is_multicast:
            reasons.append("Multicast address")
        elif ip_obj.is_reserved:
            reasons.append("Reserved address")
        else:
            reasons.append("Non-globally routable special-purpose address")

    if is_globally_routable:
        return True, itype, True, "Public globally routable address"
    else:
        return True, itype, False, ", ".join(reasons)


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
                f"Indicator '{clean_val}' is a non-routable/special-purpose IP ({scope_note}). "
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

    try:
        content = file_path.read_text(encoding="utf-8").strip()
    except (PermissionError, OSError) as err:
        raise OSError(f"Cannot read input file '{file_path}': {err}") from err

    if not content:
        return [], ["File is empty"]

    raw_candidates: List[str] = []

    # Check if content is JSON
    if content.startswith("[") or content.startswith("{"):
        import json
        try:
            data = json.loads(content)
            if isinstance(data, list):
                for idx, item in enumerate(data):
                    if isinstance(item, str):
                        raw_candidates.append(item)
                    elif isinstance(item, dict) and "indicator" in item:
                        if isinstance(item["indicator"], (str, int)):
                            raw_candidates.append(str(item["indicator"]))
                        else:
                            return [], [f"JSON item at index {idx} has invalid 'indicator' value type."]
                    else:
                        return [], [f"JSON list contains invalid element type at index {idx}: expected string or object with 'indicator' key."]
            elif isinstance(data, dict) and "indicators" in data and isinstance(data["indicators"], list):
                for idx, item in enumerate(data["indicators"]):
                    if isinstance(item, str):
                        raw_candidates.append(item)
                    elif isinstance(item, dict) and "indicator" in item:
                        if isinstance(item["indicator"], (str, int)):
                            raw_candidates.append(str(item["indicator"]))
                        else:
                            return [], [f"JSON 'indicators' item at index {idx} has invalid 'indicator' value type."]
                    else:
                        return [], [f"JSON 'indicators' list contains invalid element type at index {idx}."]
            else:
                return [], ["JSON must be a list of strings/objects or an object containing an 'indicators' list."]
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
