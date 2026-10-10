"""Unit tests for indicator validation, classification, and deduplication."""

import pytest
from pathlib import Path
from soc_intel.validators import (
    IndicatorType,
    classify_ip_address,
    classify_hash,
    validate_single_indicator,
    parse_indicator_file,
)


class TestIPValidation:
    """Test IPv4 and IPv6 classification and scoping."""

    def test_valid_public_ipv4(self):
        is_valid, itype, is_public, scope_note = classify_ip_address("8.8.8.8")
        assert is_valid is True
        assert itype == IndicatorType.IPV4
        assert is_public is True
        assert "Public" in scope_note

    def test_valid_public_ipv6(self):
        is_valid, itype, is_public, scope_note = classify_ip_address("2606:4700:4700::1111")
        assert is_valid is True
        assert itype == IndicatorType.IPV6
        assert is_public is True

    def test_private_rfc1918_ipv4(self):
        is_valid, itype, is_public, scope_note = classify_ip_address("192.168.1.100")
        assert is_valid is True
        assert itype == IndicatorType.IPV4
        assert is_public is False
        assert "Private" in scope_note

    def test_loopback_ipv4_and_ipv6(self):
        _, _, is_public_v4, note_v4 = classify_ip_address("127.0.0.1")
        _, _, is_public_v6, note_v6 = classify_ip_address("::1")
        assert is_public_v4 is False
        assert "Loopback" in note_v4
        assert is_public_v6 is False
        assert "Loopback" in note_v6

    def test_documentation_net_ipv4(self):
        # 203.0.113.10 is TEST-NET-3 (RFC 5737)
        is_valid, _, is_public, note = classify_ip_address("203.0.113.10")
        assert is_valid is True
        assert is_public is False
        assert "TEST-NET" in note

    def test_malformed_ip(self):
        is_valid, itype, is_public, note = classify_ip_address("999.999.999.999")
        assert is_valid is False
        assert itype is None


class TestHashValidation:
    """Test cryptographic hash validation and format checks."""

    def test_valid_md5(self):
        is_valid, itype, err = classify_hash("44d88612fea8a8f36de82e1278abb02f")
        assert is_valid is True
        assert itype == IndicatorType.MD5
        assert err is None

    def test_valid_sha1(self):
        is_valid, itype, err = classify_hash("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12")
        assert is_valid is True
        assert itype == IndicatorType.SHA1
        assert err is None

    def test_valid_sha256(self):
        is_valid, itype, err = classify_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert is_valid is True
        assert itype == IndicatorType.SHA256
        assert err is None

    def test_uppercase_hash_normalization(self):
        val = validate_single_indicator("44D88612FEA8A8F36DE82E1278ABB02F")
        assert val.indicator_type == IndicatorType.MD5
        assert val.normalized_value == "44d88612fea8a8f36de82e1278abb02f"

    def test_invalid_hash_non_hex(self):
        is_valid, _, err = classify_hash("zzzd8612fea8a8f36de82e1278abb02f")
        assert is_valid is False
        assert "non-hexadecimal" in err

    def test_invalid_hash_arbitrary_string(self):
        is_valid, _, err = classify_hash("not_a_hash")
        assert is_valid is False
        assert "Unsupported hash length" in err


class TestFileParsingAndDeduplication:
    """Test batch file parsing, deduplication, and error resiliency."""

    def test_private_ip_rejection_by_default(self):
        with pytest.raises(ValueError, match="non-routable/special-purpose IP"):
            validate_single_indicator("10.0.0.1", allow_private=False)

    def test_private_ip_allowed_explicitly(self):
        res = validate_single_indicator("10.0.0.1", allow_private=True)
        assert res.normalized_value == "10.0.0.1"
        assert res.is_public is False

    def test_parse_sample_text_file(self, tmp_path: Path):
        f = tmp_path / "test.txt"
        f.write_text("8.8.8.8\n\n# A comment\n8.8.8.8\n1.1.1.1\ninvalid_indicator\n")
        valid, errors = parse_indicator_file(f)
        assert len(valid) == 2
        assert valid[0].normalized_value == "8.8.8.8"
        assert valid[1].normalized_value == "1.1.1.1"
        assert len(errors) == 1
        assert "invalid_indicator" in errors[0]

    def test_parse_json_file(self, tmp_path: Path):
        f = tmp_path / "test.json"
        f.write_text('["8.8.8.8", {"indicator": "1.1.1.1"}, "8.8.8.8"]')
        valid, errors = parse_indicator_file(f)
        assert len(valid) == 2
        assert len(errors) == 0

    def test_missing_file_raises_not_found(self, tmp_path: Path):
        missing = tmp_path / "non_existent.txt"
        with pytest.raises(FileNotFoundError):
            parse_indicator_file(missing)
