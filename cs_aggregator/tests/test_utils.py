"""Tests for utility modules."""

import struct

import pytest

from cs_aggregator.utils.entropy import shannon_entropy, rolling_entropy
from cs_aggregator.utils.hashing import compute_hashes
from cs_aggregator.utils.xor_decrypt import (
    xor_single_byte,
    xor_rolling_4byte,
    brute_force_xor_single_byte,
    detect_xor_key,
)


class TestEntropy:
    def test_shannon_entropy_uniform(self):
        """All same bytes = 0.0 entropy."""
        data = b"\x00" * 1024
        assert shannon_entropy(data) == 0.0

    def test_shannon_entropy_random(self):
        """Random data should have high entropy."""
        data = bytes(range(256)) * 4  # 1024 bytes, all 256 values
        entropy = shannon_entropy(data)
        assert 7.5 <= entropy <= 8.0

    def test_shannon_entropy_empty(self):
        """Empty data = 0.0 entropy."""
        assert shannon_entropy(b"") == 0.0

    def test_rolling_entropy(self):
        """Rolling entropy should return expected number of windows."""
        data = b"\x00" * 1024
        windows = rolling_entropy(data, window_size=256, step=256)
        assert len(windows) == 4
        for _, ent in windows:
            assert ent == 0.0


class TestHashing:
    def test_compute_hashes(self):
        """Hashes should be deterministic and correct."""
        data = b"hello world"
        hashes = compute_hashes(data)
        assert hashes["sha256"] == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        assert isinstance(hashes["md5"], str)
        assert isinstance(hashes["sha1"], str)

    def test_compute_hashes_empty(self):
        """Empty data should still produce valid hashes."""
        hashes = compute_hashes(b"")
        assert len(hashes["sha256"]) == 64


class TestXorDecrypt:
    def test_xor_single_byte(self):
        """XOR with single byte key should be reversible."""
        original = b"test data 1234"
        key = 0x2E
        encrypted = xor_single_byte(original, key)
        decrypted = xor_single_byte(encrypted, key)
        assert decrypted == original

    def test_xor_rolling_4byte(self):
        """XOR with 4-byte rolling key should be reversible."""
        original = b"test data for rolling key xor"
        key = b"\x2e\x2e\x2e\x2e"
        encrypted = xor_rolling_4byte(original, key)
        decrypted = xor_rolling_4byte(encrypted, key)
        assert decrypted == original

    def test_xor_rolling_4byte_wrong_length(self):
        """Should raise on non-4-byte key."""
        with pytest.raises(ValueError):
            xor_rolling_4byte(b"test", b"\x2e\x2e")

    def test_brute_force_single_byte(self):
        """Brute force should find the correct XOR key for TLV-structured data."""
        # Build data using real CS TLV format (6-byte big-endian headers):
        # [SettingID:2 BE][DataType:2 BE][Length:2 BE][Value:N bytes]
        tlv_data = (
            # SETTING_PROTOCOL=1, DataType=SHORT=1, Length=2, Value=8 (HTTPS)
            struct.pack(">HHH", 1, 1, 2) + struct.pack(">H", 8) +
            # SETTING_PORT=2, DataType=SHORT=1, Length=2, Value=443
            struct.pack(">HHH", 2, 1, 2) + struct.pack(">H", 443) +
            # SETTING_SLEEPTIME=3, DataType=INT=2, Length=4, Value=60000
            struct.pack(">HHH", 3, 2, 4) + struct.pack(">I", 60000)
        )
        key = 0x2E
        encrypted = xor_single_byte(tlv_data, key)

        results = brute_force_xor_single_byte(encrypted)
        assert len(results) > 0, "Brute force should find at least one key for TLV data"
        found_keys = [k for k, _ in results]
        assert key in found_keys, f"Key 0x{key:02x} should be in results: {found_keys}"

    def test_detect_xor_key_returns_none_for_random(self):
        """detect_xor_key should return None for non-TLV data."""
        random_data = bytes([0xFF, 0xEE, 0xDD, 0xCC] * 64)
        key, decrypted, method = detect_xor_key(random_data)
        assert key is None
        assert decrypted is None
        assert method == "failed"
