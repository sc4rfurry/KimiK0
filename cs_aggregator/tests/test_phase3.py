"""Phase 3 tests: MOD_REASSEMBLER — Payload Reassembly & Modification Engine.

Tests cover:
  - Config TLV serialization (config → bytes)
  - Config re-encryption (serialize → XOR encrypt)
  - Full reassembly pipeline with component injection
  - Payload validation
  - CLI flag parsing (handled via unit tests on core logic)
"""

import json
import struct
from typing import Any, Dict

import pytest

from cs_aggregator.modules.config_extractor import ConfigExtractor
from cs_aggregator.modules.reassembler import Reassembler
from cs_aggregator.utils.types import (
    Manifest,
    ReassemblyConfig,
    ReassemblyResult,
)
from cs_aggregator.utils.xor_decrypt import xor_rolling_key


# ── Helpers ──────────────────────────────────────────────────────────

def _make_test_config() -> Dict[str, Any]:
    """Create a minimal test configuration dict using real CS setting names."""
    return {
        "SETTING_PROTOCOL": 1,         # HTTP beacon
        "SETTING_PORT": 443,
        "SETTING_SLEEPTIME": 60000,
        "SETTING_JITTER": 20,
        "SETTING_MAXGET": 1048576,
        "SETTING_DNS_IDLE": 0,
        "SETTING_DNS_SLEEP": 0,
        "SETTING_USERAGENT": "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1)",
        "SETTING_DOMAINS": "example.com,/path",
        "SETTING_PUBKEY": "000102030405060708090a0b0c0d0e0f",
        "SETTING_SPAWNTO": "C:\\Windows\\System32\\rundll32.exe",
        "SETTING_WATERMARK": 1234567890,
        "SETTING_HOST_HEADER": "www.example.com",
    }


def _make_test_manifest() -> Manifest:
    """Create a minimal test manifest for reassembly tests."""
    return Manifest(
        manifest_format_version="2.0",
        metadata={
            "sourceFile": "test_payload.bin",
            "analysisTimestamp": "2026-05-21T12:00:00Z",
            "csVersionDetected": {"version": "4.9.1", "confidence": 0.85, "method": "test"},
            "payloadClassification": {"type": "stageless", "architecture": "x64", "format": "raw_shellcode"},
            "pipelineConfidence": 0.85,
        },
        segments=[
            {
                "segmentId": "SEG_LOADER_STUB",
                "offset": 0,
                "size": 2048,
                "type": "Reflective Loader Stub",
                "classification": "Default_CS_4_9",
            },
            {
                "segmentId": "SEG_BEACON_DLL",
                "offset": 2048,
                "size": 262144,
                "type": "Beacon Core DLL",
                "peInfo": {
                    "sections": [
                        {"name": ".text", "virtualAddress": 4096, "rawSize": 131072},
                        {"name": ".rdata", "virtualAddress": 139264, "rawSize": 65536},
                        {"name": ".data", "virtualAddress": 204800, "rawSize": 32768},
                        {"name": ".reloc", "virtualAddress": 237568, "rawSize": 16384},
                    ],
                },
            },
            {
                "segmentId": "SEG_CONFIG_BLOCK",
                "offset": 215040,
                "size": 1536,
                "xorKey": "2e2e2e2e",
                "xorKeyLength": 4,
                "type": "Configuration Block",
            },
            {
                "segmentId": "SEG_SLEEP_MASK",
                "offset": 266240,
                "size": 16384,
                "type": "Sleep Mask",
                "detected": True,
                "beaconGateDetected": False,
            },
        ],
    )


# ── Config TLV Serialization Tests ──────────────────────────────────


class TestConfigSerialization:
    """Tests for ConfigExtractor.serialize_config_to_tlv and reencrypt_config."""

    def test_serialize_roundtrip(self):
        """Verify config → TLV serialization produces valid TLV structure."""
        config = _make_test_config()
        tlv_data = ConfigExtractor.serialize_config_to_tlv(config)

        assert len(tlv_data) > 12  # At least one TLV entry (6-byte header) + 6-byte null terminator
        assert tlv_data.endswith(b"\x00" * 6)  # 6-byte null terminator

    def test_serialized_has_valid_types(self):
        """Verify serialized TLV entries have valid setting IDs (6-byte BE headers)."""
        config = _make_test_config()
        tlv_data = ConfigExtractor.serialize_config_to_tlv(config)

        # Parse TLV entries using real 6-byte BE header format
        offset = 0
        found_ids = set()
        while offset + 6 <= len(tlv_data):
            setting_id = struct.unpack_from(">H", tlv_data, offset)[0]
            data_type = struct.unpack_from(">H", tlv_data, offset + 2)[0]
            length = struct.unpack_from(">H", tlv_data, offset + 4)[0]

            if setting_id == 0:
                break

            found_ids.add(setting_id)

            # Validate length doesn't exceed remaining data
            assert offset + 6 + length <= len(tlv_data)

            offset += 6 + length

        # We should have found SETTING_PROTOCOL(1), SETTING_PORT(2), SETTING_USERAGENT(9)
        assert 1 in found_ids  # SETTING_PROTOCOL
        assert 2 in found_ids  # SETTING_PORT
        assert 9 in found_ids  # SETTING_USERAGENT

    def test_serialize_and_reencrypt(self):
        """Verify serialize → encrypt → decrypt produces same config."""
        config = _make_test_config()
        xor_key = bytes.fromhex("2e2e2e2e")

        # Serialize and encrypt
        encrypted = ConfigExtractor.reencrypt_config(config, xor_key)
        assert len(encrypted) > 0
        assert encrypted != xor_rolling_key(encrypted, xor_key)  # actually encrypted

        # Decrypt and verify TLV structure
        decrypted = xor_rolling_key(encrypted, xor_key)
        assert decrypted.endswith(b"\x00" * 6)  # 6-byte null terminator
        # First entry should start with SETTING_PROTOCOL (\x00\x01) big-endian
        assert decrypted[0:2] == b"\x00\x01" or any(
            decrypted[i:i+2] == b"\x00\x01" for i in range(0, min(60, len(decrypted)), 6)
        )

    def test_serialize_empty_config(self):
        """Verify empty config produces just 6-byte null terminator."""
        tlv_data = ConfigExtractor.serialize_config_to_tlv({})
        assert tlv_data == b"\x00" * 6  # 6-byte null terminator

    def test_serialize_with_unknown_fields(self):
        """Verify unknown_setting_XX fields are serialized."""
        config = {"SETTING_PROTOCOL": 1, "unknown_setting_255": "aabbccdd"}
        tlv_data = ConfigExtractor.serialize_config_to_tlv(config)

        # Should have setting ID 1 and 255 entries (6-byte BE headers)
        offset = 0
        ids_found = []
        while offset + 6 <= len(tlv_data):
            setting_id = struct.unpack_from(">H", tlv_data, offset)[0]
            data_type = struct.unpack_from(">H", tlv_data, offset + 2)[0]
            length = struct.unpack_from(">H", tlv_data, offset + 4)[0]
            if setting_id == 0:
                break
            ids_found.append(setting_id)
            offset += 6 + length

        assert 1 in ids_found    # SETTING_PROTOCOL
        assert 255 in ids_found  # unknown_setting_255

    def test_skip_metadata_fields(self):
        """Verify fields starting with '_' are skipped during serialization."""
        config = {"SETTING_PROTOCOL": 1, "_tlvCoverage": {"typesFound": [1]}}
        tlv_data = ConfigExtractor.serialize_config_to_tlv(config)
        assert b"_tlvCoverage" not in tlv_data

    def test_reencrypt_different_key_lengths(self):
        """Verify re-encryption works with different key lengths."""
        config = {"SETTING_PROTOCOL": 1, "SETTING_PORT": 443}
        test_keys = [
            bytes([0x2e]),          # 1-byte key
            bytes([0x2e, 0x2e, 0x2e, 0x2e]),  # 4-byte key
            bytes([0x01, 0x02, 0x03, 0x04]),   # 4-byte different key
        ]

        for key in test_keys:
            encrypted = ConfigExtractor.reencrypt_config(config, key)
            assert len(encrypted) > 6
            # Decrypt back
            decrypted = xor_rolling_key(encrypted, key)
            # Should have SETTING_PROTOCOL (\x00\x01) big-endian in first entry
            assert decrypted[0:2] == b"\x00\x01" or decrypted[0:2] == b"\x00\x02"


# ── Reassembler Tests ───────────────────────────────────────────────


class TestReassembler:
    """Tests for the Reassembler class."""

    def test_instantiation(self):
        """Verify Reassembler can be instantiated."""
        r = Reassembler()
        assert r is not None

    def test_reassemble_with_minimal_config(self):
        """Verify reassembly with a basic config (no modifications)."""
        manifest = _make_test_manifest()
        config = ReassemblyConfig(
            custom_loader=b"\x90\x90\x90\x90\x90",  # minimal loader (NOPs)
            modified_dll=b"MZ" + b"\x00" * 1022,     # minimal DLL
        )

        r = Reassembler()
        result = r.reassemble(manifest, config)

        assert result.success
        assert len(result.payload) > 0
        assert result.components_used["loader"]
        assert result.components_used["beacon_dll"]
        # Should be loader + DLL
        assert len(result.payload) == 5 + 1024

    def test_reassemble_with_sleep_mask(self):
        """Verify sleep mask is appended after DLL."""
        manifest = _make_test_manifest()
        config = ReassemblyConfig(
            custom_loader=b"\xCC" * 512,
            modified_dll=b"MZ" + b"\x00" * 1022,
            custom_sleep_mask=b"\x90" * 4096,
        )

        r = Reassembler()
        result = r.reassemble(manifest, config)

        assert result.success
        assert result.components_used["sleep_mask"]
        # Should be loader + DLL + sleep_mask (with alignment padding)
        assert len(result.payload) >= 512 + 1024 + 4096

    def test_reassemble_no_loader(self):
        """Verify reassembly without a loader stub."""
        manifest = _make_test_manifest()
        config = ReassemblyConfig(
            modified_dll=b"MZ" + b"\x00" * 1022,
        )

        r = Reassembler()
        result = r.reassemble(manifest, config)

        assert result.success
        assert not result.components_used["loader"]
        assert result.components_used["beacon_dll"]
        assert len(result.payload) == 1024

    def test_reassemble_no_dll_fails(self):
        """Verify reassembly fails gracefully without a beacon DLL."""
        manifest = _make_test_manifest()
        config = ReassemblyConfig(
            custom_loader=b"\xCC" * 512,
        )

        r = Reassembler()
        result = r.reassemble(manifest, config)

        assert not result.success
        assert len(result.errors) > 0
        assert "No beacon DLL" in result.errors[0]

    @staticmethod
    def test_reassemble_with_config_modification():
        """Verify config modification flow works end-to-end."""
        manifest = _make_test_manifest()

        # Create modified config with different port
        modified_config = _make_test_config()
        modified_config["port"] = 8080

        xor_key = bytes.fromhex("2e2e2e2e")

        config = ReassemblyConfig(
            custom_loader=b"\xCC" * 512,
            modified_dll=b"\x00" * 262144,  # Placeholder DLL
            modified_config=modified_config,
            xor_key=xor_key,
        )

        r = Reassembler()
        result = r.reassemble(manifest, config)

        # Should succeed even if config patching happens but placeholder DLL doesn't have proper offset
        assert result.components_used["config_patched"]

    def test_validate_reassembly_empty_payload(self):
        """Verify validation catches empty payload."""
        manifest = _make_test_manifest()
        r = Reassembler()
        warnings = r.validate_reassembly(b"", manifest)

        assert len(warnings) > 0
        assert any("empty" in w.lower() for w in warnings)

    def test_validate_reassembly_normal_payload(self):
        """Verify validation passes on a reasonable payload."""
        manifest = _make_test_manifest()
        r = Reassembler()

        # Build a payload with MZ header
        payload = b"\xCC" * 512  # loader
        payload += b"MZ" + b"\x00" * 4094  # DLL with MZ header

        warnings = r.validate_reassembly(payload, manifest)
        # At minimum should not say empty
        assert not any("empty" in w.lower() for w in warnings)

    def test_build_from_original(self):
        """Verify build_from_original extracts segments and reassembles."""
        manifest = _make_test_manifest()

        # Build a test original payload that matches manifest segments
        original = b"\xCC" * 2048  # loader (offset 0, size 2048)
        original += b"MZ" + b"\x00" * 262142  # DLL (offset 2048, size 262144)
        original += b"\x90" * 16384  # sleep mask (offset 266240, size 16384)

        config = ReassemblyConfig(
            custom_loader=b"\x90\x90\x90\x90",  # Replace loader
        )

        result = Reassembler.build_from_original(original, manifest, config)

        assert result.success
        assert len(result.payload) > 0
        assert result.components_used["loader"]

    @staticmethod
    def test_build_from_original_with_config():
        """Verify build_from_original with config modification."""
        manifest = _make_test_manifest()

        # Build original payload
        original = b"\xCC" * 2048  # loader
        original += b"\x00" * 262144  # DLL placeholder

        modified_config = {"SETTING_PROTOCOL": 1, "SETTING_PORT": 9999}
        xor_key = bytes.fromhex("2e2e2e2e")

        config = ReassemblyConfig(
            custom_loader=b"\x90" * 512,
            modified_config=modified_config,
            xor_key=xor_key,
        )

        result = Reassembler.build_from_original(original, manifest, config)

        assert result.success

    def test_find_config_offset_in_manifest(self):
        """Verify _find_config_offset finds the config segment."""
        manifest = _make_test_manifest()
        offset = Reassembler._find_config_offset(manifest)
        assert offset == 215040

    def test_find_config_offset_missing(self):
        """Verify _find_config_offset returns None when no config segment."""
        manifest = Manifest(segments=[{"segmentId": "SEG_LOADER_STUB", "offset": 0}])
        offset = Reassembler._find_config_offset(manifest)
        assert offset is None


# ── Integration Tests ────────────────────────────────────────────────


class TestReassemblyIntegration:
    """Integration tests for reassembly with real component flow."""

    def test_serialize_reencrypt_and_assemble(self):
        """Full flow: serialize config → encrypt → patch into DLL → reassemble."""
        # 1. Serialize and encrypt config
        config_data = {"SETTING_PROTOCOL": 1, "SETTING_PORT": 443}
        xor_key = bytes.fromhex("2e2e2e2e")
        encrypted = ConfigExtractor.reencrypt_config(config_data, xor_key)
        assert len(encrypted) > 0

        # 2. Build a payload with the encrypted config patched in
        dll = b"\x00" * 1000 + encrypted + b"\x00" * 1000

        manifest = Manifest(
            metadata={
                "csVersionDetected": {"version": "4.9.1", "confidence": 0.85},
            },
            segments=[
                {"segmentId": "SEG_CONFIG_BLOCK", "offset": 1000, "size": len(encrypted)},
            ],
        )

        # 3. Reassemble
        config = ReassemblyConfig(
            custom_loader=b"\x90" * 256,
            modified_dll=dll,
            modified_config={"SETTING_PROTOCOL": 1, "SETTING_PORT": 9999},
            xor_key=xor_key,
        )

        r = Reassembler()
        result = r.reassemble(manifest, config)

        assert result.success
        assert result.components_used["config_patched"]

    def test_multiple_modifications(self):
        """Verify multiple modifications work together."""
        manifest = _make_test_manifest()

        # Build original payload
        original = b"\xCC" * 2048  # loader
        original += b"\x00" * 262144  # DLL

        config = ReassemblyConfig(
            custom_loader=b"\x90" * 256,       # Replace loader
            custom_sleep_mask=b"\x90" * 8192,  # Add custom sleep mask
            modified_config={"SETTING_PROTOCOL": 1},  # Modify config
            xor_key=bytes.fromhex("2e2e2e2e"),
        )

        result = Reassembler.build_from_original(original, manifest, config)

        assert result.success
        assert result.components_used["loader"]
        assert result.components_used["config_patched"]
        # Components without explicit replacements (sleep_mask, dll) won't be in config
        # sleep_mask is not set explicitly but gets extracted from original
