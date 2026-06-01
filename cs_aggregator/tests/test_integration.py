"""Integration tests using synthetic fixtures from conftest.py.

Tests cover:
  - TLV parsing of realistic config blocks (6-byte BE format)
  - XOR 0x2E detection and decryption
  - OICA magic PE header handling
  - Loader extraction with spoofed magic
  - End-to-end config extraction from synthetic payloads
"""

import struct
import pytest

from cs_aggregator.modules.config_extractor import ConfigExtractor, SETTING_NAMES
from cs_aggregator.modules.loader_extractor import LoaderExtractor
from cs_aggregator.utils.xor_decrypt import (
    TLV_HEADER_SIZE,
    _looks_like_tlv,
    _count_tlv_entries,
    detect_xor_key,
    xor_single_byte,
    KNOWN_SETTING_IDS_4_9,
)
from cs_aggregator.utils.pe_utils import (
    find_pe_offset,
    parse_pe_header,
    extract_section_names,
)


class TestTLVFixtures:
    """Test TLV parsing using synthetic fixtures from conftest.py."""

    def test_sample_config_is_valid_tlv(self, sample_config_tlv: bytes):
        """Verify sample TLV data is recognized as valid."""
        assert _looks_like_tlv(sample_config_tlv, KNOWN_SETTING_IDS_4_9)

    def test_sample_config_entry_count(self, sample_config_tlv: bytes):
        """Verify sample config has expected number of TLV entries."""
        count = _count_tlv_entries(sample_config_tlv, KNOWN_SETTING_IDS_4_9)
        assert count >= 15  # We inserted 17 entries

    def test_sample_config_first_entry(self, sample_config_tlv: bytes):
        """Verify first TLV entry is SETTING_PROTOCOL (ID=1, DataType=SHORT, Length=2)."""
        setting_id = struct.unpack_from(">H", sample_config_tlv, 0)[0]
        data_type = struct.unpack_from(">H", sample_config_tlv, 2)[0]
        length = struct.unpack_from(">H", sample_config_tlv, 4)[0]
        value = struct.unpack_from(">H", sample_config_tlv, 6)[0]

        assert setting_id == 1   # SETTING_PROTOCOL
        assert data_type == 1    # SHORT
        assert length == 2
        assert value == 8        # HTTPS

    def test_sample_config_xor_decrypt(self, sample_config_tlv: bytes, sample_config_encrypted: bytes):
        """Verify XOR 0x2E decryption recovers original TLV data."""
        decrypted = xor_single_byte(sample_config_encrypted, 0x2E)
        assert decrypted == sample_config_tlv

    def test_xor_key_detection(self, sample_config_encrypted: bytes):
        """Verify detect_xor_key finds the correct key."""
        key, decrypted, method = detect_xor_key(sample_config_encrypted)
        assert key is not None
        assert key == bytes([0x2E])
        assert decrypted is not None
        assert _looks_like_tlv(decrypted, KNOWN_SETTING_IDS_4_9)


class TestPEFixtures:
    """Test PE parsing using the OICA-magic synthetic PE fixture."""

    def test_find_pe_offset_in_payload(self, sample_payload: bytes):
        """Verify OICA magic PE is found at correct offset in synthetic payload."""
        offset = find_pe_offset(sample_payload, max_search=0x2000)
        assert offset == 2048  # After 2048-byte loader stub

    def test_parse_pe_header_oica(self, sample_minimal_pe: bytes):
        """Verify PE header parsing works with OICA magic."""
        hdr = parse_pe_header(sample_minimal_pe)
        assert hdr is not None
        assert hdr["machine"] == 0x8664  # AMD64
        assert hdr["num_sections"] == 3
        assert hdr["is_pe32_plus"] is True
        assert hdr["size_of_image"] == 0x50000

    def test_extract_section_names_oica(self, sample_minimal_pe: bytes):
        """Verify section name extraction from OICA PE."""
        names = extract_section_names(sample_minimal_pe)
        assert ".text" in names
        assert ".data" in names
        assert ".reloc" in names

    def test_loader_extractor_finds_oica(self, sample_payload: bytes):
        """Verify LoaderExtractor finds the OICA magic boundary."""
        le = LoaderExtractor()
        result = le.extract_loader(sample_payload)
        # Should find the PE at offset 2048
        assert result.size > 0 or result.metadata.get("extraction_method", "").startswith("pe_header")


class TestConfigExtractorIntegration:
    """Test ConfigExtractor against synthetic payloads."""

    def test_parse_tlv_from_fixture(self, sample_config_tlv: bytes):
        """Verify ConfigExtractor._parse_tlv_entries works on fixture data."""
        ce = ConfigExtractor()
        entries = ce._parse_tlv_entries(sample_config_tlv, KNOWN_SETTING_IDS_4_9)

        assert len(entries) >= 15

        # Verify specific settings
        settings = {e.type: e for e in entries}

        assert 1 in settings   # SETTING_PROTOCOL
        assert settings[1].as_int() == 8  # HTTPS

        assert 2 in settings   # SETTING_PORT
        assert settings[2].as_int() == 443

        assert 3 in settings   # SETTING_SLEEPTIME
        assert settings[3].as_int() == 60000

        assert 5 in settings   # SETTING_JITTER
        assert settings[5].as_int() == 37

        assert 17 in settings  # SETTING_SYSCALL_METHOD
        assert settings[17].as_int() == 2  # indirect

        assert 52 in settings  # SETTING_PROCINJ_ALLOCATOR
        assert settings[52].as_int() == 1  # NtMapViewOfSection

    def test_tlv_to_config(self, sample_config_tlv: bytes):
        """Verify TLV entries convert to correct JSON config dict."""
        ce = ConfigExtractor()
        entries = ce._parse_tlv_entries(sample_config_tlv, KNOWN_SETTING_IDS_4_9)
        config = ce._tlv_to_config(entries)

        assert config["SETTING_PROTOCOL"] == 8
        assert config["SETTING_PORT"] == 443
        assert config["SETTING_SLEEPTIME"] == 60000
        assert config["SETTING_JITTER"] == 37
        assert config["SETTING_SYSCALL_METHOD"] == 2
        assert "auth.winopsupdate.site" in str(config.get("SETTING_DOMAINS", ""))
        assert "dllhost.exe" in str(config.get("SETTING_SPAWNTO_X86", ""))

    def test_coverage_report(self, sample_config_tlv: bytes):
        """Verify coverage report shows found settings."""
        ce = ConfigExtractor()
        entries = ce._parse_tlv_entries(sample_config_tlv, KNOWN_SETTING_IDS_4_9)
        coverage = ce._compute_tlv_coverage(entries, KNOWN_SETTING_IDS_4_9)

        assert coverage["totalEntries"] >= 15
        assert 1 in coverage["settingsFound"]   # SETTING_PROTOCOL
        assert 2 in coverage["settingsFound"]   # SETTING_PORT
        assert "SETTING_PROTOCOL" in coverage["settingNames"].values()
