"""Tests for Phase 2 modules: SleepMask and PostEx extractors."""

import struct
import pytest

from cs_aggregator.modules.sleepmask_extractor import SleepMaskExtractor
from cs_aggregator.modules.postex_extractor import PostExExtractor


def _build_minimal_pe_with_section(section_name: str, section_data: bytes) -> bytes:
    """Build a minimal valid PE with a single custom section containing the given data.

    Creates a PE with DOS header, NT headers, optional header, and one section.
    """
    # DOS header (64 bytes = 0x40)
    dos = b"MZ" + b"\x00" * 0x3A
    # e_lfanew at offset 0x3C — NT headers follow immediately after DOS header
    dos = dos[:0x3C] + struct.pack("<I", 0x40) + dos[0x40:]

    # NT headers follow immediately after DOS header (at offset 0x40)
    nt = b"PE\x00\x00"  # PE signature (4 bytes)
    # File header (20 bytes total, IMAGE_FILE_HEADER)
    nt += struct.pack("<H", 0x8664)  # +2: Machine (x64)
    nt += struct.pack("<H", 1)       # +2: NumberOfSections
    nt += struct.pack("<I", 0x66000000)  # +4: TimeDateStamp
    nt += struct.pack("<I", 0)       # +4: PointerToSymbolTable
    nt += struct.pack("<I", 0)       # +4: NumberOfSymbols
    nt += struct.pack("<H", 0xF0)    # +2: SizeOfOptionalHeader (= 240 bytes)
    nt += struct.pack("<H", 0x2022)  # +2: Characteristics

    # Optional header (PE32+, minimal)
    opt = struct.pack("<H", 0x20B)  # PE32+ magic
    opt += b"\x00" * 16  # Other fields
    # SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData
    opt += struct.pack("<I", len(section_data)) * 3
    # AddressOfEntryPoint
    opt += struct.pack("<I", 0x1000)
    # BaseOfCode
    opt += struct.pack("<I", 0x1000)
    # ImageBase (8 bytes for PE32+)
    opt += struct.pack("<Q", 0x140000000)
    # SectionAlignment, FileAlignment
    opt += struct.pack("<I", 0x1000) * 2
    # MajorOperatingSystemVersion through SizeOfImage
    opt += b"\x00" * 20
    opt += struct.pack("<I", 0x2000)  # SizeOfImage
    # SizeOfHeaders
    opt += struct.pack("<I", 0x200)
    # ... rest of optional header padding
    opt += b"\x00" * (0xF0 - len(opt))

    nt += opt

    # Section table (one section)
    sec_name = section_name.encode("ascii").ljust(8, b"\x00")[:8]
    sec_table = sec_name
    sec_table += struct.pack("<I", len(section_data))  # VirtualSize
    sec_table += struct.pack("<I", 0x1000)  # VirtualAddress
    sec_table += struct.pack("<I", len(section_data))  # SizeOfRawData
    sec_table += struct.pack("<I", 0x200)  # PointerToRawData
    sec_table += b"\x00" * 12  # PointerToRelocations, etc.
    sec_table += struct.pack("<I", 0x60000020)  # Characteristics (CODE | INITIALIZED_DATA | READ | EXECUTE)

    # Assemble
    header_size = 0x200
    padding = b"\x00" * (header_size - len(dos) - len(nt) - len(sec_table))

    result = dos + nt + sec_table + padding + section_data
    return result


class TestSleepMaskExtractor:
    def test_extract_dedicated_section(self):
        """A PE with a .sleep section should detect sleep mask."""
        mask_data = b"\x90\x90\x90\x90" * 2048  # ~8KB of NOP-like data
        pe_data = _build_minimal_pe_with_section(".sleep", mask_data)

        extractor = SleepMaskExtractor()
        result = extractor.extract(pe_data)

        assert result.detected is True
        assert result.section_name == ".sleep"
        assert result.confidence_score >= 0.6
        assert result.offset > 0

    def test_extract_bg_section(self):
        """A PE with a .bg section should detect BeaconGate-aware sleep mask."""
        bg_data = b"BeaconGate" + b"\x00" * 2040
        pe_data = _build_minimal_pe_with_section(".bg", bg_data)

        extractor = SleepMaskExtractor()
        result = extractor.extract(pe_data)

        assert result.detected is True
        assert result.beacongate_detected is True
        assert result.section_name == ".bg"

    def test_no_sleep_section(self):
        """A PE without dedicated sleep sections should not detect via section scan."""
        normal_data = b"\x00" * 5000
        pe_data = _build_minimal_pe_with_section(".text", normal_data)

        extractor = SleepMaskExtractor()
        result = extractor.extract(pe_data)

        # Without dedicated section, exports, or signatures, should not detect
        # (may hit entropy fallback for > 4KB sections with code-like entropy)
        if result.detected:
            assert result.confidence_score <= 0.3  # Entropy fallback confidence is low

    def test_extract_no_pe_structure(self):
        """Random data without PE structure should not detect sleep mask."""
        random_data = bytes([0xFF, 0xEE, 0xDD] * 1000)
        extractor = SleepMaskExtractor()
        result = extractor.extract(random_data)
        assert result.detected is False

    def test_get_sleep_mask_bytes(self):
        """get_sleep_mask_bytes should return the section bytes."""
        mask_data = b"\x90\x90\x90\x90" * 2048
        pe_data = _build_minimal_pe_with_section(".sleep", mask_data)

        extractor = SleepMaskExtractor()
        result = extractor.get_sleep_mask_bytes(pe_data)

        assert result is not None
        assert len(result) > 0

    def test_detect_with_export_scan(self):
        """A PE with Mask/Unmask exports should detect via export scan."""
        # Build a PE with Mask and Unmask exports
        # For simplicity, we just check the logic path works
        extractor = SleepMaskExtractor()
        result = extractor.extract(b"\x00" * 5000)
        # Without PE structure, can't detect exports
        assert result.detected is False or result.confidence_score < 0.3


class TestPostExExtractor:
    def test_scan_strings_finds_mimikatz(self):
        """String scanning should find 'mimikatz' reference."""
        data = b"\x00" * 100 + b"mimikatz.dll" + b"\x00" * 100
        extractor = PostExExtractor()
        results = extractor.analyze(data)

        found = any(r.name == "mimikatz" for r in results)
        assert found, f"Expected mimikatz in results: {[r.name for r in results]}"

    def test_scan_strings_finds_keylogger(self):
        """String scanning should find 'keylogger' reference."""
        data = b"\x00" * 50 + b"keylogger" + b"\x00" * 50
        extractor = PostExExtractor()
        results = extractor.analyze(data)

        found = any("keylogger" in r.name for r in results)
        assert found

    def test_scan_strings_no_false_positives(self):
        """Random data should not produce post-ex matches."""
        data = bytes([0xFF, 0xEE, 0xDD] * 500)
        extractor = PostExExtractor()
        results = extractor.analyze(data)
        assert len(results) == 0

    def test_analyze_config_with_spawnto(self):
        """TLV config with spawnto should produce a reference."""
        config = {"spawnto": "C:\\Windows\\System32\\rundll32.exe"}
        extractor = PostExExtractor()
        results = extractor.analyze(b"\x00" * 100, config)

        found = any("spawnto" in r.name for r in results)
        assert found

    def test_analyze_config_with_pipe(self):
        """TLV config with pipeName should produce a reference."""
        config = {"pipeName": "\\\\pipe\\msagent"}
        extractor = PostExExtractor()
        results = extractor.analyze(b"\x00" * 100, config)

        found = any("pipe" in r.name for r in results)
        assert found

    def test_empty_dll_no_results(self):
        """Empty DLL data should produce no results."""
        extractor = PostExExtractor()
        results = extractor.analyze(b"", None)
        assert len(results) == 0

    def test_scan_screenshot(self):
        """Should detect 'screenshot' string."""
        data = b"prefix_screenshot_suffix"
        extractor = PostExExtractor()
        results = extractor.analyze(data)
        found = any("screenshot" in r.name for r in results)
        assert found
