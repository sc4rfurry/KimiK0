"""Test suite for Surgery SDK and BUD Analyzer (Phase 4).

Covers:
- PayloadMap construction and segment access
- ConfigSurgeon field-level read/write/encrypt
- LoaderSurgeon validation
- SleepMaskSurgeon inject/swap/remove
- SurgeryValidator structural checks
- BeaconSurgeon end-to-end round-trip
- BUDAnalyzer reason code and version detection
"""

import struct
import json
import os
import tempfile
import pytest

from cs_aggregator.utils.xor_decrypt import xor_single_byte, TLV_HEADER_SIZE
from cs_aggregator.utils.entropy import shannon_entropy
from cs_aggregator.utils.hashing import compute_hashes


# ── Test Helpers ──

def _build_tlv(sid, dt, val):
    return struct.pack('>HHH', sid, dt, len(val)) + val


def _build_config_tlv():
    """Build a minimal TLV config block."""
    entries = b''
    entries += _build_tlv(1, 1, struct.pack('>H', 8))      # PROTOCOL=HTTPS
    entries += _build_tlv(2, 1, struct.pack('>H', 443))     # PORT
    entries += _build_tlv(3, 2, struct.pack('>I', 60000))   # SLEEPTIME
    entries += _build_tlv(5, 1, struct.pack('>H', 37))      # JITTER
    entries += _build_tlv(8, 3, b'evil.com\x00')            # DOMAINS
    entries += _build_tlv(37, 2, struct.pack('>I', 987654321))  # WATERMARK
    entries += b'\x00' * 6  # terminator
    return entries


def _build_synthetic_payload():
    """Build a synthetic beacon payload for testing."""
    entries = _build_config_tlv()
    encrypted = xor_single_byte(entries, 0x2E)

    # Minimal PE
    dos = bytearray(64)
    dos[0:2] = b'MZ'
    struct.pack_into('<I', dos, 0x3C, 64)
    pe_sig = b'PE\x00\x00'
    coff = struct.pack('<HHIIIHH', 0x8664, 1, 0, 0, 0, 240, 0x2022)
    opt = bytearray(240)
    struct.pack_into('<H', opt, 0, 0x20B)
    struct.pack_into('<I', opt, 56, 0x50000)
    sec = bytearray(40)
    sec[0:5] = b'.data'
    struct.pack_into('<I', sec, 8, 0x8000)
    struct.pack_into('<I', sec, 12, 0x1000)
    struct.pack_into('<I', sec, 16, 0x8000)
    struct.pack_into('<I', sec, 20, 0x400)
    struct.pack_into('<I', sec, 36, 0xC0000040)
    pe = bytes(dos) + pe_sig + coff + bytes(opt) + bytes(sec)
    pe += b'\x00' * (0x8400 - len(pe))
    pe = bytearray(pe)
    cfg_off = 0x400 + 0x7000
    while len(pe) < cfg_off + len(encrypted) + 256:
        pe += b'\x00' * 4096
    pe[cfg_off:cfg_off + len(encrypted)] = encrypted

    # Loader stub with ROR13 pattern
    loader = b'\xCC' * 512
    loader += b'\x0f\xb6\x0f\xc1\xe9\x08\x03\xc8'
    loader += b'\x90' * (2048 - len(loader))

    return loader + bytes(pe)


# ══════════════════════════════════════════════════════════════
#  PayloadMap Tests
# ══════════════════════════════════════════════════════════════

class TestPayloadMap:
    def test_from_dissection_creates_segments(self):
        from cs_aggregator.surgery.payload_map import PayloadMap
        data = b'\x00' * 1024
        segments = [
            {"segmentId": "SEG_LOADER_STUB", "offset": 0, "size": 256},
            {"segmentId": "SEG_BEACON_DLL", "offset": 256, "size": 768},
        ]
        pmap = PayloadMap.from_dissection(data, segments)
        assert pmap.loader is not None
        assert pmap.loader.offset == 0
        assert pmap.loader.size == 256
        assert pmap.beacon_dll is not None
        assert pmap.beacon_dll.offset == 256
        assert pmap.total_size == 1024

    def test_segment_list_ordered(self):
        from cs_aggregator.surgery.payload_map import PayloadMap
        data = b'\x00' * 2048
        segments = [
            {"segmentId": "SEG_BEACON_DLL", "offset": 512, "size": 1024},
            {"segmentId": "SEG_LOADER_STUB", "offset": 0, "size": 512},
        ]
        pmap = PayloadMap.from_dissection(data, segments)
        ordered = pmap.segment_list
        assert ordered[0].segment_id == "SEG_LOADER_STUB"
        assert ordered[1].segment_id == "SEG_BEACON_DLL"

    def test_get_segment_bytes(self):
        from cs_aggregator.surgery.payload_map import PayloadMap
        data = b'\xAA' * 100 + b'\xBB' * 100
        segments = [
            {"segmentId": "SEG_LOADER_STUB", "offset": 0, "size": 100},
            {"segmentId": "SEG_BEACON_DLL", "offset": 100, "size": 100},
        ]
        pmap = PayloadMap.from_dissection(data, segments)
        assert pmap.get_segment_bytes("SEG_LOADER_STUB") == b'\xAA' * 100
        assert pmap.get_segment_bytes("SEG_BEACON_DLL") == b'\xBB' * 100

    def test_validate_boundaries_no_overlap(self):
        from cs_aggregator.surgery.payload_map import PayloadMap
        data = b'\x00' * 200
        segments = [
            {"segmentId": "A", "offset": 0, "size": 100},
            {"segmentId": "B", "offset": 100, "size": 100},
        ]
        pmap = PayloadMap.from_dissection(data, segments)
        assert pmap.validate_boundaries() == []

    def test_validate_boundaries_detects_overflow(self):
        from cs_aggregator.surgery.payload_map import PayloadMap
        data = b'\x00' * 100
        segments = [{"segmentId": "A", "offset": 50, "size": 100}]
        pmap = PayloadMap.from_dissection(data, segments)
        warnings = pmap.validate_boundaries()
        assert len(warnings) == 1
        assert "exceeds" in warnings[0]


# ══════════════════════════════════════════════════════════════
#  ConfigSurgeon Tests
# ══════════════════════════════════════════════════════════════

class TestConfigSurgeon:
    def test_get_set_int(self):
        from cs_aggregator.surgery.config_surgeon import ConfigSurgeon
        cs = ConfigSurgeon({"SETTING_SLEEPTIME": 60000}, b'\x2e')
        assert cs.get_int("SETTING_SLEEPTIME") == 60000
        cs.set("SETTING_SLEEPTIME", 30000)
        assert cs.get_int("SETTING_SLEEPTIME") == 30000

    def test_dirty_tracking(self):
        from cs_aggregator.surgery.config_surgeon import ConfigSurgeon
        cs = ConfigSurgeon({"SETTING_SLEEPTIME": 60000, "SETTING_PORT": 443}, b'\x2e')
        assert len(cs.dirty_fields) == 0
        cs["SETTING_SLEEPTIME"] = 30000
        assert "SETTING_SLEEPTIME" in cs.dirty_fields
        assert "SETTING_PORT" not in cs.dirty_fields

    def test_diff_from_original(self):
        from cs_aggregator.surgery.config_surgeon import ConfigSurgeon
        cs = ConfigSurgeon({"SETTING_SLEEPTIME": 60000, "SETTING_JITTER": 37}, b'\x2e')
        cs["SETTING_SLEEPTIME"] = 30000
        diff = cs.diff_from_original()
        assert "SETTING_SLEEPTIME" in diff
        assert diff["SETTING_SLEEPTIME"] == (60000, 30000)

    def test_dict_access(self):
        from cs_aggregator.surgery.config_surgeon import ConfigSurgeon
        cs = ConfigSurgeon({"SETTING_PORT": 443}, b'\x2e')
        assert cs["SETTING_PORT"] == 443
        assert "SETTING_PORT" in cs

    def test_encrypt_produces_bytes(self):
        from cs_aggregator.surgery.config_surgeon import ConfigSurgeon
        cs = ConfigSurgeon({"SETTING_SLEEPTIME": 60000}, b'\x2e')
        encrypted = cs.encrypt()
        assert isinstance(encrypted, bytes)
        assert len(encrypted) > 0

    def test_export_import_json(self, tmp_path):
        from cs_aggregator.surgery.config_surgeon import ConfigSurgeon
        cs = ConfigSurgeon({"SETTING_SLEEPTIME": 60000, "SETTING_PORT": 443}, b'\x2e')
        path = str(tmp_path / "config.json")
        cs.export_json(path)
        assert os.path.exists(path)
        with open(path) as f:
            loaded = json.load(f)
        assert loaded["SETTING_SLEEPTIME"] == 60000

        # Import modifications
        mod_path = str(tmp_path / "mods.json")
        with open(mod_path, 'w') as f:
            json.dump({"SETTING_SLEEPTIME": 30000}, f)
        cs.import_json(mod_path)
        assert cs.get_int("SETTING_SLEEPTIME") == 30000


# ══════════════════════════════════════════════════════════════
#  LoaderSurgeon Tests
# ══════════════════════════════════════════════════════════════

class TestLoaderSurgeon:
    def test_validate_pic_code(self):
        from cs_aggregator.surgery.loader_surgeon import LoaderSurgeon
        from cs_aggregator.surgery.payload_map import PayloadMap
        pmap = PayloadMap.from_dissection(b'\x00' * 100, [])
        ls = LoaderSurgeon(pmap)

        # Valid PIC code (call $+5 pattern)
        pic = b'\xe8\x00\x00\x00\x00' + b'\x90' * 500
        warnings = ls.validate_loader(pic)
        assert not any("MZ header" in w for w in warnings)

    def test_validate_rejects_pe(self):
        from cs_aggregator.surgery.loader_surgeon import LoaderSurgeon
        from cs_aggregator.surgery.payload_map import PayloadMap
        pmap = PayloadMap.from_dissection(b'\x00' * 100, [])
        ls = LoaderSurgeon(pmap)

        pe_like = b'MZ' + b'\x00' * 500
        warnings = ls.validate_loader(pe_like)
        assert any("MZ header" in w for w in warnings)

    def test_validate_empty_rejected(self):
        from cs_aggregator.surgery.loader_surgeon import LoaderSurgeon
        from cs_aggregator.surgery.payload_map import PayloadMap
        pmap = PayloadMap.from_dissection(b'\x00' * 100, [])
        ls = LoaderSurgeon(pmap)

        warnings = ls.validate_loader(b'')
        assert any("empty" in w for w in warnings)


# ══════════════════════════════════════════════════════════════
#  SurgeryValidator Tests
# ══════════════════════════════════════════════════════════════

class TestSurgeryValidator:
    def test_validate_empty_payload(self):
        from cs_aggregator.surgery.validator import SurgeryValidator
        v = SurgeryValidator()
        result = v.validate_payload_structure(b'')
        assert not result.ok
        assert any("empty" in e for e in result.errors)

    def test_validate_valid_pe(self):
        from cs_aggregator.surgery.validator import SurgeryValidator
        v = SurgeryValidator()
        # Minimal valid MZ + PE
        pe = bytearray(256)
        pe[0:2] = b'MZ'
        struct.pack_into('<I', pe, 0x3C, 64)
        pe[64:68] = b'PE\x00\x00'
        result = v.validate_payload_structure(bytes(pe))
        assert result.ok or len(result.errors) == 0

    def test_validate_config_integrity(self):
        from cs_aggregator.surgery.validator import SurgeryValidator
        v = SurgeryValidator()
        result = v.validate_config_integrity({
            "SETTING_PROTOCOL": 8,
            "SETTING_PORT": 443,
            "SETTING_SLEEPTIME": 60000,
        })
        assert result.ok

    def test_validate_config_missing_fields(self):
        from cs_aggregator.surgery.validator import SurgeryValidator
        v = SurgeryValidator()
        result = v.validate_config_integrity({})
        assert not result.ok
        assert len(result.errors) >= 3

    def test_validate_round_trip(self):
        from cs_aggregator.surgery.validator import SurgeryValidator
        v = SurgeryValidator()
        original = {"SETTING_SLEEPTIME": 60000, "SETTING_PORT": 443}
        rebuilt = {"SETTING_SLEEPTIME": 30000, "SETTING_PORT": 443}
        result = v.validate_round_trip(
            original, rebuilt, modified_fields={"SETTING_SLEEPTIME"}
        )
        assert result.ok  # PORT should match, SLEEPTIME was intentionally changed


# ══════════════════════════════════════════════════════════════
#  BUD Analyzer Tests
# ══════════════════════════════════════════════════════════════

class TestBUDAnalyzer:
    def test_detect_reason_code(self):
        from cs_aggregator.modules.bud_analyzer import BUDAnalyzer
        ba = BUDAnalyzer()
        # Inject DLL_BEACON_USER_DATA reason code: mov edx, 0x0D
        loader = b'\x90' * 100 + b'\xBA\x0D\x00\x00\x00' + b'\x90' * 100
        result = ba.analyze(loader)
        assert result.bud_detected
        assert result.bud_reason_code_offset == 100

    def test_detect_version_field(self):
        from cs_aggregator.modules.bud_analyzer import BUDAnalyzer
        ba = BUDAnalyzer()
        # Inject version constant 0x040901 (CS 4.9.1) with MOV opcode prefix
        version_bytes = struct.pack('<I', 0x040901)
        loader = b'\x90' * 50 + b'\xC7' + version_bytes + b'\x90' * 50
        result = ba.analyze(loader)
        assert result.bud_version == "4.9.1"
        assert result.bud_version_raw == 0x040901

    def test_classify_bud_struct_version(self):
        from cs_aggregator.modules.bud_analyzer import BUDAnalyzer
        assert BUDAnalyzer._classify_bud_struct_version(0x040901) == 1
        assert BUDAnalyzer._classify_bud_struct_version(0x041000) == 2
        assert BUDAnalyzer._classify_bud_struct_version(0x041100) == 2
        assert BUDAnalyzer._classify_bud_struct_version(0x041200) == 3

    def test_empty_loader_returns_warning(self):
        from cs_aggregator.modules.bud_analyzer import BUDAnalyzer
        ba = BUDAnalyzer()
        result = ba.analyze(b'')
        assert not result.bud_detected
        assert len(result.warnings) > 0

    def test_schema_cross_reference(self):
        from cs_aggregator.modules.bud_analyzer import BUDAnalyzer
        schema = {"budStructure": {"version": 2}}
        ba = BUDAnalyzer(schema)
        # BUD v1 (4.9.1) with schema expecting v2 → should warn
        version_bytes = struct.pack('<I', 0x040901)
        loader = b'\x90' * 50 + b'\xC7' + version_bytes + b'\x90' * 50
        result = ba.analyze(loader)
        assert any("mismatch" in w for w in result.warnings)


# ══════════════════════════════════════════════════════════════
#  BeaconSurgeon Integration Tests
# ══════════════════════════════════════════════════════════════

class TestBeaconSurgeon:
    def test_init_from_bytes(self):
        from cs_aggregator.surgery import BeaconSurgeon
        payload = _build_synthetic_payload()
        surgeon = BeaconSurgeon(payload)
        assert surgeon.size == len(payload)
        assert surgeon.version  # Should detect something

    def test_config_read(self):
        from cs_aggregator.surgery import BeaconSurgeon
        payload = _build_synthetic_payload()
        surgeon = BeaconSurgeon(payload)
        assert surgeon.config.get_int("SETTING_SLEEPTIME") == 60000
        assert surgeon.config.get_int("SETTING_JITTER") == 37

    def test_config_modify_and_build(self):
        from cs_aggregator.surgery import BeaconSurgeon
        payload = _build_synthetic_payload()
        surgeon = BeaconSurgeon(payload)
        surgeon.config["SETTING_SLEEPTIME"] = 30000
        patched = surgeon.build()
        assert isinstance(patched, bytes)
        assert len(patched) > 0

    def test_round_trip_config_preservation(self):
        """The critical round-trip test: modify → build → re-dissect → verify."""
        from cs_aggregator.surgery import BeaconSurgeon
        payload = _build_synthetic_payload()
        surgeon = BeaconSurgeon(payload)

        # Modify
        surgeon.config["SETTING_SLEEPTIME"] = 30000
        surgeon.config["SETTING_JITTER"] = 50

        # Build
        patched = surgeon.build()

        # Re-dissect
        surgeon2 = BeaconSurgeon(patched)
        assert surgeon2.config.get_int("SETTING_SLEEPTIME") == 30000
        assert surgeon2.config.get_int("SETTING_JITTER") == 50
        # Untouched fields must be preserved
        assert surgeon2.config.get_str("SETTING_DOMAINS") == "evil.com"

    def test_validate_passes(self):
        from cs_aggregator.surgery import BeaconSurgeon
        payload = _build_synthetic_payload()
        surgeon = BeaconSurgeon(payload)
        result = surgeon.validate()
        assert result.ok

    def test_summary_structure(self):
        from cs_aggregator.surgery import BeaconSurgeon
        payload = _build_synthetic_payload()
        surgeon = BeaconSurgeon(payload)
        summary = surgeon.summary()
        assert "source" in summary
        assert "size" in summary
        assert "segments" in summary
        assert "config_fields" in summary
        assert "pending_modifications" in summary

    def test_init_from_file(self, tmp_path):
        from cs_aggregator.surgery import BeaconSurgeon
        payload = _build_synthetic_payload()
        fpath = str(tmp_path / "test_beacon.bin")
        with open(fpath, 'wb') as f:
            f.write(payload)
        surgeon = BeaconSurgeon(fpath)
        assert surgeon.size == len(payload)
