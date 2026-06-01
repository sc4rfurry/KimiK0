"""Tests for core dissection modules."""

import struct
import pytest

from cs_aggregator.modules.input_handler import InputHandler
from cs_aggregator.modules.version_detector import VersionDetector
from cs_aggregator.modules.loader_extractor import LoaderExtractor
from cs_aggregator.modules.beacon_parser import BeaconParser
from cs_aggregator.modules.config_extractor import ConfigExtractor
from cs_aggregator.modules.manifest_generator import ManifestGenerator
from cs_aggregator.utils.errors import PayloadTooSmallError
from cs_aggregator.utils.types import ClassificationResult, VersionDetectionResult


class TestInputHandler:
    def test_classify_stageless_large(self):
        """A large payload should classify as stageless."""
        data = b"\x90" * 10000  # > 8192 bytes = stageless
        result = InputHandler.classify_payload(data)
        assert result.payload_type == "stageless"
        assert result.file_size == 10000

    def test_classify_staged_small(self):
        """A very small payload should classify as staged."""
        data = b"\x90" * 512  # 512 bytes NOP sled (small = staged)
        result = InputHandler.classify_payload(data)
        assert result.payload_type == "staged"

    def test_validate_too_small(self):
        """Payload under min size should raise."""
        with pytest.raises(PayloadTooSmallError):
            InputHandler.validate_size(b"\x90" * 100)

    def test_read_file_not_found(self):
        """Non-existent file should raise."""
        with pytest.raises(Exception):
            InputHandler.read_file("/nonexistent/path/file.bin")

    def test_detect_architecture_x64(self):
        """x64 CALL+POP pattern should be detected."""
        # Simple x64 call pattern
        data = b"\x00" * 100 + b"\xe8\x00\x00\x00\x00" + b"\x00" * 100
        arch = InputHandler.detect_architecture(data)
        assert arch == "x64"


class TestVersionDetector:
    def test_init_loads_schemas(self):
        """VersionDetector should load schema files on init."""
        detector = VersionDetector()
        versions = detector.get_available_versions()
        assert len(versions) >= 3  # 4.9.0, 4.9.1, 4.10.x
        assert "4.9.0" in versions

    def test_detect_unknown_version(self):
        """Random data should not detect a version."""
        detector = VersionDetector()
        random_data = bytes([0xFF, 0xEE, 0xDD] * 1000)
        classification = ClassificationResult(
            payload_type="unknown",
            architecture="unknown",
            format="raw_shellcode",
            file_size=len(random_data),
            hashes={"md5": "", "sha1": "", "sha256": ""},
            entropy_score=7.5,
            confidence_score=0.0,
        )
        result = detector.detect_version(random_data, classification)
        assert result.estimated_version == "unknown" or result.confidence_score < 0.3


class TestLoaderExtractor:
    def test_extract_no_mz(self):
        """Payload without MZ header should have low confidence."""
        extractor = LoaderExtractor()
        data = b"\x00" * 4096
        result = extractor.extract_loader(data)
        assert result.confidence_score < 0.5

    def test_extract_with_mz(self):
        """Payload with MZ header should be detected."""
        extractor = LoaderExtractor()
        # MZ header at end of loader region (offset 1024)
        data = b"\x90" * 1024
        data += b"MZ" + b"\x00" * 0x3A
        # Set e_lfanew to point to a valid PE offset
        data = data[:1024 + 0x3C] + struct.pack("<I", 0x100) + data[1024 + 0x40:]
        data += b"\x00" * 256

        # Also patch the e_lfanew to be correct relative to MZ start
        mz_data = bytearray(data[1024:1024 + 0x40])
        struct.pack_into("<I", mz_data, 0x3C, 0x100)
        data = data[:1024] + bytes(mz_data) + data[1024 + 0x40:]

        result = extractor.extract_loader(data)
        assert result.offset > 0
        assert result.confidence_score > 0


class TestBeaconParser:
    def test_no_mz_returns_none(self):
        """Data without MZ should return None for DLL."""
        parser = BeaconParser()
        data = b"\x00" * 512
        dll, pe_info = parser.parse_beacon_dll(data, 0)
        assert dll is None
        assert "MZ" in (pe_info.anomalies[0] if pe_info.anomalies else "")

    def test_invalid_pe_returns_anomalies(self):
        """Invalid PE header should report anomalies."""
        parser = BeaconParser()
        # MZ at offset 0 with invalid e_lfanew
        data = b"MZ" + b"\x00" * 0x3E + struct.pack("<I", 9999)
        dll, pe_info = parser.parse_beacon_dll(data, 0)
        assert dll is None
        assert len(pe_info.anomalies) > 0


class TestConfigExtractor:
    def test_extract_no_config(self):
        """Random data should raise ConfigDecryptionError."""
        extractor = ConfigExtractor()
        random_data = bytes([0xFF, 0xEE, 0xDD] * 200)
        with pytest.raises(Exception):
            extractor.extract_config(random_data)

    def test_candidate_search_empty_data(self):
        """Very small data should produce no candidates."""
        extractor = ConfigExtractor()
        candidates = extractor._find_candidate_blocks(b"\x00" * 100)
        assert len(candidates) == 0


class TestManifestGenerator:
    def test_generate_minimal(self):
        """Minimal manifest should have expected structure."""
        classification = ClassificationResult(
            payload_type="stageless",
            architecture="x64",
            format="raw_shellcode",
            file_size=4096,
            hashes={"md5": "a", "sha1": "b", "sha256": "c"},
            entropy_score=6.5,
            confidence_score=0.7,
        )
        version_result = VersionDetectionResult(
            estimated_version="4.9.1",
            confidence_score=0.85,
            detection_method="multi_stage",
            schema_used="4.9.1",
        )
        manifest = ManifestGenerator.generate(
            classification=classification,
            version_result=version_result,
            source_file="test.bin",
        )
        assert manifest.manifest_format_version == "2.0"
        assert manifest.metadata["csVersionDetected"]["version"] == "4.9.1"
        assert manifest.metadata["payloadClassification"]["type"] == "stageless"
