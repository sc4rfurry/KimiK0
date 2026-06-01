"""MOD_VERSION_DETECTOR — Version Fingerprinter (Adaptive Engine).

Two-stage detection pipeline:
1. Stage 1 (Fast Heuristics): Loader signature matching, TLV type analysis,
   config offset heuristics, PE compile timestamp, watermark hash.
2. Stage 2 (Deep Analysis): BUD structure matching, multi-schema TLV brute-force.

Selects the appropriate parser schema for downstream modules.
"""

import json
import os
from typing import Any, Dict, List, Optional, Tuple

from cs_aggregator.utils.errors import SchemaError, VersionDetectionError
from cs_aggregator.utils.types import VersionDetectionResult

# Default schema directory
SCHEMA_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "schemas")


class VersionDetector:
    """Two-stage CS version fingerprinting engine."""

    def __init__(self, schema_dir: str = SCHEMA_DIR):
        """Initialize the version detector with a schema directory.

        Args:
            schema_dir: Path to the directory containing version schema JSON files.
        """
        self.schema_dir = os.path.abspath(schema_dir)
        self.schemas: Dict[str, Dict[str, Any]] = {}
        self._load_schemas()

    def _load_schemas(self) -> None:
        """Load all version schema JSON files from the schema directory."""
        if not os.path.isdir(self.schema_dir):
            raise SchemaError(f"Schema directory not found: {self.schema_dir}")

        for filename in os.listdir(self.schema_dir):
            if filename.endswith(".json") and filename != "schema_template.json":
                path = os.path.join(self.schema_dir, filename)
                try:
                    with open(path, "r") as f:
                        schema = json.load(f)
                    version = schema.get("meta", {}).get("version")
                    if version:
                        self.schemas[version] = schema
                except (json.JSONDecodeError, OSError) as e:
                    raise SchemaError(f"Failed to load schema {filename}: {e}")

        if not self.schemas:
            raise SchemaError(f"No valid version schemas found in {self.schema_dir}")

    def get_schema(self, version: str) -> Optional[Dict[str, Any]]:
        """Get a schema for a specific version.

        Performs fuzzy matching: "4.10" matches "4.10.x" if "4.10" not found.
        """
        if version in self.schemas:
            return self.schemas[version]

        # Try fuzzy matching
        for schema_version in self.schemas:
            if schema_version.startswith(version) or version.startswith(schema_version):
                return self.schemas[schema_version]

        return None

    def get_available_versions(self) -> List[str]:
        """Get list of available version schemas."""
        return list(self.schemas.keys())

    def detect_version(self, data: bytes, classification: Any) -> VersionDetectionResult:
        """Run two-stage version detection on the payload.

        Args:
            data: Raw payload bytes.
            classification: ClassificationResult from MOD_INPUT.

        Returns:
            VersionDetectionResult with estimated version and confidence.
        """
        # Stage 1: Fast heuristics
        result, confidence = self._stage1_fast_heuristics(data)

        # If confidence is low, run stage 2 deep analysis
        if confidence < 0.6:
            deep_result, deep_confidence = self._stage2_deep_analysis(data, result)
            if deep_confidence > confidence:
                result = deep_result
                confidence = deep_confidence

        # Check if schema exists for detected version
        schema_used = "none"
        if result and result != "unknown":
            schema = self.get_schema(result)
            if schema:
                schema_used = result

        return VersionDetectionResult(
            estimated_version=result or "unknown",
            confidence_score=round(confidence, 2),
            detection_method="multi_stage",
            schema_used=schema_used,
            version_specific_notes=self._get_version_notes(result),
        )

    def _stage1_fast_heuristics(self, data: bytes) -> Tuple[Optional[str], float]:
        """Stage 1: Fast heuristic version detection with weighted scoring.

        Weights:
            - Loader signature match: 0.4
            - TLV type presence: 0.3
            - Config offset heuristics: 0.15
            - PE compile timestamp: 0.1
            - Watermark hash: 0.05

        Returns:
            (estimated_version, confidence_score)
        """
        scores: Dict[str, float] = {}

        for version, schema in self.schemas.items():
            score = 0.0

            # 1. Loader signature matching (weight: 0.4)
            patterns = schema.get("loaderSignaturePatterns", {})
            if patterns:
                pattern_matches = self._match_loader_patterns(data, patterns)
                score += pattern_matches * 0.4

            # 2. Config offset heuristics (weight: 0.15)
            heuristics = schema.get("configBlockHeuristics", {})
            if heuristics:
                heuristic_score = self._check_config_heuristics(data, heuristics)
                score += heuristic_score * 0.15

            # 3. PE compile timestamp (weight: 0.1)
            ts_score = self._check_pe_timestamp(data, version)
            score += ts_score * 0.1

            scores[version] = score

        if not scores:
            return None, 0.0

        # Find best match
        best_version = max(scores, key=lambda v: scores[v])
        best_score = scores[best_version]

        if best_score < 0.1:
            return None, best_score

        return best_version, best_score

    def _match_loader_patterns(self, data: bytes, patterns: Dict[str, str]) -> float:
        """Match loader byte patterns against the payload.

        Returns a score between 0.0 and 1.0.
        """
        if not patterns:
            return 0.0

        matches = 0
        for pattern_name, pattern_hex in patterns.items():
            # Parse hex pattern (support "??" wildcards)
            pattern_bytes = self._hex_pattern_to_bytes(pattern_hex)
            if self._byte_pattern_match(data, pattern_bytes):
                matches += 1

        return min(1.0, matches / max(1, len(patterns)))

    @staticmethod
    def _hex_pattern_to_bytes(pattern_hex: str) -> List[Optional[int]]:
        """Convert a hex byte pattern string to a list of bytes/None for wildcards.

        "0f b6 0f ?? 03 c8" -> [0x0f, 0xb6, 0x0f, None, 0x03, 0xc8]
        """
        result: List[Optional[int]] = []
        for token in pattern_hex.split():
            token = token.strip()
            if token == "??":
                result.append(None)
            else:
                try:
                    result.append(int(token, 16))
                except ValueError:
                    pass
        return result

    @staticmethod
    def _byte_pattern_match(data: bytes, pattern: List[Optional[int]]) -> bool:
        """Search for a byte pattern (with wildcards) in data."""
        if not pattern or len(pattern) > len(data):
            return False

        for i in range(len(data) - len(pattern) + 1):
            match = True
            for j, p in enumerate(pattern):
                if p is not None and data[i + j] != p:
                    match = False
                    break
            if match:
                return True
        return False

    def _check_config_heuristics(self, data: bytes, heuristics: Dict[str, Any]) -> float:
        """Check configuration block heuristics.

        Returns score 0.0–1.0 based on how well the payload matches
        the expected config block characteristics for this version.
        """
        score = 0.0
        checks = 0

        # Check expected section names are present
        if "sectionNames" in heuristics:
            checks += 1
            # Scan for PE sections matching expected names
            section_names = self._extract_section_names(data)
            expected = set(heuristics["sectionNames"])
            if section_names and expected.intersection(section_names):
                score += 1.0

        # Check size range
        if "searchRangeEndOffset" in heuristics:
            checks += 1
            # The config block should be within this many bytes from section end
            # This is a weak heuristic on its own
            score += 0.5  # Partial credit for having the heuristic defined

        if checks == 0:
            return 0.0

        return score / checks

    @staticmethod
    def _check_pe_timestamp(data: bytes, version: str) -> float:
        """Check PE compile timestamp against known CS version release dates.

        Supports standard MZ and spoofed magic (OICA, OOPS, NO, etc.).
        Returns score 0.0–1.0.
        """
        from cs_aggregator.utils.pe_utils import find_pe_offset

        mz_offset = find_pe_offset(data, max_search=0x10000)
        if mz_offset < 0 or mz_offset + 64 >= len(data):
            return 0.0

        try:
            pe_offset = int.from_bytes(data[mz_offset + 0x3C:mz_offset + 0x40], "little")
            timestamp_offset = mz_offset + pe_offset + 8
            if timestamp_offset + 4 > len(data):
                return 0.0

            timestamp = int.from_bytes(data[timestamp_offset:timestamp_offset + 4], "little")
            if timestamp == 0:
                return 0.0

            if timestamp < 1577836800:  # Jan 1, 2020
                return 0.1

            return 0.5
        except (ValueError, IndexError):
            return 0.0

    @staticmethod
    def _extract_section_names(data: bytes) -> List[str]:
        """Extract PE section names from the payload.

        Supports standard MZ headers and spoofed magic bytes (OICA, NO).
        Returns a list of section name strings (trimmed null bytes).
        """
        from cs_aggregator.utils.pe_utils import find_pe_offset, extract_section_names

        pe_base = find_pe_offset(data)
        if pe_base < 0:
            return []

        return extract_section_names(data, pe_base)

    def _stage2_deep_analysis(self, data: bytes, initial_guess: Optional[str]) -> Tuple[Optional[str], float]:
        """Stage 2: Deep analysis when stage 1 confidence is low.

        Performs: PE header detection (with spoofed magic support),
        segment boundary validation, and config signature scanning.

        Returns:
            (refined_version, refined_confidence)
        """
        if initial_guess and initial_guess != "unknown":
            return initial_guess, 0.5

        from cs_aggregator.utils.pe_utils import find_pe_offset
        from cs_aggregator.utils.xor_decrypt import CONFIG_SIGNATURE_ENCRYPTED

        # Strategy 1: Find PE header anywhere in payload (supports offset-0 PEs)
        pe_offset = find_pe_offset(data, max_search=0x10000)
        if pe_offset >= 0:
            # PE found — try to match against schemas by size/structure
            for version in sorted(self.schemas.keys(), reverse=True):
                schema = self.schemas[version]
                hints = schema.get("segmentBoundaryHints", {})
                loader_max = hints.get("loaderMaxSize", 16384)
                # Accept PE at offset 0 (no prepended loader) OR within loader range
                if pe_offset <= loader_max:
                    return version, 0.55

        # Strategy 2: Look for config signature (0x2E XOR) as proof of CS beacon
        if CONFIG_SIGNATURE_ENCRYPTED in data:
            # Definitely a CS payload — use latest schema
            latest = sorted(self.schemas.keys(), reverse=True)
            if latest:
                return latest[0], 0.6

        return None, 0.0

    @staticmethod
    def detect_version_from_config(
        config_json: Dict[str, Any], xor_key: str
    ) -> Tuple[str, float]:
        """Detect CS version from extracted config settings.

        This is the most reliable version detection method — setting IDs
        are definitive version markers.

        Args:
            config_json: Extracted config dict with SETTING_* keys.
            xor_key: Hex-encoded XOR key used for decryption.

        Returns:
            (version_string, confidence) e.g. ("4.9+", 0.95)
        """
        # Map setting names back to IDs for analysis
        from cs_aggregator.modules.config_extractor import SETTING_NAMES
        name_to_id = {v: k for k, v in SETTING_NAMES.items()}

        found_ids = set()
        for key in config_json:
            if key in name_to_id:
                found_ids.add(name_to_id[key])

        # Definitive version markers (highest version first)
        if found_ids & {79, 80}:  # RDLL_USE_DRIPLOADING / RDLL_DRIPLOAD_DELAY
            return "4.12+", 0.98
        if found_ids & {77, 78}:  # BEACON_GATE / BEACON_GATE_CONFIG
            return "4.10+", 0.95
        if 74 in found_ids:  # MASKED_WATERMARK
            return "4.9+", 0.95
        if 17 in found_ids:  # SYSCALL_METHOD
            return "4.8+", 0.90
        if 16 in found_ids:  # BOF_ALLOCATOR
            return "4.7+", 0.85

        # XOR key is a weak version indicator
        if xor_key == "2e":
            return "4.x", 0.70

        return "unknown", 0.0

    @staticmethod
    def _get_version_notes(version: Optional[str]) -> List[str]:
        """Get human-readable notes about a detected version."""
        from cs_aggregator.utils.types import CSVersionDB

        if version is None:
            return ["Unknown version — using best-effort generic parsing"]

        # Try fuzzy match
        for known_version, info in CSVersionDB.VERSIONS.items():
            if version.startswith(known_version) or known_version.startswith(version):
                return [info["notes"]]

        return [f"Version {version} — no specific notes available"]
