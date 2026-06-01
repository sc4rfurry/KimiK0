"""MOD_LOADER_EXTRACTOR — Loader Stub Extractor & Classifier.

Identifies, extracts, and classifies the reflective loader stub from
the beginning of the shellcode blob. Detects MZ header boundary,
uses entropy analysis as fallback, and classifies the loader type.
"""

from typing import Any, Dict, List, Optional, Tuple

from cs_aggregator.utils.entropy import shannon_entropy, find_entropy_drop_boundary
from cs_aggregator.utils.hashing import compute_hashes
from cs_aggregator.utils.types import LoaderStubResult

MZ_MAGIC = b"MZ"

# CobaltStrike's `stage.magic_mz_x64` / `magic_mz_x86` Malleable C2 option allows
# operators to replace the MZ header bytes with custom values. Common known values:
KNOWN_PE_MAGICS = [
    b"MZ",    # Standard PE
    b"OICA",  # dec eax, inc eax, dec ebx, inc ebx — NOP-equivalent, very common in prod profiles
    b"NO",    # Another common replacement
]


class LoaderExtractor:
    """Extracts and classifies the reflective loader stub from a beacon payload."""

    def __init__(self, version_schema: Optional[Dict[str, Any]] = None):
        """Initialize with an optional version schema for version-specific heuristics.

        Args:
            version_schema: Version schema dict from VersionDetector.
        """
        self.schema = version_schema or {}

    def extract_loader(self, data: bytes) -> LoaderStubResult:
        """Extract the reflective loader stub from the payload.

        Primary strategy: find MZ header boundary.
        Fallback: entropy analysis for encrypted/obfuscated DLLs.

        Args:
            data: Raw payload bytes.

        Returns:
            LoaderStubResult with extracted loader data and metadata.
        """
        # Get version-specific loader size hints
        hints = self.schema.get("segmentBoundaryHints", {})
        loader_max = hints.get("loaderMaxSize", 8192)
        loader_min = hints.get("loaderMinSize", 512)

        # Primary strategy: find MZ header
        loader_bytes, offset, method = self._find_loader_by_mz(data, loader_max)

        # Fallback: entropy analysis
        if loader_bytes is None:
            loader_bytes, offset, method = self._find_loader_by_entropy(
                data, loader_min, loader_max
            )

        # Second fallback: use version-specific known offset
        if loader_bytes is None:
            loader_bytes, offset, method = self._find_loader_by_known_offset(
                data, loader_min, loader_max
            )

        # If all strategies fail, report failed extraction
        if loader_bytes is None:
            return LoaderStubResult(
                segment_id="SEG_LOADER_STUB",
                offset=0,
                size=0,
                sha256="0" * 64,
                entropy=0.0,
                confidence_score=0.0,
                metadata={"error": "Loader stub not found — payload may be encrypted or corrupted"},
                classification="Unknown",
            )

        # Classify the loader
        classification = self._classify_loader(loader_bytes)
        confidence = self._calculate_confidence(loader_bytes, method, classification)

        hashes = compute_hashes(loader_bytes)
        entropy = shannon_entropy(loader_bytes)

        return LoaderStubResult(
            segment_id="SEG_LOADER_STUB",
            offset=offset,
            size=len(loader_bytes),
            sha256=hashes["sha256"],
            entropy=entropy,
            confidence_score=confidence,
            metadata={
                "extraction_method": method,
                "loader_type": classification,
                "loader_size": len(loader_bytes),
            },
            classification=classification,
        )

    @staticmethod
    def _find_loader_by_mz(data: bytes, max_loader_size: int) -> Tuple[Optional[bytes], int, str]:
        """Primary strategy: locate PE header boundary to find loader/DLL split.

        Scans for standard MZ magic AND known spoofed magic bytes
        (e.g. 'OICA' from stage.magic_mz_x64). For each candidate,
        validates via e_lfanew → PE signature check.

        Returns:
            (loader_bytes, offset, method_name) or (None, 0, "failed")
        """
        search_end = min(max_loader_size, len(data))

        for offset in range(search_end):
            # Check all known PE magic patterns (standard MZ + spoofed values)
            for magic in KNOWN_PE_MAGICS:
                if data[offset:offset + len(magic)] == magic:
                    # Verify it's a plausible PE header via e_lfanew
                    if offset + 64 < len(data):
                        try:
                            e_lfanew = int.from_bytes(data[offset + 0x3C:offset + 0x40], "little")
                            # e_lfanew should point to PE signature within reasonable range
                            if 0 < e_lfanew < 0x1000 and offset + e_lfanew + 4 < len(data):
                                pe_sig = data[offset + e_lfanew:offset + e_lfanew + 4]
                                # Check for real PE signature OR spoofed PE magic (e.g. 'NO')
                                if pe_sig == b'PE\x00\x00' or pe_sig[:2] in (b'NO', b'PE'):
                                    loader_bytes = data[:offset]
                                    magic_desc = magic.decode('ascii', errors='replace')
                                    return loader_bytes, offset, f"pe_header_magic_{magic_desc}"
                        except (ValueError, IndexError):
                            continue

        return None, 0, "failed"

    @staticmethod
    def _find_loader_by_entropy(data: bytes, min_size: int, max_size: int) -> Tuple[Optional[bytes], int, str]:
        """Fallback: use entropy analysis to find loader/DLL boundary.

        The loader stub typically has lower entropy than the encrypted DLL
        that follows. Look for a significant entropy drop.

        Returns:
            (loader_bytes, offset, method_name) or (None, 0, "failed")
        """
        if len(data) < min_size:
            return None, 0, "failed"

        boundary = find_entropy_drop_boundary(data, 0, max_size, 0.5)
        if boundary > min_size:
            loader_bytes = data[:boundary]
            return loader_bytes, boundary, "entropy_drop"

        return None, 0, "failed"

    @staticmethod
    def _find_loader_by_known_offset(data: bytes, min_size: int, max_size: int) -> Tuple[Optional[bytes], int, str]:
        """Second fallback: use known default loader sizes from version schema.

        Validates that the data at each candidate offset actually looks like
        a PE header boundary (MZ/OICA/NO/OOPS magic or valid e_lfanew).

        Returns:
            (loader_bytes, offset, method_name) or (None, 0, "failed")
        """
        # Try common loader sizes: 0x800, 0x1000, 0x2000
        common_sizes = [0x800, 0x1000, 0x2000, 0x4000]

        for size in common_sizes:
            if min_size <= size <= max_size <= len(data):
                if size + 64 <= len(data):
                    # Validate: data at this offset must resemble a PE header
                    boundary = data[size:]
                    has_pe_magic = False
                    for magic in KNOWN_PE_MAGICS:
                        if boundary[:len(magic)] == magic:
                            # Further validate via e_lfanew → PE signature
                            try:
                                e_lfanew = int.from_bytes(boundary[0x3C:0x40], "little")
                                if 0 < e_lfanew < 0x1000 and e_lfanew + 4 <= len(boundary):
                                    pe_sig = boundary[e_lfanew:e_lfanew + 4]
                                    if pe_sig == b'PE\x00\x00' or pe_sig[:2] in (b'NO', b'PE'):
                                        has_pe_magic = True
                                        break
                            except (ValueError, IndexError):
                                continue
                    if has_pe_magic:
                        loader_bytes = data[:size]
                        return loader_bytes, size, "known_offset"

        return None, 0, "failed"

    def _classify_loader(self, loader_bytes: bytes) -> str:
        """Classify the loader stub type.

        Uses byte signature matching against known default loader stubs
        and heuristic analysis.

        Returns:
            Classification string: "Default_CS_4_9", "Default_CS_4_10",
            "Default_CS_4_11", "Default_CS_4_12", "Custom_UDRL", "sRDI_variant",
            "BokuLoader", or "Unknown".
        """
        if not loader_bytes:
            return "Unknown"

        # Check version-specific loader patterns from schema
        patterns = self.schema.get("loaderSignaturePatterns", {})
        if patterns:
            for pattern_name, pattern_hex in patterns.items():
                pattern = self._hex_to_bytes(pattern_hex)
                if pattern and self._pattern_match(loader_bytes, pattern):
                    return f"Default_Detected"

        # Heuristic checks
        # sRDI / DoublePulsar pattern check
        if b"\x55\x53\x56\x57\x41\x54\x41\x55" in loader_bytes[:64]:
            return "sRDI_variant"

        # ROR13 hash loop pattern
        if b"\x0f\xb6\x0f" in loader_bytes and b"\xc1\xe9\x08" in loader_bytes:
            return "Default_CS_4_9"

        # Check entropy level: very low entropy might indicate custom/packed loader
        entropy = shannon_entropy(loader_bytes)
        if entropy < 4.0:
            return "Custom_UDRL"

        return "Unknown"

    @staticmethod
    def _calculate_confidence(loader_bytes: bytes, method: str, classification: str) -> float:
        """Calculate confidence score for the extraction.

        Factors:
            - Extraction method (MZ header is most reliable)
            - Classification confidence
            - Loader size reasonableness
        """
        base_confidence = {
            "mz_header": 0.9,
            "pe_header_magic_MZ": 0.9,
            "pe_header_magic_OICA": 0.85,
            "pe_header_magic_NO": 0.85,
            "entropy_drop": 0.6,
            "known_offset": 0.4,
        }
        conf = 0.3
        for key, val in base_confidence.items():
            if method.startswith(key) or method == key:
                conf = val
                break

        classification_bonus = 0.1 if classification != "Unknown" else 0.0

        # Size reasonableness
        size_bonus = 0.0
        if 512 <= len(loader_bytes) <= 16384:
            size_bonus = 0.05

        return min(1.0, conf + classification_bonus + size_bonus)

    @staticmethod
    def _hex_to_bytes(hex_str: str) -> list:
        """Convert a hex string like '0f b6 0f ?? 03 c8' to a pattern list.

        Returns a list where each element is either an int (exact byte)
        or None (wildcard '??' — matches any byte).
        """
        pattern = []
        for token in hex_str.split():
            token = token.strip()
            if token == "??":
                pattern.append(None)  # Wildcard — matches any byte
            else:
                try:
                    pattern.append(int(token, 16))
                except ValueError:
                    pass
        return pattern

    @staticmethod
    def _pattern_match(data: bytes, pattern: list) -> bool:
        """Match a pattern (with wildcards) against data.

        Pattern is a list of int (exact byte) or None (wildcard).
        Returns True if pattern is found anywhere in data.
        """
        if not pattern:
            return False
        plen = len(pattern)
        for i in range(len(data) - plen + 1):
            match = True
            for j in range(plen):
                if pattern[j] is not None and data[i + j] != pattern[j]:
                    match = False
                    break
            if match:
                return True
        return False

    def extract_loader_bytes(self, data: bytes) -> Optional[bytes]:
        """Convenience method to get just the raw loader bytes.

        Args:
            data: Raw payload bytes.

        Returns:
            Raw loader stub bytes, or None if extraction failed.
        """
        result = self.extract_loader(data)
        if result.confidence_score > 0 and result.size > 0:
            return data[:result.size]
        return None
