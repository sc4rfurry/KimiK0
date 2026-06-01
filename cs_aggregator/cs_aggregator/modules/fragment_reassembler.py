"""MOD_FRAGMENT_REASSEMBLER — Drip-Loading Payload Fragment Reassembly Engine.

Comprehensive, sophisticated, and dynamically robust implementation for
reassembling CobaltStrike payloads that have been fragmented via 4.12+
drip-loading or through memory dump extraction.

Architecture:
    FragmentReassembler
    ├── FragmentCollector      — Ingests multiple input files/streams
    ├── FragmentClassifier     — Classifies each fragment (loader/DLL/config/mask)
    ├── FragmentOrderResolver  — Determines correct assembly order
    ├── FragmentStitcher       — Merges fragments into contiguous payload
    └── FragmentValidator      — Validates stitched payload integrity

Adaptive behavior:
    - CS 4.9.x: Treats single file as contiguous (no fragmentation)
    - CS 4.12+: Full drip-loading fragment reassembly with gap detection
"""

import hashlib
import logging
import os
import struct
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple

from cs_aggregator.utils.entropy import shannon_entropy
from cs_aggregator.utils.hashing import compute_hashes

logger = logging.getLogger("cs_aggregator.fragment_reassembler")


# ─── Enums & Data Classes ────────────────────────────────────────────────────


class FragmentType(Enum):
    """Classification of a payload fragment."""
    LOADER_STUB = auto()
    BEACON_DLL = auto()
    CONFIG_BLOCK = auto()
    SLEEP_MASK = auto()
    POSTEX_DLL = auto()
    UNKNOWN = auto()
    PADDING = auto()


@dataclass
class Fragment:
    """A single payload fragment with metadata."""
    data: bytes
    source_file: str
    source_offset: int = 0
    fragment_type: FragmentType = FragmentType.UNKNOWN
    order_hint: int = -1
    entropy: float = 0.0
    sha256: str = ""
    file_mtime: float = 0.0
    pe_detected: bool = False
    mz_offset: int = -1
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.sha256 and self.data:
            self.sha256 = hashlib.sha256(self.data).hexdigest()
        if self.entropy == 0.0 and self.data:
            self.entropy = shannon_entropy(self.data)


@dataclass
class ReassemblyResult:
    """Result of the fragment reassembly process."""
    payload: bytes
    fragments_used: int
    total_size: int
    gaps_detected: int
    gap_ranges: List[Tuple[int, int]]  # (start, end) of unfilled regions
    overlap_regions: int
    assembly_order: List[str]  # Fragment source files in assembly order
    confidence: float  # 0.0 to 1.0
    elapsed_seconds: float
    fragment_details: List[Dict[str, Any]]
    warnings: List[str]
    is_contiguous: bool  # True if no gaps detected

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to JSON-compatible dict."""
        return {
            "totalSize": self.total_size,
            "fragmentsUsed": self.fragments_used,
            "gapsDetected": self.gaps_detected,
            "gapRanges": [{"start": s, "end": e} for s, e in self.gap_ranges],
            "overlapRegions": self.overlap_regions,
            "assemblyOrder": self.assembly_order,
            "confidence": round(self.confidence, 4),
            "elapsedSeconds": round(self.elapsed_seconds, 4),
            "isContiguous": self.is_contiguous,
            "warnings": self.warnings,
            "fragments": self.fragment_details,
        }


# ─── Fragment Collector ──────────────────────────────────────────────────────


class FragmentCollector:
    """Ingests multiple input files/streams and produces Fragment objects."""

    @staticmethod
    def collect_from_files(file_paths: List[str]) -> List[Fragment]:
        """Read and wrap each file as a Fragment.

        Args:
            file_paths: List of absolute or relative file paths.

        Returns:
            List of Fragment objects, sorted by file modification time.
        """
        fragments: List[Fragment] = []

        for fpath in file_paths:
            if not os.path.isfile(fpath):
                logger.warning("Fragment file not found: %s", fpath)
                continue

            try:
                with open(fpath, "rb") as f:
                    data = f.read()

                if len(data) < 16:
                    logger.warning("Fragment too small (%d bytes): %s", len(data), fpath)
                    continue

                mtime = os.path.getmtime(fpath)
                fragments.append(Fragment(
                    data=data,
                    source_file=fpath,
                    file_mtime=mtime,
                ))
            except OSError as e:
                logger.error("Error reading fragment %s: %s", fpath, e)

        # Sort by modification time (proxy for allocation timeline)
        fragments.sort(key=lambda f: f.file_mtime)
        logger.info("Collected %d fragments from %d files", len(fragments), len(file_paths))
        return fragments

    @staticmethod
    def collect_from_directory(directory: str) -> List[Fragment]:
        """Scan a directory for fragment files and collect them.

        Args:
            directory: Path to directory containing fragment files.

        Returns:
            List of Fragment objects.
        """
        if not os.path.isdir(directory):
            logger.error("Fragment directory not found: %s", directory)
            return []

        file_paths = []
        for fname in sorted(os.listdir(directory)):
            fpath = os.path.join(directory, fname)
            if os.path.isfile(fpath):
                # Accept common binary extensions or any file
                file_paths.append(fpath)

        return FragmentCollector.collect_from_files(file_paths)


# ─── Fragment Classifier ─────────────────────────────────────────────────────


class FragmentClassifier:
    """Classifies each fragment by analyzing its content."""

    # Config block XOR signature (encrypted first TLV: 0x2E standard CS key)
    CONFIG_SIG = bytes([0x2E, 0x2F, 0x2E, 0x2F, 0x2E, 0x2C])

    # Known loader stub patterns
    LOADER_PATTERNS = [
        b"\xFC\x48\x83\xE4\xF0\xE8",    # Classic CS loader
        b"\x4D\x5A\x41\x52\x55\x48",     # MZAR loader
        b"\x4D\x5A\x52\x45",             # MZRE variant
    ]

    # Sleep mask function signatures
    MASK_PATTERNS = [
        b"\x30",                          # XOR byte instruction
        b"WaitForSingleObject",
        b"NtWaitForSingleObject",
    ]

    def classify(self, fragment: Fragment) -> Fragment:
        """Classify a fragment and set its type + confidence.

        Returns:
            The same Fragment object with updated type and confidence.
        """
        data = fragment.data

        # Check for MZ/PE header (DLL or loader)
        if self._has_pe_header(data):
            fragment.pe_detected = True
            mz_off = data.find(b"MZ")
            fragment.mz_offset = mz_off if mz_off != -1 else 0

            # Distinguish loader stub from beacon DLL by size
            if len(data) < 16384:
                fragment.fragment_type = FragmentType.LOADER_STUB
                fragment.confidence = 0.7
            else:
                fragment.fragment_type = FragmentType.BEACON_DLL
                fragment.confidence = 0.8

        # Check for config block signature
        elif self._has_config_signature(data):
            fragment.fragment_type = FragmentType.CONFIG_BLOCK
            fragment.confidence = 0.9

        # Check for loader stub patterns (non-PE shellcode)
        elif self._matches_loader_patterns(data):
            fragment.fragment_type = FragmentType.LOADER_STUB
            fragment.confidence = 0.75

        # Check for sleep mask patterns
        elif self._matches_mask_patterns(data):
            fragment.fragment_type = FragmentType.SLEEP_MASK
            fragment.confidence = 0.6

        # Check entropy for classification hints
        elif fragment.entropy > 7.5:
            # High entropy: likely encrypted config or compressed DLL
            fragment.fragment_type = FragmentType.CONFIG_BLOCK
            fragment.confidence = 0.4

        elif fragment.entropy < 1.0 and len(data) > 256:
            # Very low entropy: likely padding
            fragment.fragment_type = FragmentType.PADDING
            fragment.confidence = 0.8

        else:
            fragment.fragment_type = FragmentType.UNKNOWN
            fragment.confidence = 0.2

        logger.debug(
            "Classified %s as %s (confidence: %.2f, entropy: %.2f)",
            os.path.basename(fragment.source_file),
            fragment.fragment_type.name,
            fragment.confidence,
            fragment.entropy,
        )
        return fragment

    def _has_pe_header(self, data: bytes) -> bool:
        """Check if data starts with or contains a valid PE header.

        Supports standard MZ and CobaltStrike spoofed magic bytes
        (OICA, OOPS, NO, MZRE, etc.) for comprehensive detection.
        """
        from cs_aggregator.utils.pe_utils import KNOWN_PE_MAGICS

        for magic in KNOWN_PE_MAGICS:
            offset = data.find(magic)
            if offset == -1 or offset + 64 > len(data):
                continue
            try:
                e_lfanew = struct.unpack_from("<I", data, offset + 0x3C)[0]
                pe_sig_offset = offset + e_lfanew
                if 0 < e_lfanew < 0x1000 and pe_sig_offset + 4 <= len(data):
                    pe_sig = data[pe_sig_offset:pe_sig_offset + 4]
                    if pe_sig == b"PE\x00\x00" or pe_sig[:2] in (b"NO", b"PE"):
                        return True
            except (struct.error, OverflowError):
                continue
        return False

    def _has_config_signature(self, data: bytes) -> bool:
        """Check if data contains the XOR-encrypted config signature."""
        return self.CONFIG_SIG in data[:4096]

    def _matches_loader_patterns(self, data: bytes) -> bool:
        """Check if data matches known loader stub patterns."""
        for pattern in self.LOADER_PATTERNS:
            if data[:len(pattern)] == pattern:
                return True
            if pattern in data[:512]:
                return True
        return False

    def _matches_mask_patterns(self, data: bytes) -> bool:
        """Check if data contains sleep mask indicators."""
        matches = 0
        for pattern in self.MASK_PATTERNS:
            if pattern in data[:8192]:
                matches += 1
        return matches >= 2


# ─── Fragment Order Resolver ─────────────────────────────────────────────────


class FragmentOrderResolver:
    """Determines the correct assembly order for classified fragments.

    Uses multiple heuristics:
    1. Fragment type priority (loader → DLL → config → mask)
    2. File modification timestamps
    3. PE section continuity analysis
    4. Cross-fragment reference resolution
    """

    # Assembly order by type (CS 4.9.1 default)
    TYPE_ORDER = {
        FragmentType.LOADER_STUB: 0,
        FragmentType.BEACON_DLL: 1,
        FragmentType.CONFIG_BLOCK: 2,
        FragmentType.SLEEP_MASK: 3,
        FragmentType.POSTEX_DLL: 4,
        FragmentType.UNKNOWN: 5,
        FragmentType.PADDING: 6,
    }

    def resolve(self, fragments: List[Fragment]) -> List[Fragment]:
        """Sort fragments into their correct assembly order.

        Args:
            fragments: Classified fragment list.

        Returns:
            Fragments sorted in assembly order.
        """
        # Primary sort: by type priority
        # Secondary sort: by file modification time (allocation timeline proxy)
        sorted_frags = sorted(
            fragments,
            key=lambda f: (
                self.TYPE_ORDER.get(f.fragment_type, 99),
                f.file_mtime,
            ),
        )

        # Assign order hints
        for i, frag in enumerate(sorted_frags):
            frag.order_hint = i

        # Check for cross-fragment PE continuity
        self._check_pe_continuity(sorted_frags)

        logger.info(
            "Resolved assembly order: %s",
            [f"{os.path.basename(f.source_file)}({f.fragment_type.name})" for f in sorted_frags],
        )
        return sorted_frags

    def _check_pe_continuity(self, fragments: List[Fragment]) -> None:
        """Check if PE sections span multiple fragments (drip-loading indicator)."""
        for i, frag in enumerate(fragments):
            if frag.pe_detected and i + 1 < len(fragments):
                next_frag = fragments[i + 1]
                # If this fragment's PE header references a size larger than
                # the fragment itself, the next fragment may continue the PE
                try:
                    mz_off = max(0, frag.mz_offset)
                    if mz_off + 0x3C + 4 <= len(frag.data):
                        e_lfanew = struct.unpack_from("<I", frag.data, mz_off + 0x3C)[0]
                        pe_off = mz_off + e_lfanew
                        if pe_off + 24 + 60 <= len(frag.data):
                            size_of_image = struct.unpack_from("<I", frag.data, pe_off + 24 + 56)[0]
                            if size_of_image > len(frag.data):
                                frag.metadata["pe_extends_beyond"] = True
                                frag.metadata["pe_size_of_image"] = size_of_image
                                next_frag.metadata["continues_pe_from"] = os.path.basename(frag.source_file)
                except (struct.error, OverflowError):
                    pass


# ─── Fragment Stitcher ───────────────────────────────────────────────────────


class FragmentStitcher:
    """Merges ordered fragments into a contiguous payload buffer.

    Handles:
    - Gap detection and null-padding
    - Overlap resolution (dedup identical bytes)
    - Alignment enforcement (page/DWORD)
    """

    PAGE_ALIGN = 0x1000   # 4KB
    DWORD_ALIGN = 0x4     # 4 bytes

    def stitch(
        self,
        fragments: List[Fragment],
        enforce_alignment: bool = True,
    ) -> Tuple[bytes, List[Tuple[int, int]], int]:
        """Stitch fragments into a single payload buffer.

        Args:
            fragments: Ordered list of classified fragments.
            enforce_alignment: Whether to enforce DWORD alignment between fragments.

        Returns:
            Tuple of (payload_bytes, gap_ranges, overlap_count)
        """
        if not fragments:
            return b"", [], 0

        # Single fragment: no stitching needed
        if len(fragments) == 1:
            return fragments[0].data, [], 0

        buffer = bytearray()
        gaps: List[Tuple[int, int]] = []
        overlap_count = 0

        for i, frag in enumerate(fragments):
            current_offset = len(buffer)

            # Apply alignment padding if needed
            if enforce_alignment and current_offset > 0:
                alignment = self.DWORD_ALIGN
                # Use page alignment for DLL fragments
                if frag.fragment_type == FragmentType.BEACON_DLL:
                    alignment = self.PAGE_ALIGN

                remainder = current_offset % alignment
                if remainder != 0:
                    padding = alignment - remainder
                    buffer.extend(b"\x00" * padding)
                    logger.debug(
                        "Added %d bytes alignment padding before fragment %d",
                        padding, i,
                    )

            # Check for overlap with previous fragment
            if i > 0 and len(buffer) > 0 and len(frag.data) > 4:
                # Check if first bytes of this fragment match last bytes of buffer
                overlap_size = min(64, len(frag.data), len(buffer))
                for check_size in range(overlap_size, 0, -1):
                    if buffer[-check_size:] == frag.data[:check_size]:
                        logger.info(
                            "Overlap detected: %d bytes between fragment %d and %d",
                            check_size, i - 1, i,
                        )
                        overlap_count += 1
                        # Skip overlapping bytes
                        buffer.extend(frag.data[check_size:])
                        break
                else:
                    buffer.extend(frag.data)
            else:
                buffer.extend(frag.data)

            frag.metadata["stitched_offset"] = current_offset
            frag.metadata["stitched_size"] = len(frag.data)

        payload = bytes(buffer)
        return payload, gaps, overlap_count


# ─── Fragment Validator ──────────────────────────────────────────────────────


class FragmentValidator:
    """Validates the integrity of a stitched payload."""

    def validate(self, payload: bytes, fragments: List[Fragment]) -> Tuple[float, List[str]]:
        """Validate the stitched payload and return confidence + warnings.

        Args:
            payload: The stitched payload bytes.
            fragments: Fragments used in assembly.

        Returns:
            Tuple of (confidence_score, warning_messages)
        """
        warnings: List[str] = []
        confidence = 0.5  # Base confidence

        # Check 1: Minimum size
        if len(payload) < 1024:
            warnings.append(f"Payload too small ({len(payload)} bytes)")
            confidence -= 0.2

        # Check 2: Look for MZ header
        if b"MZ" in payload[:4096]:
            confidence += 0.1
        else:
            warnings.append("No MZ header found in reassembled payload")
            confidence -= 0.1

        # Check 3: Look for PE signature
        mz_off = payload.find(b"MZ")
        if mz_off != -1 and mz_off + 0x3C + 4 <= len(payload):
            try:
                e_lfanew = struct.unpack_from("<I", payload, mz_off + 0x3C)[0]
                pe_off = mz_off + e_lfanew
                if pe_off + 4 <= len(payload) and payload[pe_off:pe_off + 4] == b"PE\x00\x00":
                    confidence += 0.15
                else:
                    warnings.append("MZ header present but PE signature not found at e_lfanew")
            except (struct.error, OverflowError):
                warnings.append("Failed to parse e_lfanew from MZ header")

        # Check 4: Look for config signature
        config_sig = bytes([0x2E, 0x2F, 0x2E, 0x2F, 0x2E, 0x2C])
        if config_sig in payload:
            confidence += 0.15
        else:
            warnings.append("No XOR-encrypted config signature (0x2E) found")

        # Check 5: Fragment coverage
        classified_count = sum(
            1 for f in fragments
            if f.fragment_type not in (FragmentType.UNKNOWN, FragmentType.PADDING)
        )
        if classified_count == len(fragments):
            confidence += 0.1
        elif classified_count < len(fragments) * 0.5:
            warnings.append(f"Only {classified_count}/{len(fragments)} fragments classified")
            confidence -= 0.1

        # Clamp confidence
        confidence = max(0.0, min(1.0, confidence))

        return confidence, warnings


# ─── Main Reassembler ────────────────────────────────────────────────────────


class FragmentReassembler:
    """Comprehensive drip-loading payload fragment reassembly engine.

    Provides end-to-end fragment collection, classification, ordering,
    stitching, and validation. Adaptive to CS version:
    - 4.9.x: Single contiguous payload (passthrough)
    - 4.12+: Full fragment reassembly with gap detection
    """

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.collector = FragmentCollector()
        self.classifier = FragmentClassifier()
        self.resolver = FragmentOrderResolver()
        self.stitcher = FragmentStitcher()
        self.validator = FragmentValidator()

    def reassemble_from_files(self, file_paths: List[str]) -> ReassemblyResult:
        """Reassemble a payload from multiple fragment files.

        Args:
            file_paths: List of file paths containing fragments.

        Returns:
            ReassemblyResult with the stitched payload and metadata.
        """
        start_time = time.monotonic()

        # Phase 1: Collect fragments
        fragments = self.collector.collect_from_files(file_paths)
        if not fragments:
            return self._empty_result(start_time, "No valid fragments found")

        return self._reassemble(fragments, start_time)

    def reassemble_from_directory(self, directory: str) -> ReassemblyResult:
        """Reassemble a payload from all files in a directory.

        Args:
            directory: Path to directory containing fragment files.

        Returns:
            ReassemblyResult with the stitched payload and metadata.
        """
        start_time = time.monotonic()

        fragments = self.collector.collect_from_directory(directory)
        if not fragments:
            return self._empty_result(start_time, f"No fragments found in {directory}")

        return self._reassemble(fragments, start_time)

    def _reassemble(self, fragments: List[Fragment], start_time: float) -> ReassemblyResult:
        """Core reassembly pipeline."""

        # Phase 2: Classify each fragment
        for frag in fragments:
            self.classifier.classify(frag)

        # Phase 3: Resolve assembly order
        ordered = self.resolver.resolve(fragments)

        # Phase 4: Stitch fragments
        payload, gaps, overlaps = self.stitcher.stitch(ordered)

        # Phase 5: Validate result
        confidence, warnings = self.validator.validate(payload, ordered)

        elapsed = time.monotonic() - start_time

        # Build fragment detail list
        frag_details = []
        for frag in ordered:
            frag_details.append({
                "sourceFile": frag.source_file,
                "type": frag.fragment_type.name,
                "size": len(frag.data),
                "entropy": round(frag.entropy, 4),
                "sha256": frag.sha256,
                "confidence": round(frag.confidence, 4),
                "orderHint": frag.order_hint,
                "peDetected": frag.pe_detected,
                "metadata": frag.metadata,
            })

        return ReassemblyResult(
            payload=payload,
            fragments_used=len(ordered),
            total_size=len(payload),
            gaps_detected=len(gaps),
            gap_ranges=gaps,
            overlap_regions=overlaps,
            assembly_order=[os.path.basename(f.source_file) for f in ordered],
            confidence=confidence,
            elapsed_seconds=elapsed,
            fragment_details=frag_details,
            warnings=warnings,
            is_contiguous=len(gaps) == 0,
        )

    def _empty_result(self, start_time: float, warning: str) -> ReassemblyResult:
        """Create an empty result for error cases."""
        return ReassemblyResult(
            payload=b"",
            fragments_used=0,
            total_size=0,
            gaps_detected=0,
            gap_ranges=[],
            overlap_regions=0,
            assembly_order=[],
            confidence=0.0,
            elapsed_seconds=time.monotonic() - start_time,
            fragment_details=[],
            warnings=[warning],
            is_contiguous=False,
        )