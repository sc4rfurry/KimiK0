"""PayloadMap — Byte-accurate segment boundary mapping.

Provides a structural map of a dissected CobaltStrike beacon payload,
identifying the exact byte offsets and sizes of every component.
Used as the foundation for all surgical operations.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from cs_aggregator.utils.hashing import compute_hashes
from cs_aggregator.utils.entropy import shannon_entropy

logger = logging.getLogger("cs_aggregator.surgery.payload_map")


@dataclass
class SegmentInfo:
    """Byte-accurate information about a single payload segment."""

    segment_id: str
    offset: int
    size: int
    sha256: str = ""
    entropy: float = 0.0
    confidence: float = 0.0
    classification: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def end_offset(self) -> int:
        """Byte offset of the first byte AFTER this segment."""
        return self.offset + self.size

    def contains(self, offset: int) -> bool:
        """Check if a byte offset falls within this segment."""
        return self.offset <= offset < self.end_offset

    def overlaps(self, other: "SegmentInfo") -> bool:
        """Check if this segment overlaps with another."""
        return self.offset < other.end_offset and other.offset < self.end_offset


@dataclass
class ConfigLocation:
    """Location of the config block within the beacon DLL."""

    offset_in_dll: int  # Offset within the DLL bytes (not payload-global)
    offset_in_payload: int  # Global offset in the full payload
    size_encrypted: int
    size_decrypted: int
    xor_key: bytes
    xor_key_length: int
    key_detection_method: str = ""


class PayloadMap:
    """Byte-accurate structural map of a CobaltStrike beacon payload.

    After dissection, this map provides O(1) access to any segment's
    boundaries, enabling surgical read/write operations without
    re-parsing the entire payload.
    """

    def __init__(self) -> None:
        self._segments: Dict[str, SegmentInfo] = {}
        self._config_location: Optional[ConfigLocation] = None
        self._total_size: int = 0
        self._raw_data: bytes = b""

    # ── Segment Accessors ──

    @property
    def loader(self) -> Optional[SegmentInfo]:
        """The reflective loader stub segment."""
        return self._segments.get("SEG_LOADER_STUB")

    @property
    def beacon_dll(self) -> Optional[SegmentInfo]:
        """The beacon core DLL segment."""
        return self._segments.get("SEG_BEACON_DLL")

    @property
    def config_block(self) -> Optional[SegmentInfo]:
        """The configuration block segment."""
        return self._segments.get("SEG_CONFIG_BLOCK")

    @property
    def sleep_mask(self) -> Optional[SegmentInfo]:
        """The sleep mask segment (may be None if not present)."""
        return self._segments.get("SEG_SLEEP_MASK")

    @property
    def config_location(self) -> Optional[ConfigLocation]:
        """Detailed config block location with XOR key info."""
        return self._config_location

    @property
    def total_size(self) -> int:
        """Total size of the payload in bytes."""
        return self._total_size

    @property
    def segments(self) -> Dict[str, SegmentInfo]:
        """All mapped segments."""
        return dict(self._segments)

    @property
    def segment_list(self) -> List[SegmentInfo]:
        """All segments ordered by offset."""
        return sorted(self._segments.values(), key=lambda s: s.offset)

    # ── Data Access ──

    def get_segment_bytes(self, segment_id: str) -> bytes:
        """Extract raw bytes for a segment from the payload.

        Args:
            segment_id: The segment ID (e.g. "SEG_LOADER_STUB").

        Returns:
            Raw bytes of the segment.

        Raises:
            KeyError: If segment not found.
            ValueError: If raw data not available.
        """
        seg = self._segments.get(segment_id)
        if seg is None:
            raise KeyError(f"Segment {segment_id!r} not found in payload map")
        if not self._raw_data:
            raise ValueError("Raw payload data not loaded — call from_dissection() first")
        return self._raw_data[seg.offset:seg.end_offset]

    def get_bytes_at(self, offset: int, size: int) -> bytes:
        """Read arbitrary bytes from the payload.

        Args:
            offset: Byte offset to start reading.
            size: Number of bytes to read.

        Returns:
            Raw bytes from the payload.
        """
        if not self._raw_data:
            raise ValueError("Raw payload data not loaded")
        return self._raw_data[offset:offset + size]

    # ── Builder ──

    @classmethod
    def from_dissection(
        cls,
        raw_data: bytes,
        manifest_segments: List[Dict[str, Any]],
        config_result: Optional[Any] = None,
    ) -> "PayloadMap":
        """Build a PayloadMap from dissection results.

        Args:
            raw_data: The full raw payload bytes.
            manifest_segments: Segment list from the Manifest.
            config_result: Optional ConfigBlockResult with XOR key info.

        Returns:
            A fully populated PayloadMap.
        """
        pmap = cls()
        pmap._raw_data = raw_data
        pmap._total_size = len(raw_data)

        for seg_dict in manifest_segments:
            seg_id = seg_dict.get("segmentId", "UNKNOWN")
            offset = seg_dict.get("offset", 0)
            size = seg_dict.get("size", 0)

            # Calculate hash and entropy from actual bytes
            seg_bytes = raw_data[offset:offset + size] if offset + size <= len(raw_data) else b""
            sha256 = compute_hashes(seg_bytes)["sha256"] if seg_bytes else ""
            entropy = shannon_entropy(seg_bytes) if seg_bytes else 0.0

            info = SegmentInfo(
                segment_id=seg_id,
                offset=offset,
                size=size,
                sha256=sha256,
                entropy=entropy,
                confidence=seg_dict.get("confidence", 0.0),
                classification=seg_dict.get("classification", seg_dict.get("type", "")),
                metadata={k: v for k, v in seg_dict.items()
                          if k not in ("segmentId", "offset", "size", "type", "classification")},
            )
            pmap._segments[seg_id] = info

        # Parse config location from config result
        if config_result is not None:
            loader_seg = pmap._segments.get("SEG_LOADER_STUB")
            loader_offset = loader_seg.size if loader_seg else 0

            xor_key_bytes = b""
            if hasattr(config_result, "xor_key") and config_result.xor_key:
                try:
                    xor_key_bytes = bytes.fromhex(config_result.xor_key)
                except ValueError:
                    xor_key_bytes = config_result.xor_key.encode() if isinstance(config_result.xor_key, str) else b""

            pmap._config_location = ConfigLocation(
                offset_in_dll=max(0, (config_result.offset if hasattr(config_result, "offset") else 0) - loader_offset),
                offset_in_payload=config_result.offset if hasattr(config_result, "offset") else 0,
                size_encrypted=config_result.size_encrypted if hasattr(config_result, "size_encrypted") else 0,
                size_decrypted=config_result.size_decrypted if hasattr(config_result, "size_decrypted") else 0,
                xor_key=xor_key_bytes,
                xor_key_length=config_result.xor_key_length if hasattr(config_result, "xor_key_length") else len(xor_key_bytes),
                key_detection_method=config_result.key_detection_method if hasattr(config_result, "key_detection_method") else "",
            )

        return pmap

    # ── Validation ──

    def validate_boundaries(self) -> List[str]:
        """Validate that segment boundaries are consistent.

        Returns:
            List of warning messages (empty if all OK).
        """
        warnings: List[str] = []
        ordered = self.segment_list

        for i, seg in enumerate(ordered):
            # Check segment doesn't exceed payload
            if seg.end_offset > self._total_size:
                warnings.append(
                    f"{seg.segment_id}: end offset {seg.end_offset:#x} exceeds "
                    f"payload size {self._total_size:#x}"
                )

            # Check for overlaps with next segment
            if i + 1 < len(ordered):
                next_seg = ordered[i + 1]
                if seg.overlaps(next_seg):
                    warnings.append(
                        f"{seg.segment_id} overlaps with {next_seg.segment_id}: "
                        f"[{seg.offset:#x}-{seg.end_offset:#x}] vs "
                        f"[{next_seg.offset:#x}-{next_seg.end_offset:#x}]"
                    )

        return warnings

    def __repr__(self) -> str:
        segs = ", ".join(
            f"{s.segment_id}@{s.offset:#x}[{s.size}B]"
            for s in self.segment_list
        )
        return f"PayloadMap({self._total_size}B: {segs})"
