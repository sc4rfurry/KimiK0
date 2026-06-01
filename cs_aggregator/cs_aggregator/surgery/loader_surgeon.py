"""LoaderSurgeon — Loader stub swap, validation, and BUD-aware replacement.

Handles replacing the reflective loader stub while preserving
the beacon DLL boundary and MZ header alignment.
"""

import logging
from typing import Any, Dict, List, Optional

from cs_aggregator.surgery.payload_map import PayloadMap
from cs_aggregator.utils.entropy import shannon_entropy
from cs_aggregator.utils.hashing import compute_hashes

logger = logging.getLogger("cs_aggregator.surgery.loader_surgeon")


class LoaderSurgeon:
    """Surgical loader stub replacement preserving payload integrity.

    Handles:
    - Replacing the default CS loader with a custom UDRL
    - Validating the replacement loader is PIC-compatible
    - Adjusting segment offsets when loader size changes
    - Warning about BUD compatibility requirements
    """

    def __init__(self, payload_map: PayloadMap) -> None:
        self._pmap = payload_map

    def replace(
        self,
        new_loader: bytes,
        raw_payload: bytes,
    ) -> bytes:
        """Replace the loader stub in the payload.

        The beacon DLL and all subsequent segments are preserved
        byte-for-byte. If the new loader differs in size from the
        original, all downstream offsets shift accordingly.

        Args:
            new_loader: New loader stub bytes (PIC shellcode or UDRL).
            raw_payload: The full original payload bytes.

        Returns:
            New payload bytes with the loader replaced.
        """
        loader_seg = self._pmap.loader
        if loader_seg is None:
            raise ValueError("No loader stub segment found in payload map")

        original_end = loader_seg.end_offset
        remaining = raw_payload[original_end:]

        result = new_loader + remaining

        logger.info(
            "Loader replaced: %d → %d bytes (delta: %+d)",
            loader_seg.size, len(new_loader),
            len(new_loader) - loader_seg.size,
        )
        return result

    def validate_loader(self, loader_bytes: bytes) -> List[str]:
        """Validate a loader stub for compatibility.

        Checks:
        - Non-empty
        - Reasonable size (64B – 64KB)
        - Entropy profile consistent with PIC code
        - No raw MZ header at offset 0 (loader should be shellcode)

        Args:
            loader_bytes: The loader stub bytes to validate.

        Returns:
            List of warning strings (empty if all checks pass).
        """
        warnings: List[str] = []

        if not loader_bytes:
            warnings.append("Loader is empty (0 bytes)")
            return warnings

        if len(loader_bytes) < 64:
            warnings.append(f"Loader is suspiciously small ({len(loader_bytes)} bytes)")

        if len(loader_bytes) > 65536:
            warnings.append(f"Loader is unusually large ({len(loader_bytes)} bytes)")

        # PIC shellcode should NOT start with MZ
        if loader_bytes[:2] == b"MZ":
            warnings.append(
                "Loader starts with MZ header — this looks like a PE, not PIC shellcode. "
                "UDRLs should be raw position-independent code."
            )

        # Check entropy (PIC code typically 4.0–7.0)
        entropy = shannon_entropy(loader_bytes)
        if entropy < 3.0:
            warnings.append(f"Loader entropy is very low ({entropy:.2f}) — may be mostly null bytes")
        elif entropy > 7.5:
            warnings.append(f"Loader entropy is very high ({entropy:.2f}) — may be encrypted/compressed")

        # Check for common PIC bootstrap patterns
        has_pic_pattern = False
        # call $+5; pop reg (x64)
        if b"\xe8\x00\x00\x00\x00" in loader_bytes[:32]:
            has_pic_pattern = True
        # PEB access via GS segment (x64)
        if b"\x65\x48\x8b" in loader_bytes[:64]:
            has_pic_pattern = True
        # Standard function prologue
        if loader_bytes[:1] in (b"\x55", b"\x48"):
            has_pic_pattern = True

        if not has_pic_pattern and len(loader_bytes) > 64:
            warnings.append(
                "No common PIC bootstrap patterns detected in first 64 bytes. "
                "Verify this is valid position-independent code."
            )

        return warnings

    def extract(self, raw_payload: bytes) -> bytes:
        """Extract the current loader stub bytes from the payload.

        Args:
            raw_payload: The full payload bytes.

        Returns:
            Raw loader stub bytes.
        """
        loader_seg = self._pmap.loader
        if loader_seg is None:
            raise ValueError("No loader stub segment in payload map")
        return raw_payload[loader_seg.offset:loader_seg.end_offset]

    def get_info(self) -> Dict[str, Any]:
        """Get loader stub metadata."""
        seg = self._pmap.loader
        if seg is None:
            return {"present": False}
        return {
            "present": True,
            "offset": seg.offset,
            "size": seg.size,
            "sha256": seg.sha256,
            "entropy": seg.entropy,
            "classification": seg.classification,
        }
