"""SleepMaskSurgeon — Sleep mask injection, swap, and removal.

Handles adding, replacing, or removing sleep mask components
from beacon payloads with version-aware alignment.
"""

import logging
from typing import Any, Dict, List, Optional

from cs_aggregator.surgery.payload_map import PayloadMap
from cs_aggregator.utils.entropy import shannon_entropy

logger = logging.getLogger("cs_aggregator.surgery.sleepmask_surgeon")

# Alignment for appended sleep masks
DWORD_ALIGN = 4


class SleepMaskSurgeon:
    """Surgical sleep mask injection/swap/removal.

    Handles:
    - Replacing an existing sleep mask with a custom one
    - Injecting a sleep mask into a payload that doesn't have one
    - Removing a sleep mask from a payload
    - Validating sleep mask compatibility with the detected CS version
    """

    def __init__(self, payload_map: PayloadMap) -> None:
        self._pmap = payload_map

    def replace(
        self,
        new_mask: bytes,
        raw_payload: bytes,
    ) -> bytes:
        """Replace or inject a sleep mask in the payload.

        If the payload already has a sleep mask segment, it is replaced.
        If not, the new mask is appended after the beacon DLL with
        proper DWORD alignment.

        Args:
            new_mask: New sleep mask bytes (BOF or raw shellcode).
            raw_payload: The full original payload bytes.

        Returns:
            Modified payload bytes with the new sleep mask.
        """
        mask_seg = self._pmap.sleep_mask

        if mask_seg is not None and mask_seg.size > 0:
            # Replace existing mask
            before = raw_payload[:mask_seg.offset]
            after = raw_payload[mask_seg.end_offset:]
            result = before + new_mask + after
            logger.info(
                "Sleep mask replaced: %d → %d bytes at offset %#x",
                mask_seg.size, len(new_mask), mask_seg.offset,
            )
        else:
            # Append after the last known segment
            segments = self._pmap.segment_list
            if segments:
                last = segments[-1]
                append_offset = last.end_offset
            else:
                append_offset = len(raw_payload)

            # DWORD-align
            padding_needed = (DWORD_ALIGN - (append_offset % DWORD_ALIGN)) % DWORD_ALIGN
            result = raw_payload[:append_offset] + (b"\x00" * padding_needed) + new_mask
            logger.info(
                "Sleep mask injected: %d bytes at offset %#x (padded %d)",
                len(new_mask), append_offset + padding_needed, padding_needed,
            )

        return result

    def remove(self, raw_payload: bytes) -> bytes:
        """Remove the sleep mask segment from the payload.

        Args:
            raw_payload: The full original payload bytes.

        Returns:
            Payload bytes with the sleep mask removed.
        """
        mask_seg = self._pmap.sleep_mask
        if mask_seg is None or mask_seg.size == 0:
            logger.warning("No sleep mask segment found — nothing to remove")
            return raw_payload

        before = raw_payload[:mask_seg.offset]
        after = raw_payload[mask_seg.end_offset:]
        result = before + after
        logger.info("Sleep mask removed: %d bytes from offset %#x", mask_seg.size, mask_seg.offset)
        return result

    def extract(self, raw_payload: bytes) -> Optional[bytes]:
        """Extract the current sleep mask bytes.

        Args:
            raw_payload: The full payload bytes.

        Returns:
            Sleep mask bytes, or None if not present.
        """
        mask_seg = self._pmap.sleep_mask
        if mask_seg is None or mask_seg.size == 0:
            return None
        return raw_payload[mask_seg.offset:mask_seg.end_offset]

    def validate_mask(self, mask_bytes: bytes) -> List[str]:
        """Validate a sleep mask for compatibility.

        Args:
            mask_bytes: The sleep mask bytes.

        Returns:
            List of warnings (empty if all checks pass).
        """
        warnings: List[str] = []

        if not mask_bytes:
            warnings.append("Sleep mask is empty")
            return warnings

        # CS 4.9.x expects 4-16KB masks
        if len(mask_bytes) < 256:
            warnings.append(f"Sleep mask very small ({len(mask_bytes)} bytes) — min expected ~4KB")

        if len(mask_bytes) > 32768:
            warnings.append(f"Sleep mask very large ({len(mask_bytes)} bytes) — max expected ~32KB")

        # Check entropy
        entropy = shannon_entropy(mask_bytes)
        if entropy < 2.0:
            warnings.append(f"Sleep mask entropy very low ({entropy:.2f}) — may be mostly null")

        # Look for known export patterns (Mask/Unmask)
        has_function_markers = False
        if b"Mask" in mask_bytes or b"mask" in mask_bytes:
            has_function_markers = True
        if b"\xc3" in mask_bytes[:64]:  # RET in first 64 bytes (function boundary)
            has_function_markers = True

        if not has_function_markers and len(mask_bytes) > 256:
            warnings.append(
                "No function markers (Mask/Unmask exports or RET) found — "
                "verify this is a valid sleep mask BOF or shellcode"
            )

        return warnings

    def get_info(self) -> Dict[str, Any]:
        """Get sleep mask segment metadata."""
        seg = self._pmap.sleep_mask
        if seg is None:
            return {"present": False}
        return {
            "present": True,
            "offset": seg.offset,
            "size": seg.size,
            "sha256": seg.sha256,
            "entropy": seg.entropy,
        }
