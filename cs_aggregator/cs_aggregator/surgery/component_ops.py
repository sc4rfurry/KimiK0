"""ComponentOps — Extract/replace/patch individual payload components.

Provides low-level byte operations on payload segments,
used by the higher-level surgeons for actual data manipulation.
"""

import logging
import os
from typing import Any, Dict, List, Optional

from cs_aggregator.surgery.payload_map import PayloadMap
from cs_aggregator.utils.hashing import compute_hashes

logger = logging.getLogger("cs_aggregator.surgery.component_ops")


class ComponentExtractor:
    """Extracts individual components from a beacon payload to disk.

    Produces the full set of PRD-compliant output files:
    - loader_stub.bin
    - beacon.dll
    - config.json + config_encrypted.bin + config_decrypted.bin
    - sleep_mask.bin
    """

    def __init__(self, payload_map: PayloadMap) -> None:
        self._pmap = payload_map

    def extract_all(
        self,
        raw_payload: bytes,
        output_dir: str,
        config_json: Optional[Dict[str, Any]] = None,
        config_encrypted: Optional[bytes] = None,
        config_decrypted: Optional[bytes] = None,
    ) -> Dict[str, str]:
        """Extract all components to an output directory.

        Args:
            raw_payload: Full payload bytes.
            output_dir: Directory to write extracted files.
            config_json: Parsed config dict (for config.json).
            config_encrypted: Raw encrypted config bytes.
            config_decrypted: Raw decrypted TLV bytes.

        Returns:
            Dict mapping component name to output file path.
        """
        os.makedirs(output_dir, exist_ok=True)
        extracted: Dict[str, str] = {}

        # Loader stub
        loader_seg = self._pmap.loader
        if loader_seg and loader_seg.size > 0:
            path = os.path.join(output_dir, "loader_stub.bin")
            data = raw_payload[loader_seg.offset:loader_seg.end_offset]
            _write_bytes(path, data)
            extracted["loader_stub"] = path

            # Loader metadata
            meta_path = os.path.join(output_dir, "loader_stub_metadata.json")
            _write_json(meta_path, {
                "offset": loader_seg.offset,
                "size": loader_seg.size,
                "sha256": compute_hashes(data)["sha256"],
                "entropy": loader_seg.entropy,
                "classification": loader_seg.classification,
            })
            extracted["loader_stub_metadata"] = meta_path

        # Beacon DLL
        dll_seg = self._pmap.beacon_dll
        if dll_seg and dll_seg.size > 0:
            path = os.path.join(output_dir, "beacon.dll")
            data = raw_payload[dll_seg.offset:dll_seg.end_offset]
            _write_bytes(path, data)
            extracted["beacon_dll"] = path

            # PE metadata
            meta_path = os.path.join(output_dir, "beacon_pe_metadata.json")
            _write_json(meta_path, {
                "offset": dll_seg.offset,
                "size": dll_seg.size,
                "sha256": compute_hashes(data)["sha256"],
                "entropy": dll_seg.entropy,
                "pe_info": dll_seg.metadata.get("peInfo", {}),
            })
            extracted["beacon_pe_metadata"] = meta_path

        # Config
        if config_json is not None:
            path = os.path.join(output_dir, "config.json")
            _write_json(path, config_json)
            extracted["config_json"] = path

        if config_encrypted is not None:
            path = os.path.join(output_dir, "config_encrypted.bin")
            _write_bytes(path, config_encrypted)
            extracted["config_encrypted"] = path

        if config_decrypted is not None:
            path = os.path.join(output_dir, "config_decrypted.bin")
            _write_bytes(path, config_decrypted)
            extracted["config_decrypted"] = path

        # Sleep mask
        mask_seg = self._pmap.sleep_mask
        if mask_seg and mask_seg.size > 0:
            path = os.path.join(output_dir, "sleep_mask.bin")
            data = raw_payload[mask_seg.offset:mask_seg.end_offset]
            _write_bytes(path, data)
            extracted["sleep_mask"] = path

            meta_path = os.path.join(output_dir, "sleep_mask_metadata.json")
            _write_json(meta_path, {
                "offset": mask_seg.offset,
                "size": mask_seg.size,
                "sha256": compute_hashes(data)["sha256"],
                "entropy": mask_seg.entropy,
                "section_name": mask_seg.metadata.get("sectionName", ""),
            })
            extracted["sleep_mask_metadata"] = meta_path

        logger.info("Extracted %d components to %s", len(extracted), output_dir)
        return extracted


def patch_bytes(
    payload: bytes,
    offset: int,
    new_data: bytes,
) -> bytes:
    """Patch bytes at a specific offset in a payload.

    If new_data is shorter than the region, the remainder is null-padded.
    If new_data is longer, the payload is extended.

    Args:
        payload: Original payload bytes.
        offset: Byte offset to start patching.
        new_data: Replacement bytes.

    Returns:
        Modified payload bytes.
    """
    result = bytearray(payload)
    end = offset + len(new_data)

    if end <= len(result):
        result[offset:end] = new_data
    else:
        # Extend payload
        result[offset:] = new_data
        if len(result) < end:
            result.extend(b"\x00" * (end - len(result)))

    return bytes(result)


def splice_segment(
    payload: bytes,
    old_offset: int,
    old_size: int,
    new_data: bytes,
) -> bytes:
    """Replace a segment in the payload, handling size changes.

    Args:
        payload: Original payload bytes.
        old_offset: Start of the segment to replace.
        old_size: Size of the old segment.
        new_data: Replacement data (may differ in size).

    Returns:
        Modified payload with the segment replaced.
    """
    before = payload[:old_offset]
    after = payload[old_offset + old_size:]
    return before + new_data + after


# ── Helpers ──

def _write_bytes(path: str, data: bytes) -> None:
    """Write bytes to a file."""
    with open(path, "wb") as f:
        f.write(data)


def _write_json(path: str, data: Any) -> None:
    """Write a dict to a JSON file."""
    import json
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
