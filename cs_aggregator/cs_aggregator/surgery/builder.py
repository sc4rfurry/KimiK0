"""BeaconSurgeon — High-level orchestrator for CS shellcode surgery.

The primary entry point for the Surgery SDK. Provides a clean API
for disassembling, modifying, and reassembling CobaltStrike beacon
payloads at the micro level.

Usage:
    surgeon = BeaconSurgeon("beacon.bin")
    surgeon.config["SETTING_SLEEPTIME"] = 30000
    surgeon.replace_loader(open("my_udrl.bin", "rb").read())
    patched = surgeon.build()
"""

import logging
import os
from typing import Any, Dict, List, Optional, Union

from cs_aggregator.engine import DissectionPipeline
from cs_aggregator.surgery.config_surgeon import ConfigSurgeon
from cs_aggregator.surgery.loader_surgeon import LoaderSurgeon
from cs_aggregator.surgery.payload_map import PayloadMap
from cs_aggregator.surgery.sleepmask_surgeon import SleepMaskSurgeon
from cs_aggregator.surgery.validator import SurgeryValidator, ValidationResult
from cs_aggregator.utils.hashing import compute_hashes
from cs_aggregator.utils.types import Manifest, ReassemblyConfig

logger = logging.getLogger("cs_aggregator.surgery.builder")


class BeaconSurgeon:
    """High-level orchestrator for surgical beacon payload modification.

    Wraps the dissection pipeline and surgery components into a
    single, developer-friendly API for CS shellcode disassembly
    and reassembly.

    Lifecycle:
        1. Load/dissect payload → builds PayloadMap
        2. Read/modify components via surgeons (config, loader, mask)
        3. Validate modifications
        4. Build → reassemble into a valid payload

    Thread Safety:
        Not thread-safe. Use one BeaconSurgeon per payload.
    """

    def __init__(
        self,
        source: Union[str, bytes],
        profile: Optional[Any] = None,
    ) -> None:
        """Initialize by dissecting a beacon payload.

        Args:
            source: Path to a beacon payload file, or raw bytes.
            profile: Optional parsed C2Profile for assisted dissection.
        """
        # Load raw data
        if isinstance(source, str):
            if not os.path.isfile(source):
                raise FileNotFoundError(f"Payload not found: {source}")
            with open(source, "rb") as f:
                self._raw_data = f.read()
            self._source_path = source
        elif isinstance(source, bytes):
            self._raw_data = source
            self._source_path = "<bytes>"
        else:
            raise TypeError(f"source must be str or bytes, got {type(source).__name__}")

        # Run dissection pipeline
        self._pipeline = DissectionPipeline()
        self._manifest = self._pipeline.process(
            self._raw_data,
            source_file=self._source_path,
            profile=profile,
        )

        # Build payload map from dissection results
        self._payload_map = PayloadMap.from_dissection(
            raw_data=self._raw_data,
            manifest_segments=self._manifest.segments,
            config_result=self._pipeline._config_result,
        )

        # Initialize config surgeon from extracted config
        config_json: Dict[str, Any] = {}
        xor_key = b"\x2e"
        xor_key_length = 1
        if self._pipeline._config_result is not None:
            config_json = dict(self._pipeline._config_result.config_json)
            try:
                xor_key = bytes.fromhex(self._pipeline._config_result.xor_key)
            except (ValueError, AttributeError):
                pass
            xor_key_length = self._pipeline._config_result.xor_key_length

        self._config_surgeon = ConfigSurgeon(config_json, xor_key, xor_key_length)

        # Initialize component surgeons
        self._loader_surgeon = LoaderSurgeon(self._payload_map)
        self._sleepmask_surgeon = SleepMaskSurgeon(self._payload_map)
        self._validator = SurgeryValidator()

        # Track modifications for the build step
        self._new_loader: Optional[bytes] = None
        self._new_sleep_mask: Optional[bytes] = None
        self._remove_sleep_mask: bool = False

        logger.info(
            "BeaconSurgeon initialized: %s (%d bytes, %s)",
            self._source_path, len(self._raw_data),
            self._manifest.metadata.get("csVersionDetected", {}).get("version", "unknown"),
        )

    # ── Properties ──

    @property
    def config(self) -> ConfigSurgeon:
        """Access the config surgeon for field-level read/write."""
        return self._config_surgeon

    @property
    def payload_map(self) -> PayloadMap:
        """The byte-accurate segment boundary map."""
        return self._payload_map

    @property
    def manifest(self) -> Manifest:
        """The dissection manifest."""
        return self._manifest

    @property
    def raw_data(self) -> bytes:
        """The original raw payload bytes."""
        return self._raw_data

    @property
    def version(self) -> str:
        """Detected CobaltStrike version."""
        return self._manifest.metadata.get(
            "csVersionDetected", {}
        ).get("version", "unknown")

    @property
    def size(self) -> int:
        """Original payload size in bytes."""
        return len(self._raw_data)

    # ── Loader Operations ──

    def replace_loader(self, new_loader: bytes) -> List[str]:
        """Stage a loader stub replacement.

        The actual replacement happens during build(). This method
        validates the new loader and returns any warnings.

        Args:
            new_loader: New loader stub bytes (PIC shellcode / UDRL).

        Returns:
            List of validation warnings.
        """
        warnings = self._loader_surgeon.validate_loader(new_loader)
        self._new_loader = new_loader
        logger.info("Loader replacement staged: %d bytes, %d warnings",
                     len(new_loader), len(warnings))
        return warnings

    def extract_loader(self, output_path: Optional[str] = None) -> bytes:
        """Extract the current loader stub.

        Args:
            output_path: Optional file path to write the loader bytes.

        Returns:
            Raw loader stub bytes.
        """
        loader_bytes = self._loader_surgeon.extract(self._raw_data)
        if output_path:
            with open(output_path, "wb") as f:
                f.write(loader_bytes)
            logger.info("Loader extracted to %s (%d bytes)", output_path, len(loader_bytes))
        return loader_bytes

    # ── Sleep Mask Operations ──

    def replace_sleep_mask(self, new_mask: bytes) -> List[str]:
        """Stage a sleep mask replacement.

        Args:
            new_mask: New sleep mask bytes (BOF or raw shellcode).

        Returns:
            List of validation warnings.
        """
        warnings = self._sleepmask_surgeon.validate_mask(new_mask)
        self._new_sleep_mask = new_mask
        self._remove_sleep_mask = False
        logger.info("Sleep mask replacement staged: %d bytes", len(new_mask))
        return warnings

    def remove_sleep_mask(self) -> None:
        """Stage sleep mask removal."""
        self._remove_sleep_mask = True
        self._new_sleep_mask = None
        logger.info("Sleep mask removal staged")

    def extract_sleep_mask(self, output_path: Optional[str] = None) -> Optional[bytes]:
        """Extract the current sleep mask.

        Args:
            output_path: Optional file path to write the mask bytes.

        Returns:
            Sleep mask bytes, or None if not present.
        """
        mask_bytes = self._sleepmask_surgeon.extract(self._raw_data)
        if mask_bytes and output_path:
            with open(output_path, "wb") as f:
                f.write(mask_bytes)
            logger.info("Sleep mask extracted to %s (%d bytes)", output_path, len(mask_bytes))
        return mask_bytes

    # ── Beacon DLL Operations ──

    def extract_beacon_dll(self, output_path: Optional[str] = None) -> bytes:
        """Extract the beacon core DLL.

        Args:
            output_path: Optional file path to write the DLL.

        Returns:
            Raw beacon DLL bytes.
        """
        dll_bytes = self._payload_map.get_segment_bytes("SEG_BEACON_DLL")
        if output_path:
            with open(output_path, "wb") as f:
                f.write(dll_bytes)
            logger.info("Beacon DLL extracted to %s (%d bytes)", output_path, len(dll_bytes))
        return dll_bytes

    # ── Config Operations ──

    def extract_config_json(self, output_path: Optional[str] = None) -> Dict[str, Any]:
        """Extract the parsed config as a dict (and optionally to file).

        Args:
            output_path: Optional JSON file path.

        Returns:
            Config dictionary.
        """
        config = self._config_surgeon.fields
        if output_path:
            self._config_surgeon.export_json(output_path)
        return config

    # ── Validation ──

    def validate(self) -> ValidationResult:
        """Validate all staged modifications before building.

        Returns:
            ValidationResult with any errors/warnings.
        """
        result = ValidationResult()

        # Validate config
        config_result = self._validator.validate_config_integrity(
            self._config_surgeon.fields
        )
        result.errors.extend(config_result.errors)
        result.warnings.extend(config_result.warnings)

        # Validate new loader
        if self._new_loader is not None:
            loader_warnings = self._loader_surgeon.validate_loader(self._new_loader)
            result.warnings.extend(loader_warnings)

        # Validate new sleep mask
        if self._new_sleep_mask is not None:
            mask_warnings = self._sleepmask_surgeon.validate_mask(self._new_sleep_mask)
            result.warnings.extend(mask_warnings)

        result.passed = len(result.errors) == 0
        return result

    # ── Build ──

    def build(self) -> bytes:
        """Reassemble the payload with all staged modifications.

        Applies all modifications in order:
        1. Patch config into beacon DLL (if modified)
        2. Replace loader stub (if staged)
        3. Replace/remove sleep mask (if staged)

        Returns:
            Complete reassembled payload bytes.

        Raises:
            ValueError: If validation fails with errors.
        """
        # Start with the original payload
        working_payload = bytearray(self._raw_data)
        dll_offset = 0
        dll_size = 0

        # Get segment info
        loader_seg = self._payload_map.loader
        dll_seg = self._payload_map.beacon_dll
        config_loc = self._payload_map.config_location

        if dll_seg is not None:
            dll_offset = dll_seg.offset
            dll_size = dll_seg.size

        # Step 1: Patch config into the DLL (if modified)
        if self._config_surgeon.dirty_fields and config_loc is not None:
            encrypted_config = self._config_surgeon.encrypt()
            patch_offset = config_loc.offset_in_payload
            patch_end = patch_offset + len(encrypted_config)

            if patch_end <= len(working_payload):
                working_payload[patch_offset:patch_end] = encrypted_config
                logger.info(
                    "Config patched at offset %#x (%d bytes, %d fields modified)",
                    patch_offset, len(encrypted_config),
                    len(self._config_surgeon.dirty_fields),
                )
            else:
                logger.warning("Config patch extends beyond payload — skipping")

        payload = bytes(working_payload)

        # Step 2: Replace loader (if staged)
        if self._new_loader is not None:
            payload = self._loader_surgeon.replace(self._new_loader, payload)

        # Step 3: Handle sleep mask modifications
        if self._remove_sleep_mask:
            payload = self._sleepmask_surgeon.remove(payload)
        elif self._new_sleep_mask is not None:
            payload = self._sleepmask_surgeon.replace(self._new_sleep_mask, payload)

        # Post-build validation
        post_result = self._validator.validate_payload_structure(payload)
        if not post_result.ok:
            for err in post_result.errors:
                logger.error("Post-build validation error: %s", err)
        for warn in post_result.warnings:
            logger.warning("Post-build validation warning: %s", warn)

        hashes = compute_hashes(payload)
        logger.info(
            "Build complete: %d bytes (delta: %+d), SHA256: %s",
            len(payload), len(payload) - len(self._raw_data),
            hashes["sha256"][:16] + "...",
        )

        return payload

    # ── Utility ──

    def summary(self) -> Dict[str, Any]:
        """Get a summary of the current state.

        Returns:
            Dict with payload info, segment map, and pending modifications.
        """
        return {
            "source": self._source_path,
            "size": len(self._raw_data),
            "version": self.version,
            "segments": {
                seg_id: {
                    "offset": seg.offset,
                    "size": seg.size,
                    "entropy": round(seg.entropy, 2),
                }
                for seg_id, seg in self._payload_map.segments.items()
            },
            "config_fields": len(self._config_surgeon.fields),
            "config_modified": len(self._config_surgeon.dirty_fields),
            "pending_modifications": {
                "loader_replacement": self._new_loader is not None,
                "sleep_mask_replacement": self._new_sleep_mask is not None,
                "sleep_mask_removal": self._remove_sleep_mask,
                "config_changes": len(self._config_surgeon.dirty_fields),
            },
        }

    def __repr__(self) -> str:
        ver = self.version
        n_mods = (
            (1 if self._new_loader else 0) +
            (1 if self._new_sleep_mask else 0) +
            (1 if self._remove_sleep_mask else 0) +
            len(self._config_surgeon.dirty_fields)
        )
        return f"BeaconSurgeon({self._source_path!r}, {self.size}B, v{ver}, {n_mods} pending)"
