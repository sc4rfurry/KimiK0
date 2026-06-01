"""SurgeryValidator — Pre/post surgery structural validation.

Validates that surgical modifications produce a structurally
valid beacon payload that preserves CS functionality.
"""

import logging
from typing import Any, Dict, List, Optional

from cs_aggregator.surgery.payload_map import PayloadMap
from cs_aggregator.utils.entropy import shannon_entropy
from cs_aggregator.utils.hashing import compute_hashes

logger = logging.getLogger("cs_aggregator.surgery.validator")


class ValidationResult:
    """Result from a validation pass."""

    def __init__(self) -> None:
        self.passed: bool = True
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def add_error(self, msg: str) -> None:
        self.errors.append(msg)
        self.passed = False

    def add_warning(self, msg: str) -> None:
        self.warnings.append(msg)

    @property
    def ok(self) -> bool:
        return self.passed

    def __repr__(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        return f"ValidationResult({status}, {len(self.errors)} errors, {len(self.warnings)} warnings)"


class SurgeryValidator:
    """Validates payload integrity before and after surgery.

    Pre-surgery: Validates the original payload is parseable
    Post-surgery: Validates the modified payload is structurally sound
    Round-trip: Validates dissect→modify→reassemble→re-dissect consistency
    """

    def validate_payload_structure(self, payload: bytes) -> ValidationResult:
        """Validate basic payload structural integrity.

        Checks:
        - Non-empty
        - Minimum size for stageless (> 8KB)
        - MZ header present within first 16KB
        - Valid e_lfanew at MZ offset
        - Reasonable total size

        Args:
            payload: Raw payload bytes.

        Returns:
            ValidationResult with errors and warnings.
        """
        result = ValidationResult()

        if not payload:
            result.add_error("Payload is empty")
            return result

        if len(payload) < 8192:
            result.add_warning(
                f"Payload is small ({len(payload)} bytes) — "
                "may be a stager, not a stageless beacon"
            )

        # Find MZ header
        mz_offset = payload.find(b"MZ", 0, min(16384, len(payload)))
        if mz_offset == -1:
            result.add_error("No MZ header found in first 16KB — cannot locate beacon DLL")
            return result

        if mz_offset == 0:
            result.add_warning("MZ at offset 0 — no loader stub prepended")

        # Validate PE signature at e_lfanew
        if mz_offset + 0x3C + 4 <= len(payload):
            e_lfanew = int.from_bytes(payload[mz_offset + 0x3C:mz_offset + 0x40], "little")
            pe_sig_offset = mz_offset + e_lfanew
            if pe_sig_offset + 4 <= len(payload):
                pe_sig = payload[pe_sig_offset:pe_sig_offset + 4]
                if pe_sig != b"PE\x00\x00":
                    result.add_error(
                        f"Invalid PE signature at e_lfanew offset {pe_sig_offset:#x}: "
                        f"expected PE\\x00\\x00, got {pe_sig.hex()}"
                    )
            else:
                result.add_error(f"e_lfanew ({e_lfanew:#x}) points beyond payload bounds")
        else:
            result.add_error("Payload too small to read e_lfanew at MZ header")

        # Size sanity
        if len(payload) > 10 * 1024 * 1024:
            result.add_warning(f"Payload is very large ({len(payload)} bytes) — unusual for CS beacon")

        return result

    def validate_config_integrity(
        self,
        config_json: Dict[str, Any],
    ) -> ValidationResult:
        """Validate that a config dict has required fields.

        Args:
            config_json: The config dict to validate.

        Returns:
            ValidationResult.
        """
        result = ValidationResult()

        required_fields = [
            "SETTING_PROTOCOL",
            "SETTING_PORT",
            "SETTING_SLEEPTIME",
        ]
        for field_name in required_fields:
            if field_name not in config_json:
                result.add_error(f"Required config field missing: {field_name}")

        # Validate field value ranges
        port = config_json.get("SETTING_PORT", 0)
        if isinstance(port, int) and (port < 1 or port > 65535):
            result.add_warning(f"SETTING_PORT ({port}) is outside valid range 1-65535")

        jitter = config_json.get("SETTING_JITTER", 0)
        if isinstance(jitter, int) and (jitter < 0 or jitter > 99):
            result.add_warning(f"SETTING_JITTER ({jitter}) is outside valid range 0-99")

        sleep = config_json.get("SETTING_SLEEPTIME", 0)
        if isinstance(sleep, int) and sleep < 0:
            result.add_warning(f"SETTING_SLEEPTIME ({sleep}) is negative")

        return result

    def validate_round_trip(
        self,
        original_config: Dict[str, Any],
        rebuilt_config: Dict[str, Any],
        modified_fields: Optional[set] = None,
    ) -> ValidationResult:
        """Validate that unmodified fields survive a round-trip.

        Compares original and rebuilt configs. Fields in modified_fields
        are expected to differ; all others must match.

        Args:
            original_config: Config before surgery.
            rebuilt_config: Config after dissect→modify→reassemble→re-dissect.
            modified_fields: Set of field names that were intentionally changed.

        Returns:
            ValidationResult.
        """
        result = ValidationResult()
        modified_fields = modified_fields or set()

        for key, orig_val in original_config.items():
            if key.startswith("_"):
                continue  # Skip metadata fields
            if key in modified_fields:
                continue  # Expected to differ

            rebuilt_val = rebuilt_config.get(key)
            if rebuilt_val is None:
                result.add_error(f"Field {key} lost during round-trip (was: {orig_val!r})")
            elif rebuilt_val != orig_val:
                result.add_warning(
                    f"Field {key} changed during round-trip: "
                    f"{orig_val!r} → {rebuilt_val!r}"
                )

        # Check no unexpected new fields appeared
        for key in rebuilt_config:
            if key.startswith("_"):
                continue
            if key not in original_config:
                result.add_warning(f"New field {key} appeared after round-trip")

        return result

    def validate_loader_dll_boundary(
        self,
        payload: bytes,
        loader_size: int,
    ) -> ValidationResult:
        """Validate loader→DLL boundary after surgery.

        Ensures the MZ header is at the expected offset after
        loader replacement.

        Args:
            payload: The modified payload bytes.
            loader_size: Expected loader stub size.

        Returns:
            ValidationResult.
        """
        result = ValidationResult()

        if loader_size > len(payload):
            result.add_error("Loader size exceeds payload length")
            return result

        # Check MZ at the expected boundary
        expected_mz_offset = loader_size
        if expected_mz_offset + 2 <= len(payload):
            mz_bytes = payload[expected_mz_offset:expected_mz_offset + 2]
            if mz_bytes != b"MZ":
                # Search for nearest MZ
                actual_mz = payload.find(b"MZ", max(0, expected_mz_offset - 32),
                                          expected_mz_offset + 32)
                if actual_mz == -1:
                    result.add_error(
                        f"No MZ header at expected boundary (offset {expected_mz_offset:#x})"
                    )
                else:
                    result.add_warning(
                        f"MZ header at {actual_mz:#x}, expected at {expected_mz_offset:#x} "
                        f"(off by {actual_mz - expected_mz_offset:+d} bytes)"
                    )

        return result
