"""MOD_INPUT — Input Handler & Classifier.

Accepts, validates, normalizes, and classifies input payloads.
Detects payload type (staged vs stageless), architecture (x86 vs x64),
and format (raw shellcode, PE, memory dump).
"""

import os
from typing import Optional

from cs_aggregator.utils.errors import (
    PayloadError,
    PayloadTooSmallError,
    UnsupportedFormatError,
)
from cs_aggregator.utils.entropy import shannon_entropy
from cs_aggregator.utils.hashing import compute_hashes
from cs_aggregator.utils.types import ClassificationResult


STAGLESS_MIN_SIZE = 8192  # 8KB
STAGED_MIN_SIZE = 256
STAGED_MAX_SIZE = 8192

# PE magic bytes
MZ_MAGIC = b"MZ"
PE_MAGIC = b"PE\x00\x00"

# Common shellcode architecture detection patterns
X64_CALL_POP = b"\xe8\x00\x00\x00\x00"  # call $+5; pop reg
X86_CALL_POP = b"\xe8\x00\x00\x00\x00\x5b"  # call $+5; pop ebx


class InputHandler:
    """Handles payload ingestion, validation, and classification."""

    @staticmethod
    def read_file(path: str) -> bytes:
        """Read a payload file from disk.

        Args:
            path: Path to the payload file.

        Returns:
            Raw bytes of the payload.

        Raises:
            PayloadError: If the file cannot be read.
        """
        if not os.path.isfile(path):
            raise PayloadError(f"File not found: {path}")

        try:
            with open(path, "rb") as f:
                return f.read()
        except OSError as e:
            raise PayloadError(f"Failed to read file {path}: {e}")

    @staticmethod
    def read_stdin() -> bytes:
        """Read payload bytes from stdin.

        Returns:
            Raw bytes read from stdin.

        Raises:
            PayloadError: If stdin is empty.
        """
        import sys
        data = sys.stdin.buffer.read()
        if not data:
            raise PayloadError("No data received from stdin")
        return data

    @staticmethod
    def validate_size(data: bytes, strict: bool = True) -> int:
        """Validate payload size meets minimum thresholds.

        Args:
            data: Payload bytes.
            strict: If True, raise on invalid size. If False, return status code.

        Returns:
            0 if size is valid. If not strict: -1 if too small for staged, -2 if too small for stageless.

        Raises:
            PayloadTooSmallError: If data is below minimum size.
        """
        if len(data) < STAGED_MIN_SIZE:
            if strict:
                raise PayloadTooSmallError(
                    f"Payload too small: {len(data)} bytes "
                    f"(minimum {STAGED_MIN_SIZE} bytes for staged, "
                    f"{STAGLESS_MIN_SIZE} bytes for stageless)"
                )
            return -1

        if len(data) < STAGLESS_MIN_SIZE:
            if strict:
                # Warn but don't fail — could be a stager
                return -2

        return 0

    @staticmethod
    def detect_architecture(data: bytes) -> str:
        """Detect payload architecture (x86 vs x64).

        Uses PE header machine type if available (supports spoofed magic),
        otherwise falls back to shellcode pattern analysis.

        Args:
            data: Payload bytes.

        Returns:
            "x64", "x86", or "unknown".
        """
        from cs_aggregator.utils.pe_utils import find_pe_offset

        # Check PE header if present (supports MZ, OICA, OOPS, NO, etc.)
        mz_offset = find_pe_offset(data, max_search=0x10000)
        if mz_offset >= 0 and mz_offset + 64 < len(data):
            pe_offset = int.from_bytes(data[mz_offset + 0x3C:mz_offset + 0x40], "little")
            if pe_offset + 6 <= len(data):
                machine_bytes = data[mz_offset + pe_offset + 4:mz_offset + pe_offset + 6]
                if len(machine_bytes) == 2:
                    machine = int.from_bytes(machine_bytes, "little")
                    if machine == 0x8664:
                        return "x64"
                    elif machine == 0x14C:
                        return "x86"

        # Shellcode heuristic: look for call/pop patterns
        if X64_CALL_POP in data[:512]:
            return "x64"
        if X86_CALL_POP in data[:512]:
            return "x86"

        return "unknown"

    @staticmethod
    def detect_format(path: str, data: bytes) -> str:
        """Detect payload format. Supports spoofed PE magic bytes.

        Args:
            path: Original file path (for extension hints).
            data: Payload bytes.

        Returns:
            "raw_shellcode", "pe_exe", "pe_dll", or "memory_dump".
        """
        from cs_aggregator.utils.pe_utils import find_pe_offset

        ext = os.path.splitext(path)[1].lower()

        # Check for PE headers (standard MZ + spoofed magics)
        mz_offset = find_pe_offset(data, max_search=0x10000)
        if mz_offset >= 0 and mz_offset + 64 < len(data):
            try:
                pe_offset = int.from_bytes(data[mz_offset + 0x3C:mz_offset + 0x40], "little")
                pe_sig = data[mz_offset + pe_offset:mz_offset + pe_offset + 4]
                if pe_sig == PE_MAGIC or pe_sig[:2] in (b'NO', b'PE'):
                    characteristics_offset = mz_offset + pe_offset + 22
                    if characteristics_offset + 2 <= len(data):
                        characteristics = int.from_bytes(
                            data[characteristics_offset:characteristics_offset + 2], "little"
                        )
                        if characteristics & 0x2000:  # IMAGE_FILE_DLL
                            return "pe_dll"
                        return "pe_exe"
            except (IndexError, ValueError):
                pass

        # Extension-based hints
        if ext in (".exe",):
            return "pe_exe"
        if ext in (".dll",):
            return "pe_dll"
        if ext in (".bin",):
            return "raw_shellcode"

        if mz_offset >= 0:
            return "pe_exe"

        return "raw_shellcode"

    @staticmethod
    def classify_payload(data: bytes, path: Optional[str] = None) -> ClassificationResult:
        """Classify the payload — staged vs stageless, architecture, format.

        This is the main entry point for MOD_INPUT.

        Args:
            data: Raw payload bytes.
            path: Optional original file path for format detection.

        Returns:
            ClassificationResult with all classification metadata.
        """
        format_str = "raw_shellcode"
        if path:
            format_str = InputHandler.detect_format(path, data)

        architecture = InputHandler.detect_architecture(data)

        # Staged vs stageless classification
        payload_type = "stageless"
        confidence = 0.7
        warnings = []

        if len(data) < STAGED_MAX_SIZE:
            payload_type = "staged"
            confidence = 0.8
        elif len(data) < STAGLESS_MIN_SIZE:
            payload_type = "staged"
            confidence = 0.6
            warnings.append(f"Payload size ({len(data)} bytes) is between staged and stageless thresholds")

        # No MZ found — confidence penalty but still check for OICA/OOPS
        from cs_aggregator.utils.pe_utils import find_pe_offset
        spoofed_offset = find_pe_offset(data, max_search=0x10000)
        if spoofed_offset >= 0 and payload_type == "stageless":
            # Found a spoofed PE header — restore confidence
            pass
        elif payload_type == "stageless":
            confidence -= 0.2
            warnings.append("No PE header found (MZ or spoofed) in stageless-classified payload (may be encrypted)")

        # Calculate entropy
        entropy = shannon_entropy(data)

        hashes = compute_hashes(data)

        return ClassificationResult(
            payload_type=payload_type,
            architecture=architecture,
            format=format_str,
            file_size=len(data),
            hashes=hashes,
            entropy_score=entropy,
            confidence_score=max(0.1, round(confidence, 2)),
            warnings=warnings,
        )
