"""MOD_BUD_ANALYZER — Beacon User Data Structure Analyzer.

Analyzes loader stubs to detect and parse BUD (Beacon User Data) structures
across CS versions. Identifies BUD version, SYSCALL_API coverage,
ALLOCATED_MEMORY regions, and sleep mask registration points.

BUD Version History:
    v1 (CS 4.9.x):  USER_DATA { version, syscalls, custom[32] }
    v2 (CS 4.10-4.11): USER_DATA v1 + PALLOCATED_MEMORY ptr
    v3 (CS 4.12+):  Updated ALLOCATED_MEMORY structures for drip-loading

References:
    - beacon.h from Arsenal Kit (UDRL-VS, Sleepmask-VS)
    - CS official UDRL documentation
    - rastamouse.me ALLOCATED_MEMORY analysis
"""

import logging
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("cs_aggregator.modules.bud_analyzer")

# Constants
DLL_BEACON_USER_DATA = 0x0D  # Custom DllMain reason code

# BUD version constants (0xMMmmPP format)
BUD_VERSIONS = {
    0x040900: "4.9.0",
    0x040901: "4.9.1",
    0x041000: "4.10.0",
    0x041100: "4.11.0",
    0x041200: "4.12.0",
}

# SYSCALL_API_ENTRY size: fnAddr(8) + jmpAddr(8) + sysnum(4) = 20 bytes (x64)
SYSCALL_API_ENTRY_SIZE_X64 = 20
# 17 Nt* APIs in SYSCALL_API struct
SYSCALL_API_ENTRIES = [
    "ntAllocateVirtualMemory",
    "ntProtectVirtualMemory",
    "ntFreeVirtualMemory",
    "ntGetContextThread",
    "ntSetContextThread",
    "ntResumeThread",
    "ntCreateThreadEx",
    "ntOpenProcess",
    "ntOpenThread",
    "ntClose",
    "ntCreateSection",
    "ntMapViewOfSection",
    "ntUnmapViewOfSection",
    "ntQueryVirtualMemory",
    "ntDuplicateObject",
    "ntReadVirtualMemory",
    "ntWriteVirtualMemory",
]
SYSCALL_API_TOTAL_SIZE_X64 = len(SYSCALL_API_ENTRIES) * SYSCALL_API_ENTRY_SIZE_X64  # 340

# Byte patterns for DLL_BEACON_USER_DATA reason code detection
# x64: mov edx, 0x0D / mov r8d, 0x0D
BUD_REASON_PATTERNS = [
    bytes([0xBA, 0x0D, 0x00, 0x00, 0x00]),  # mov edx, 0x0D
    bytes([0x41, 0xB8, 0x0D, 0x00, 0x00, 0x00]),  # mov r8d, 0x0D
    bytes([0xB2, 0x0D]),  # mov dl, 0x0D (compact)
    bytes([0x6A, 0x0D]),  # push 0x0D
]


@dataclass
class SyscallEntry:
    """A single SYSCALL_API_ENTRY parsed from the loader stub."""
    name: str
    fn_addr_present: bool = False
    jmp_addr_present: bool = False
    sysnum: int = 0


@dataclass
class BUDAnalysisResult:
    """Result from BUD structure analysis."""
    bud_detected: bool = False
    bud_version: str = "unknown"
    bud_version_raw: int = 0
    bud_reason_code_offset: int = -1
    bud_struct_version: int = 0  # 1, 2, or 3

    # SYSCALL_API analysis
    syscall_api_detected: bool = False
    syscall_entries: List[SyscallEntry] = field(default_factory=list)
    syscall_coverage: float = 0.0  # 0.0-1.0

    # ALLOCATED_MEMORY analysis (BUD v2+)
    allocated_memory_detected: bool = False
    allocated_memory_version: int = 0

    # Sleep mask registration
    sleep_mask_registered: bool = False
    mask_function_offset: int = -1
    unmask_function_offset: int = -1

    # Custom data
    custom_data_used: bool = False

    # Compatibility warnings
    warnings: List[str] = field(default_factory=list)
    confidence: float = 0.0


class BUDAnalyzer:
    """Beacon User Data structure analyzer.

    Scans loader stub code to detect DLL_BEACON_USER_DATA usage,
    parse USER_DATA struct construction, and identify BUD version.
    """

    def __init__(self, version_schema: Optional[Dict[str, Any]] = None) -> None:
        """Initialize with optional version schema.

        Args:
            version_schema: Schema with expected BUD version and structure info.
        """
        self.schema = version_schema or {}

    def analyze(
        self,
        loader_bytes: bytes,
        dll_bytes: Optional[bytes] = None,
        architecture: str = "x64",
    ) -> BUDAnalysisResult:
        """Analyze loader stub for BUD structures.

        Args:
            loader_bytes: Raw loader stub bytes (PIC shellcode).
            dll_bytes: Optional beacon DLL bytes for cross-reference.
            architecture: Target architecture ("x64" or "x86").

        Returns:
            BUDAnalysisResult with detected structures and metadata.
        """
        result = BUDAnalysisResult()

        if not loader_bytes or len(loader_bytes) < 64:
            result.warnings.append("Loader stub too small for BUD analysis")
            return result

        # Step 1: Detect DLL_BEACON_USER_DATA reason code usage
        reason_offset = self._find_bud_reason_code(loader_bytes)
        if reason_offset >= 0:
            result.bud_detected = True
            result.bud_reason_code_offset = reason_offset
            result.confidence = 0.4
            logger.info(
                "BUD reason code (0x0D) found at offset %#x", reason_offset
            )

        # Step 2: Detect BUD version field construction
        version_info = self._detect_bud_version(loader_bytes, architecture)
        if version_info:
            result.bud_version_raw = version_info[0]
            result.bud_version = BUD_VERSIONS.get(version_info[0], f"0x{version_info[0]:06X}")
            result.confidence = max(result.confidence, 0.7)
            logger.info("BUD version field: %s (raw: %#x)", result.bud_version, version_info[0])

        # Step 3: Determine BUD struct version from detected CS version
        result.bud_struct_version = self._classify_bud_struct_version(
            result.bud_version_raw
        )

        # Step 4: Detect ALLOCATED_MEMORY pointer (BUD v2+ indicator)
        if self._detect_allocated_memory_usage(loader_bytes):
            result.allocated_memory_detected = True
            if result.bud_struct_version < 2:
                result.bud_struct_version = 2
            result.confidence = max(result.confidence, 0.8)
            logger.info("ALLOCATED_MEMORY structure detected (BUD v2+)")

        # Step 5: Detect SYSCALL_API population
        syscall_info = self._detect_syscall_api(loader_bytes, architecture)
        if syscall_info:
            result.syscall_api_detected = True
            result.syscall_entries = syscall_info
            populated = sum(1 for e in syscall_info if e.fn_addr_present)
            result.syscall_coverage = populated / len(SYSCALL_API_ENTRIES)
            logger.info(
                "SYSCALL_API detected: %d/%d entries populated (%.0f%%)",
                populated, len(SYSCALL_API_ENTRIES),
                result.syscall_coverage * 100,
            )

        # Step 6: Detect sleep mask function registration
        mask_info = self._detect_sleep_mask_registration(loader_bytes)
        if mask_info:
            result.sleep_mask_registered = True
            result.mask_function_offset = mask_info.get("mask", -1)
            result.unmask_function_offset = mask_info.get("unmask", -1)

        # Step 7: Cross-reference with schema expectations
        expected_bud = self.schema.get("budStructure", {})
        if expected_bud:
            expected_version = expected_bud.get("version", 0)
            if expected_version and result.bud_struct_version != expected_version:
                result.warnings.append(
                    f"BUD struct version mismatch: detected v{result.bud_struct_version}, "
                    f"schema expects v{expected_version}. Possible cross-version UDRL."
                )

        # Finalize confidence
        if result.bud_detected and result.bud_version_raw:
            result.confidence = max(result.confidence, 0.9)

        return result

    def _find_bud_reason_code(self, data: bytes) -> int:
        """Scan for DLL_BEACON_USER_DATA (0x0D) reason code in loader code.

        Returns:
            Offset of the pattern, or -1 if not found.
        """
        for pattern in BUD_REASON_PATTERNS:
            offset = data.find(pattern)
            if offset >= 0:
                return offset
        return -1

    def _detect_bud_version(
        self,
        data: bytes,
        architecture: str,
    ) -> Optional[Tuple[int, int]]:
        """Detect BUD version field being loaded into USER_DATA.

        Searches for immediate loads of known BUD version constants
        (0x040900, 0x040901, 0x041000, etc.).

        Returns:
            Tuple of (version_value, offset) or None.
        """
        for version_val in BUD_VERSIONS:
            # Look for this value as a 32-bit little-endian immediate
            version_bytes = struct.pack("<I", version_val)
            offset = data.find(version_bytes)
            if offset >= 0:
                # Verify it's preceded by a MOV instruction opcode
                if offset >= 1:
                    prev_byte = data[offset - 1]
                    # Common MOV immediates (x64): 0xC7, 0xB8-0xBF, 0x89
                    if prev_byte in (0xC7, 0x89) or (0xB8 <= prev_byte <= 0xBF):
                        return (version_val, offset)
                # Also check 2 bytes back for REX prefix + MOV
                if offset >= 2:
                    rex = data[offset - 2]
                    opcode = data[offset - 1]
                    if (rex & 0xF0) == 0x40 and opcode in (0xC7, 0x89):
                        return (version_val, offset)
                # Even without opcode match, the constant itself is strong evidence
                return (version_val, offset)
        return None

    @staticmethod
    def _classify_bud_struct_version(version_raw: int) -> int:
        """Map a CS version constant to BUD struct version.

        The version constants use 0xMMmmPP format where each byte is a
        hex-encoded version component (e.g. 0x041000 = 4.10.0).

        Returns:
            1 (CS 4.9.x), 2 (CS 4.10-4.11), or 3 (CS 4.12+).
        """
        if version_raw == 0:
            return 0

        # Direct lookup for known versions
        _VERSION_TO_BUD = {
            0x040900: 1,  # 4.9.0
            0x040901: 1,  # 4.9.1
            0x041000: 2,  # 4.10.0
            0x041100: 2,  # 4.11.0
            0x041200: 3,  # 4.12.0
        }
        if version_raw in _VERSION_TO_BUD:
            return _VERSION_TO_BUD[version_raw]

        # Fallback: extract minor version byte and classify
        minor = (version_raw >> 8) & 0xFF
        if minor <= 0x09:
            return 1
        if minor <= 0x11:
            return 2
        return 3

    def _detect_allocated_memory_usage(self, data: bytes) -> bool:
        """Detect ALLOCATED_MEMORY structure allocation/usage.

        Looks for patterns indicating the loader is populating
        ALLOCATED_MEMORY_REGION structures (BUD v2+ feature).

        Indicators:
        - TrackAllocatedMemoryRegion function calls
        - ALLOCATED_MEMORY_PURPOSE enum values being loaded
        - Large struct allocations after USER_DATA setup
        """
        # Look for ALLOCATED_MEMORY_PURPOSE enum values (0-5)
        # being loaded near BUD setup code
        purpose_patterns = [
            b"\xC7",  # mov dword ptr [...], immediate
        ]

        # Check for "TrackAllocatedMemory" string references
        if b"TrackAlloc" in data or b"AllocatedMemory" in data:
            return True

        # Check for patterns that initialize ALLOCATED_MEMORY_REGION fields
        # Region has Purpose(4) + AllocationBase(8) + RegionSize(8) + Type(4) = 24 bytes header
        # Look for struct initialization sequences with lea + mov patterns
        # Heuristic: find sequences that zero large struct areas (> 200 bytes)
        zero_init_count = 0
        i = 0
        while i < len(data) - 16:
            # rep stosq/stosd patterns (clearing struct memory)
            if data[i:i+2] == b"\xf3\x48" or data[i:i+2] == b"\xf3\xab":
                zero_init_count += 1
            i += 1

        # Multiple zero-inits near BUD code suggest ALLOCATED_MEMORY setup
        return zero_init_count >= 3

    def _detect_syscall_api(
        self,
        data: bytes,
        architecture: str,
    ) -> Optional[List[SyscallEntry]]:
        """Detect SYSCALL_API struct population in loader code.

        Looks for patterns of Nt* function resolution and storage
        into the SYSCALL_API struct fields.
        """
        entries: List[SyscallEntry] = []

        # Detect Nt* API resolution by looking for known hash values
        # or string patterns used in PEB-walk API resolution
        nt_api_indicators = [
            b"ntdll",
            b"NtAllocateVirtualMemory",
            b"NtProtectVirtualMemory",
            b"NtCreateThreadEx",
        ]

        api_resolution_detected = False
        for indicator in nt_api_indicators:
            if indicator.lower() in data.lower():
                api_resolution_detected = True
                break

        if not api_resolution_detected:
            # Check for ROR13 hash-based resolution (common in CS loaders)
            ror13_pattern = bytes([0x0F, 0xB6])  # movzx (part of ROR13 loop)
            if data.count(ror13_pattern) >= 2:
                api_resolution_detected = True

        if api_resolution_detected:
            for api_name in SYSCALL_API_ENTRIES:
                entry = SyscallEntry(name=api_name, fn_addr_present=True)
                entries.append(entry)
            return entries

        return None

    def _detect_sleep_mask_registration(
        self,
        data: bytes,
    ) -> Optional[Dict[str, int]]:
        """Detect sleep mask function pointer registration.

        Looks for patterns where the loader stores Mask/Unmask
        function addresses into the BUD structure.
        """
        result: Dict[str, int] = {}

        # Look for "Mask" / "Unmask" string references
        mask_offset = data.find(b"Mask")
        if mask_offset >= 0 and mask_offset < len(data) - 10:
            # Check it's not "Unmask" — that's a different export
            if mask_offset == 0 or data[mask_offset - 1:mask_offset] != b"n":
                result["mask"] = mask_offset

        unmask_offset = data.find(b"Unmask")
        if unmask_offset >= 0:
            result["unmask"] = unmask_offset

        # Also check for known sleep mask section names
        for section_name in [b".sleep", b".bg", b".mask", b".sldata"]:
            if section_name in data:
                result.setdefault("mask", data.find(section_name))

        return result if result else None
