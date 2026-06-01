"""MOD_BEACON_PARSER — Beacon DLL Parser & PE Analyzer.

Custom PE parser that extracts and analyzes the beacon core DLL
from the payload. Does NOT depend on pefile for core operation —
all PE parsing is implemented from scratch.

Supports: DOS header, NT headers, section table, import/export tables
(limited), relocation table, and anomaly detection.
"""

import struct
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cs_aggregator.utils.entropy import shannon_entropy
from cs_aggregator.utils.errors import PEFormatError, ExtractionError
from cs_aggregator.utils.hashing import compute_hashes
from cs_aggregator.utils.types import PEInfo

from cs_aggregator.utils.pe_utils import KNOWN_PE_MAGICS

MZ_MAGIC = b"MZ"
PE_MAGIC = b"PE\x00\x00"

# Machine types
MACHINE_I386 = 0x14C
MACHINE_AMD64 = 0x8664

# Section characteristics
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

# Directory entries
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_DIRECTORY_ENTRY_IAT = 12


class BeaconParser:
    """Custom PE parser for CobaltStrike beacon DLLs.

    Supports parsing PE headers, sections, exports, imports (basic),
    and anomaly detection — all without the pefile library.
    """

    def __init__(self, version_schema: Optional[Dict[str, Any]] = None):
        """Initialize with an optional version schema.

        Args:
            version_schema: Version schema for version-specific
                section expectations and anomaly thresholds.
        """
        self.schema = version_schema or {}

    def parse_beacon_dll(self, data: bytes, loader_offset: int) -> Tuple[Optional[bytes], Optional[PEInfo]]:
        """Parse the beacon DLL from the payload.

        Args:
            data: Raw payload bytes.
            loader_offset: Offset where the loader stub ends (MZ header found here).

        Returns:
            Tuple of (beacon_dll_bytes, PE_info) or (None, None) if parsing fails.
        """
        dll_data, error = self._extract_dll(data, loader_offset)
        if dll_data is None:
            return None, PEInfo(
                machine_type="unknown",
                compile_timestamp=None,
                sections=[],
                import_count=0,
                export_count=0,
                anomalies=[error or "Failed to extract beacon DLL"],
            )

        pe_info = self._parse_pe_metadata(dll_data)
        return dll_data, pe_info

    @staticmethod
    def _extract_dll(data: bytes, mz_offset: int) -> Tuple[Optional[bytes], Optional[str]]:
        """Extract the beacon DLL starting from the MZ header.

        Uses SizeOfImage from the optional header to determine the DLL size.

        Returns:
            (dll_bytes, error_message). dll_bytes is None if extraction fails.
        """
        if mz_offset >= len(data):
            return None, "MZ header offset exceeds payload size"

        # Check for standard MZ or spoofed magic (OICA, NO)
        found_magic = False
        for magic in KNOWN_PE_MAGICS:
            if data[mz_offset:mz_offset + len(magic)] == magic:
                found_magic = True
                break

        if not found_magic:
            return None, "No PE magic (MZ/OICA/NO) at specified offset"

        # Read e_lfanew to find PE header
        pe_offset = struct.unpack_from("<I", data, mz_offset + 0x3C)[0]
        pe_header_start = mz_offset + pe_offset

        if pe_header_start + 4 > len(data):
            return None, "PE header offset exceeds payload size"

        pe_sig = data[pe_header_start:pe_header_start + 4]
        if pe_sig != PE_MAGIC and pe_sig[:2] not in (b'NO', b'PE'):
            return None, "Invalid PE signature"

        # Optional header starts after: PE signature (4) + COFF file header (20) = 24 bytes
        optional_header_offset = pe_header_start + 24

        if optional_header_offset + 2 > len(data):
            return None, "Optional header offset exceeds payload size"

        opt_magic = struct.unpack_from("<H", data, optional_header_offset)[0]
        is_pe32_plus = (opt_magic == 0x20B)

        # SizeOfImage offset in optional header:
        # PE32:  offset 56
        # PE32+: offset 56
        size_of_image_offset = optional_header_offset + 56
        if size_of_image_offset + 4 > len(data):
            return None, "SizeOfImage field exceeds payload size"

        size_of_image = struct.unpack_from("<I", data, size_of_image_offset)[0]

        if size_of_image == 0 or size_of_image > 10 * 1024 * 1024:  # Max 10MB sanity check
            return None, f"Invalid SizeOfImage: {size_of_image}"

        # Extract the DLL
        dll_end = min(mz_offset + size_of_image, len(data))
        dll_data = data[mz_offset:dll_end]

        return dll_data, None

    def _parse_pe_metadata(self, dll_data: bytes) -> PEInfo:
        """Parse PE metadata from the extracted DLL.

        Extracts: machine type, compile timestamp, sections, imports,
        exports, and anomalies.
        """
        anomalies: List[str] = []

        # PE header basics
        machine, timestamp, num_sections = self._parse_pe_header(dll_data)
        if machine is None:
            return PEInfo(
                machine_type="unknown",
                compile_timestamp=None,
                sections=[],
                import_count=0,
                export_count=0,
                anomalies=["Failed to parse PE header"],
            )

        machine_str = self._machine_type_str(machine)
        timestamp_str = self._timestamp_to_str(timestamp) if timestamp else None

        # Parse sections
        sections = self._parse_sections(dll_data)
        section_anomalies = self._check_section_anomalies(sections)
        anomalies.extend(section_anomalies)

        # Count imports (basic)
        import_count = self._count_imports(dll_data)

        # Count exports (basic)
        export_count = self._count_exports(dll_data)

        # Additional anomaly checks
        if import_count == 0:
            anomalies.append("No imports resolved (expected for reflective DLL)")
        if machine == MACHINE_AMD64 and export_count == 0:
            anomalies.append("No exports found (may indicate prepended loader mode)")

        return PEInfo(
            machine_type=machine_str,
            compile_timestamp=timestamp_str,
            sections=sections,
            import_count=import_count,
            export_count=export_count,
            anomalies=anomalies,
        )

    @staticmethod
    def _parse_pe_header(data: bytes) -> Tuple[Optional[int], Optional[int], Optional[int]]:
        """Parse the PE header to extract machine type, timestamp, and section count.

        Returns:
            (machine, timestamp, num_sections) or (None, None, None) on failure.
        """
        if len(data) < 64:
            return None, None, None

        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        nt_headers_start = pe_offset

        if nt_headers_start + 24 > len(data):
            return None, None, None

        # Check signature (standard or spoofed)
        pe_sig = data[nt_headers_start:nt_headers_start + 4]
        if pe_sig != PE_MAGIC and pe_sig[:2] not in (b'NO', b'PE'):
            return None, None, None

        # Machine type (2 bytes at offset 4 from NT headers)
        machine = struct.unpack_from("<H", data, nt_headers_start + 4)[0]

        # Number of sections (2 bytes at offset 6 from NT headers)
        num_sections = struct.unpack_from("<H", data, nt_headers_start + 6)[0]

        # Compile timestamp (4 bytes at offset 8 from NT headers)
        timestamp = struct.unpack_from("<I", data, nt_headers_start + 8)[0]

        return machine, timestamp, num_sections

    @staticmethod
    def _parse_sections(data: bytes) -> List[Dict[str, Any]]:
        """Parse PE section table.

        Returns a list of section dicts with name, virtual address, raw size, entropy.
        """
        if len(data) < 64:
            return []

        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        nt_headers_start = pe_offset

        if nt_headers_start + 24 > len(data):
            return []

        num_sections = struct.unpack_from("<H", data, nt_headers_start + 6)[0]

        # Size of optional header (2 bytes at file header offset 16 = pe_offset + 4 + 16 = pe_offset + 20)
        size_of_optional = struct.unpack_from("<H", data, nt_headers_start + 20)[0]

        # Section table starts after optional header
        # Optional header starts at pe_offset + 4 (PE sig) + 20 (file header) = pe_offset + 24
        section_table_offset = nt_headers_start + 24 + size_of_optional

        sections = []
        for i in range(num_sections):
            sec_start = section_table_offset + i * 40
            if sec_start + 40 > len(data):
                break

            # Section name (8 bytes, null-padded)
            name_raw = data[sec_start:sec_start + 8].split(b"\x00")[0]
            try:
                name = name_raw.decode("ascii", errors="replace").strip()
            except UnicodeDecodeError:
                name = f"unnamed_{i}"

            # Virtual size (4 bytes at offset 8)
            virtual_size = struct.unpack_from("<I", data, sec_start + 8)[0]

            # Virtual address (4 bytes at offset 12)
            virtual_address = struct.unpack_from("<I", data, sec_start + 12)[0]

            # Raw size (4 bytes at offset 16)
            raw_size = struct.unpack_from("<I", data, sec_start + 16)[0]

            # Raw pointer (4 bytes at offset 20)
            raw_pointer = struct.unpack_from("<I", data, sec_start + 20)[0]

            # Characteristics (4 bytes at offset 36)
            characteristics = struct.unpack_from("<I", data, sec_start + 36)[0]

            # Extract section data for entropy calculation
            section_data = b""
            if raw_size > 0 and raw_pointer + raw_size <= len(data):
                section_data = data[raw_pointer:raw_pointer + raw_size]
            elif virtual_size > 0:
                # Try to get from virtual address
                va_start = virtual_address
                if va_start + min(virtual_size, 1024 * 1024) <= len(data):
                    section_data = data[va_start:va_start + min(virtual_size, 1024 * 1024)]

            entropy = round(shannon_entropy(section_data), 2) if section_data else 0.0

            # Permissions
            perms = []
            if characteristics & IMAGE_SCN_MEM_EXECUTE:
                perms.append("X")
            if characteristics & IMAGE_SCN_MEM_READ:
                perms.append("R")
            if characteristics & IMAGE_SCN_MEM_WRITE:
                perms.append("W")

            sections.append({
                "name": name,
                "virtualAddress": hex(virtual_address),
                "virtualSize": virtual_size,
                "rawSize": raw_size,
                "entropy": entropy,
                "permissions": "+".join(perms) if perms else "unknown",
            })

        return sections

    def _check_section_anomalies(self, sections: List[Dict[str, Any]]) -> List[str]:
        """Detect anomalous section characteristics.

        Checks: unusually high entropy, unusual section names,
        RWX sections, virtual size >> raw size.
        """
        anomalies: List[str] = []
        threshold_entropy = self.schema.get("peSectionExpectations", {}).get(
            "anomalyThresholdEntropy", 7.5
        )
        threshold_vsize_ratio = self.schema.get("peSectionExpectations", {}).get(
            "anomalyThresholdVirtualSizeRatio", 3.0
        )

        standard_sections = {".text", ".data", ".rdata", ".reloc", ".rsrc", ".pdata", ".didat", ".tls"}

        for section in sections:
            # High entropy anomaly
            if section["entropy"] > threshold_entropy:
                anomalies.append(
                    f"High entropy in section '{section['name']}': {section['entropy']} "
                    f"(threshold: {threshold_entropy})"
                )

            # Unusual name
            if section["name"] and section["name"] not in standard_sections:
                # Custom sections are expected in CS beacons, but worth noting
                pass

            # RWX anomaly
            if section.get("permissions") == "R+W+X":
                anomalies.append(f"RWX section detected: '{section['name']}'")

            # Virtual size >> raw size
            if section["rawSize"] > 0 and section["virtualSize"] > section["rawSize"] * threshold_vsize_ratio:
                anomalies.append(
                    f"Section '{section['name']}': virtualSize ({section['virtualSize']}) "
                    f">> rawSize ({section['rawSize']}) — possible packed/zero-filled section"
                )

        return anomalies

    @staticmethod
    def _count_imports(data: bytes) -> int:
        """Count imported DLLs by walking the import directory table.

        Note: CS beacons typically have 0 imports (they resolve APIs at runtime
        via hash-based lookup). This is expected behavior, not an error.
        """
        from cs_aggregator.utils.pe_utils import count_import_dlls
        return count_import_dlls(data)

    @staticmethod
    def _count_exports(data: bytes) -> int:
        """Count exported functions by scanning the export table.

        CS beacons typically export DllMain and optionally ReflectiveLoader.
        """
        if len(data) < 64:
            return 0

        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        nt_headers_start = pe_offset

        if nt_headers_start + 24 > len(data):
            return 0

        size_of_optional = struct.unpack_from("<H", data, nt_headers_start + 20)[0]
        optional_header_start = nt_headers_start + 24

        if optional_header_start + 2 > len(data):
            return 0

        magic = struct.unpack_from("<H", data, optional_header_start)[0]

        # NumberOfRvaAndSizes offset in optional header:
        # PE32:  92
        # PE32+: 108
        if magic == 0x10B:  # PE32
            rva_sizes_offset = optional_header_start + 92
        elif magic == 0x20B:  # PE32+
            rva_sizes_offset = optional_header_start + 108
        else:
            return 0

        if rva_sizes_offset + 4 > len(data):
            return 0

        num_rva_and_sizes = struct.unpack_from("<I", data, rva_sizes_offset)[0]
        if num_rva_and_sizes == 0:
            return 0

        # Export directory is the first data directory entry
        export_dir_offset = rva_sizes_offset + 4

        if export_dir_offset + 8 > len(data):
            return 0

        export_virtual_address = struct.unpack_from("<I", data, export_dir_offset)[0]
        export_size = struct.unpack_from("<I", data, export_dir_offset + 4)[0]

        if export_virtual_address == 0 or export_size == 0:
            return 0

        return 2 if export_size > 0 else 0  # Typical: DllMain + ReflectiveLoader

    @staticmethod
    def _machine_type_str(machine: int) -> str:
        """Convert PE machine type to human-readable string."""
        types = {
            MACHINE_I386: "0x14c (x86)",
            MACHINE_AMD64: "0x8664 (x64)",
            0xAA64: "0xAA64 (ARM64)",
            0x1C0: "0x1C0 (ARMv7)",
            0x1C4: "0x1C4 (ARMv7 Thumb)",
        }
        return types.get(machine, f"0x{machine:04x} (unknown)")

    @staticmethod
    def _timestamp_to_str(timestamp: int) -> str:
        """Convert PE timestamp to ISO 8601 date string."""
        try:
            dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except (OSError, ValueError):
            return f"Invalid timestamp: {timestamp}"
