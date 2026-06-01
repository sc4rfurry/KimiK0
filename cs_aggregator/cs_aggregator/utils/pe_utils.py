"""Shared PE parsing utilities used across multiple modules.

Centralizes common PE header operations that were previously duplicated
in version_detector.py, beacon_parser.py, config_extractor.py, and
loader_extractor.py.
"""

import struct
from typing import Any, Dict, List, Optional, Tuple

# CobaltStrike's stage.magic_mz_x64/x86 option replaces MZ header bytes.
# We must search for all known magic values when locating PE boundaries.
# This list is MUTABLE — profiles can register custom magics at runtime.
KNOWN_PE_MAGICS: list = [
    b"MZ",      # Standard PE
    b"OICA",    # dec eax,inc eax,dec ebx,inc ebx — NOP-equivalent
    b"OOPS",    # Common in Sophos-evasion profiles
    b"NO",      # Another common replacement
    b"MZRE",    # Seen in aggressive profiles
    b"MZAR",    # MZARUH stub remnant
    b"\x90\x90",  # NOP sled magic (2-byte)
    b"FC",      # cld instruction magic
]


def register_magic(magic_bytes: bytes) -> None:
    """Register a custom PE magic value for dynamic detection.

    Called by the profile parser when a C2 profile specifies
    non-standard magic_mz_x64/x86 values.

    Args:
        magic_bytes: The custom magic bytes to register.
    """
    if magic_bytes and magic_bytes not in KNOWN_PE_MAGICS:
        # Insert after MZ but before shorter magics for priority
        KNOWN_PE_MAGICS.insert(1, magic_bytes)


def find_pe_offset(data: bytes, max_search: int = 0x10000) -> int:
    """Find the offset of the first valid PE header in the data.

    Searches for standard MZ magic AND known spoofed magic bytes
    (e.g. 'OICA' from stage.magic_mz_x64). Validates via e_lfanew.

    Returns:
        Offset of the PE header, or -1 if not found.
    """
    search_end = min(max_search, len(data))

    for offset in range(search_end):
        for magic in KNOWN_PE_MAGICS:
            if data[offset:offset + len(magic)] == magic:
                if offset + 64 < len(data):
                    try:
                        e_lfanew = struct.unpack_from("<I", data, offset + 0x3C)[0]
                        if 0 < e_lfanew < 0x1000 and offset + e_lfanew + 4 < len(data):
                            pe_sig = data[offset + e_lfanew:offset + e_lfanew + 4]
                            # Real PE signature or spoofed PE magic (e.g. 'NO')
                            if pe_sig == b'PE\x00\x00' or pe_sig[:2] in (b'NO', b'PE'):
                                return offset
                    except (ValueError, IndexError, struct.error):
                        continue
    return -1


def parse_pe_header(data: bytes, pe_base: int = 0) -> Optional[Dict[str, Any]]:
    """Parse fundamental PE header fields from data starting at pe_base.

    Returns a dict with keys:
        pe_offset, machine, num_sections, timestamp, size_of_optional,
        section_table_offset, is_pe32_plus, size_of_image, entry_point

    Returns None if parsing fails.
    """
    if pe_base + 64 > len(data):
        return None

    e_lfanew = struct.unpack_from("<I", data, pe_base + 0x3C)[0]
    nt_start = pe_base + e_lfanew

    if nt_start + 24 > len(data):
        return None

    # Validate PE signature (or known spoofed)
    sig = data[nt_start:nt_start + 4]
    if sig != b'PE\x00\x00' and sig[:2] not in (b'NO', b'PE'):
        return None

    machine = struct.unpack_from("<H", data, nt_start + 4)[0]
    num_sections = struct.unpack_from("<H", data, nt_start + 6)[0]
    timestamp = struct.unpack_from("<I", data, nt_start + 8)[0]
    size_of_optional = struct.unpack_from("<H", data, nt_start + 20)[0]

    opt_start = nt_start + 24
    if opt_start + 2 > len(data):
        return None

    magic = struct.unpack_from("<H", data, opt_start)[0]
    is_pe32_plus = (magic == 0x20B)

    # SizeOfImage at optional header offset 56 (same for PE32 and PE32+)
    soi_off = opt_start + 56
    size_of_image = struct.unpack_from("<I", data, soi_off)[0] if soi_off + 4 <= len(data) else 0

    # AddressOfEntryPoint at optional header offset 16
    ep_off = opt_start + 16
    entry_point = struct.unpack_from("<I", data, ep_off)[0] if ep_off + 4 <= len(data) else 0

    section_table_offset = opt_start + size_of_optional

    return {
        "pe_offset": nt_start,
        "machine": machine,
        "num_sections": num_sections,
        "timestamp": timestamp,
        "size_of_optional": size_of_optional,
        "section_table_offset": section_table_offset,
        "is_pe32_plus": is_pe32_plus,
        "size_of_image": size_of_image,
        "entry_point": entry_point,
        "optional_header_magic": magic,
    }


def parse_sections(data: bytes, pe_base: int = 0) -> List[Dict[str, Any]]:
    """Parse PE section table from data.

    Returns a list of section dicts with: name, virtual_address, virtual_size,
    raw_size, raw_pointer, characteristics.
    """
    hdr = parse_pe_header(data, pe_base)
    if hdr is None:
        return []

    sections = []
    for i in range(hdr["num_sections"]):
        so = hdr["section_table_offset"] + i * 40
        if so + 40 > len(data):
            break

        name_raw = data[so:so + 8].split(b"\x00")[0]
        try:
            name = name_raw.decode("ascii", errors="replace").strip()
        except UnicodeDecodeError:
            name = f"unnamed_{i}"

        sections.append({
            "name": name,
            "virtual_size": struct.unpack_from("<I", data, so + 8)[0],
            "virtual_address": struct.unpack_from("<I", data, so + 12)[0],
            "raw_size": struct.unpack_from("<I", data, so + 16)[0],
            "raw_pointer": struct.unpack_from("<I", data, so + 20)[0],
            "characteristics": struct.unpack_from("<I", data, so + 36)[0],
        })

    return sections


def extract_section_names(data: bytes, pe_base: int = 0) -> List[str]:
    """Extract just the section names from a PE file."""
    return [s["name"] for s in parse_sections(data, pe_base) if s["name"]]


def rva_to_offset(rva: int, sections: List[Dict[str, Any]]) -> int:
    """Convert a Relative Virtual Address to a file offset using the section table.

    Returns -1 if the RVA doesn't fall within any section.
    """
    for sec in sections:
        va = sec["virtual_address"]
        vs = sec["virtual_size"]
        if va <= rva < va + vs:
            return sec["raw_pointer"] + (rva - va)
    return -1


def count_import_dlls(data: bytes, pe_base: int = 0) -> int:
    """Count the number of imported DLLs by walking the Import Directory Table.

    Returns 0 for beacons with no static imports (expected for reflective DLLs).
    """
    hdr = parse_pe_header(data, pe_base)
    if hdr is None:
        return 0

    opt_start = hdr["pe_offset"] + 24
    magic = hdr["optional_header_magic"]

    # NumberOfRvaAndSizes offset in optional header
    if magic == 0x10B:  # PE32
        num_dd_off = opt_start + 92
    elif magic == 0x20B:  # PE32+
        num_dd_off = opt_start + 108
    else:
        return 0

    if num_dd_off + 4 > len(data):
        return 0

    num_dd = struct.unpack_from("<I", data, num_dd_off)[0]
    if num_dd < 2:  # Need at least import directory entry
        return 0

    # Import directory is data directory entry index 1 (each entry = 8 bytes: RVA + Size)
    import_dd_off = num_dd_off + 4 + (1 * 8)
    if import_dd_off + 8 > len(data):
        return 0

    import_rva = struct.unpack_from("<I", data, import_dd_off)[0]
    import_size = struct.unpack_from("<I", data, import_dd_off + 4)[0]

    if import_rva == 0 or import_size == 0:
        return 0

    # Convert RVA to file offset
    sections = parse_sections(data, pe_base)
    import_offset = rva_to_offset(import_rva, sections)
    if import_offset < 0 or import_offset + 20 > len(data):
        return 0

    # Each import descriptor is 20 bytes. Walk until we hit a null entry.
    count = 0
    pos = import_offset
    while pos + 20 <= len(data):
        # Import descriptor: [OriginalFirstThunk:4][TimeDateStamp:4][ForwarderChain:4][Name:4][FirstThunk:4]
        name_rva = struct.unpack_from("<I", data, pos + 12)[0]
        first_thunk = struct.unpack_from("<I", data, pos + 16)[0]

        if name_rva == 0 and first_thunk == 0:
            break  # Null terminator

        count += 1
        pos += 20

        if count > 500:  # Sanity limit
            break

    return count
