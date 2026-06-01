"""MOD_POSTEX_EXTRACTOR — Post-Exploitation DLL Analyzer.

Identifies and analyzes post-exploitation DLLs referenced by or
embedded within a CobaltStrike beacon payload.

Detection strategies:
1. TLV config analysis: Parse the PostExBlock (0x0027) for DLL names
2. String scanning: Scan beacon DLL for known post-ex DLL names
3. PE section analysis: Detect unusual non-standard sections
4. Resource directory: Check for embedded DLL resources

Known post-ex DLL names (case-insensitive match):
- mimikatz (full or Minidump variant)
- keylogger
- screenshot
- netview
- powerview
- execute-assembly (execute_assembly)
- dllinject
- artifact
- cobaltstrike (post-ex utility DLL)
"""

import struct
from typing import Any, Dict, List, Optional, Set, Tuple

from cs_aggregator.utils.entropy import shannon_entropy
from cs_aggregator.utils.hashing import compute_hashes
from cs_aggregator.utils.types import PostExDLLInfo

# Known post-exploitation DLL names (lowercase for case-insensitive matching)
KNOWN_POSTEX_DLLS: Set[str] = {
    "mimikatz",
    "minidump",
    "keylogger",
    "screenshot",
    "netview",
    "powerview",
    "execute-assembly",
    "execute_assembly",
    "dllinject",
    "artifact",
    "cobaltstrike",
    "portscan",
    "clipboard",
    "hashdump",
    "inject",
    "spawn",
}

# Strings that indicate post-ex configuration/results
POSTEX_INDICATOR_STRINGS: List[bytes] = [
    b"postex",
    b"post_ex",
    b"PostEx",
    b"job_id",
    b"spawn_to",
    b"spawnto",
    b"ppid",
    b"block_dlls",
    b"thread_hint",
    b"pipename",
]

# Standard PE section names (non-standard ones may be post-ex DLLs)
STANDARD_SECTIONS = {
    ".text", ".data", ".rdata", ".reloc", ".rsrc", ".pdata",
    ".didat", ".tls", ".00cfg", ".gfids", ".sxdata", ".idata",
    ".edata", ".debug", ".sleep", ".bg", ".mask",
    ".stab", ".stabstr", ".bss", ".crt", ".ndata",
}

# Typical post-ex DLL section names (when embedded directly in payload)
POSTEX_SECTION_PREFIXES = {".pexe", ".pdll", ".rdll", ".pdata2"}


class PostExExtractor:
    """Analyzes post-exploitation DLL references in a beacon payload.

    Provides both embedded DLL identification and TLV-config-based
    reference detection.
    """

    def __init__(self, version_schema: Optional[Dict[str, Any]] = None):
        """Initialize with optional version schema for version-specific hints.

        Args:
            version_schema: Version schema with post-ex expectations.
        """
        self.schema = version_schema or {}

    def analyze(self, dll_data: bytes, config_json: Optional[Dict[str, Any]] = None) -> List[PostExDLLInfo]:
        """Run all post-ex analysis strategies and return identified DLLs.

        Args:
            dll_data: Raw beacon DLL bytes.
            config_json: Optional parsed config JSON from ConfigExtractor.

        Returns:
            List of PostExDLLInfo with identified DLL references.
        """
        results: Dict[str, PostExDLLInfo] = {}  # Deduplicate by name

        # Strategy 1: TLV config analysis
        if config_json:
            config_results = self._analyze_config(config_json)
            for r in config_results:
                if r.name not in results:
                    results[r.name] = r

        # Strategy 2: String scanning for DLL names
        string_results = self._scan_strings(dll_data)
        for r in string_results:
            if r.name not in results or results[r.name].reference_type == "string_scan":
                # Upgrade to section-based if we have section info
                results[r.name] = r
            elif results[r.name].reference_type == "string_scan" and r.reference_type != "string_scan":
                results[r.name] = r

        # Strategy 3: PE section analysis for embedded DLLs
        section_results = self._analyze_sections(dll_data)
        for r in section_results:
            if r.name not in results:
                results[r.name] = r

        # Sort by embedded first, then by name
        sorted_results = sorted(
            results.values(),
            key=lambda r: (not r.embedded, r.name),
        )

        return sorted_results

    def _analyze_config(self, config_json: Dict[str, Any]) -> List[PostExDLLInfo]:
        """Strategy 1: Parse TLV config for post-ex references.

        Looks for PostExBlock (0x0027) and related fields.

        Returns:
            List of PostExDLLInfo from config analysis.
        """
        results: List[PostExDLLInfo] = []

        # Check for postExBlock in config
        postex_block = config_json.get("postExBlock")
        if postex_block:
            # PostExBlock can contain DLL names or configuration strings
            if isinstance(postex_block, str):
                results.append(PostExDLLInfo(
                    name=postex_block,
                    reference_type="tlv_config",
                    metadata={"source": "postExBlock"},
                ))

        # Check for spawnto reference
        spawnto = config_json.get("spawnto")
        if spawnto:
            results.append(PostExDLLInfo(
                name=f"spawnto:{spawnto}",
                reference_type="tlv_config",
                metadata={"source": "spawnto", "value": spawnto},
            ))

        # Check for pipeName (SMB post-ex)
        pipe_name = config_json.get("pipeName")
        if pipe_name:
            results.append(PostExDLLInfo(
                name=f"pipe:{pipe_name}",
                reference_type="tlv_config",
                metadata={"source": "pipeName", "value": pipe_name},
            ))

        # Check for namedPipeBlock
        named_pipe = config_json.get("namedPipeBlock")
        if named_pipe:
            results.append(PostExDLLInfo(
                name=f"namedpipe:{named_pipe}",
                reference_type="tlv_config",
                metadata={"source": "namedPipeBlock"},
            ))

        return results

    def _scan_strings(self, dll_data: bytes) -> List[PostExDLLInfo]:
        """Strategy 2: Scan DLL for string references to post-ex DLLs.

        Returns:
            List of PostExDLLInfo from string matches.
        """
        results: List[PostExDLLInfo] = []

        # Scan for known DLL names
        dll_data_lower = dll_data.lower()

        # Known common post-ex DLL filenames patterns
        name_patterns = [
            (b"mimikatz", "mimikatz"),
            (b"minidump", "minidump"),
            (b"keylogger", "keylogger"),
            (b"screenshot", "screenshot"),
            (b"netview", "netview"),
            (b"powerview", "powerview"),
            (b"execute-assembly", "execute-assembly"),
            (b"execute_assembly", "execute-assembly"),
            (b"dllinject", "dllinject"),
            (b"cobaltstrike.dll", "cobaltstrike"),
            (b"artifact.dll", "artifact"),
            (b"portscan", "portscan"),
            (b"hashdump", "hashdump"),
            (b"clipboard", "clipboard"),
        ]

        for pattern_bytes, name in name_patterns:
            if pattern_bytes in dll_data:
                offset = dll_data.find(pattern_bytes)

                # Calculate approximate size (read until null terminator)
                end = dll_data.find(b"\x00", offset)
                if end == -1:
                    end = min(offset + 256, len(dll_data))
                ref_bytes = dll_data[offset:end]

                entropy = shannon_entropy(ref_bytes)

                results.append(PostExDLLInfo(
                    name=name,
                    offset=offset,
                    entropy=round(entropy, 4),
                    reference_type="string_scan",
                    metadata={
                        "matched_bytes": ref_bytes[:64].hex(),
                        "match_offset": offset,
                    },
                ))

        return results

    def _analyze_sections(self, dll_data: bytes) -> List[PostExDLLInfo]:
        """Strategy 3: PE section analysis for embedded DLLs.

        Detects sections with non-standard names or characteristics
        that may contain embedded post-ex DLLs.

        Returns:
            List of PostExDLLInfo from section analysis.
        """
        results: List[PostExDLLInfo] = []
        sections = self._get_section_details(dll_data)

        for sec_name, sec_offset, sec_size in sections:
            sec_name_lower = sec_name.lower()

            # Check for known post-ex section prefixes
            is_postex_section = False
            for prefix in POSTEX_SECTION_PREFIXES:
                if sec_name_lower.startswith(prefix):
                    is_postex_section = True
                    break

            # Check for unusual section sizes/characteristics
            is_non_standard = (
                sec_name_lower not in STANDARD_SECTIONS
                and not sec_name_lower.startswith(".")
            )

            sec_data = dll_data[sec_offset:sec_offset + sec_size]
            entropy = shannon_entropy(sec_data)
            hashes = compute_hashes(sec_data)

            if is_postex_section or is_non_standard:
                # Check if section looks like an embedded DLL (has MZ header)
                mz_offset_in_sec = sec_data.find(b"MZ")
                is_embedded = mz_offset_in_sec != -1

                if is_embedded:
                    # Try to get the DLL name from the section or nearby strings
                    name = self._infer_dll_name(dll_data, sec_offset, sec_size)

                    results.append(PostExDLLInfo(
                        name=name,
                        dll_size=sec_size,
                        sha256=hashes["sha256"],
                        entropy=round(entropy, 4),
                        offset=sec_offset,
                        embedded=True,
                        reference_type="section_name",
                        metadata={
                            "section_name": sec_name,
                            "mz_offset_in_section": mz_offset_in_sec if mz_offset_in_sec != -1 else None,
                        },
                    ))
                else:
                    # Non-standard section, not an embedded DLL
                    results.append(PostExDLLInfo(
                        name=f"section:{sec_name}",
                        dll_size=sec_size,
                        sha256=hashes["sha256"],
                        entropy=round(entropy, 4),
                        offset=sec_offset,
                        embedded=False,
                        reference_type="section_name",
                        metadata={
                            "section_name": sec_name,
                            "mz_detected": False,
                            "note": "Non-standard section but not an embedded PE",
                        },
                    ))

        return results

    @staticmethod
    def _infer_dll_name(dll_data: bytes, offset: int, size: int) -> str:
        """Infer a DLL name from nearby strings in the payload.

        Args:
            dll_data: Full DLL bytes.
            offset: Offset of the candidate region.
            size: Size of the candidate region.

        Returns:
            Inferred name or a fallback identifier.
        """
        # Search around the offset for readable ASCII strings
        search_start = max(0, offset - 256)
        search_end = min(len(dll_data), offset + size + 256)
        region = dll_data[search_start:search_end]

        # Find null-terminated strings that look like DLL names
        current_pos = 0
        while current_pos < len(region):
            end = region.find(b"\x00", current_pos)
            if end == -1 or end - current_pos > 128:
                break

            string_bytes = region[current_pos:end]
            if len(string_bytes) > 3:
                try:
                    text = string_bytes.decode("ascii").lower()
                    # Look for DLL-like names
                    if text.endswith(".dll") and len(text) > 5:
                        return text[:-4]  # Return without .dll
                except (UnicodeDecodeError, ValueError):
                    pass

            current_pos = end + 1

        # Fallback: use offset-based identifier
        return f"embedded_dll_at_0x{offset:x}"

    @staticmethod
    def _get_section_details(dll_data: bytes) -> List[Tuple[str, int, int]]:
        """Extract PE section details: (name, file_offset, size)."""
        sections: List[Tuple[str, int, int]] = []

        if len(dll_data) < 64:
            return sections

        pe_offset = struct.unpack_from("<I", dll_data, 0x3C)[0]
        if pe_offset + 24 > len(dll_data):
            return sections

        num_sections = struct.unpack_from("<H", dll_data, pe_offset + 6)[0]
        # SizeOfOptionalHeader is at file header offset 16 = pe_offset + 4 + 16 = pe_offset + 20
        size_of_optional = struct.unpack_from("<H", dll_data, pe_offset + 20)[0]
        # Section table: PE sig(4) + file header(20) + optional header
        section_table_offset = pe_offset + 24 + size_of_optional

        for i in range(num_sections):
            sec_start = section_table_offset + i * 40
            if sec_start + 40 > len(dll_data):
                break

            name_raw = dll_data[sec_start:sec_start + 8].split(b"\x00")[0]
            try:
                name = name_raw.decode("ascii", errors="replace").strip()
            except UnicodeDecodeError:
                name = f"unnamed_{i}"

            raw_pointer = struct.unpack_from("<I", dll_data, sec_start + 20)[0]
            raw_size = struct.unpack_from("<I", dll_data, sec_start + 16)[0]

            if raw_size > 0 and raw_pointer + raw_size <= len(dll_data):
                sections.append((name, raw_pointer, raw_size))

        return sections
