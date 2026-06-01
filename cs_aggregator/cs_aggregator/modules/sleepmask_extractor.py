"""MOD_SLEEPMASK_EXTRACTOR — Sleep Mask Detection & Analysis.

Identifies and extracts the sleep mask segment from the beacon DLL.
The sleep mask is responsible for obfuscating beacon memory during
sleep cycles to evade memory scanning.

Detection strategies:
1. PE section analysis: Look for dedicated sections (.sleep, .bg)
2. Export scanning: Find Mask/Unmask/BeaconGate export functions
3. Byte signature matching: Known sleep mask function prologues
4. Entropy analysis: Sleep mask sections typically have lower entropy
   than encrypted config blocks but structured code-like entropy

Supports BeaconGate (CS 4.10+) detection and extraction.
"""

import struct
from typing import Any, Dict, List, Optional, Tuple

from cs_aggregator.utils.entropy import shannon_entropy
from cs_aggregator.utils.errors import ExtractionError
from cs_aggregator.utils.hashing import compute_hashes
from cs_aggregator.utils.types import SleepMaskResult

# Known sleep mask export names (as byte sequences for scanning)
SLEEP_MASK_EXPORTS = [b"Mask", b"Unmask", b"BeaconGate", b"BeaconGateSetup"]

# Typical Mask function prologue patterns (x64)
MASK_PROLOGUES: List[bytes] = [
    # Standard x64 prologue with shadow space + sub rsp
    bytes([0x48, 0x89, 0x5C, 0x24]),  # mov [rsp+XX], rbx
    bytes([0x48, 0x89, 0x74, 0x24]),  # mov [rsp+XX], rsi
    bytes([0x57]),  # push rdi
    bytes([0x48, 0x83, 0xEC]),  # sub rsp, XX
    bytes([0x48, 0x81, 0xEC]),  # sub rsp, XXXXXXXX
]

# BeaconGate-specific patterns
BEACONGATE_SIGNATURES = [
    bytes([0x48, 0x8B, 0x05]),  # mov rax, [rip+XX]  — RIP-relative load (common in BeaconGate)
    b"BeaconGate",
]

# Section names that indicate sleep mask content
SLEEP_SECTION_NAMES = {".sleep", ".bg", ".mask", ".sldata", ".scode"}


class SleepMaskExtractor:
    """Extracts and analyzes the sleep mask from a beacon DLL.

    Supports both pre-4.10 (classic sleep mask) and 4.10+
    (BeaconGate-aware) sleep mask architectures.
    """

    def __init__(self, version_schema: Optional[Dict[str, Any]] = None):
        """Initialize with optional version schema for version-specific heuristics.

        Args:
            version_schema: Version schema with sleep mask signatures,
                expected sizes, and section expectations.
        """
        self.schema = version_schema or {}

    def extract(self, dll_data: bytes) -> SleepMaskResult:
        """Extract and analyze the sleep mask from a beacon DLL.

        Args:
            dll_data: Raw beacon DLL bytes.

        Returns:
            SleepMaskResult with detection status and metadata.
        """
        result = None

        # Strategy 1: Check for dedicated sleep mask sections
        section_result = self._check_sleep_sections(dll_data)
        if section_result.detected and section_result.confidence_score >= 0.6:
            result = section_result
        else:
            # Strategy 2: Scan exports for Mask/Unmask functions
            export_result = self._scan_exports(dll_data)
            if export_result.detected:
                # Merge: prefer export-based for RVA info, section-based for offset/size
                if section_result.detected:
                    export_result.offset = section_result.offset
                    export_result.size = section_result.size
                    export_result.section_name = section_result.section_name
                    export_result.sha256 = section_result.sha256
                    export_result.entropy = section_result.entropy
                    export_result.confidence_score = max(
                        export_result.confidence_score, section_result.confidence_score
                    )
                result = export_result
            else:
                # Strategy 3: Byte signature scanning
                sig_result = self._scan_signatures(dll_data)
                if sig_result.detected:
                    result = sig_result
                else:
                    # Strategy 4: Entropy-based heuristic for unknown sections
                    fallback = self._entropy_fallback(dll_data)
                    if fallback.detected:
                        result = fallback

        if result is None:
            return SleepMaskResult(
                detected=False,
                confidence_score=0.0,
                warnings=["No sleep mask detected — may use default system loader"],
            )

        # ─── Post-extraction Algorithm & Version Classification ───
        # 1. Determine Algorithm
        # CobaltStrike sleep masks use custom XOR-based obfuscation, NOT AES.
        # Classification is based on structural indicators from official CS
        # release notes and Arsenal Kit documentation.
        if result.beacongate_detected:
            result.mask_algorithm = "BeaconGate"
        else:
            sec_data = None
            if result.offset >= 0 and result.size > 0 and result.offset + result.size <= len(dll_data):
                sec_data = dll_data[result.offset:result.offset + result.size]

            if sec_data:
                sec_entropy = shannon_entropy(sec_data)
                # CS 4.11+ novel auto-obfuscation produces structured code with
                # moderate entropy (5.0–7.0) and larger section sizes (16KB+)
                if result.size >= 16384 and 5.0 <= sec_entropy <= 7.0:
                    result.mask_algorithm = "Novel Auto-Obfuscation"
                # Classic XOR masks have lower entropy code-like patterns
                elif sec_entropy < 5.0:
                    result.mask_algorithm = "Classic XOR"
                else:
                    result.mask_algorithm = "Obfuscated Code"
            else:
                result.mask_algorithm = "Classic XOR"

        # 2. Determine Version — inherit from the pipeline-detected schema
        schema_version = self.schema.get("meta", {}).get("version", "")
        if schema_version:
            result.version = schema_version
        else:
            result.version = "unknown"

        return result

    def _check_sleep_sections(self, dll_data: bytes) -> SleepMaskResult:
        """Strategy 1: Check for dedicated sleep mask PE sections.

        Scans PE sections for names matching known sleep mask patterns
        (.sleep, .bg, .mask, etc.).

        Returns:
            SleepMaskResult if a matching section is found.
        """
        sections = self._get_section_details(dll_data)

        best_section: Optional[Tuple[str, int, int, bytes]] = None

        for sec_name, sec_offset, sec_size in sections:
            if sec_name.lower() in SLEEP_SECTION_NAMES:
                sec_data = dll_data[sec_offset:sec_offset + sec_size]
                best_section = (sec_name, sec_offset, sec_size, sec_data)
                break

            # Also check for section names starting with .sleep or .bg
            if sec_name.lower().startswith(".sleep") or sec_name.lower().startswith(".bg"):
                sec_data = dll_data[sec_offset:sec_offset + sec_size]
                best_section = (sec_name, sec_offset, sec_size, sec_data)
                break

        if best_section is None:
            return SleepMaskResult()

        sec_name, sec_offset, sec_size, sec_data = best_section

        # Check against expected size range from schema
        expected_size_range = self.schema.get("sleepMaskSignatures", {}).get(
            "expectedSizeRange", [8192, 32768]
        )
        size_ok = expected_size_range[0] <= sec_size <= expected_size_range[1]

        entropy = shannon_entropy(sec_data)
        hashes = compute_hashes(sec_data)

        # Scan within section for Mask/Unmask export references
        mask_rva = self._find_export_in_data(sec_data, b"Mask", sec_offset)
        unmask_rva = self._find_export_in_data(sec_data, b"Unmask", sec_offset)
        beacongate = b"BeaconGate" in sec_data

        confidence = 0.7  # Base for dedicated section
        if size_ok:
            confidence += 0.15
        if mask_rva is not None:
            confidence += 0.1
        if beacongate:
            confidence = min(1.0, confidence + 0.1)

        warnings = []
        if not size_ok:
            warnings.append(
                f"Sleep section size ({sec_size}) outside expected range "
                f"{expected_size_range}"
            )

        return SleepMaskResult(
            detected=True,
            offset=sec_offset,
            size=sec_size,
            section_name=sec_name,
            sha256=hashes["sha256"],
            entropy=round(entropy, 4),
            confidence_score=round(min(1.0, confidence), 2),
            mask_function_rva=mask_rva,
            unmask_function_rva=unmask_rva,
            beacongate_detected=beacongate,
            metadata={
                "detection_method": "dedicated_section",
                "section_name": sec_name,
                "size_in_range": size_ok,
            },
            warnings=warnings,
        )

    def _scan_exports(self, dll_data: bytes) -> SleepMaskResult:
        """Strategy 2: Scan the export table for Mask/Unmask functions.

        Returns:
            SleepMaskResult if Mask/Unmask exports are found.
        """
        if len(dll_data) < 64:
            return SleepMaskResult()

        pe_offset = struct.unpack_from("<I", dll_data, 0x3C)[0]
        nt_headers = pe_offset

        if nt_headers + 24 > len(dll_data):
            return SleepMaskResult()

        # Locate the export directory via the PE data directory array.
        # Structure: PE sig(4) + COFF header(20) + optional_header(size_of_optional)
        # The data directory entries are at the END of the optional header.
        # First read the optional header magic to determine the correct offset
        # for NumberOfRvaAndSizes, then find the export directory entry.
        optional_header_start = nt_headers + 4 + 20  # after PE sig + COFF header
        if optional_header_start + 2 > len(dll_data):
            return SleepMaskResult()

        magic = struct.unpack_from("<H", dll_data, optional_header_start)[0]

        # PE32  -> NumberOfRvaAndSizes at offset 92 from optional header start
        # PE32+ -> NumberOfRvaAndSizes at offset 108 from optional header start
        if magic == 0x10B:  # PE32
            rva_and_sizes_offset = optional_header_start + 92
        elif magic == 0x20B:  # PE32+
            rva_and_sizes_offset = optional_header_start + 108
        else:
            return SleepMaskResult()

        if rva_and_sizes_offset + 4 > len(dll_data):
            return SleepMaskResult()

        num_rva_and_sizes = struct.unpack_from("<I", dll_data, rva_and_sizes_offset)[0]

        # Data directory entries start immediately after NumberOfRvaAndSizes
        data_dir_offset = rva_and_sizes_offset + 4

        # Export directory is the first entry (index 0)
        export_dir_entry_offset = data_dir_offset
        if export_dir_entry_offset + 8 > len(dll_data):
            return SleepMaskResult()

        export_rva = struct.unpack_from("<I", dll_data, export_dir_entry_offset)[0]
        export_size = struct.unpack_from("<I", dll_data, export_dir_entry_offset + 4)[0]

        if export_rva == 0 or export_size == 0:
            return SleepMaskResult()

        # Convert RVA to file offset
        export_offset = self._rva_to_offset(dll_data, export_rva)
        if export_offset is None or export_offset + export_size > len(dll_data):
            return SleepMaskResult()

        # Parse export directory to find name pointers
        # Structure: Characteristics(4), TimeDateStamp(4), MajorVersion(2),
        # MinorVersion(2), Name(4), Base(4), NumberOfFunctions(4),
        # NumberOfNames(4), AddressOfFunctions(4), AddressOfNames(4),
        # AddressOfNameOrdinals(4)
        if export_offset + 40 > len(dll_data):
            return SleepMaskResult()

        number_of_names = struct.unpack_from("<I", dll_data, export_offset + 24)[0]
        address_of_names = struct.unpack_from("<I", dll_data, export_offset + 32)[0]
        address_of_name_ordinals = struct.unpack_from("<I", dll_data, export_offset + 36)[0]

        names_offset = self._rva_to_offset(dll_data, address_of_names)
        ordinals_offset = self._rva_to_offset(dll_data, address_of_name_ordinals)

        if names_offset is None or ordinals_offset is None:
            return SleepMaskResult()

        found_mask = False
        found_unmask = False
        beacongate = False
        mask_rva_val: Optional[int] = None
        unmask_rva_val: Optional[int] = None

        for i in range(min(number_of_names, 256)):
            name_rva_offset = names_offset + i * 4
            if name_rva_offset + 4 > len(dll_data):
                break

            name_rva = struct.unpack_from("<I", dll_data, name_rva_offset)[0]
            name_offset = self._rva_to_offset(dll_data, name_rva)

            if name_offset is None:
                continue

            # Read export name (null-terminated)
            name_end = dll_data.find(b"\x00", name_offset)
            if name_end == -1 or name_end - name_offset > 64:
                continue

            export_name = dll_data[name_offset:name_end]

            if export_name == b"Mask":
                found_mask = True
                # Get the function address from AddressOfFunctions
                ordinal_offset = ordinals_offset + i * 2
                if ordinal_offset + 2 <= len(dll_data):
                    ordinal = struct.unpack_from("<H", dll_data, ordinal_offset)[0]
                    addr_of_funcs = struct.unpack_from("<I", dll_data, export_offset + 28)[0]
                    funcs_offset = self._rva_to_offset(dll_data, addr_of_funcs)
                    if funcs_offset is not None:
                        func_rva_offset = funcs_offset + ordinal * 4
                        if func_rva_offset + 4 <= len(dll_data):
                            mask_rva_val = struct.unpack_from("<I", dll_data, func_rva_offset)[0]

            elif export_name == b"Unmask":
                found_unmask = True

            elif export_name == b"BeaconGate":
                beacongate = True

        if not found_mask and not found_unmask:
            return SleepMaskResult()

        # Calculate confidence
        confidence = 0.5
        detection_notes = []
        if found_mask and found_unmask:
            confidence += 0.25
            detection_notes.append("mask+unmask_exports_found")
        elif found_mask:
            detection_notes.append("mask_export_found")
        elif found_unmask:
            detection_notes.append("unmask_export_found")
        if beacongate:
            confidence += 0.15
            detection_notes.append("beacongate_export_found")

        # If we found via exports but also know the section, try to find it
        offset = -1
        size = 0
        section_name = ""

        # Scan sections to find which one contains the mask RVA
        if mask_rva_val is not None:
            sections = self._get_section_details(dll_data)
            for sec_name, sec_offset, sec_size in sections:
                sec_rva = self._offset_to_rva(dll_data, sec_offset)
                if sec_rva is not None and sec_rva <= mask_rva_val < sec_rva + sec_size:
                    offset = sec_offset
                    size = sec_size
                    section_name = sec_name
                    break

        return SleepMaskResult(
            detected=True,
            offset=offset,
            size=size,
            section_name=section_name,
            sha256=compute_hashes(dll_data)["sha256"],
            entropy=round(shannon_entropy(dll_data), 4) if offset == -1 else 0.0,
            confidence_score=round(min(1.0, confidence), 2),
            mask_function_rva=mask_rva_val,
            unmask_function_rva=unmask_rva_val,
            beacongate_detected=beacongate,
            metadata={
                "detection_method": "export_scan",
                "detection_notes": detection_notes,
                "mask_found": found_mask,
                "unmask_found": found_unmask,
            },
        )

    def _scan_signatures(self, dll_data: bytes) -> SleepMaskResult:
        """Strategy 3: Byte signature scanning for sleep mask patterns.

        Uses known sleep mask function prologues and BeaconGate signatures.

        Returns:
            SleepMaskResult if signatures are found.
        """
        # Get schema-specific patterns if available
        schema_patterns = self.schema.get("sleepMaskSignatures", {}).get("patterns", [])
        patterns: List[bytes] = []
        for p in schema_patterns:
            try:
                pattern_bytes = bytes.fromhex(p.replace(" ", ""))
                patterns.append(pattern_bytes)
            except ValueError:
                pass

        # Combine with known patterns
        all_patterns = patterns + MASK_PROLOGUES

        matches = 0
        for pattern in all_patterns:
            if pattern in dll_data:
                matches += 1

        beacongate_matches = 0
        for sig in BEACONGATE_SIGNATURES:
            if sig in dll_data:
                beacongate_matches += 1

        if matches == 0 and beacongate_matches == 0:
            return SleepMaskResult()

        # Find which section contains the most pattern matches
        sections = self._get_section_details(dll_data)
        best_section: Optional[Tuple[str, int, int]] = None
        best_matches = 0

        for sec_name, sec_offset, sec_size in sections:
            sec_data = dll_data[sec_offset:sec_offset + sec_size]
            sec_matches = sum(1 for p in all_patterns if p in sec_data)
            if sec_matches > best_matches:
                best_matches = sec_matches
                best_section = (sec_name, sec_offset, sec_size)

        confidence = 0.3 + (matches * 0.1)
        if beacongate_matches > 0:
            confidence += 0.15
        confidence = min(1.0, confidence)

        if best_section is not None:
            sec_name, sec_offset, sec_size = best_section
            sec_data = dll_data[sec_offset:sec_offset + sec_size]
            entropy = shannon_entropy(sec_data)
            hashes = compute_hashes(sec_data)

            return SleepMaskResult(
                detected=True,
                offset=sec_offset,
                size=sec_size,
                section_name=sec_name,
                sha256=hashes["sha256"],
                entropy=round(entropy, 4),
                confidence_score=round(confidence, 2),
                beacongate_detected=beacongate_matches > 0,
                metadata={
                    "detection_method": "signature_scan",
                    "pattern_matches": matches,
                    "beacongate_signature_matches": beacongate_matches,
                },
            )

        return SleepMaskResult(
            detected=True,
            confidence_score=round(confidence, 2),
            beacongate_detected=beacongate_matches > 0,
            metadata={
                "detection_method": "signature_scan",
                "pattern_matches": matches,
                "beacongate_signature_matches": beacongate_matches,
            },
        )

    def _entropy_fallback(self, dll_data: bytes) -> SleepMaskResult:
        """Strategy 4: Entropy-based heuristic fallback.

        Identifies candidate regions that match sleep mask entropy profiles:
        - Lower than encrypted data but higher than plain padding
        - Located near the end of the PE file (post-main sections)
        - Reasonable size (8-32KB)
        """
        sections = self._get_section_details(dll_data)

        candidates: List[Tuple[str, int, int, float]] = []

        for sec_name, sec_offset, sec_size in sections:
            if sec_size < 4096 or sec_size > 65536:
                continue

            sec_data = dll_data[sec_offset:sec_offset + sec_size]
            entropy = shannon_entropy(sec_data)

            # Sleep mask entropy is typically 4.0-6.5 (code-like)
            if 4.0 <= entropy <= 6.5:
                candidates.append((sec_name, sec_offset, sec_size, entropy))

        if not candidates:
            return SleepMaskResult()

        # Sort by how well entropy matches expected range (closer to 5.5 is ideal)
        candidates.sort(key=lambda c: abs(c[3] - 5.5))

        best = candidates[0]
        sec_name, sec_offset, sec_size, entropy = best

        # Very low confidence for entropy-only detection
        confidence = 0.25

        sec_data = dll_data[sec_offset:sec_offset + sec_size]

        return SleepMaskResult(
            detected=True,
            offset=sec_offset,
            size=sec_size,
            section_name=sec_name,
            sha256=compute_hashes(sec_data)["sha256"],
            entropy=round(entropy, 4),
            confidence_score=confidence,
            metadata={
                "detection_method": "entropy_fallback",
                "section_name": sec_name,
            },
            warnings=[
                "Sleep mask detected via entropy heuristic only — confirm with additional analysis"
            ],
        )

    def get_sleep_mask_bytes(self, dll_data: bytes) -> Optional[bytes]:
        """Get the raw sleep mask bytes from the DLL.

        Args:
            dll_data: Raw beacon DLL bytes.

        Returns:
            Raw sleep mask bytes, or None if not detected.
        """
        result = self.extract(dll_data)
        if result.detected and result.offset >= 0 and result.size > 0:
            if result.offset + result.size <= len(dll_data):
                return dll_data[result.offset:result.offset + result.size]
        return None

    # ---- Helper methods ----

    def _get_section_details(self, dll_data: bytes) -> List[Tuple[str, int, int]]:
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

    @staticmethod
    def _rva_to_offset(dll_data: bytes, rva: int) -> Optional[int]:
        """Convert a relative virtual address (RVA) to a file offset.

        Uses the PE section table to map RVA -> file offset.
        """
        if len(dll_data) < 64:
            return None

        pe_offset = struct.unpack_from("<I", dll_data, 0x3C)[0]
        if pe_offset + 24 > len(dll_data):
            return None

        num_sections = struct.unpack_from("<H", dll_data, pe_offset + 6)[0]
        size_of_optional = struct.unpack_from("<H", dll_data, pe_offset + 20)[0]
        section_table_offset = pe_offset + 24 + size_of_optional

        for i in range(num_sections):
            sec_start = section_table_offset + i * 40
            if sec_start + 40 > len(dll_data):
                break

            virtual_address = struct.unpack_from("<I", dll_data, sec_start + 12)[0]
            virtual_size = struct.unpack_from("<I", dll_data, sec_start + 8)[0]
            raw_pointer = struct.unpack_from("<I", dll_data, sec_start + 20)[0]

            if virtual_address <= rva < virtual_address + virtual_size:
                return raw_pointer + (rva - virtual_address)

        return None

    @staticmethod
    def _offset_to_rva(dll_data: bytes, file_offset: int) -> Optional[int]:
        """Convert a file offset to an RVA.

        Uses the PE section table to map file offset -> RVA.
        """
        if len(dll_data) < 64:
            return None

        pe_offset = struct.unpack_from("<I", dll_data, 0x3C)[0]
        if pe_offset + 24 > len(dll_data):
            return None

        num_sections = struct.unpack_from("<H", dll_data, pe_offset + 6)[0]
        size_of_optional = struct.unpack_from("<H", dll_data, pe_offset + 20)[0]
        section_table_offset = pe_offset + 24 + size_of_optional

        for i in range(num_sections):
            sec_start = section_table_offset + i * 40
            if sec_start + 40 > len(dll_data):
                break

            virtual_address = struct.unpack_from("<I", dll_data, sec_start + 12)[0]
            virtual_size = struct.unpack_from("<I", dll_data, sec_start + 8)[0]
            raw_pointer = struct.unpack_from("<I", dll_data, sec_start + 20)[0]

            if raw_pointer <= file_offset < raw_pointer + virtual_size:
                return virtual_address + (file_offset - raw_pointer)

        return None

    @staticmethod
    def _find_export_in_data(section_data: bytes, name: bytes, base_offset: int) -> Optional[int]:
        """Find an export name string in a section and return its RVA.

        Returns approximate RVA or None.
        """
        pos = section_data.find(name)
        if pos != -1:
            return base_offset + pos
        return None
