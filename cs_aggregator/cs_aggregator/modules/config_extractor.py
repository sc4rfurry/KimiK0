"""MOD_CONFIG_EXTRACTOR — Configuration Block Extractor & Decryptor (Custom Engine).

Fully custom TLV parser and XOR decryption engine. Does NOT depend on
dissect.cobaltstrike for core operation — that library is only used
as an optional cross-validation reference.

TLV Format (validated against real CS 4.9.1 payload):
    Each entry: [SettingID: uint16 BE] [DataType: uint16 BE] [Length: uint16 BE] [Value: N bytes]
    DataType: 1=short(2B), 2=int(4B), 3=data/blob(variable)
    All multi-byte fields are BIG-ENDIAN.

Detection Strategy:
    Phase 1: Section scan for candidate encrypted blocks
    Phase 2: Multi-pass XOR brute-force (single-byte, 4-byte rolling)
    Phase 3: TLV validation against version schema
"""

import struct
from typing import Any, Dict, List, Optional, Tuple

from cs_aggregator.utils.entropy import shannon_entropy
from cs_aggregator.utils.errors import ConfigDecryptionError
from cs_aggregator.utils.xor_decrypt import (
    CONFIG_SIGNATURE_ENCRYPTED,
    KNOWN_TLV_TYPES_4_10,
    KNOWN_TLV_TYPES_4_12,
    KNOWN_TLV_TYPES_4_9,
    TLV_HEADER_SIZE,
    VALID_DATA_TYPES,
    detect_xor_key,
    xor_rolling_key,
    xor_single_byte,
)
from cs_aggregator.utils.types import ConfigBlockResult


# ─── Authoritative CS 4.9.1 Setting ID → Name Mapping ──────────────────────
# Source: dissect.cobaltstrike BeaconSetting enum + validated against real payload
SETTING_NAMES: Dict[int, str] = {
    1:  "SETTING_PROTOCOL",
    2:  "SETTING_PORT",
    3:  "SETTING_SLEEPTIME",
    4:  "SETTING_MAXGET",
    5:  "SETTING_JITTER",
    6:  "SETTING_MAXDNS",
    7:  "SETTING_PUBKEY",
    8:  "SETTING_DOMAINS",
    9:  "SETTING_USERAGENT",
    10: "SETTING_SUBMITURI",
    11: "SETTING_C2_RECOVER",
    12: "SETTING_C2_REQUEST",
    13: "SETTING_C2_POSTREQ",
    14: "SETTING_SPAWNTO",
    15: "SETTING_PIPENAME",
    16: "SETTING_BOF_ALLOCATOR",
    17: "SETTING_SYSCALL_METHOD",
    18: "SETTING_KILLDATE_DAY",
    19: "SETTING_DNS_IDLE",
    20: "SETTING_DNS_SLEEP",
    21: "SETTING_SSH_HOST",
    22: "SETTING_SSH_PORT",
    23: "SETTING_SSH_USERNAME",
    24: "SETTING_SSH_PASSWORD",
    25: "SETTING_SSH_KEY",
    26: "SETTING_C2_VERB_GET",
    27: "SETTING_C2_VERB_POST",
    28: "SETTING_C2_CHUNK_POST",
    29: "SETTING_SPAWNTO_X86",
    30: "SETTING_SPAWNTO_X64",
    31: "SETTING_CRYPTO_SCHEME",
    32: "SETTING_PROXY_CONFIG",
    33: "SETTING_PROXY_USER",
    34: "SETTING_PROXY_PASSWORD",
    35: "SETTING_PROXY_BEHAVIOR",
    36: "SETTING_WATERMARKHASH",
    37: "SETTING_WATERMARK",
    38: "SETTING_CLEANUP",
    39: "SETTING_CFG_CAUTION",
    40: "SETTING_KILLDATE",
    41: "SETTING_GARGLE_NOOK",
    42: "SETTING_GARGLE_SECTIONS",
    43: "SETTING_PROCINJ_PERMS_I",
    44: "SETTING_PROCINJ_PERMS",
    45: "SETTING_PROCINJ_MINALLOC",
    46: "SETTING_PROCINJ_TRANSFORM_X86",
    47: "SETTING_PROCINJ_TRANSFORM_X64",
    48: "SETTING_PROCINJ_BOF_REUSE_MEM",
    49: "SETTING_BINDHOST",
    50: "SETTING_HTTP_NO_COOKIES",
    51: "SETTING_PROCINJ_EXECUTE",
    52: "SETTING_PROCINJ_ALLOCATOR",
    53: "SETTING_PROCINJ_STUB",
    54: "SETTING_HOST_HEADER",
    55: "SETTING_EXIT_FUNK",
    56: "SETTING_SSH_BANNER",
    57: "SETTING_SMB_FRAME_HEADER",
    58: "SETTING_TCP_FRAME_HEADER",
    59: "SETTING_HEADERS_REMOVE",
    60: "SETTING_DNS_BEACON_BEACON",
    61: "SETTING_DNS_BEACON_GET_A",
    62: "SETTING_DNS_BEACON_GET_AAAA",
    63: "SETTING_DNS_BEACON_GET_TXT",
    64: "SETTING_DNS_BEACON_PUT_METADATA",
    65: "SETTING_DNS_BEACON_PUT_OUTPUT",
    66: "SETTING_DNSRESOLVER",
    67: "SETTING_DOMAIN_STRATEGY",
    68: "SETTING_DOMAIN_STRATEGY_SECONDS",
    69: "SETTING_DOMAIN_STRATEGY_FAIL_X",
    70: "SETTING_DOMAIN_STRATEGY_FAIL_SECONDS",
    71: "SETTING_MAX_RETRY_STRATEGY_ATTEMPTS",
    72: "SETTING_MAX_RETRY_STRATEGY_INCREASE",
    73: "SETTING_MAX_RETRY_STRATEGY_DURATION",
    74: "SETTING_MASKED_WATERMARK",
    75: "SETTING_DATA_STORE_SIZE",
    76: "SETTING_HTTP_DATA_REQUIRED",
    77: "SETTING_BEACON_GATE",
    78: "SETTING_BEACON_GATE_CONFIG",
    # CS 4.12+ (drip-loading)
    79: "SETTING_RDLL_USE_DRIPLOADING",
    80: "SETTING_RDLL_DRIPLOAD_DELAY",
}

# ─── Authoritative Per-Setting Expected Data Types ───────────────────────────
# Source: PRD_4.9.1 settingIDMap + dissect.cobaltstrike BeaconSetting enum
# 1 = SHORT (uint16), 2 = INT (uint32), 3 = DATA (blob/string)
SETTING_EXPECTED_TYPES: Dict[int, int] = {
    1: 1, 2: 1, 3: 2, 4: 2, 5: 1, 6: 1,
    7: 3, 8: 3, 9: 3, 10: 3, 11: 3, 12: 3, 13: 3,
    14: 3, 15: 3, 16: 1, 17: 1, 18: 1,
    19: 2, 20: 2,
    21: 3, 22: 1, 23: 3, 24: 3, 25: 3,
    26: 3, 27: 3, 28: 2,
    29: 3, 30: 3, 31: 1,
    32: 3, 33: 3, 34: 3, 35: 1,
    36: 3, 37: 2, 38: 1, 39: 1, 40: 3,
    41: 2, 42: 3,
    43: 1, 44: 1, 45: 2,
    46: 3, 47: 3, 48: 1,
    49: 3, 50: 1, 51: 3, 52: 1, 53: 3,
    54: 3, 55: 1, 56: 3,
    57: 3, 58: 3, 59: 3,
    60: 3, 61: 3, 62: 3, 63: 3, 64: 3, 65: 3,
    66: 3, 67: 1, 68: 2, 69: 2, 70: 2,
    71: 2, 72: 2, 73: 2,
    74: 3, 75: 2, 76: 1,
    # 4.10+ additions (BeaconGate)
    77: 3, 78: 3,
    # 4.12+ additions (drip-loading)
    79: 1, 80: 2,
}

# ─── Semantic Validation Rules ────────────────────────────────────────────────
# Checks applied after type validation on decoded values
SETTING_VALIDATION: Dict[int, Dict[str, Any]] = {
    1:  {"validValues": [0, 1, 2, 4, 8, 14, 16], "desc": "BeaconType"},
    2:  {"min": 1, "max": 65535, "desc": "Port"},
    5:  {"min": 0, "max": 99, "desc": "Jitter (0-99%)"},
    17: {"validValues": [0, 1, 2], "desc": "SyscallMethod: 0=None,1=Direct,2=Indirect"},
    38: {"validValues": [0, 1], "desc": "Stage cleanup flag"},
    39: {"validValues": [0, 1], "desc": "Config caution flag"},
    50: {"validValues": [0, 1], "desc": "HTTP no-cookies flag"},
    52: {"validValues": [0, 1], "desc": "Allocator: 0=VirtualAllocEx,1=NtMapViewOfSection"},
    55: {"validValues": [0, 1, 2], "desc": "ExitFunction: 0=process,1=thread,2=ntdll"},
}



class TLVField:
    """A single TLV entry in the configuration block.

    Format: [SettingID:2 BE][DataType:2 BE][Length:2 BE][Value:N bytes]
    """

    def __init__(self, setting_id: int, data_type: int, length: int, value: bytes):
        self.type = setting_id       # Setting ID (1-78)
        self.data_type = data_type   # 1=short, 2=int, 3=data
        self.length = length
        self.value = value

    def __repr__(self) -> str:
        name = SETTING_NAMES.get(self.type, f"UNKNOWN_{self.type}")
        return f"TLVField({name}, dt={self.data_type}, len={self.length})"

    def as_int(self) -> int:
        """Interpret value as big-endian integer."""
        if self.data_type == 1 and len(self.value) >= 2:
            return struct.unpack(">H", self.value[:2])[0]
        elif self.data_type == 2 and len(self.value) >= 4:
            return struct.unpack(">I", self.value[:4])[0]
        return int.from_bytes(self.value, "big") if self.value else 0

    def as_string(self) -> str:
        """Interpret value as ASCII string, null-terminated.

        Handles all-null values (e.g. empty SETTING_PIPENAME) by returning
        empty string instead of garbage.
        """
        if not self.value or all(b == 0 for b in self.value):
            return ""
        return self.value.split(b"\x00")[0].decode("ascii", errors="replace")

    def as_hex(self) -> str:
        return self.value.hex()


class ConfigExtractor:
    """Configuration block extractor with custom XOR brute-force and TLV parsing.

    This is the core custom parsing logic — NOT relying on dissect.cobaltstrike.
    """

    def __init__(self, version_schema: Optional[Dict[str, Any]] = None):
        """Initialize with an optional version schema.

        Args:
            version_schema: Version schema with TLV type definitions,
                config block heuristics, and known XOR keys.
        """
        self.schema = version_schema or {}

    def extract_config(self, dll_data: bytes) -> ConfigBlockResult:
        """Extract and decrypt the configuration block from the beacon DLL.

        Args:
            dll_data: Raw beacon DLL bytes (after extraction from payload).

        Returns:
            ConfigBlockResult with parsed config and XOR key metadata.

        Raises:
            ConfigDecryptionError: If config block cannot be located or decrypted.
        """
        # Phase 0: Fast path — search for the 0x2E XOR config signature
        # Scan the ENTIRE DLL (not just offset 0) — config block can be
        # anywhere in initialized data sections.
        valid_types = self._get_valid_tlv_types()
        search_offset = 0
        while True:
            sig_offset = dll_data.find(CONFIG_SIGNATURE_ENCRYPTED, search_offset)
            if sig_offset < 0:
                break

            # Found a candidate. Try expanding block sizes.
            best_result = None
            for block_size in [4096, 8192, 16384]:
                block_end = min(sig_offset + block_size, len(dll_data))
                block_data = dll_data[sig_offset:block_end]
                decrypted = xor_single_byte(block_data, 0x2E)
                tlv_entries = self._parse_tlv_entries(decrypted, valid_types)

                if tlv_entries:
                    best_result = (block_data, decrypted, tlv_entries)
                    # Check if last TLV entry might be truncated
                    pos = sum(TLV_HEADER_SIZE + e.length for e in tlv_entries)
                    if pos >= len(decrypted) - TLV_HEADER_SIZE and block_size < 16384:
                        continue  # Might be truncated, try bigger
                    break  # Good parse, stop expanding

            if best_result:
                block_data, decrypted, tlv_entries = best_result
                config_json = self._tlv_to_config(tlv_entries)
                tlv_coverage = self._compute_tlv_coverage(tlv_entries, valid_types)

                return ConfigBlockResult(
                    xor_key="2e",
                    xor_key_length=1,
                    key_detection_method="signature_match_0x2e",
                    offset=sig_offset,
                    size_encrypted=len(block_data),
                    size_decrypted=len(decrypted),
                    config_json=config_json,
                    tlv_coverage=tlv_coverage,
                )

            # This match was invalid, keep searching after it
            search_offset = sig_offset + 1

        # Phase 0b: Heuristic — try common XOR keys against the first-TLV pattern
        # For payloads using non-standard single-byte keys (e.g. 0x69)
        for candidate_key in [0x69, 0x2E, 0x00]:
            expected = bytes([
                0x00 ^ candidate_key, 0x01 ^ candidate_key,  # SettingID=1
                0x00 ^ candidate_key, 0x01 ^ candidate_key,  # DataType=1
                0x00 ^ candidate_key, 0x02 ^ candidate_key,  # Length=2
            ])
            sig_offset = dll_data.find(expected)
            if sig_offset >= 0 and candidate_key != 0x2E:  # 0x2E already tried above
                for block_size in [4096, 8192, 16384]:
                    block_end = min(sig_offset + block_size, len(dll_data))
                    block_data = dll_data[sig_offset:block_end]
                    decrypted = xor_single_byte(block_data, candidate_key)
                    tlv_entries = self._parse_tlv_entries(decrypted, valid_types)
                    if tlv_entries and len(tlv_entries) >= 3:
                        config_json = self._tlv_to_config(tlv_entries)
                        tlv_coverage = self._compute_tlv_coverage(tlv_entries, valid_types)
                        return ConfigBlockResult(
                            xor_key=f"{candidate_key:02x}",
                            xor_key_length=1,
                            key_detection_method=f"signature_match_0x{candidate_key:02x}",
                            offset=sig_offset,
                            size_encrypted=len(block_data),
                            size_decrypted=len(decrypted),
                            config_json=config_json,
                            tlv_coverage=tlv_coverage,
                        )

        # Phase 1: Find candidate encrypted blocks in PE sections
        # Uses fallback to scan ALL initialized data sections when
        # obfuscate=true causes section names to be XOR'd garbage.
        candidates = self._find_candidate_blocks_with_fallback(dll_data)

        if not candidates:
            raise ConfigDecryptionError(
                "No candidate configuration blocks found in the beacon DLL data sections"
            )

        # Get version-specific valid TLV types
        valid_types = self._get_valid_tlv_types()

        # Phase 2: Try XOR brute-force on each candidate
        for offset, block_data in candidates:
            key, decrypted, method = detect_xor_key(block_data, valid_types)

            if key is not None and decrypted is not None:
                # Phase 3: Parse TLV entries
                tlv_entries = self._parse_tlv_entries(decrypted, valid_types)

                if tlv_entries:
                    config_json = self._tlv_to_config(tlv_entries)
                    tlv_coverage = self._compute_tlv_coverage(tlv_entries, valid_types)

                    return ConfigBlockResult(
                        xor_key=key.hex(),
                        xor_key_length=len(key),
                        key_detection_method=method,
                        offset=offset,
                        size_encrypted=len(block_data),
                        size_decrypted=len(decrypted),
                        config_json=config_json,
                        tlv_coverage=tlv_coverage,
                    )

        # If all brute-force attempts fail
        raise ConfigDecryptionError(
            f"Failed to decrypt configuration block after trying {len(candidates)} "
            f"candidate blocks. Payload may use an unknown XOR scheme or custom encryption."
        )

    def _find_candidate_blocks(self, dll_data: bytes) -> List[Tuple[int, bytes]]:
        """Phase 1: Scan PE data sections for candidate encrypted config blocks.

        Candidates are identified by:
        - Location near end of .data or .rdata section
        - Low-variance byte distribution (characteristic of XOR-encrypted data)
        - High entropy (encrypted data)
        - Size between 256–4096 bytes

        Returns:
            List of (offset, block_bytes) candidates, sorted by likelihood.
        """
        candidates: List[Tuple[int, bytes, float]] = []

        # Get section boundaries from the DLL
        sections = self._get_section_ranges(dll_data)

        for sec_name, sec_start, sec_end in sections:
            if sec_name not in self._get_target_sections():
                continue

            section_data = dll_data[sec_start:sec_end]

            if len(section_data) < 256:
                continue

            # Scan the last portion of the section for config blocks
            search_start = max(0, len(section_data) - 4096)
            search_end = len(section_data)

            for offset in range(search_start, search_end - 256):
                # Try different block sizes
                for size in [256, 512, 1024, 2048, 4096]:
                    if offset + size > len(section_data):
                        continue

                    block = section_data[offset:offset + size]
                    entropy = shannon_entropy(block)

                    # Config blocks typically have moderate-to-high entropy
                    # XOR-encrypted TLV data usually scores between 5.5 and 7.8
                    if 5.5 <= entropy <= 7.8:
                        # Check for low-variance byte distribution (XOR characteristic)
                        variance = self._byte_variance(block)
                        if variance < 0.15:  # Low variance = likely XOR-encrypted
                            likelihood = self._score_candidate(entropy, variance, offset, sec_name)
                            candidates.append((
                                sec_start + offset,
                                block,
                                likelihood,
                            ))

        # Sort by likelihood descending, return unique offsets
        candidates.sort(key=lambda x: x[2], reverse=True)

        # Deduplicate by offset (keep highest likelihood)
        seen_offsets: set = set()
        unique_candidates: List[Tuple[int, bytes]] = []
        for offset, block, _ in candidates:
            if offset not in seen_offsets:
                seen_offsets.add(offset)
                unique_candidates.append((offset, block))

        # Limit to top candidates
        return unique_candidates[:20]

    def _get_section_ranges(self, dll_data: bytes) -> List[Tuple[str, int, int]]:
        """Extract PE section ranges (name, start_offset, end_offset) from the DLL."""
        sections: List[Tuple[str, int, int]] = []

        if len(dll_data) < 64:
            return sections

        pe_offset = struct.unpack_from("<I", dll_data, 0x3C)[0]

        if pe_offset + 24 > len(dll_data):
            return sections

        num_sections = struct.unpack_from("<H", dll_data, pe_offset + 6)[0]
        size_of_optional = struct.unpack_from("<H", dll_data, pe_offset + 20)[0]
        section_table_offset = pe_offset + 24 + size_of_optional

        for i in range(num_sections):
            sec_start = section_table_offset + i * 40
            if sec_start + 40 > len(dll_data):
                break

            # Section name
            name_raw = dll_data[sec_start:sec_start + 8].split(b"\x00")[0]
            try:
                name = name_raw.decode("ascii", errors="replace").strip()
            except UnicodeDecodeError:
                name = f"unnamed_{i}"

            raw_pointer = struct.unpack_from("<I", dll_data, sec_start + 20)[0]
            raw_size = struct.unpack_from("<I", dll_data, sec_start + 16)[0]

            if raw_size > 0 and raw_pointer + raw_size <= len(dll_data):
                sections.append((name, raw_pointer, raw_pointer + raw_size))

        return sections

    def _get_target_sections(self) -> set:
        """Get section names to search for config blocks, from schema or defaults."""
        heuristics = self.schema.get("configBlockHeuristics", {})
        section_names = heuristics.get("sectionNames", [".data", ".rdata"])
        return set(section_names)

    def _find_candidate_blocks_with_fallback(self, dll_data: bytes) -> List[Tuple[int, bytes]]:
        """Find candidates, with fallback to ALL initialized data sections.

        When obfuscate=true in the C2 profile, section names are XOR'd to
        non-ASCII garbage. The standard name-based match will fail, so we
        fallback to scanning any section with IMAGE_SCN_CNT_INITIALIZED_DATA.
        """
        # First try standard name-based search
        candidates = self._find_candidate_blocks(dll_data)
        if candidates:
            return candidates

        # Fallback: scan ALL initialized data sections (flag 0x40)
        IMAGE_SCN_CNT_INITIALIZED_DATA = 0x40
        sections = self._get_section_ranges_with_flags(dll_data)

        fallback_candidates: List[Tuple[int, bytes, float]] = []
        for sec_name, sec_start, sec_end, flags in sections:
            if not (flags & IMAGE_SCN_CNT_INITIALIZED_DATA):
                continue

            section_data = dll_data[sec_start:sec_end]
            if len(section_data) < 256:
                continue

            # Scan for config signature in this section
            sig_pos = section_data.find(CONFIG_SIGNATURE_ENCRYPTED)
            if sig_pos >= 0:
                block_end = min(sig_pos + 8192, len(section_data))
                block = section_data[sig_pos:block_end]
                fallback_candidates.append((sec_start + sig_pos, block, 1.0))
                continue

            # General entropy scan
            search_start = max(0, len(section_data) - 4096)
            for offset in range(search_start, len(section_data) - 256):
                for size in [512, 1024, 2048, 4096]:
                    if offset + size > len(section_data):
                        continue
                    block = section_data[offset:offset + size]
                    entropy = shannon_entropy(block)
                    if 5.5 <= entropy <= 7.8:
                        variance = self._byte_variance(block)
                        if variance < 0.15:
                            fallback_candidates.append((
                                sec_start + offset, block,
                                self._score_candidate(entropy, variance, offset, sec_name)
                            ))

        fallback_candidates.sort(key=lambda x: x[2], reverse=True)
        return [(o, b) for o, b, _ in fallback_candidates[:20]]

    def _get_section_ranges_with_flags(
        self, dll_data: bytes
    ) -> List[Tuple[str, int, int, int]]:
        """Extract PE section ranges with characteristic flags."""
        sections: List[Tuple[str, int, int, int]] = []
        if len(dll_data) < 64:
            return sections

        pe_offset = struct.unpack_from("<I", dll_data, 0x3C)[0]
        if pe_offset + 24 > len(dll_data):
            return sections

        num_sections = struct.unpack_from("<H", dll_data, pe_offset + 6)[0]
        size_of_optional = struct.unpack_from("<H", dll_data, pe_offset + 20)[0]
        section_table_offset = pe_offset + 24 + size_of_optional

        for i in range(num_sections):
            sec_start = section_table_offset + i * 40
            if sec_start + 40 > len(dll_data):
                break

            name_raw = dll_data[sec_start:sec_start + 8].split(b"\x00")[0]
            # Detect obfuscated names: if any byte > 127, it's garbage
            is_obfuscated = any(b > 127 for b in name_raw)
            if is_obfuscated:
                name = f"obfuscated_{i}"
            else:
                try:
                    name = name_raw.decode("ascii", errors="replace").strip()
                except UnicodeDecodeError:
                    name = f"unnamed_{i}"

            raw_pointer = struct.unpack_from("<I", dll_data, sec_start + 20)[0]
            raw_size = struct.unpack_from("<I", dll_data, sec_start + 16)[0]
            flags = struct.unpack_from("<I", dll_data, sec_start + 36)[0]

            if raw_size > 0 and raw_pointer + raw_size <= len(dll_data):
                sections.append((name, raw_pointer, raw_pointer + raw_size, flags))

        return sections

    @staticmethod
    def _byte_variance(data: bytes) -> float:
        """Calculate byte value variance (lower = more uniform = likely XOR-encrypted).

        Returns a value between 0.0 (all bytes same) and ~1.0 (even distribution).
        XOR-encrypted TLV data typically scores between 0.01 and 0.15.
        """
        if not data:
            return 1.0

        freq = [0] * 256
        for b in data:
            freq[b] += 1

        mean = len(data) / 256
        variance = sum((f - mean) ** 2 for f in freq) / 256

        # Normalize
        max_variance = (len(data) - mean) ** 2 / 256 if mean > 0 else 0
        if max_variance == 0:
            return 1.0

        return min(1.0, variance / max_variance)

    @staticmethod
    def _score_candidate(entropy: float, variance: float, offset: int, section_name: str) -> float:
        """Score a candidate config block for likelihood.

        Higher score = more likely to be a valid config block.
        """
        score = 0.0

        # Entropy in sweet spot (6.0–7.5 is ideal for XOR-encrypted TLV)
        if 6.0 <= entropy <= 7.5:
            score += 0.4
        elif 5.5 <= entropy < 6.0 or 7.5 < entropy <= 7.8:
            score += 0.2

        # Low variance is good (indicates XOR encryption)
        if variance < 0.05:
            score += 0.4
        elif variance < 0.1:
            score += 0.3
        elif variance < 0.15:
            score += 0.1

        # Prefer .data section (most common location)
        if section_name == ".data":
            score += 0.2
        elif section_name == ".rdata":
            score += 0.1

        return score

    def _get_valid_tlv_types(self) -> set:
        """Get valid TLV setting IDs from version schema or defaults."""
        tlv_types = self.schema.get("tlvTypes", {})
        if tlv_types:
            # Schema keys may be hex strings like "0x0001" or decimal
            result = set()
            for key in tlv_types.keys():
                try:
                    result.add(int(key, 16) if key.startswith("0x") else int(key))
                except ValueError:
                    pass
            return result if result else KNOWN_TLV_TYPES_4_9

        # Fallback: try to determine from version
        version = self.schema.get("meta", {}).get("version", "")
        if version.startswith("4.12"):
            return KNOWN_TLV_TYPES_4_12
        elif version.startswith("4.10"):
            return KNOWN_TLV_TYPES_4_10
        else:
            return KNOWN_TLV_TYPES_4_9

    def _parse_tlv_entries(self, data: bytes, valid_types: set) -> List[TLVField]:
        """Parse TLV entries from decrypted config data.

        Real CS TLV format (big-endian):
            [SettingID: uint16] [DataType: uint16] [Length: uint16] [Value: Length bytes]
        """
        entries: List[TLVField] = []
        offset = 0

        while offset + TLV_HEADER_SIZE <= len(data):
            setting_id = struct.unpack_from(">H", data, offset)[0]
            data_type = struct.unpack_from(">H", data, offset + 2)[0]
            length = struct.unpack_from(">H", data, offset + 4)[0]

            # End marker: setting_id == 0
            if setting_id == 0:
                break

            # Sanity: data type must be valid
            if data_type not in VALID_DATA_TYPES:
                break

            if length > 10000:  # Sanity check
                break

            if offset + TLV_HEADER_SIZE + length > len(data):
                break

            value = data[offset + TLV_HEADER_SIZE:offset + TLV_HEADER_SIZE + length]
            entries.append(TLVField(setting_id, data_type, length, value))

            offset += TLV_HEADER_SIZE + length

        return entries

    def _tlv_to_config(self, entries: List[TLVField]) -> Dict[str, Any]:
        """Convert parsed TLV entries to a JSON-serializable config dict.

        Maps each setting ID to its human-readable name using the authoritative
        SETTING_NAMES mapping (derived from dissect.cobaltstrike BeaconSetting enum).
        """
        config: Dict[str, Any] = {}

        for entry in entries:
            field_name = SETTING_NAMES.get(entry.type, f"unknown_setting_{entry.type}")

            try:
                if entry.data_type == 1:  # SHORT
                    config[field_name] = entry.as_int()
                elif entry.data_type == 2:  # INT
                    config[field_name] = entry.as_int()
                elif entry.data_type == 3:  # DATA/BLOB
                    # Try to decode as ASCII string if it looks printable
                    try:
                        decoded = entry.as_string()
                        if decoded and all(32 <= ord(c) < 127 for c in decoded[:20] if c):
                            config[field_name] = decoded
                        elif len(entry.value) <= 32:
                            config[field_name] = entry.as_hex()
                        else:
                            # Store as hex for binary blobs
                            config[field_name] = entry.as_hex()
                    except (UnicodeDecodeError, ValueError):
                        config[field_name] = entry.as_hex()
            except (ValueError, UnicodeDecodeError, struct.error):
                config[field_name] = entry.as_hex()

        return config

    def _compute_tlv_coverage(self, entries: List[TLVField], valid_types: set) -> Dict[str, Any]:
        """Compute TLV parsing coverage statistics with type and semantic validation.

        Reports: which types were found, which expected types are missing,
        unknown types encountered, type mismatches, and semantic violations.
        """
        found_ids = {e.type for e in entries}
        missing = valid_types - found_ids
        unknown = found_ids - valid_types

        # Per-field type validation
        type_mismatches: List[Dict[str, Any]] = []
        semantic_warnings: List[Dict[str, Any]] = []

        for entry in entries:
            # Check data type against expected
            expected_dt = SETTING_EXPECTED_TYPES.get(entry.type)
            if expected_dt is not None and entry.data_type != expected_dt:
                type_mismatches.append({
                    "settingId": entry.type,
                    "name": SETTING_NAMES.get(entry.type, "UNKNOWN"),
                    "expectedType": expected_dt,
                    "actualType": entry.data_type,
                })

            # Semantic validation on decoded values
            validation = SETTING_VALIDATION.get(entry.type)
            if validation and entry.data_type in (1, 2):
                try:
                    value = entry.as_int()
                    if "validValues" in validation:
                        if value not in validation["validValues"]:
                            semantic_warnings.append({
                                "settingId": entry.type,
                                "name": SETTING_NAMES.get(entry.type, "UNKNOWN"),
                                "value": value,
                                "rule": validation["desc"],
                                "severity": "warn",
                            })
                    if "min" in validation and value < validation["min"]:
                        semantic_warnings.append({
                            "settingId": entry.type,
                            "name": SETTING_NAMES.get(entry.type, "UNKNOWN"),
                            "value": value,
                            "rule": f"below minimum {validation['min']}",
                            "severity": "warn",
                        })
                    if "max" in validation and value > validation["max"]:
                        semantic_warnings.append({
                            "settingId": entry.type,
                            "name": SETTING_NAMES.get(entry.type, "UNKNOWN"),
                            "value": value,
                            "rule": f"above maximum {validation['max']}",
                            "severity": "warn",
                        })
                except (ValueError, struct.error):
                    pass

        return {
            "settingsFound": sorted(found_ids),
            "settingsMissing": sorted(missing),
            "settingsUnknown": sorted(unknown),
            "totalEntries": len(entries),
            "settingNames": {sid: SETTING_NAMES.get(sid, "UNKNOWN") for sid in sorted(found_ids)},
            "typeMismatches": type_mismatches,
            "semanticWarnings": semantic_warnings,
        }

    @staticmethod
    def serialize_config_to_tlv(config_json: Dict[str, Any]) -> bytes:
        """Serialize a configuration dictionary back to TLV byte format.

        This is the inverse of _tlv_to_config(). Maps field names back
        to setting IDs, serializes values appropriately, and produces
        a contiguous TLV byte stream using the real 6-byte header format.

        Args:
            config_json: The configuration dictionary to serialize.

        Returns:
            TLV-encoded bytes ready for XOR encryption.
        """
        # Build reverse mapping: field_name -> setting ID
        name_to_id: Dict[str, int] = {v: k for k, v in SETTING_NAMES.items()}

        tlv_parts: List[bytes] = []

        for field_name, value in config_json.items():
            # Skip metadata fields
            if field_name.startswith("_"):
                continue

            # Look up setting ID
            setting_id = name_to_id.get(field_name)
            if setting_id is None:
                # Try parsing from "unknown_setting_XX" format
                if field_name.startswith("unknown_setting_"):
                    try:
                        setting_id = int(field_name.split("_")[-1])
                    except (ValueError, IndexError):
                        continue
                else:
                    continue

            # Serialize value to bytes and determine data type
            value_bytes, data_type = ConfigExtractor._serialize_tlv_value(setting_id, value)
            if value_bytes is not None:
                # 6-byte header: [SettingID:2 BE][DataType:2 BE][Length:2 BE]
                header = struct.pack(">HHH", setting_id, data_type, len(value_bytes))
                tlv_parts.append(header + value_bytes)

        # Add null terminator (6 null bytes)
        tlv_parts.append(b"\x00" * TLV_HEADER_SIZE)

        return b"".join(tlv_parts)

    @staticmethod
    def _serialize_tlv_value(setting_id: int, value: Any) -> Tuple[Optional[bytes], int]:
        """Serialize a Python value to bytes for a given setting ID.

        Returns (value_bytes, data_type) or (None, 0) if cannot serialize.
        """
        # Determine data type from setting ID
        # SHORT settings (data_type=1): small numeric values
        short_settings = {1, 2, 5, 6, 16, 17, 18, 22, 31, 35, 38, 39,
                          43, 44, 48, 50, 52, 55, 67}
        # INT settings (data_type=2): larger numeric values
        int_settings = {3, 4, 19, 20, 28, 37, 40, 41, 45, 68, 69, 70,
                        71, 72, 73, 75, 76}

        if setting_id in short_settings:
            if isinstance(value, (int, float)):
                return struct.pack(">H", int(value)), 1
            try:
                return struct.pack(">H", int(value)), 1
            except (ValueError, struct.error):
                return None, 0

        if setting_id in int_settings:
            if isinstance(value, (int, float)):
                return struct.pack(">I", int(value)), 2
            try:
                return struct.pack(">I", int(value)), 2
            except (ValueError, struct.error):
                return None, 0

        # DATA/BLOB settings (data_type=3): strings and binary data
        if isinstance(value, str):
            # Try hex decode first
            try:
                return bytes.fromhex(value), 3
            except ValueError:
                return value.encode("ascii", errors="replace") + b"\x00", 3
        if isinstance(value, bytes):
            return value, 3
        if isinstance(value, (int, float)):
            return struct.pack(">I", int(value)), 2

        return str(value).encode("ascii", errors="replace"), 3

    @staticmethod
    def reencrypt_config(config_json: Dict[str, Any], xor_key: bytes) -> bytes:
        """Re-encrypt a modified config JSON back to XOR-encrypted format.

        This is used by MOD_REASSEMBLER for payload modification.
        Step 1: Serialize config dict to TLV bytes
        Step 2: XOR-encrypt with the provided key

        Args:
            config_json: The configuration dictionary.
            xor_key: XOR key bytes to use for encryption.

        Returns:
            Re-encrypted configuration block bytes.
        """
        # Serialize the config dict to TLV format
        tlv_data = ConfigExtractor.serialize_config_to_tlv(config_json)

        if not tlv_data:
            raise ValueError("Config serialization produced empty TLV data")

        # XOR-encrypt the TLV data with the provided key
        encrypted = xor_rolling_key(tlv_data, xor_key)

        return encrypted
