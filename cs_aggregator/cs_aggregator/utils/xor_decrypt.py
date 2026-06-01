"""XOR decryption utilities for CobaltStrike configuration block extraction.

Supports single-byte XOR and 4-byte rolling XOR key decryption,
with brute-force key detection algorithms.

TLV Format (confirmed via dissect.cobaltstrike + real payload validation):
    Each entry: [SettingID: uint16 BE] [DataType: uint16 BE] [Length: uint16 BE] [Value: Length bytes]
    DataType: 1=short(2B), 2=int(4B), 3=data(variable)
    All multi-byte fields are BIG-ENDIAN.
"""

from typing import List, Optional, Tuple


def xor_single_byte(data: bytes, key: int) -> bytes:
    """Decrypt data using single-byte XOR key."""
    return bytes(b ^ key for b in data)


def xor_rolling_4byte(data: bytes, key: bytes) -> bytes:
    """Decrypt data using 4-byte rolling XOR key.

    The key repeats every 4 bytes: data[i] ^= key[i % 4]
    """
    if len(key) != 4:
        raise ValueError(f"4-byte rolling XOR key required, got {len(key)} bytes")
    return bytes(b ^ key[i % 4] for i, b in enumerate(data))


def xor_rolling_key(data: bytes, key: bytes) -> bytes:
    """Decrypt data using a rolling XOR key of arbitrary length."""
    if not key:
        raise ValueError("Key must not be empty")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


# ─── TLV Validation Constants ────────────────────────────────────────────────
# Real CS setting IDs are decimal 1-78 (not hex 0x0001-0x002B).
# Source: dissect.cobaltstrike BeaconSetting enum + real payload validation.
KNOWN_SETTING_IDS_4_9 = set(range(1, 77))     # IDs 1-76 (4.9.x includes DATA_STORE_SIZE=76)
KNOWN_SETTING_IDS_4_10 = set(range(1, 79))    # IDs 1-78 (4.10.x adds BEACON_GATE=77,78)
KNOWN_SETTING_IDS_4_11 = set(range(1, 79))    # IDs 1-78 (same TLV set as 4.10, novel sleepmask)
KNOWN_SETTING_IDS_4_12 = set(range(1, 81))    # IDs 1-80 (4.12 adds drip-loading: 79,80)

# Valid data types in TLV entries
VALID_DATA_TYPES = {1, 2, 3}  # 1=short, 2=int, 3=data/blob

# Legacy aliases for backward compatibility
KNOWN_TLV_TYPES_4_9 = KNOWN_SETTING_IDS_4_9
KNOWN_TLV_TYPES_4_10 = KNOWN_SETTING_IDS_4_10
KNOWN_TLV_TYPES_4_11 = KNOWN_SETTING_IDS_4_11
KNOWN_TLV_TYPES_4_12 = KNOWN_SETTING_IDS_4_12

# The XOR 0x2E config detection signature:
# Encrypted bytes [0x2E,0x2F,0x2E,0x2F,0x2E,0x2C] decrypt to [0x00,0x01,0x00,0x01,0x00,0x02]
# which is the first TLV header: SettingID=1 (PROTOCOL), DataType=1 (SHORT), Length=2
CONFIG_SIGNATURE_ENCRYPTED = bytes([0x2E, 0x2F, 0x2E, 0x2F, 0x2E, 0x2C])
CONFIG_SIGNATURE_DECRYPTED = bytes([0x00, 0x01, 0x00, 0x01, 0x00, 0x02])

# TLV header size: 6 bytes (SettingID:2 + DataType:2 + Length:2), all big-endian
TLV_HEADER_SIZE = 6


def _looks_like_tlv(data: bytes, valid_types: set) -> bool:
    """Check if decrypted data contains valid TLV structure.

    Real CS TLV format (big-endian):
        [SettingID: uint16] [DataType: uint16] [Length: uint16] [Value: Length bytes]

    Quick validation: check first few entries have valid setting IDs,
    valid data types (1-3), and lengths that don't exceed remaining data.
    """
    offset = 0
    entries_checked = 0
    while offset + TLV_HEADER_SIZE <= len(data) and entries_checked < 5:
        setting_id = int.from_bytes(data[offset:offset + 2], "big")
        data_type = int.from_bytes(data[offset + 2:offset + 4], "big")
        length = int.from_bytes(data[offset + 4:offset + 6], "big")

        # Setting ID must be in known range
        if setting_id not in valid_types:
            return False

        # Data type must be 1 (short), 2 (int), or 3 (data)
        if data_type not in VALID_DATA_TYPES:
            return False

        # Length must not exceed remaining data
        if offset + TLV_HEADER_SIZE + length > len(data):
            return False

        # Cross-validate length against data type
        if data_type == 1 and length != 2:
            return False
        if data_type == 2 and length != 4:
            return False

        offset += TLV_HEADER_SIZE + length
        entries_checked += 1

    return entries_checked > 0


def brute_force_xor_single_byte(data: bytes, valid_types: set = KNOWN_SETTING_IDS_4_9) -> List[Tuple[int, bytes]]:
    """Try all 256 single-byte XOR keys and return valid-looking results.

    Returns list of (key, decrypted_data) tuples for keys that produce
    valid TLV-like output, sorted by plausibility.
    """
    results: List[Tuple[int, bytes, int]] = []

    # Try 0x2E first (standard CS v4.x key) for speed
    priority_keys = [0x2E, 0x69]
    other_keys = [k for k in range(256) if k not in priority_keys]

    for key in priority_keys + other_keys:
        decrypted = xor_single_byte(data, key)
        if _looks_like_tlv(decrypted, valid_types):
            # Score: count valid TLV entries
            score = _count_tlv_entries(decrypted, valid_types)
            results.append((key, decrypted, score))

    # Sort by score descending (most TLV entries = most likely)
    results.sort(key=lambda x: x[2], reverse=True)
    return [(k, d) for k, d, _ in results]


def brute_force_xor_four_byte(
    data: bytes,
    valid_types: set = KNOWN_SETTING_IDS_4_9,
    max_candidates: int = 10000,
) -> List[Tuple[bytes, bytes]]:
    """Brute-force 4-byte rolling XOR keys.

    Since 4-byte keyspace is 2^32, we use heuristics:
    1. If the encrypted data has null bytes, the key byte at that position
       is revealed (null ^ key = key).
    2. First 4 bytes of data as potential key.
    3. Common key patterns from known CS versions.
    4. Null-byte position analysis to infer key bytes.

    Returns list of (key, decrypted_data) sorted by plausibility.
    """
    results: List[Tuple[bytes, bytes, int]] = []

    # Heuristic: find known key patterns from frequent positions
    key_candidates = _generate_4byte_key_candidates(data, max_candidates)

    for key in key_candidates:
        decrypted = xor_rolling_4byte(data, key)
        if _looks_like_tlv(decrypted, valid_types):
            score = _count_tlv_entries(decrypted, valid_types)
            results.append((key, decrypted, score))

    results.sort(key=lambda x: x[2], reverse=True)
    return [(k, d) for k, d, _ in results]


def _generate_4byte_key_candidates(data: bytes, max_candidates: int) -> List[bytes]:
    """Generate candidate 4-byte XOR keys using heuristics.

    1. Known common CobaltStrike XOR keys
    2. First 4 bytes of data as key (common pattern)
    3. Null-byte analysis: if plaintext[i] should be 0x00, then key[i%4] = data[i]
       We know the first TLV entry should start with 0x00,0x01 (SETTING_PROTOCOL=1, big-endian)
       so key[0] = data[0] ^ 0x00, key[1] = data[1] ^ 0x01, etc.
    4. Position-based frequency analysis
    """
    candidates: List[bytes] = []
    seen: set = set()

    def _add(key: bytes) -> None:
        t = tuple(key)
        if t not in seen and len(key) == 4:
            seen.add(t)
            candidates.append(key)

    # Known common CobaltStrike XOR keys (from historical analysis)
    _add(bytes([0x2e, 0x2e, 0x2e, 0x2e]))  # CS 4.x common single-byte 0x2e as rolling
    _add(bytes([0x69, 0x69, 0x69, 0x69]))  # CS 3.x common
    _add(bytes([0x00, 0x00, 0x00, 0x00]))  # No obfuscation (edge case)

    if len(data) >= 4:
        # First 4 bytes as key
        _add(data[:4])

    if len(data) >= 6:
        # Infer key from known first TLV header structure:
        # Expected plaintext: [0x00, 0x01, 0x00, 0x01, 0x00, 0x02]
        # (SETTING_PROTOCOL=1, DataType=SHORT=1, Length=2)
        expected_plaintext = CONFIG_SIGNATURE_DECRYPTED
        for start in range(min(16, len(data) - 5)):
            key = bytes([
                data[start + 0] ^ expected_plaintext[0],
                data[start + 1] ^ expected_plaintext[1],
                data[start + 2] ^ expected_plaintext[2],
                data[start + 3] ^ expected_plaintext[3],
            ])
            _add(key)

    # Null-byte analysis: positions where data[i] could be the key byte
    # (because plaintext is 0x00 at that position)
    if len(data) >= 8:
        # Collect most common byte at each position mod 4
        pos_bytes: list = [[] for _ in range(4)]
        for i, b in enumerate(data[:min(256, len(data))]):
            pos_bytes[i % 4].append(b)

        # Try the most frequent byte at each position as the key byte
        from collections import Counter
        for combo_idx in range(min(5, max_candidates)):
            key_bytes = []
            for pos in range(4):
                counter = Counter(pos_bytes[pos])
                most_common = counter.most_common(min(5, len(counter)))
                idx = min(combo_idx, len(most_common) - 1)
                key_bytes.append(most_common[idx][0])
            _add(bytes(key_bytes))

    # Limit candidates
    return candidates[:max_candidates]


def _count_tlv_entries(data: bytes, valid_types: set) -> int:
    """Count the number of valid TLV entries in decrypted data.

    Uses the real 6-byte TLV header format (big-endian):
        [SettingID:2][DataType:2][Length:2][Value:N]
    """
    count = 0
    offset = 0
    while offset + TLV_HEADER_SIZE <= len(data):
        setting_id = int.from_bytes(data[offset:offset + 2], "big")
        data_type = int.from_bytes(data[offset + 2:offset + 4], "big")
        length = int.from_bytes(data[offset + 4:offset + 6], "big")

        if setting_id not in valid_types:
            break
        if data_type not in VALID_DATA_TYPES:
            break
        if offset + TLV_HEADER_SIZE + length > len(data):
            break

        count += 1
        offset += TLV_HEADER_SIZE + length

    return count


def brute_force_xor_two_byte(
    data: bytes,
    valid_types: set = KNOWN_SETTING_IDS_4_9,
) -> List[Tuple[bytes, bytes]]:
    """Brute-force 2-byte rolling XOR keys (0x0000–0xFFFF).

    Slower than single-byte (65536 candidates) but catches custom 2-byte keys
    used by some operators for additional obfuscation.

    Returns list of (key, decrypted_data) sorted by plausibility.
    """
    results: List[Tuple[bytes, bytes, int]] = []

    for k0 in range(256):
        for k1 in range(256):
            key = bytes([k0, k1])
            decrypted = bytes(b ^ key[i % 2] for i, b in enumerate(data[:64]))
            if _looks_like_tlv(decrypted, valid_types):
                # Full decryption for scoring
                full_decrypted = bytes(b ^ key[i % 2] for i, b in enumerate(data))
                score = _count_tlv_entries(full_decrypted, valid_types)
                if score >= 3:  # Require at least 3 valid entries
                    results.append((key, full_decrypted, score))

        # Early termination if we have good results
        if len(results) >= 5:
            break

    results.sort(key=lambda x: x[2], reverse=True)
    return [(k, d) for k, d, _ in results]


def detect_xor_key(
    encrypted_block: bytes,
    known_types: set = KNOWN_SETTING_IDS_4_9,
    extended_bruteforce: bool = False,
) -> Tuple[Optional[bytes], Optional[bytes], str]:
    """Detect XOR key for an encrypted configuration block.

    Strategy:
    1. Fast check: look for the 0x2E config signature pattern
    2. Then single-byte brute-force (0x2E first)
    3. Then 4-byte rolling brute-force with heuristics
    4. (Extended) Then 2-byte brute-force (0x0000–0xFFFF) — slower

    Args:
        encrypted_block: The encrypted config bytes.
        known_types: Set of valid TLV setting IDs for validation.
        extended_bruteforce: If True, also try 2-byte key space.

    Returns:
        (key, decrypted_data, method_used)
        If detection fails: (None, None, "failed")
    """
    # Step 0: Fast signature check for 0x2E (standard CS v4.x key)
    if len(encrypted_block) >= 6:
        if encrypted_block[:6] == CONFIG_SIGNATURE_ENCRYPTED:
            decrypted = xor_single_byte(encrypted_block, 0x2E)
            if _looks_like_tlv(decrypted, known_types):
                return bytes([0x2E]), decrypted, "signature_match_0x2e"

    # Step 1: Try single-byte brute-force (fastest)
    single_results = brute_force_xor_single_byte(encrypted_block, known_types)
    if single_results:
        key_byte, decrypted = single_results[0]
        key = bytes([key_byte])
        return key, decrypted, "single_byte_bruteforce"

    # Step 2: Try 4-byte rolling brute-force
    four_results = brute_force_xor_four_byte(encrypted_block, known_types)
    if four_results:
        key, decrypted = four_results[0]
        return key, decrypted, "four_byte_bruteforce"

    # Step 3: Extended 2-byte brute-force (gated behind flag)
    if extended_bruteforce:
        two_results = brute_force_xor_two_byte(encrypted_block, known_types)
        if two_results:
            key, decrypted = two_results[0]
            return key, decrypted, "two_byte_bruteforce_extended"

    return None, None, "failed"
