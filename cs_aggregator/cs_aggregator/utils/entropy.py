"""Entropy calculation utilities for payload analysis.

Shannon entropy is used to identify encrypted/obfuscated regions,
loader stubs (low entropy) vs encrypted DLLs (high entropy),
and segment boundaries.
"""

import math
from typing import List, Tuple


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence.

    Returns a float between 0.0 (all same byte) and 8.0 (perfectly random).
    Typical ranges:
        - 0.0–4.0:  Low entropy (plaintext, code, padding)
        - 4.0–6.5:  Moderate entropy (compressed data, mixed content)
        - 6.5–8.0:  High entropy (encrypted, compressed, or randomized data)
    """
    if not data:
        return 0.0

    # Count byte frequencies
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1

    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)

    return round(entropy, 4)


def rolling_entropy(data: bytes, window_size: int = 256, step: int = 64) -> List[Tuple[int, float]]:
    """Compute rolling window entropy across the data.

    Returns list of (offset, entropy) tuples for each window position.
    Useful for finding segment boundaries via entropy drops/spikes.
    """
    if len(data) < window_size:
        return [(0, shannon_entropy(data))]

    results: List[Tuple[int, float]] = []
    for offset in range(0, len(data) - window_size + 1, step):
        window = data[offset:offset + window_size]
        ent = shannon_entropy(window)
        results.append((offset, ent))

    return results


def find_entropy_drop_boundary(
    data: bytes,
    initial_offset: int = 0,
    search_size: int = 8192,
    entropy_threshold: float = 0.5,
    window_size: int = 256,
) -> int:
    """Find a significant entropy drop boundary in the data.

    This is used for locating the loader stub → beacon DLL boundary
    when no MZ header is found (encrypted/obfuscated DLLs).

    Returns the offset where a significant entropy drop occurs.
    Returns -1 if no significant drop is found.
    """
    search_end = min(initial_offset + search_size, len(data))
    if search_end - initial_offset < window_size * 2:
        return -1

    entropies = rolling_entropy(data[initial_offset:search_end], window_size, window_size // 4)

    if len(entropies) < 2:
        return -1

    # Look for a drop of at least entropy_threshold between consecutive windows
    for i in range(1, len(entropies)):
        prev_ent = entropies[i - 1][1]
        curr_ent = entropies[i][1]
        if prev_ent - curr_ent >= entropy_threshold:
            return initial_offset + entropies[i][0]

    return -1


def section_entropy_analysis(data: bytes) -> dict:
    """Compute comprehensive entropy metrics for the entire payload.

    Returns a dict with overall entropy, per-window breakdown,
    and detection of high/low entropy regions.
    """
    overall = shannon_entropy(data)
    windows = rolling_entropy(data)

    high_entropy_regions = [
        (offset, ent) for offset, ent in windows if ent >= 6.5
    ]
    low_entropy_regions = [
        (offset, ent) for offset, ent in windows if ent <= 4.0
    ]

    return {
        "overall_entropy": overall,
        "num_windows": len(windows),
        "high_entropy_regions": len(high_entropy_regions),
        "low_entropy_regions": len(low_entropy_regions),
        "max_entropy": max(ent for _, ent in windows) if windows else 0.0,
        "min_entropy": min(ent for _, ent in windows) if windows else 0.0,
    }
