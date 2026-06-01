"""Hashing utilities for payload integrity verification."""

import hashlib


def compute_hashes(data: bytes) -> dict:
    """Compute MD5, SHA1, and SHA256 hashes of the provided data.

    Returns a dict with hex digest strings:
        {'md5': '...', 'sha1': '...', 'sha256': '...'}
    """
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
