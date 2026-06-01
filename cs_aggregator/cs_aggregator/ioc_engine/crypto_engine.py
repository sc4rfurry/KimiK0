"""Crypto Sub-Engine — Cryptographic artifact extraction."""

from typing import Any, Dict, Optional


class CryptoEngine:
    """Extract cryptographic IOCs: XOR keys, watermarks, pubkeys, kill dates."""

    def extract(
        self, config: Dict[str, Any], ctx: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Extract all cryptographic artifacts."""
        ctx = ctx or {}
        result: Dict[str, Any] = {
            "identifiers": {},
            "timestamps": {},
            "keys": {},
        }

        # Watermark
        wm = config.get("SETTING_WATERMARK")
        if wm is not None:
            result["identifiers"]["watermark"] = (
                int(wm) if isinstance(wm, (int, float)) else str(wm)
            )

        # Masked watermark
        masked_wm = config.get("SETTING_MASKED_WATERMARK")
        if masked_wm:
            result["identifiers"]["masked_watermark"] = str(masked_wm)

        # Public key hash
        pubkey = config.get("SETTING_PUBKEY")
        if pubkey:
            pk_str = str(pubkey)
            result["identifiers"]["pubkey_hash"] = (
                pk_str[:64] if len(pk_str) > 64 else pk_str
            )

        # Crypto scheme
        crypto = config.get("SETTING_CRYPTO_SCHEME")
        if crypto is not None:
            result["identifiers"]["crypto_scheme"] = int(crypto)

        # Kill date
        killdate = config.get("SETTING_KILLDATE")
        if killdate and int(killdate) > 0:
            kd = int(killdate)
            y, m, d = kd // 10000, (kd % 10000) // 100, kd % 100
            result["timestamps"]["kill_date"] = (
                f"{y}-{m:02d}-{d:02d}" if y > 2000 else str(kd)
            )

        # XOR key from pipeline context
        xor_key = ctx.get("xor_key", "")
        if xor_key:
            result["keys"]["xor_key"] = str(xor_key)
            result["keys"]["xor_key_length"] = len(str(xor_key)) // 2

        return result
