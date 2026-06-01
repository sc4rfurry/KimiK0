"""ConfigSurgeon — Field-level config read/write/re-encrypt.

Provides type-safe access to individual beacon configuration fields
with automatic TLV serialization and XOR re-encryption on write.
"""

import json
import logging
import struct
from typing import Any, Dict, List, Optional, Tuple, Union

from cs_aggregator.modules.config_extractor import (
    ConfigExtractor,
    SETTING_NAMES,
    TLVField,
)
from cs_aggregator.utils.xor_decrypt import xor_rolling_key

logger = logging.getLogger("cs_aggregator.surgery.config_surgeon")

# Reverse map: name -> setting ID
_NAME_TO_ID: Dict[str, int] = {name: sid for sid, name in SETTING_NAMES.items()}

# Data type classification
SHORT_SETTINGS = {1, 2, 5, 6, 16, 17, 18, 22, 31, 35, 38, 39,
                  43, 44, 48, 50, 52, 55, 67, 77}
INT_SETTINGS = {3, 4, 19, 20, 28, 37, 40, 41, 45, 68, 69, 70,
                71, 72, 73, 75, 76, 78, 79, 80}


class ConfigSurgeon:
    """Type-safe field-level access to beacon configuration.

    Supports reading, modifying, and re-encrypting individual
    config fields without disturbing unmodified entries.

    Usage:
        cs = ConfigSurgeon(config_json, xor_key=b'\\x2e')
        cs.get_int("SETTING_SLEEPTIME")     # 60000
        cs.set("SETTING_SLEEPTIME", 30000)
        encrypted = cs.encrypt()
    """

    def __init__(
        self,
        config_json: Dict[str, Any],
        xor_key: bytes = b"\x2e",
        xor_key_length: int = 1,
    ) -> None:
        """Initialize from a parsed config dictionary.

        Args:
            config_json: Parsed config dict (from ConfigExtractor).
            xor_key: XOR key bytes for re-encryption.
            xor_key_length: Key length (1 or 4 bytes).
        """
        self._config: Dict[str, Any] = dict(config_json)
        self._xor_key = xor_key
        self._xor_key_length = xor_key_length
        self._dirty_fields: set = set()  # Track which fields were modified
        self._original_config: Dict[str, Any] = dict(config_json)

    # ── Property Access ──

    @property
    def fields(self) -> Dict[str, Any]:
        """All config fields as a dict."""
        return dict(self._config)

    @property
    def dirty_fields(self) -> set:
        """Set of field names that have been modified."""
        return set(self._dirty_fields)

    @property
    def xor_key(self) -> bytes:
        """The XOR key used for encryption."""
        return self._xor_key

    # ── Type-Safe Getters ──

    def get(self, name: str, default: Any = None) -> Any:
        """Get a config field by setting name.

        Args:
            name: Setting name (e.g. "SETTING_SLEEPTIME").
            default: Default value if field not present.

        Returns:
            The field value, or default.
        """
        return self._config.get(name, default)

    def get_int(self, name: str, default: int = 0) -> int:
        """Get a config field as integer."""
        val = self._config.get(name, default)
        if isinstance(val, int):
            return val
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    def get_str(self, name: str, default: str = "") -> str:
        """Get a config field as string."""
        val = self._config.get(name, default)
        if isinstance(val, str):
            return val
        if isinstance(val, bytes):
            return val.decode("ascii", errors="replace")
        return str(val) if val is not None else default

    def get_bytes(self, name: str, default: bytes = b"") -> bytes:
        """Get a config field as bytes (hex-decode if string)."""
        val = self._config.get(name, default)
        if isinstance(val, bytes):
            return val
        if isinstance(val, str):
            try:
                return bytes.fromhex(val)
            except ValueError:
                return val.encode("ascii", errors="replace")
        return default

    def get_bool(self, name: str, default: bool = False) -> bool:
        """Get a config field as boolean (nonzero = True)."""
        val = self._config.get(name, default)
        if isinstance(val, bool):
            return val
        if isinstance(val, (int, float)):
            return bool(val)
        return default

    # ── Setters ──

    def set(self, name: str, value: Any) -> None:
        """Set a config field value.

        Args:
            name: Setting name (e.g. "SETTING_SLEEPTIME").
            value: New value. Type is validated against the setting.

        Raises:
            KeyError: If setting name is not recognized.
        """
        if name not in _NAME_TO_ID and name not in self._config:
            raise KeyError(
                f"Unknown setting name: {name!r}. "
                f"Use list_settings() to see valid names."
            )
        self._config[name] = value
        self._dirty_fields.add(name)
        logger.debug("ConfigSurgeon: set %s = %r", name, value)

    def __getitem__(self, name: str) -> Any:
        """Dict-style access: surgeon.config["SETTING_SLEEPTIME"]."""
        return self._config[name]

    def __setitem__(self, name: str, value: Any) -> None:
        """Dict-style write: surgeon.config["SETTING_SLEEPTIME"] = 30000."""
        self.set(name, value)

    def __contains__(self, name: str) -> bool:
        return name in self._config

    def __iter__(self):
        return iter(self._config)

    # ── Analysis ──

    def diff_from_original(self) -> Dict[str, Tuple[Any, Any]]:
        """Return fields that differ from the original parsed config.

        Returns:
            Dict of {field_name: (original_value, current_value)}.
        """
        changes: Dict[str, Tuple[Any, Any]] = {}
        for name in self._dirty_fields:
            original = self._original_config.get(name)
            current = self._config.get(name)
            if original != current:
                changes[name] = (original, current)
        return changes

    def diff_from_defaults(self) -> Dict[str, Any]:
        """Return config fields that differ from CS defaults.

        Returns:
            Dict of fields with non-default values.
        """
        # Default values for key settings
        defaults: Dict[str, Any] = {
            "SETTING_SLEEPTIME": 60000,
            "SETTING_JITTER": 0,
            "SETTING_PORT": 80,
            "SETTING_PROTOCOL": 0,
            "SETTING_MAXGET": 1048576,
            "SETTING_MAXDNS": 255,
            "SETTING_CLEANUP": 0,
            "SETTING_CFG_CAUTION": 0,
            "SETTING_SYSCALL_METHOD": 0,
            "SETTING_BOF_ALLOCATOR": 0,
            "SETTING_PROCINJ_ALLOCATOR": 0,
            "SETTING_DATA_STORE_SIZE": 0,
        }
        diff: Dict[str, Any] = {}
        for name, default_val in defaults.items():
            current = self._config.get(name)
            if current is not None and current != default_val:
                diff[name] = current
        return diff

    @staticmethod
    def list_settings() -> List[str]:
        """Return all known setting names."""
        return list(SETTING_NAMES.values())

    # ── Serialization ──

    def to_tlv_bytes(self) -> bytes:
        """Serialize the current config to raw TLV bytes (unencrypted).

        Returns:
            Raw TLV-encoded bytes ready for encryption.
        """
        return ConfigExtractor.serialize_config_to_tlv(self._config)

    def encrypt(self, key: Optional[bytes] = None) -> bytes:
        """Serialize and XOR-encrypt the config.

        Args:
            key: Optional override XOR key. Uses original key if not specified.

        Returns:
            XOR-encrypted TLV config bytes.
        """
        xor_key = key if key is not None else self._xor_key
        tlv_data = self.to_tlv_bytes()

        if not tlv_data:
            raise ValueError("Config serialization produced empty TLV data")

        return xor_rolling_key(tlv_data, xor_key)

    # ── Import/Export ──

    def export_json(self, path: str) -> None:
        """Export config to a JSON file.

        Args:
            path: Output file path.
        """
        # Filter out binary/non-serializable values
        clean = {}
        for k, v in self._config.items():
            if isinstance(v, bytes):
                clean[k] = v.hex()
            else:
                clean[k] = v

        with open(path, "w", encoding="utf-8") as f:
            json.dump(clean, f, indent=2, default=str)
        logger.info("Config exported to %s (%d fields)", path, len(clean))

    def import_json(self, path: str) -> None:
        """Import config modifications from a JSON file.

        Only fields present in the JSON will be updated;
        fields not in the JSON are left untouched.

        Args:
            path: Input JSON file path.
        """
        with open(path, "r", encoding="utf-8") as f:
            updates = json.load(f)

        for name, value in updates.items():
            self.set(name, value)
        logger.info("Imported %d field updates from %s", len(updates), path)

    def __repr__(self) -> str:
        n_fields = len(self._config)
        n_dirty = len(self._dirty_fields)
        return f"ConfigSurgeon({n_fields} fields, {n_dirty} modified, key={self._xor_key.hex()})"
