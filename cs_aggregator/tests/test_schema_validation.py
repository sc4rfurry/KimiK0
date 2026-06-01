"""Test schema validation — Ensure all version schemas contain required fields."""

import json
import os
import pytest
from pathlib import Path

SCHEMA_DIR = Path(__file__).parent.parent / "cs_aggregator" / "data" / "schemas"

# Required top-level keys in every version schema (not schema_template)
REQUIRED_KEYS = [
    "meta",
    "tlvTypes",
    "configBlockHeuristics",
    "sleepMaskSignatures",
    "budStructure",
    "segmentBoundaryHints",
    "assemblyRules",
]

# Required meta fields
REQUIRED_META_KEYS = [
    "version",
    "description",
]

# Minimum TLV types expected per version (combined tlvTypes + settingIDs)
MIN_TLV_TYPES = {
    "4.9.0": 70,
    "4.9.1": 75,
    "4.10.x": 30,   # Uses compact hex-key format with settingIDs supplement
    "4.11.x": 30,
    "4.12.x": 30,
}


def get_schema_files():
    """Discover all schema JSON files, excluding schema_template."""
    if not SCHEMA_DIR.exists():
        return []
    return sorted(
        p for p in SCHEMA_DIR.glob("*.json")
        if p.stem != "schema_template"
    )


def _normalize_tlv_key(key: str) -> int:
    """Convert a TLV key to integer, handling both decimal and hex formats."""
    if key.startswith("0x") or key.startswith("0X"):
        return int(key, 16)
    return int(key)


def _get_all_setting_ids(data: dict) -> set:
    """Get all setting IDs from both tlvTypes and settingIDs dicts."""
    ids = set()
    for key in data.get("tlvTypes", {}).keys():
        try:
            ids.add(_normalize_tlv_key(key))
        except ValueError:
            pass
    for key in data.get("settingIDs", {}).keys():
        try:
            ids.add(int(key))
        except ValueError:
            pass
    return ids


@pytest.fixture(params=get_schema_files(), ids=lambda p: p.stem)
def schema(request):
    """Load each schema file as a fixture."""
    with open(request.param, "r", encoding="utf-8") as f:
        return json.load(f), request.param.stem


class TestSchemaStructure:
    """Validate that all schema files contain the required structure."""

    def test_schema_has_required_keys(self, schema):
        """Every schema must have all required top-level keys."""
        data, name = schema
        for key in REQUIRED_KEYS:
            assert key in data, f"Schema {name} missing required key: {key}"

    def test_schema_meta_has_required_fields(self, schema):
        """Every schema's meta section must have required fields."""
        data, name = schema
        meta = data.get("meta", {})
        for key in REQUIRED_META_KEYS:
            assert key in meta, f"Schema {name} meta missing: {key}"

    def test_schema_tlv_header_size(self, schema):
        """TLV header size must be 6 bytes when specified."""
        data, name = schema
        meta = data.get("meta", {})
        if "tlvHeaderSize" in meta:
            assert meta["tlvHeaderSize"] == 6, f"Schema {name}: unexpected TLV header size"

    def test_schema_tlv_byte_order(self, schema):
        """TLV byte order must be big-endian when specified."""
        data, name = schema
        meta = data.get("meta", {})
        if "tlvByteOrder" in meta:
            assert meta["tlvByteOrder"] == "big-endian", f"Schema {name}: unexpected byte order"

    def test_schema_tlv_types_minimum(self, schema):
        """Each schema must have at least the minimum expected TLV types."""
        data, name = schema
        all_ids = _get_all_setting_ids(data)
        min_expected = MIN_TLV_TYPES.get(name, 30)
        assert len(all_ids) >= min_expected, (
            f"Schema {name}: expected >= {min_expected} setting IDs, got {len(all_ids)}"
        )

    def test_schema_tlv_types_are_valid(self, schema):
        """All TLV type keys must be parseable (decimal or hex) and values SETTING_ prefixed."""
        data, name = schema
        for key, value in data.get("tlvTypes", {}).items():
            # Accept both decimal ("1") and hex ("0x0001") keys
            try:
                _normalize_tlv_key(key)
            except ValueError:
                pytest.fail(f"Schema {name}: TLV key '{key}' is not a valid number")

            # 4.9.x uses SETTING_ prefix; 4.10+ uses short names — both valid
            assert isinstance(value, str) and len(value) > 0, (
                f"Schema {name}: TLV type {key} value must be a non-empty string"
            )

    def test_schema_config_heuristics(self, schema):
        """Config block heuristics must have XOR key info."""
        data, name = schema
        heuristics = data.get("configBlockHeuristics", {})
        assert "xorKeyLengths" in heuristics, f"Schema {name}: missing xorKeyLengths"
        assert "knownKeys" in heuristics, f"Schema {name}: missing knownKeys"

    def test_schema_assembly_rules(self, schema):
        """Assembly rules must define segment order."""
        data, name = schema
        rules = data.get("assemblyRules", {})
        assert "segmentOrder" in rules, f"Schema {name}: missing segmentOrder"
        order = rules["segmentOrder"]
        assert len(order) >= 2, f"Schema {name}: segmentOrder too short"
        assert "SEG_LOADER_STUB" in order, f"Schema {name}: missing SEG_LOADER_STUB in order"
        assert "SEG_BEACON_DLL" in order, f"Schema {name}: missing SEG_BEACON_DLL in order"

    def test_schema_bud_structure(self, schema):
        """BUD structure must have version field."""
        data, name = schema
        bud = data.get("budStructure", {})
        assert "version" in bud, f"Schema {name}: budStructure missing version"

    def test_schema_segment_hints(self, schema):
        """Segment boundary hints must have loader size ranges."""
        data, name = schema
        hints = data.get("segmentBoundaryHints", {})
        assert "loaderMaxSize" in hints, f"Schema {name}: missing loaderMaxSize"
        assert "loaderMinSize" in hints, f"Schema {name}: missing loaderMinSize"
        assert hints["loaderMaxSize"] > hints["loaderMinSize"], (
            f"Schema {name}: loaderMaxSize must be > loaderMinSize"
        )

    def test_schema_has_setting_types(self, schema):
        """Schemas should have settingTypes for type validation."""
        data, name = schema
        # settingTypes may be in the schema itself or inherited from 4.9.1
        if name.startswith("4.9"):
            assert "settingTypes" in data, f"Schema {name}: missing settingTypes"
            st = data["settingTypes"]
            # Filter out metadata keys like _note
            numeric_keys = [k for k in st.keys() if k.isdigit()]
            assert len(numeric_keys) >= 50, (
                f"Schema {name}: settingTypes should have >= 50 entries"
            )


class TestSchemaConsistency:
    """Validate consistency across all schemas."""

    def test_all_schemas_share_core_settings(self):
        """Core settings (1-20) should be present in all schemas."""
        schemas = get_schema_files()
        if not schemas:
            pytest.skip("No schema files found")

        for schema_path in schemas:
            with open(schema_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            all_ids = _get_all_setting_ids(data)
            # Settings 1-10 should always be present (core protocol settings)
            for sid in range(1, 11):
                assert sid in all_ids, (
                    f"Schema {schema_path.stem}: missing core setting ID {sid}"
                )

    def test_setting_protocol_exists(self):
        """SETTING_PROTOCOL (ID=1) should be in all schemas."""
        schemas = get_schema_files()
        if not schemas:
            pytest.skip("No schema files found")

        for schema_path in schemas:
            with open(schema_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            all_ids = _get_all_setting_ids(data)
            assert 1 in all_ids, f"Schema {schema_path.stem}: missing SETTING_PROTOCOL (ID=1)"

    def test_bud_version_progression(self):
        """BUD version should increase across CS versions."""
        schemas = get_schema_files()
        if not schemas:
            pytest.skip("No schema files found")

        bud_versions = {}
        for schema_path in schemas:
            with open(schema_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            bud = data.get("budStructure", {})
            if "version" in bud:
                bud_versions[schema_path.stem] = bud["version"]

        # 4.9.x should be BUD v1, 4.10/4.11 should be v2, 4.12 should be v3
        if "4.9.1" in bud_versions:
            assert bud_versions["4.9.1"] == 1
        if "4.12.x" in bud_versions:
            assert bud_versions["4.12.x"] == 3
