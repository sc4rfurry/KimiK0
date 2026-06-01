"""Common type definitions and data classes for the cs_aggregator engine."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ClassificationResult:
    """Result from MOD_INPUT — payload classification metadata."""
    payload_type: str  # "staged" | "stageless" | "unknown"
    architecture: str  # "x86" | "x64" | "unknown"
    format: str  # "raw_shellcode" | "pe_exe" | "pe_dll" | "memory_dump"
    file_size: int
    hashes: Dict[str, str]
    entropy_score: float
    confidence_score: float
    warnings: List[str] = field(default_factory=list)


@dataclass
class VersionDetectionResult:
    """Result from MOD_VERSION_DETECTOR — CS version fingerprint."""
    estimated_version: str  # "4.9.0", "4.9.1", "4.10.x", etc.
    confidence_score: float  # 0.0–1.0
    detection_method: str  # "loader_signature", "tlv_type_presence", etc.
    schema_used: str  # Path to schema file or "none"
    version_specific_notes: List[str] = field(default_factory=list)


@dataclass
class SegmentResult:
    """Result for an extracted payload segment."""
    segment_id: str
    offset: int
    size: int
    sha256: str
    entropy: float
    confidence_score: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LoaderStubResult(SegmentResult):
    """Extended result for loader stub with classification."""
    classification: str = "Unknown"  # "Default_CS_4_9", "Custom_UDRL", etc.
    bud_detected: bool = False
    bud_version: Optional[str] = None


@dataclass
class PEInfo:
    """PE header metadata for the beacon DLL."""
    machine_type: str
    compile_timestamp: Optional[str]
    sections: List[Dict[str, Any]]
    import_count: int
    export_count: int
    anomalies: List[str]


@dataclass
class ConfigBlockResult:
    """Result from MOD_CONFIG_EXTRACTOR."""
    xor_key: str  # Hex-encoded XOR key
    xor_key_length: int
    key_detection_method: str
    offset: int
    size_encrypted: int
    size_decrypted: int
    config_json: Dict[str, Any]
    tlv_coverage: Dict[str, Any]


@dataclass
class SleepMaskResult:
    """Result from MOD_SLEEPMASK_EXTRACTOR — sleep mask segment analysis."""
    detected: bool = False
    offset: int = -1
    size: int = 0
    section_name: str = ""
    sha256: str = ""
    entropy: float = 0.0
    confidence_score: float = 0.0
    mask_function_rva: Optional[int] = None
    unmask_function_rva: Optional[int] = None
    beacongate_detected: bool = False
    mask_algorithm: str = "unknown"
    version: str = "unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)


@dataclass
class PostExDLLInfo:
    """Information about a single post-exploitation DLL reference."""
    name: str
    dll_size: int = 0
    sha256: str = ""
    entropy: float = 0.0
    offset: int = -1
    embedded: bool = False  # True if DLL is embedded in the payload
    reference_type: str = "tlv_config"  # "tlv_config", "embedded", "section_name"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReassemblyConfig:
    """Configuration for payload reassembly (MOD_REASSEMBLER).

    Specifies which components to replace or modify in the reassembled payload.
    Only components explicitly set will be replaced; None means keep original.
    """
    custom_loader: Optional[bytes] = None
    modified_dll: Optional[bytes] = None
    custom_sleep_mask: Optional[bytes] = None
    modified_config: Optional[Dict[str, Any]] = None
    xor_key: Optional[bytes] = None
    original_partial_data: Optional[bytes] = None  # If reassembling from partial/template


@dataclass
class ReassemblyResult:
    """Result from MOD_REASSEMBLER — the reassembled payload and metadata."""
    success: bool = False
    payload: bytes = b""
    size: int = 0
    sha256: str = ""
    components_used: Dict[str, bool] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


@dataclass
class Manifest:
    """Complete dissection manifest for a payload."""
    manifest_format_version: str = "2.0"
    metadata: Dict[str, Any] = field(default_factory=dict)
    segments: List[Dict[str, Any]] = field(default_factory=list)


class CSVersionDB:
    """Known CobaltStrike version metadata.

    Setting ID ranges and release dates sourced from dissect.cobaltstrike
    BeaconSetting enum and official Fortra release notes (2025-2026).
    """

    VERSIONS: Dict[str, Dict[str, Any]] = {
        "4.9.0": {
            "release_date": "2023-07-12",
            "max_setting_id": 76,
            "notes": "First version with UDRL interface (BUD), SETTING_DATA_STORE_SIZE(75)",
        },
        "4.9.1": {
            "release_date": "2023-10-10",
            "max_setting_id": 76,
            "notes": "Stable point after 4.9 architectural overhaul, MASKED_WATERMARK(74)",
        },
        "4.10": {
            "release_date": "2024-05-15",
            "max_setting_id": 78,
            "notes": "BREAKING: BeaconGate introduced (ID 77-78), BUD structures overhauled",
        },
        "4.11": {
            "release_date": "2025-03-20",
            "max_setting_id": 78,
            "notes": "Novel out-of-the-box sleepmask, ObfSetThreadContext injection, prepend-style loaders default",
        },
        "4.12": {
            "release_date": "2025-11-05",
            "max_setting_id": 80,
            "notes": "BREAKING: Drip-loading, ALLOCATED_MEMORY changes, UDC2, RtlCloneUserProcess injection, Java 17 required",
        },
    }
