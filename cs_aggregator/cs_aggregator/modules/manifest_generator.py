"""MOD_MANIFEST_GENERATOR — Payload Manifest Generator.

Aggregates all findings from previous modules into a comprehensive,
version-annotated JSON manifest with confidence scores for each segment.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cs_aggregator import __version__

from cs_aggregator.utils.types import (
    ClassificationResult,
    ConfigBlockResult,
    LoaderStubResult,
    Manifest,
    PEInfo,
    VersionDetectionResult,
)


class ManifestGenerator:
    """Generates comprehensive JSON manifests for dissected payloads."""

    @staticmethod
    def generate(
        classification: ClassificationResult,
        version_result: VersionDetectionResult,
        loader_result: Optional[LoaderStubResult] = None,
        pe_info: Optional[PEInfo] = None,
        beacon_dll_hashes: Optional[Dict[str, str]] = None,
        config_result: Optional[ConfigBlockResult] = None,
        additional_segments: Optional[List[Dict[str, Any]]] = None,
        source_file: Optional[str] = None,
    ) -> Manifest:
        """Generate a complete manifest from all dissection module outputs.

        Args:
            classification: Result from InputHandler.
            version_result: Result from VersionDetector.
            loader_result: Result from LoaderExtractor (optional).
            pe_info: PE metadata from BeaconParser (optional).
            beacon_dll_hashes: Hashes of the extracted beacon DLL (optional).
            config_result: Result from ConfigExtractor (optional).
            additional_segments: Any additional segment results (sleep mask, post-ex, etc.).
            source_file: Original input filename.

        Returns:
            Manifest object containing all dissection results.
        """
        manifest = Manifest()

        # Build metadata section
        metadata: Dict[str, Any] = {
            "sourceFile": source_file or "unknown",
            "analysisTimestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "toolVersion": __version__,
            "csVersionDetected": {
                "version": version_result.estimated_version,
                "confidence": version_result.confidence_score,
                "method": version_result.detection_method,
            },
            "payloadClassification": {
                "type": classification.payload_type,
                "architecture": classification.architecture,
                "format": classification.format,
            },
            "fileHashes": classification.hashes,
            "fileSize": classification.file_size,
            "overallEntropy": classification.entropy_score,
            "classificationConfidence": classification.confidence_score,
        }

        if classification.warnings:
            metadata["warnings"] = classification.warnings

        manifest.metadata = metadata

        # Build segments array
        segments: List[Dict[str, Any]] = []

        # SEG_LOADER_STUB
        if loader_result:
            loader_segment = {
                "segmentId": "SEG_LOADER_STUB",
                "offset": loader_result.offset,
                "size": loader_result.size,
                "sha256": loader_result.sha256,
                "entropy": loader_result.entropy,
                "type": "Reflective Loader Stub",
                "classification": loader_result.classification,
                "confidenceScore": loader_result.confidence_score,
                "extractionMethod": loader_result.metadata.get("extraction_method", "unknown"),
            }
            segments.append(loader_segment)

        # SEG_BEACON_DLL
        if pe_info:
            beacon_segment: Dict[str, Any] = {
                "segmentId": "SEG_BEACON_DLL",
                "type": "Beacon Core DLL",
                "offset": 0,  # Updated by loader offset below
                "size": 0,
                "confidenceScore": 0.0,
                "peInfo": {
                    "machineType": pe_info.machine_type,
                    "compileTimestamp": pe_info.compile_timestamp,
                    "sections": pe_info.sections,
                    "importCount": pe_info.import_count,
                    "exportCount": pe_info.export_count,
                    "anomalies": pe_info.anomalies if pe_info.anomalies else None,
                },
            }
            # Calculate confidence from PE anomaly count
            anomaly_count = len(pe_info.anomalies) if pe_info.anomalies else 0
            beacon_segment["confidenceScore"] = max(0.3, 1.0 - (anomaly_count * 0.1))
            # Set offset from loader size
            if loader_result and loader_result.size > 0:
                beacon_segment["offset"] = loader_result.offset + loader_result.size
            if beacon_dll_hashes:
                beacon_segment["sha256"] = beacon_dll_hashes.get("sha256", "")
                beacon_segment["hashes"] = beacon_dll_hashes
            segments.append(beacon_segment)

        # SEG_CONFIG_BLOCK
        if config_result:
            config_segment: Dict[str, Any] = {
                "segmentId": "SEG_CONFIG_BLOCK",
                "offset": config_result.offset,
                "size": config_result.size_encrypted,
                "sizeEncrypted": config_result.size_encrypted,
                "sizeDecrypted": config_result.size_decrypted,
                "xorKey": config_result.xor_key,
                "xorKeyLength": config_result.xor_key_length,
                "keyDetectionMethod": config_result.key_detection_method,
                "type": "Configuration Block",
                "confidenceScore": min(1.0, 0.5 + (len(config_result.config_json) * 0.05)),
                "config": config_result.config_json,
                "tlvCoverage": config_result.tlv_coverage,
            }
            segments.append(config_segment)

        # Additional segments (sleep mask, post-ex DLLs, etc.)
        if additional_segments:
            segments.extend(additional_segments)

        manifest.segments = segments
        return manifest

    @staticmethod
    def manifest_to_json(manifest: Manifest, pretty: bool = True) -> str:
        """Serialize a Manifest to a JSON string.

        Args:
            manifest: The Manifest object to serialize.
            pretty: If True, format with indentation.

        Returns:
            JSON string.
        """
        manifest_dict: Dict[str, Any] = {
            "manifestFormatVersion": manifest.manifest_format_version,
            "metadata": manifest.metadata,
            "segments": manifest.segments,
        }

        return json.dumps(manifest_dict, indent=2 if pretty else None, default=str)

    @staticmethod
    def write_manifest(manifest: Manifest, output_path: str) -> str:
        """Write the manifest to a JSON file.

        Args:
            manifest: The Manifest object.
            output_path: Path to write the manifest file.

        Returns:
            The path to the written file.
        """
        json_str = ManifestGenerator.manifest_to_json(manifest)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_str)

        return output_path
