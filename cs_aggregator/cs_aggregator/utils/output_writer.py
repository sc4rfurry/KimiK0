"""Output writer for surgical payload dissection results.

Handles writing extracted components (loader stub, beacon DLL, config block,
sleep mask) to individual files in a structured output directory.
"""

import json
import os
import time
from typing import Any, Dict, List, Optional

from cs_aggregator.utils.hashing import compute_hashes
from cs_aggregator.utils.entropy import shannon_entropy


class OutputWriter:
    """Writes dissection results and extracted components to disk."""

    def __init__(self, output_dir: str, source_file: Optional[str] = None):
        """Initialize the output writer.

        Args:
            output_dir: Directory to write output files to. Created if it doesn't exist.
            source_file: Original payload filename for naming output files.
        """
        self.output_dir = output_dir
        self.source_file = source_file or "payload"
        self.base_name = os.path.splitext(os.path.basename(self.source_file))[0]

        os.makedirs(self.output_dir, exist_ok=True)

    def write_manifest(self, manifest_dict: Dict[str, Any]) -> str:
        """Write the full JSON manifest.

        Returns the path to the written file.
        """
        path = os.path.join(self.output_dir, f"{self.base_name}_manifest.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(manifest_dict, f, indent=2, default=str)
        return path

    def write_config(self, config_json: Dict[str, Any]) -> str:
        """Write the extracted config as a standalone JSON file.

        Returns the path to the written file.
        """
        path = os.path.join(self.output_dir, f"{self.base_name}_config.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(config_json, f, indent=2, default=str)
        return path

    def write_component(
        self,
        component_name: str,
        data: bytes,
        extension: str = ".bin",
    ) -> str:
        """Write a raw binary component (loader, DLL, sleep mask, etc.).

        Args:
            component_name: Component identifier (e.g. "loader", "beacon_dll", "sleep_mask")
            data: Raw bytes to write
            extension: File extension (default: .bin)

        Returns the path to the written file.
        """
        path = os.path.join(self.output_dir, f"{self.base_name}_{component_name}{extension}")
        with open(path, "wb") as f:
            f.write(data)
        return path

    def write_config_block(
        self,
        encrypted: bytes,
        decrypted: bytes,
        xor_key: str,
    ) -> Dict[str, str]:
        """Write both encrypted and decrypted config blocks.

        Returns a dict of {type: path} for the written files.
        """
        paths = {}

        enc_path = os.path.join(self.output_dir, f"{self.base_name}_config_encrypted.bin")
        with open(enc_path, "wb") as f:
            f.write(encrypted)
        paths["encrypted"] = enc_path

        dec_path = os.path.join(self.output_dir, f"{self.base_name}_config_decrypted.bin")
        with open(dec_path, "wb") as f:
            f.write(decrypted)
        paths["decrypted"] = dec_path

        return paths

    def write_dissection_summary(
        self,
        manifest_dict: Dict[str, Any],
        payload_data: bytes,
    ) -> str:
        """Write a human-readable dissection summary.

        Returns the path to the written file.
        """
        path = os.path.join(self.output_dir, f"{self.base_name}_summary.txt")

        meta = manifest_dict.get("metadata", {})
        version_info = meta.get("csVersionDetected", {})
        classification = meta.get("payloadClassification", {})
        segments = manifest_dict.get("segments", [])

        hashes = compute_hashes(payload_data)

        lines = [
            f"{'=' * 72}",
            f"  KimiK0 Beacon Dissection Report",
            f"{'=' * 72}",
            f"",
            f"Source:         {self.source_file}",
            f"Size:           {len(payload_data):,} bytes",
            f"SHA256:         {hashes['sha256']}",
            f"MD5:            {hashes['md5']}",
            f"",
            f"CS Version:     {version_info.get('version', 'unknown')}",
            f"Confidence:     {version_info.get('confidence', 0.0):.0%}",
            f"Payload Type:   {classification.get('type', 'unknown')}",
            f"Architecture:   {classification.get('architecture', 'unknown')}",
            f"",
            f"Segments ({len(segments)}):",
        ]

        for seg in segments:
            sid = seg.get("segmentId", "???")
            offset = seg.get("offset", 0)
            size = seg.get("size", 0)
            stype = seg.get("type", "unknown")
            lines.append(f"  {sid:30s} offset=0x{offset:06X}  size={size:>8,}  [{stype}]")

        # Config summary
        for seg in segments:
            if seg.get("segmentId") == "SEG_CONFIG_BLOCK":
                config = seg.get("config", {})
                if config:
                    lines.append("")
                    lines.append("Configuration:")
                    for key, value in sorted(config.items()):
                        val_str = str(value)
                        if len(val_str) > 80:
                            val_str = val_str[:80] + "..."
                        lines.append(f"  {key:45s} = {val_str}")

        warnings = meta.get("warnings", [])
        if warnings:
            lines.append("")
            lines.append(f"Warnings ({len(warnings)}):")
            for w in warnings:
                lines.append(f"  - {w}")

        lines.append("")
        lines.append(f"{'=' * 72}")

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return path

    def write_full_extraction(
        self,
        manifest_dict: Dict[str, Any],
        payload_data: bytes,
        pipeline: Any,
    ) -> Dict[str, str]:
        """Write full PRD-compliant extraction to structured output directory.

        Creates:
            manifest.json, loader_stub.bin, loader_stub_metadata.json,
            beacon.dll, beacon_pe_metadata.json, config.json,
            config_raw_encrypted.bin, config_raw_decrypted.bin,
            sleep_mask.bin (if present), sleep_mask_metadata.json,
            summary.txt

        Args:
            manifest_dict: Complete dissection manifest dict.
            payload_data: Original raw payload bytes.
            pipeline: DissectionPipeline instance with cached results.

        Returns:
            Dict mapping component name to written file path.
        """
        written: Dict[str, str] = {}

        # ─── Manifest ───
        manifest_path = os.path.join(self.output_dir, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest_dict, f, indent=2, default=str)
        written["manifest"] = manifest_path

        # ─── Loader Stub ───
        if pipeline._loader_result is not None:
            loader_data = payload_data[:pipeline._loader_result.size]
            if loader_data:
                loader_path = os.path.join(self.output_dir, "loader_stub.bin")
                with open(loader_path, "wb") as f:
                    f.write(loader_data)
                written["loader_stub"] = loader_path

                # Loader metadata JSON
                loader_hashes = compute_hashes(loader_data)
                loader_meta = {
                    "segmentId": "SEG_LOADER_STUB",
                    "size": len(loader_data),
                    "sha256": loader_hashes["sha256"],
                    "md5": loader_hashes["md5"],
                    "entropy": round(shannon_entropy(loader_data), 4),
                    "classification": getattr(pipeline._loader_result, "classification", "Unknown"),
                    "budDetected": getattr(pipeline._loader_result, "bud_detected", False),
                }
                meta_path = os.path.join(self.output_dir, "loader_stub_metadata.json")
                with open(meta_path, "w", encoding="utf-8") as f:
                    json.dump(loader_meta, f, indent=2)
                written["loader_stub_metadata"] = meta_path

        # ─── Beacon DLL ───
        if pipeline._beacon_dll_data is not None:
            dll_path = os.path.join(self.output_dir, "beacon.dll")
            with open(dll_path, "wb") as f:
                f.write(pipeline._beacon_dll_data)
            written["beacon_dll"] = dll_path

            # PE metadata JSON
            if pipeline._pe_info is not None:
                pe_meta = {
                    "segmentId": "SEG_BEACON_DLL",
                    "size": len(pipeline._beacon_dll_data),
                    "sha256": compute_hashes(pipeline._beacon_dll_data)["sha256"],
                    "entropy": round(shannon_entropy(pipeline._beacon_dll_data), 4),
                    "machineType": getattr(pipeline._pe_info, "machine_type", "unknown"),
                    "compileTimestamp": getattr(pipeline._pe_info, "timestamp", None),
                    "sections": getattr(pipeline._pe_info, "sections", []),
                    "importCount": getattr(pipeline._pe_info, "import_count", 0),
                    "exportCount": getattr(pipeline._pe_info, "export_count", 0),
                    "anomalies": getattr(pipeline._pe_info, "anomalies", []),
                }
                pe_meta_path = os.path.join(self.output_dir, "beacon_pe_metadata.json")
                with open(pe_meta_path, "w", encoding="utf-8") as f:
                    json.dump(pe_meta, f, indent=2, default=str)
                written["beacon_pe_metadata"] = pe_meta_path

        # ─── Config Block ───
        if pipeline._config_result is not None:
            config_result = pipeline._config_result

            # Parsed config JSON
            config_json = getattr(config_result, "config_json", {})
            if config_json:
                config_path = os.path.join(self.output_dir, "config.json")
                with open(config_path, "w", encoding="utf-8") as f:
                    json.dump(config_json, f, indent=2, default=str)
                written["config"] = config_path

            # Raw encrypted config
            encrypted_data = getattr(config_result, "encrypted_block", None)
            if encrypted_data:
                enc_path = os.path.join(self.output_dir, "config_raw_encrypted.bin")
                with open(enc_path, "wb") as f:
                    f.write(encrypted_data)
                written["config_raw_encrypted"] = enc_path

            # Raw decrypted config
            decrypted_data = getattr(config_result, "decrypted_block", None)
            if decrypted_data:
                dec_path = os.path.join(self.output_dir, "config_raw_decrypted.bin")
                with open(dec_path, "wb") as f:
                    f.write(decrypted_data)
                written["config_raw_decrypted"] = dec_path

        # ─── Sleep Mask ───
        if pipeline._sleepmask_result is not None:
            sm_data = getattr(pipeline._sleepmask_result, "mask_data", None)
            if sm_data:
                sm_path = os.path.join(self.output_dir, "sleep_mask.bin")
                with open(sm_path, "wb") as f:
                    f.write(sm_data)
                written["sleep_mask"] = sm_path

                sm_meta = {
                    "segmentId": "SEG_SLEEP_MASK",
                    "size": len(sm_data),
                    "sha256": compute_hashes(sm_data)["sha256"],
                    "entropy": round(shannon_entropy(sm_data), 4),
                    "present": True,
                    "version": getattr(pipeline._sleepmask_result, "version", "unknown"),
                    "algorithm": getattr(pipeline._sleepmask_result, "mask_algorithm", "unknown"),
                }
                sm_meta_path = os.path.join(self.output_dir, "sleep_mask_metadata.json")
                with open(sm_meta_path, "w", encoding="utf-8") as f:
                    json.dump(sm_meta, f, indent=2)
                written["sleep_mask_metadata"] = sm_meta_path

        # ─── Post-Exploitation DLLs ───
        postex_results = getattr(pipeline, "_postex_results", [])
        if postex_results:
            postex_dir = os.path.join(self.output_dir, "postex")
            os.makedirs(postex_dir, exist_ok=True)
            postex_metadata = []

            for idx, r in enumerate(postex_results):
                r_meta = {
                    "name": r.name,
                    "referenceType": r.reference_type,
                    "offset": r.offset,
                    "size": r.dll_size,
                    "sha256": r.sha256,
                    "entropy": r.entropy,
                    "embedded": r.embedded,
                    "metadata": r.metadata,
                }

                if r.embedded and r.offset >= 0 and r.dll_size > 0 and pipeline._beacon_dll_data is not None:
                    try:
                        ext_bytes = pipeline._beacon_dll_data[r.offset:r.offset + r.dll_size]
                        if ext_bytes and len(ext_bytes) == r.dll_size:
                            dll_filename = f"{r.name}.dll"
                            dll_filename = "".join(c for c in dll_filename if c.isalnum() or c in "._-")
                            dll_path = os.path.join(postex_dir, dll_filename)
                            with open(dll_path, "wb") as f:
                                f.write(ext_bytes)
                            r_meta["filePath"] = os.path.relpath(dll_path, self.output_dir)
                            written[f"postex_dll_{idx}"] = dll_path
                    except Exception as e:
                        import logging
                        logging.getLogger("cs_aggregator.utils.output_writer").warning(
                            "Failed to extract physical PostEx DLL %s: %s", r.name, e
                        )

                postex_metadata.append(r_meta)

            meta_json_path = os.path.join(postex_dir, "metadata.json")
            with open(meta_json_path, "w", encoding="utf-8") as f:
                json.dump(postex_metadata, f, indent=2, default=str)
            written["postex_metadata"] = meta_json_path

        # ─── Summary ───
        summary_path = self.write_dissection_summary(manifest_dict, payload_data)
        written["summary"] = summary_path

        return written

