"""Engine — Core Pipeline Orchestrator.

Coordinates the sequential execution of all dissection modules through
a configurable processing pipeline. Handles error propagation, partial
results, and graceful degradation.
"""

import logging
import sys
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from cs_aggregator.plugins.manager import PluginManager

from cs_aggregator.modules.input_handler import InputHandler
from cs_aggregator.modules.version_detector import VersionDetector
from cs_aggregator.modules.loader_extractor import LoaderExtractor
from cs_aggregator.modules.beacon_parser import BeaconParser
from cs_aggregator.modules.config_extractor import ConfigExtractor
from cs_aggregator.modules.sleepmask_extractor import SleepMaskExtractor
from cs_aggregator.modules.postex_extractor import PostExExtractor
from cs_aggregator.modules.bud_analyzer import BUDAnalyzer
from cs_aggregator.modules.manifest_generator import ManifestGenerator
from cs_aggregator.modules.reassembler import Reassembler
from cs_aggregator.utils.errors import (
    ConfigDecryptionError,
    CSAggregatorError,
    ExtractionError,
    PayloadError,
)
from cs_aggregator.utils.hashing import compute_hashes
from cs_aggregator.utils.types import (
    ClassificationResult,
    ConfigBlockResult,
    LoaderStubResult,
    Manifest,
    PEInfo,
    PostExDLLInfo,
    ReassemblyConfig,
    ReassemblyResult,
    SleepMaskResult,
    VersionDetectionResult,
)

logger = logging.getLogger("cs_aggregator.engine")


class DissectionPipeline:
    """Sequential pipeline orchestrator for beacon dissection.

    The pipeline runs each module in order, collecting results and
    propagating metadata downstream. Each step is designed to degrade
    gracefully — if a module fails, the pipeline continues with
    partial results.
    """

    def __init__(self, schema_dir: Optional[str] = None, plugin_manager: Optional["PluginManager"] = None):
        """Initialize the pipeline with all sub-modules.

        Args:
            schema_dir: Optional path to version schema directory.
                Defaults to the built-in schemas directory.
            plugin_manager: Optional PluginManager for integrated hook dispatch.
        """
        self.input_handler = InputHandler()
        self.version_detector = VersionDetector(schema_dir) if schema_dir else VersionDetector()
        self.loader_extractor: Optional[LoaderExtractor] = None
        self.beacon_parser: Optional[BeaconParser] = None
        self.config_extractor: Optional[ConfigExtractor] = None
        self.sleepmask_extractor: Optional[SleepMaskExtractor] = None
        self.postex_extractor: Optional[PostExExtractor] = None
        self.manifest_generator = ManifestGenerator()
        self._plugin_manager = plugin_manager

        # Cached results for downstream access
        self._classification: Optional[ClassificationResult] = None
        self._version_result: Optional[VersionDetectionResult] = None
        self._loader_result: Optional[LoaderStubResult] = None
        self._pe_info: Optional[PEInfo] = None
        self._beacon_dll_data: Optional[bytes] = None
        self._config_result: Optional[ConfigBlockResult] = None
        self._sleepmask_result: Optional[SleepMaskResult] = None
        self._postex_results: List[PostExDLLInfo] = []
        self._bud_result: Optional[Any] = None  # BUDAnalysisResult
        self._profile: Optional[Any] = None  # C2Profile if provided

        # Pipeline context passed to plugins
        self._ctx: Dict[str, Any] = {}

        # Processing metrics
        self._warnings: List[str] = []
        self._errors: List[str] = []

    def process(
        self,
        data: bytes,
        source_file: Optional[str] = None,
        profile: Optional[Any] = None,
    ) -> Manifest:
        """Run the complete dissection pipeline on a payload.

        Pipeline stages:
            1. MOD_INPUT            — Payload classification
            2. MOD_VERSION_DETECTOR  — CS version detection
            3. MOD_LOADER_EXTRACTOR  — Loader stub extraction
            4. MOD_BEACON_PARSER     — Beacon DLL parsing
            5. MOD_CONFIG_EXTRACTOR  — Config block decryption
           5b. VERSION_REFINE        — Refine version from config
            6. MOD_MANIFEST_GENERATOR — Manifest assembly

        Args:
            data: Raw payload bytes.
            source_file: Optional source filename for metadata.
            profile: Optional parsed C2Profile to guide dissection.

        Returns:
            Manifest containing all successfully extracted results.
        """
        # Register profile magic bytes for PE detection
        self._profile = profile
        if profile is not None:
            self._register_profile_magic(profile)

        # Stage 1: Input Classification
        self._stage1_classify(data, source_file)
        self._dispatch_hook("on_payload_loaded", data=data, ctx=self._ctx)

        # Stage 2: Version Detection
        self._stage2_detect_version(data)
        self._dispatch_hook("on_version_detected", version_result=self._version_result, ctx=self._ctx)

        # Stage 3: Loader Extraction
        self._stage3_extract_loader(data)
        self._dispatch_hook("on_loader_extracted", loader_result=self._loader_result, ctx=self._ctx)

        # Stage 3b: BUD Analysis
        self._stage3b_analyze_bud(data)

        # Stage 4: Beacon DLL Parsing
        self._stage4_parse_beacon(data)
        self._dispatch_hook("on_pe_parsed", pe_info=self._pe_info, dll_data=self._beacon_dll_data or b"", ctx=self._ctx)

        # Stage 5: Config Block Extraction
        if self._beacon_dll_data is not None:
            self._stage5_extract_config(self._beacon_dll_data)

        # Stage 5b: Refine version detection from extracted config
        self._stage5b_refine_version()

        # Dispatch config hook after extraction + refinement
        if self._config_result is not None:
            self._dispatch_hook("on_config_extracted", config=self._config_result.config_json, ctx=self._ctx)

        # Stage 6a: Sleep Mask Extraction
        if self._beacon_dll_data is not None:
            self._stage6a_extract_sleepmask(self._beacon_dll_data)

        # Stage 6b: Post-Exploitation DLL Analysis
        if self._beacon_dll_data is not None:
            config_json = None
            if self._config_result is not None:
                config_json = self._config_result.config_json
            self._stage6b_analyze_postex(self._beacon_dll_data, config_json)

        # Stage 7: Manifest Generation
        manifest = self._stage7_generate_manifest(source_file)
        self._dispatch_hook("on_manifest_ready", manifest=manifest.metadata, ctx=self._ctx)

        return manifest

    @staticmethod
    def _register_profile_magic(profile: Any) -> None:
        """Register C2 profile magic bytes into PE utils for dynamic detection."""
        from cs_aggregator.utils.pe_utils import register_magic

        # Register magic_mz (x64 and x86)
        for attr in ('magic_mz_x64', 'magic_mz_x86', 'magic_mz'):
            magic_str = getattr(profile, attr, None)
            if magic_str and magic_str not in ('MZ', ''):
                register_magic(magic_str.encode('utf-8', errors='replace'))

    def process_with_path(self, path: str) -> Manifest:
        """Read a file and run the dissection pipeline.

        Args:
            path: Path to the payload file.

        Returns:
            Manifest with dissection results.
        """
        data = self.input_handler.read_file(path)
        return self.process(data, source_file=path)

    def _stage1_classify(self, data: bytes, source_file: Optional[str]) -> None:
        """Stage 1: Classify the input payload."""
        try:
            self._classification = self.input_handler.classify_payload(
                data, path=source_file
            )
            logger.info(
                "Stage 1 [MOD_INPUT]: %s %s payload (confidence: %.2f)",
                self._classification.payload_type,
                self._classification.architecture,
                self._classification.confidence_score,
            )
        except PayloadError as e:
            self._errors.append(f"Stage 1 (Input): {e}")
            self._classification = ClassificationResult(
                payload_type="unknown",
                architecture="unknown",
                format="unknown",
                file_size=len(data),
                hashes=compute_hashes(data),
                entropy_score=0.0,
                confidence_score=0.0,
                warnings=[str(e)],
            )
            logger.warning("Stage 1 failed: %s", e)

    def _stage2_detect_version(self, data: bytes) -> None:
        """Stage 2: Detect CS version using version-adaptive engine."""
        if self._classification is None:
            self._version_result = VersionDetectionResult(
                estimated_version="unknown",
                confidence_score=0.0,
                detection_method="skipped",
                schema_used="none",
                version_specific_notes=["Classification stage failed"],
            )
            return

        try:
            self._version_result = self.version_detector.detect_version(
                data, self._classification
            )
            logger.info(
                "Stage 2 [MOD_VERSION_DETECTOR]: CS %s (confidence: %.2f)",
                self._version_result.estimated_version,
                self._version_result.confidence_score,
            )

            # Instantiate version-specific modules if version was detected
            schema = self.version_detector.get_schema(
                self._version_result.estimated_version
            )
            self.loader_extractor = LoaderExtractor(schema)
            self.beacon_parser = BeaconParser(schema)
            self.config_extractor = ConfigExtractor(schema)
            self.sleepmask_extractor = SleepMaskExtractor(schema)
            self.postex_extractor = PostExExtractor(schema)

        except Exception as e:
            self._errors.append(f"Stage 2 (Version Detection): {e}")
            self._version_result = VersionDetectionResult(
                estimated_version="unknown",
                confidence_score=0.0,
                detection_method="errored",
                schema_used="none",
                version_specific_notes=[f"Version detection error: {e}"],
            )
            # Fall back to generic modules
            self.loader_extractor = LoaderExtractor()
            self.beacon_parser = BeaconParser()
            self.config_extractor = ConfigExtractor()
            self.sleepmask_extractor = SleepMaskExtractor()
            self.postex_extractor = PostExExtractor()
            logger.warning("Stage 2 failed: %s", e)

    def _stage3_extract_loader(self, data: bytes) -> None:
        """Stage 3: Extract the reflective loader stub."""
        if self.loader_extractor is None:
            self._errors.append("Stage 3 (Loader): LoaderExtractor not initialized")
            return

        try:
            self._loader_result = self.loader_extractor.extract_loader(data)
            logger.info(
                "Stage 3 [MOD_LOADER_EXTRACTOR]: %s at offset %d (confidence: %.2f)",
                self._loader_result.classification,
                self._loader_result.offset,
                self._loader_result.confidence_score,
            )
        except Exception as e:
            self._errors.append(f"Stage 3 (Loader Extraction): {e}")
            logger.warning("Stage 3 failed: %s", e)

    def _stage3b_analyze_bud(self, data: bytes) -> None:
        """Stage 3b: Analyze Beacon User Data structures in the loader stub."""
        if self._loader_result is None or self._loader_result.size == 0:
            return  # No loader to analyze

        try:
            # Get the version schema for BUD analysis context
            schema = None
            if self._version_result and hasattr(self.version_detector, 'get_schema'):
                schema = self.version_detector.get_schema(
                    self._version_result.estimated_version
                )

            bud_analyzer = BUDAnalyzer(schema)

            # Extract loader bytes from the payload
            loader_start = self._loader_result.offset
            loader_end = loader_start + self._loader_result.size
            loader_bytes = data[loader_start:loader_end]

            arch = "x64"
            if self._classification and self._classification.architecture == "x86":
                arch = "x86"

            self._bud_result = bud_analyzer.analyze(
                loader_bytes, self._beacon_dll_data, arch
            )

            if self._bud_result.bud_detected:
                # Update loader result with BUD info
                self._loader_result.bud_detected = True
                self._loader_result.bud_version = self._bud_result.bud_version

                logger.info(
                    "Stage 3b [MOD_BUD_ANALYZER]: BUD v%d detected (CS %s, "
                    "confidence: %.2f, syscall coverage: %.0f%%)",
                    self._bud_result.bud_struct_version,
                    self._bud_result.bud_version,
                    self._bud_result.confidence,
                    self._bud_result.syscall_coverage * 100,
                )
            else:
                logger.info("Stage 3b [MOD_BUD_ANALYZER]: No BUD structures detected")

        except Exception as e:
            self._warnings.append(f"Stage 3b (BUD Analysis): {e}")
            logger.warning("Stage 3b failed: %s", e)

    def _stage4_parse_beacon(self, data: bytes) -> None:
        """Stage 4: Parse the beacon DLL from the payload."""
        if self.beacon_parser is None:
            self._errors.append("Stage 4 (Beacon): BeaconParser not initialized")
            return

        # Determine the loader offset boundary
        loader_offset = 0
        if self._loader_result is not None and self._loader_result.size > 0:
            loader_offset = self._loader_result.offset

        try:
            # Always use find_pe_offset as primary (handles MZ/OICA/OOPS/NO)
            from cs_aggregator.utils.pe_utils import find_pe_offset

            mz_offset = find_pe_offset(data, max_search=0x10000)
            if mz_offset < 0 and loader_offset > 0:
                # Fallback: try loader offset as PE boundary hint
                mz_offset = loader_offset

            if mz_offset >= 0:
                self._beacon_dll_data, self._pe_info = self.beacon_parser.parse_beacon_dll(
                    data, mz_offset
                )
                if self._beacon_dll_data:
                    logger.info(
                        "Stage 4 [MOD_BEACON_PARSER]: DLL at offset %d, %d sections",
                        mz_offset,
                        len(self._pe_info.sections) if self._pe_info else 0,
                    )
                else:
                    self._warnings.append(
                        "Beacon DLL extraction returned no data at PE boundary"
                    )
            else:
                self._warnings.append(
                    "No PE header found (MZ/OICA/OOPS/NO) — beacon DLL may be encrypted or staged payload"
                )
        except Exception as e:
            self._errors.append(f"Stage 4 (Beacon Parser): {e}")
            logger.warning("Stage 4 failed: %s", e)

    def _dispatch_hook(self, hook_name: str, **kwargs: Any) -> None:
        """Dispatch a hook to the plugin manager if one is attached.

        All exceptions are caught so plugin failures never crash the pipeline.
        """
        if self._plugin_manager is None:
            return
        try:
            self._plugin_manager.run_hook(hook_name, **kwargs)
        except Exception as e:
            logger.debug("Plugin hook %s dispatch failed: %s", hook_name, e)

    def _stage5_extract_config(self, dll_data: bytes) -> None:
        """Stage 5: Extract and decrypt the configuration block."""
        if self.config_extractor is None:
            self._errors.append("Stage 5 (Config): ConfigExtractor not initialized")
            return

        try:
            self._config_result = self.config_extractor.extract_config(dll_data)
            logger.info(
                "Stage 5 [MOD_CONFIG_EXTRACTOR]: XOR key %s (%d bytes) at offset %d",
                self._config_result.xor_key[:16],
                self._config_result.xor_key_length,
                self._config_result.offset,
            )
        except ConfigDecryptionError as e:
            self._warnings.append(f"Config decryption: {e}")
            logger.warning("Stage 5 failed: %s", e)
        except Exception as e:
            self._errors.append(f"Stage 5 (Config Extraction): {e}")
            logger.warning("Stage 5 failed: %s", e)

    def _stage5b_refine_version(self) -> None:
        """Stage 5b: Refine version detection using extracted config features.

        This is the most reliable version detection — setting IDs are
        definitive version markers (e.g. setting 74 = CS 4.9+).
        """
        if self._config_result is None:
            return

        try:
            from cs_aggregator.modules.version_detector import VersionDetector

            refined_version, refined_confidence = VersionDetector.detect_version_from_config(
                self._config_result.config_json,
                self._config_result.xor_key,
            )

            if refined_confidence > 0.0:
                # Only override if config-driven detection is more confident
                current_conf = self._version_result.confidence_score if self._version_result else 0.0
                if refined_confidence > current_conf:
                    self._version_result = VersionDetectionResult(
                        estimated_version=refined_version,
                        confidence_score=refined_confidence,
                        detection_method="config_setting_ids",
                        schema_used=self._version_result.schema_used if self._version_result else "none",
                        version_specific_notes=[
                            f"Refined from config: {refined_version} (confidence {refined_confidence:.0%})"
                        ],
                    )
                    logger.info(
                        "Stage 5b [VERSION_REFINE]: %s (confidence: %.2f, method: config_setting_ids)",
                        refined_version,
                        refined_confidence,
                    )
        except Exception as e:
            logger.debug("Stage 5b version refinement failed: %s", e)

    def _stage6a_extract_sleepmask(self, dll_data: bytes) -> None:
        """Stage 6a: Extract and analyze the sleep mask."""
        if self.sleepmask_extractor is None:
            self._errors.append("Stage 6a (SleepMask): SleepMaskExtractor not initialized")
            return

        try:
            self._sleepmask_result = self.sleepmask_extractor.extract(dll_data)
            if self._sleepmask_result.detected:
                logger.info(
                    "Stage 6a [MOD_SLEEPMASK_EXTRACTOR]: %s at offset %d (BeaconGate: %s, confidence: %.2f)",
                    self._sleepmask_result.section_name,
                    self._sleepmask_result.offset,
                    self._sleepmask_result.beacongate_detected,
                    self._sleepmask_result.confidence_score,
                )
            else:
                logger.info("Stage 6a [MOD_SLEEPMASK_EXTRACTOR]: No sleep mask detected")
        except Exception as e:
            self._errors.append(f"Stage 6a (SleepMask): {e}")
            logger.warning("Stage 6a failed: %s", e)

    def _stage6b_analyze_postex(self, dll_data: bytes, config_json: Optional[Dict[str, Any]] = None) -> None:
        """Stage 6b: Analyze post-exploitation DLL references."""
        if self.postex_extractor is None:
            self._errors.append("Stage 6b (PostEx): PostExExtractor not initialized")
            return

        try:
            self._postex_results = self.postex_extractor.analyze(dll_data, config_json)
            if self._postex_results:
                logger.info(
                    "Stage 6b [MOD_POSTEX_EXTRACTOR]: Found %d post-ex DLL references",
                    len(self._postex_results),
                )
                for r in self._postex_results:
                    logger.debug("  - %s (embedded: %s, type: %s)", r.name, r.embedded, r.reference_type)
            else:
                logger.info("Stage 6b [MOD_POSTEX_EXTRACTOR]: No post-ex DLL references found")
        except Exception as e:
            self._errors.append(f"Stage 6b (PostEx): {e}")
            logger.warning("Stage 6b failed: %s", e)

    def _stage7_generate_manifest(self, source_file: Optional[str]) -> Manifest:
        """Stage 7: Assemble all results into a manifest."""
        beacon_dll_hashes = None
        if self._beacon_dll_data is not None:
            beacon_dll_hashes = compute_hashes(self._beacon_dll_data)

        # Build additional segments from Phase 2 results
        additional_segments: List[Dict[str, Any]] = []

        if self._sleepmask_result and self._sleepmask_result.detected:
            sm = self._sleepmask_result
            sm_segment: Dict[str, Any] = {
                "segmentId": "SEG_SLEEP_MASK",
                "type": "Sleep Mask",
                "offset": sm.offset,
                "size": sm.size,
                "sha256": sm.sha256,
                "entropy": sm.entropy,
                "sectionName": sm.section_name,
                "confidenceScore": sm.confidence_score,
                "beaconGateDetected": sm.beacongate_detected,
            }
            if sm.mask_function_rva is not None:
                sm_segment["maskFunctionRVA"] = hex(sm.mask_function_rva)
            if sm.unmask_function_rva is not None:
                sm_segment["unmaskFunctionRVA"] = hex(sm.unmask_function_rva)
            if sm.metadata:
                sm_segment["metadata"] = sm.metadata
            if sm.warnings:
                sm_segment["warnings"] = sm.warnings
            additional_segments.append(sm_segment)

        if self._postex_results:
            postex_segment: Dict[str, Any] = {
                "segmentId": "SEG_POSTEX_REFS",
                "type": "Post-Exploitation DLL References",
                "count": len(self._postex_results),
                "dllReferences": [],
            }
            for r in self._postex_results:
                ref: Dict[str, Any] = {
                    "name": r.name,
                    "referenceType": r.reference_type,
                    "embedded": r.embedded,
                }
                if r.offset >= 0:
                    ref["offset"] = r.offset
                if r.dll_size > 0:
                    ref["size"] = r.dll_size
                if r.sha256:
                    ref["sha256"] = r.sha256
                if r.entropy > 0:
                    ref["entropy"] = r.entropy
                if r.metadata:
                    ref["metadata"] = r.metadata
                postex_segment["dllReferences"].append(ref)
            additional_segments.append(postex_segment)

        manifest = self.manifest_generator.generate(
            classification=self._classification or ClassificationResult(
                payload_type="unknown",
                architecture="unknown",
                format="unknown",
                file_size=0,
                hashes={"md5": "", "sha1": "", "sha256": ""},
                entropy_score=0.0,
                confidence_score=0.0,
            ),
            version_result=self._version_result or VersionDetectionResult(
                estimated_version="unknown",
                confidence_score=0.0,
                detection_method="skipped",
                schema_used="none",
            ),
            loader_result=self._loader_result,
            pe_info=self._pe_info,
            beacon_dll_hashes=beacon_dll_hashes,
            config_result=self._config_result,
            additional_segments=additional_segments if additional_segments else None,
            source_file=source_file,
        )

        # Inject pipeline-level warnings/errors
        if self._warnings:
            if "warnings" not in manifest.metadata:
                manifest.metadata["warnings"] = []
            manifest.metadata["warnings"].extend(self._warnings)

        if self._errors:
            manifest.metadata["errors"] = self._errors

        # Inject BUD analysis results if available
        if self._bud_result and self._bud_result.bud_detected:
            manifest.metadata["budAnalysis"] = {
                "budDetected": True,
                "budVersion": self._bud_result.bud_version,
                "budStructVersion": self._bud_result.bud_struct_version,
                "syscallApiDetected": self._bud_result.syscall_api_detected,
                "syscallCoverage": round(self._bud_result.syscall_coverage, 2),
                "allocatedMemoryDetected": self._bud_result.allocated_memory_detected,
                "sleepMaskRegistered": self._bud_result.sleep_mask_registered,
                "confidence": round(self._bud_result.confidence, 2),
            }
            if self._bud_result.warnings:
                manifest.metadata["budAnalysis"]["warnings"] = self._bud_result.warnings

        # Weighted pipeline confidence
        # Config extraction is the strongest signal (40%)
        weights = {
            'config': 0.40,
            'version': 0.20,
            'pe_dll': 0.20,
            'loader': 0.10,
            'input': 0.10,
        }
        weighted_sum = 0.0

        # Config extraction success
        if self._config_result is not None:
            tlv_count = len(self._config_result.config_json)
            config_score = min(1.0, tlv_count / 30.0)  # 30+ settings = 1.0
            weighted_sum += weights['config'] * config_score

        # Version detection
        if self._version_result is not None:
            weighted_sum += weights['version'] * self._version_result.confidence_score

        # PE/DLL extraction
        if self._beacon_dll_data is not None:
            pe_score = 1.0 if self._pe_info and len(self._pe_info.sections) >= 3 else 0.5
            weighted_sum += weights['pe_dll'] * pe_score

        # Loader classification
        if self._loader_result is not None:
            weighted_sum += weights['loader'] * self._loader_result.confidence_score

        # Input classification
        if self._classification is not None:
            weighted_sum += weights['input'] * self._classification.confidence_score

        manifest.metadata["pipelineConfidence"] = round(weighted_sum, 2)

        logger.info(
            "Stage 7 [MOD_MANIFEST_GENERATOR]: Manifest complete — %d segments",
            len(manifest.segments),
        )
        return manifest

    @property
    def classification(self) -> Optional[ClassificationResult]:
        return self._classification

    @property
    def version_result(self) -> Optional[VersionDetectionResult]:
        return self._version_result

    @property
    def loader_result(self) -> Optional[LoaderStubResult]:
        return self._loader_result

    @property
    def config_result(self) -> Optional[ConfigBlockResult]:
        return self._config_result

    @property
    def sleepmask_result(self) -> Optional[SleepMaskResult]:
        return self._sleepmask_result

    @property
    def postex_results(self) -> List[PostExDLLInfo]:
        return list(self._postex_results)

    @property
    def warnings(self) -> List[str]:
        return list(self._warnings)

    @property
    def errors(self) -> List[str]:
        return list(self._errors)


    def reassemble(
        self,
        manifest: Manifest,
        config: ReassemblyConfig,
    ) -> ReassemblyResult:
        """Run the reassembly pipeline on a previously dissected payload.

        Takes a manifest from a dissection and a ReassemblyConfig describing
        which components to modify, then assembles the modified payload.

        Args:
            manifest: The dissection manifest from a previous pipeline run.
            config: Reassembly configuration specifying modifications.

        Returns:
            ReassemblyResult with the reassembled payload.
        """
        # Get the version schema from the manifest's version detection
        version = manifest.metadata.get("csVersionDetected", {}).get("version", "unknown")
        schema = self.version_detector.get_schema(version) if hasattr(self, 'version_detector') else None

        reassembler = Reassembler(schema)
        result = reassembler.reassemble(manifest, config)
        return result

    def rebuild_from_original(
        self,
        original_payload: bytes,
        manifest: Manifest,
        config: ReassemblyConfig,
    ) -> ReassemblyResult:
        """Rebuild a payload from the original bytes and a manifest.

        Convenience method that extracts original segments from the payload
        buffer and applies the reassembly config.

        Args:
            original_payload: The original raw payload bytes.
            manifest: The dissection manifest.
            config: Reassembly configuration specifying modifications.

        Returns:
            ReassemblyResult with the reassembled payload.
        """
        from cs_aggregator.modules.reassembler import Reassembler as ReassemblerCls

        result = ReassemblerCls.build_from_original(
            original_payload, manifest, config
        )
        return result


# Convenience functions

def dissect(data: bytes, source_file: Optional[str] = None) -> Manifest:
    """One-shot dissection of beacon payload bytes.

    Args:
        data: Raw payload bytes.
        source_file: Optional source filename.

    Returns:
        Manifest with comprehensive dissection results.
    """
    pipeline = DissectionPipeline()
    return pipeline.process(data, source_file)


def dissect_file(path: str) -> Manifest:
    """One-shot dissection of a beacon payload file.

    Args:
        path: Path to the payload file.

    Returns:
        Manifest with comprehensive dissection results.
    """
    pipeline = DissectionPipeline()
    return pipeline.process_with_path(path)
