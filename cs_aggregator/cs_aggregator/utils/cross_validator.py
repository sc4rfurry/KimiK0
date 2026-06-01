"""Cross-Validation Reporter — Parallel parsing with pefile/dissect + diff generation.

Enables the --validate-with CLI flag to run our analysis alongside
third-party parsers and produce a field-by-field comparison report.

Supported backends:
    - pefile: PE section/import comparison
    - dissect.cobaltstrike: Config extraction comparison
    - both: Run both backends and merge diffs
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("cs_aggregator.cross_validator")


class CrossValidationResult:
    """Result of cross-validation against a third-party parser."""

    def __init__(self, backend: str):
        self.backend = backend
        self.our_fields: Dict[str, Any] = {}
        self.their_fields: Dict[str, Any] = {}
        self.matches: List[str] = []
        self.mismatches: List[Dict[str, Any]] = []
        self.our_only: List[str] = []
        self.their_only: List[str] = []
        self.confidence_delta: float = 0.0
        self.error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "backend": self.backend,
            "totalMatches": len(self.matches),
            "totalMismatches": len(self.mismatches),
            "ourOnlyFields": len(self.our_only),
            "theirOnlyFields": len(self.their_only),
            "confidenceDelta": round(self.confidence_delta, 4),
            "mismatches": self.mismatches,
            "error": self.error,
        }


class CrossValidator:
    """Cross-validates analysis results against third-party parsers."""

    def validate(
        self,
        data: bytes,
        our_manifest: Dict[str, Any],
        backend: str = "both",
    ) -> List[CrossValidationResult]:
        """Run cross-validation against the specified backend(s).

        Args:
            data: Raw payload bytes.
            our_manifest: Our pipeline's manifest dict.
            backend: "pefile", "dissect", or "both".

        Returns:
            List of CrossValidationResult objects.
        """
        results = []

        if backend in ("pefile", "both"):
            results.append(self._validate_pefile(data, our_manifest))

        if backend in ("dissect", "both"):
            results.append(self._validate_dissect(data, our_manifest))

        return results

    def _validate_pefile(self, data: bytes, manifest: Dict[str, Any]) -> CrossValidationResult:
        """Validate PE parsing against pefile library."""
        result = CrossValidationResult("pefile")

        try:
            import pefile
        except ImportError:
            result.error = "pefile not installed — install with: pip install pefile"
            return result

        # Find beacon DLL segment
        dll_data = None
        for seg in manifest.get("segments", []):
            if seg.get("segmentId") == "SEG_BEACON_DLL":
                offset = seg.get("offset", 0)
                size = seg.get("size", 0)
                if offset + size <= len(data):
                    dll_data = data[offset:offset + size]
                break

        if not dll_data:
            result.error = "No SEG_BEACON_DLL segment found in manifest"
            return result

        # Find MZ header in DLL data
        mz_off = dll_data.find(b"MZ")
        if mz_off == -1:
            result.error = "No MZ header in beacon DLL segment"
            return result

        try:
            pe = pefile.PE(data=dll_data[mz_off:], fast_load=True)
            pe.parse_data_directories()

            # Compare sections
            our_pe_info = {}
            for seg in manifest.get("segments", []):
                if seg.get("segmentId") == "SEG_BEACON_DLL":
                    our_pe_info = seg.get("peInfo", {})
                    break

            our_sections = {s["name"]: s for s in our_pe_info.get("sections", [])}

            for section in pe.sections:
                name = section.Name.decode("ascii", errors="replace").strip("\x00")
                their_data = {
                    "virtualSize": section.Misc_VirtualSize,
                    "rawSize": section.SizeOfRawData,
                    "virtualAddress": section.VirtualAddress,
                }

                result.their_fields[f"section.{name}"] = their_data

                if name in our_sections:
                    our_sec = our_sections[name]
                    # Compare raw sizes
                    our_raw = our_sec.get("rawSize", our_sec.get("size", 0))
                    if our_raw == their_data["rawSize"]:
                        result.matches.append(f"section.{name}.rawSize")
                    else:
                        result.mismatches.append({
                            "field": f"section.{name}.rawSize",
                            "ours": our_raw,
                            "theirs": their_data["rawSize"],
                        })
                else:
                    result.their_only.append(f"section.{name}")

            # Compare machine type
            our_machine = our_pe_info.get("machineType", "")
            their_machine = hex(pe.FILE_HEADER.Machine)
            result.our_fields["machineType"] = our_machine
            result.their_fields["machineType"] = their_machine

            # Compare timestamp
            result.their_fields["timestamp"] = pe.FILE_HEADER.TimeDateStamp

            pe.close()

        except Exception as e:
            result.error = f"pefile parsing error: {e}"

        # Calculate confidence delta
        total = len(result.matches) + len(result.mismatches)
        if total > 0:
            result.confidence_delta = len(result.matches) / total
        else:
            result.confidence_delta = 0.5

        return result

    def _validate_dissect(self, data: bytes, manifest: Dict[str, Any]) -> CrossValidationResult:
        """Validate config extraction against dissect.cobaltstrike."""
        result = CrossValidationResult("dissect.cobaltstrike")

        try:
            from dissect.cobaltstrike import beacon as dissect_beacon
        except ImportError:
            result.error = (
                "dissect.cobaltstrike not installed — "
                "install with: pip install dissect.cobaltstrike"
            )
            return result

        try:
            # Run dissect's beacon parser
            bconfig = dissect_beacon.BeaconConfig(data)

            if not bconfig.settings:
                result.error = "dissect.cobaltstrike found no settings in payload"
                return result

            # Build their config dict
            for setting_id, value in bconfig.settings.items():
                key = str(setting_id)
                result.their_fields[key] = str(value) if value is not None else None

            # Get our config
            our_config = {}
            for seg in manifest.get("segments", []):
                if seg.get("segmentId") == "SEG_CONFIG_BLOCK":
                    our_config = seg.get("config", {})
                    break

            if not our_config:
                result.error = "No config block in our manifest for comparison"
                return result

            # Compare field by field
            for key, our_val in our_config.items():
                result.our_fields[key] = our_val
                if key in result.their_fields:
                    their_val = result.their_fields[key]
                    if str(our_val) == str(their_val):
                        result.matches.append(key)
                    else:
                        result.mismatches.append({
                            "field": key,
                            "ours": our_val,
                            "theirs": their_val,
                        })
                else:
                    result.our_only.append(key)

            for key in result.their_fields:
                if key not in result.our_fields:
                    result.their_only.append(key)

        except Exception as e:
            result.error = f"dissect.cobaltstrike error: {e}"

        # Calculate confidence delta
        total = len(result.matches) + len(result.mismatches)
        if total > 0:
            result.confidence_delta = len(result.matches) / total
        else:
            result.confidence_delta = 0.5

        return result

    def format_report(self, results: List[CrossValidationResult]) -> str:
        """Format cross-validation results as a human-readable report."""
        lines = ["═" * 60, "  CROSS-VALIDATION REPORT", "═" * 60]

        for r in results:
            lines.append(f"\n  Backend: {r.backend}")
            lines.append(f"  {'─' * 50}")

            if r.error:
                lines.append(f"  ERROR: {r.error}")
                continue

            lines.append(f"  Matches:     {len(r.matches)}")
            lines.append(f"  Mismatches:  {len(r.mismatches)}")
            lines.append(f"  Our-only:    {len(r.our_only)}")
            lines.append(f"  Their-only:  {len(r.their_only)}")
            lines.append(f"  Agreement:   {r.confidence_delta:.0%}")

            if r.mismatches:
                lines.append(f"\n  Mismatches:")
                for m in r.mismatches[:20]:
                    lines.append(
                        f"    {m['field']:40s}  "
                        f"ours={m['ours']}  theirs={m['theirs']}"
                    )

        lines.append("\n" + "═" * 60)
        return "\n".join(lines)
