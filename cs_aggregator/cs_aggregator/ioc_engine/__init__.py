"""IOC Central Engine — Unified threat intelligence extraction and export.

Coordinates multiple sub-engines for comprehensive IOC extraction from
CobaltStrike beacon payloads. Each sub-engine handles a distinct
intelligence domain.

Sub-Engines:
    - NetworkEngine: C2 domains, IPs, URIs, pipes, proxy, DNS beacon
    - BehavioralEngine: Syscalls, injection, spawn-to, sleep patterns, TTPs
    - CryptoEngine: XOR keys, watermarks, pubkeys, config signatures
    - YaraEngine: Static + dynamic YARA rule matching and generation
    - TTPMapper: MITRE ATT&CK ID mapping from detected techniques

Export Formats:
    - STIX 2.1 JSON bundles
    - MISP JSON events
    - CSV flat files for SIEM ingestion
"""

from typing import Any, Dict, List, Optional

from cs_aggregator.ioc_engine.network_engine import NetworkEngine
from cs_aggregator.ioc_engine.behavioral_engine import BehavioralEngine
from cs_aggregator.ioc_engine.crypto_engine import CryptoEngine
from cs_aggregator.ioc_engine.yara_engine import YaraEngine
from cs_aggregator.ioc_engine.ttp_mapper import TTPMapper
from cs_aggregator.ioc_engine.exporters import STIXExporter, MISPExporter, CSVExporter


class IOCCentralEngine:
    """Central orchestrator for all IOC sub-engines.

    Usage:
        engine = IOCCentralEngine()
        results = engine.analyze(config_json, raw_data, pe_info, ctx)
        engine.export("stix", results, output_path)
    """

    def __init__(self) -> None:
        self.network = NetworkEngine()
        self.behavioral = BehavioralEngine()
        self.crypto = CryptoEngine()
        self.yara = YaraEngine()
        self.ttp_mapper = TTPMapper()
        self._exporters = {
            "stix": STIXExporter(),
            "misp": MISPExporter(),
            "csv": CSVExporter(),
        }

    def analyze(
        self,
        config: Optional[Dict[str, Any]] = None,
        raw_data: Optional[bytes] = None,
        pe_info: Optional[Any] = None,
        dll_data: Optional[bytes] = None,
        ctx: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Run all sub-engines and aggregate results.

        Args:
            config: Extracted beacon config dict (SETTING_* keys).
            raw_data: Raw payload bytes.
            pe_info: Parsed PE info object.
            dll_data: Decrypted beacon DLL bytes.
            ctx: Pipeline context dict.

        Returns:
            Consolidated IOC report with results from all sub-engines.
        """
        config = config or {}
        ctx = ctx or {}
        report: Dict[str, Any] = {}

        # Network IOCs
        report["network"] = self.network.extract(config, dll_data)

        # Behavioral analysis
        report["behavioral"] = self.behavioral.extract(config, raw_data, pe_info)

        # Cryptographic artifacts
        report["crypto"] = self.crypto.extract(config, ctx)

        # YARA matches (static rules)
        if raw_data:
            report["yara"] = self.yara.scan(raw_data)

        # TTP mapping from all findings
        report["ttps"] = self.ttp_mapper.map_from_report(report)

        # Compute totals
        total = 0
        for section in report.values():
            if isinstance(section, dict):
                for v in section.values():
                    if isinstance(v, list):
                        total += len(v)
                    elif v and not isinstance(v, (dict, bool)):
                        total += 1
        report["total_iocs"] = total

        return report

    def generate_yara_rules(
        self, report: Dict[str, Any], config: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate dynamic YARA rules from analysis results.

        Returns YARA rule source text.
        """
        return self.yara.generate_rules(report, config or {})

    def export(
        self, fmt: str, report: Dict[str, Any], output_path: str
    ) -> str:
        """Export IOC report in the specified format.

        Args:
            fmt: Export format — 'stix', 'misp', or 'csv'.
            report: Consolidated IOC report from analyze().
            output_path: Path to write the export file.

        Returns:
            Path to the written export file.
        """
        exporter = self._exporters.get(fmt)
        if exporter is None:
            raise ValueError(f"Unknown export format: {fmt}. Use: stix, misp, csv")
        return exporter.export(report, output_path)

    def get_available_formats(self) -> List[str]:
        """Return list of available export format names."""
        return list(self._exporters.keys())
