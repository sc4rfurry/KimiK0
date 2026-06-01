"""IOC Extractor Plugin — Delegates to the IOC Central Engine.

Thin orchestration wrapper that wires the pipeline hooks to the IOC Central
Engine's sub-engines (Network, Behavioral, Crypto, YARA, TTP Mapper).
"""

from typing import Any, Dict, List, Optional


class IOCExtractorPlugin:
    """Extract all actionable IOCs via the IOC Central Engine."""

    name = "ioc_extractor"
    version = "2.0.0"
    description = "Central IOC engine: network, behavioral, crypto, YARA, TTP mapping + STIX/MISP/CSV export"
    hooks = ["on_pe_parsed", "on_config_extracted"]

    def __init__(self) -> None:
        self._report: Dict[str, Any] = {}
        self._pe_iocs: Dict[str, Any] = {}
        self._engine: Optional[Any] = None

    def initialize(self, config: Dict[str, Any]) -> None:
        """Initialize the IOC Central Engine."""
        try:
            from cs_aggregator.ioc_engine import IOCCentralEngine
            self._engine = IOCCentralEngine()
        except ImportError:
            self._engine = None

    def on_payload_loaded(self, data: bytes, ctx: Dict[str, Any]) -> None:
        pass

    def on_version_detected(self, version_result: Any, ctx: Dict[str, Any]) -> None:
        pass

    def on_loader_extracted(self, loader_result: Any, ctx: Dict[str, Any]) -> None:
        pass

    def on_pe_parsed(self, pe_info: Any, dll_data: bytes, ctx: Dict[str, Any]) -> None:
        """Store DLL data for later analysis."""
        ctx["_ioc_dll_data"] = dll_data
        ctx["_ioc_pe_info"] = pe_info

    def on_config_extracted(self, config: Dict[str, Any], ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Run the full IOC Central Engine analysis."""
        if self._engine is None:
            # Fallback: basic extraction without central engine
            self._report = self._basic_extract(config, ctx)
        else:
            self._report = self._engine.analyze(
                config=config,
                raw_data=ctx.get("raw_data"),
                pe_info=ctx.get("_ioc_pe_info"),
                dll_data=ctx.get("_ioc_dll_data"),
                ctx=ctx,
            )

        ctx["iocs"] = self._report
        return None

    def on_manifest_ready(self, manifest: Dict, ctx: Dict) -> Optional[Dict]:
        if self._report:
            manifest.setdefault("metadata", {})["iocs"] = self._report
            return manifest
        return None

    def render_results(self) -> Optional[Any]:
        """Render IOC results using Rich components."""
        if not self._report or self._report.get("total_iocs", 0) == 0:
            return None
        try:
            from rich.text import Text
            from rich.console import Group
            from cs_aggregator.utils.rich_output import (
                DIM, MUTED, ACCENT_DANGER, ACCENT_PRIMARY,
                ACCENT_SUCCESS, ACCENT_WARN,
            )

            parts = []

            # Header
            h = Text()
            h.append("    ◈ ", style=ACCENT_DANGER)
            h.append("IOC CENTRAL ENGINE", style=f"bold {ACCENT_DANGER}")
            h.append(f"  ·  {self._report.get('total_iocs', 0)} indicators", style=MUTED)
            parts.append(h)
            parts.append(Text(f"    {'─' * 68}", style=DIM))

            # Network IOCs
            network = self._report.get("network", {})
            domains = network.get("domains", [])
            ips = network.get("ips", [])
            uris = network.get("uris", [])
            pipes = network.get("pipes", [])

            if domains or ips:
                parts.append(Text("    C2 Infrastructure", style="bold bright_red"))
                for d in domains:
                    t = Text()
                    t.append("      › ", style="bright_yellow")
                    t.append(d, style="bright_yellow")
                    parts.append(t)
                for ip in ips:
                    t = Text()
                    t.append("      › ", style="bright_cyan")
                    t.append(ip, style="bright_cyan")
                    parts.append(t)
                for uri in uris:
                    t = Text()
                    t.append("      › ", style=DIM)
                    t.append(uri, style=MUTED)
                    parts.append(t)

            # C2 Profile
            c2 = network.get("c2_profile", {})
            if c2:
                parts.append(Text())
                parts.append(Text("    Network Profile", style=f"bold {ACCENT_PRIMARY}"))
                n = Text()
                n.append("      Protocol ", style=DIM)
                n.append(f"{c2.get('protocol', '?')}", style="bright_white")
                n.append(f"  Port ", style=DIM)
                n.append(f"{c2.get('port', '?')}", style="bright_white")
                sleep = c2.get("sleep_ms", 0)
                jitter = c2.get("jitter_pct", 0)
                if sleep:
                    n.append(f"  Callback ", style=DIM)
                    n.append(f"{sleep / 1000:.1f}s ±{jitter}%", style="bright_white")
                parts.append(n)
                ua = c2.get("user_agent", "")
                if ua:
                    u = Text()
                    u.append("      UA       ", style=DIM)
                    u.append(ua[:60] + ("…" if len(ua) > 60 else ""), style=DIM)
                    parts.append(u)

            # Pipes
            if pipes:
                parts.append(Text())
                parts.append(Text("    Named Pipes", style=f"bold {ACCENT_SUCCESS}"))
                for p in pipes:
                    t = Text()
                    t.append("      › ", style=ACCENT_SUCCESS)
                    t.append(p, style=ACCENT_SUCCESS)
                    parts.append(t)

            # Behavioral
            behavioral = self._report.get("behavioral", {})
            processes = behavioral.get("processes", [])
            syscall = behavioral.get("syscall", {})
            evasion = behavioral.get("evasion", {})

            if processes:
                parts.append(Text("    Spawn-To Targets", style="bold bright_blue"))
                for p in processes:
                    t = Text()
                    t.append("      › ", style="bright_blue")
                    t.append(p, style="bright_blue")
                    parts.append(t)

            if evasion:
                parts.append(Text())
                parts.append(Text("    Evasion Profile", style=f"bold {ACCENT_WARN}"))
                ev = Text()
                ev.append("      Syscall ", style=DIM)
                ev.append(syscall.get("method", "none"), style="bright_white")
                if evasion.get("beacon_gate_enabled"):
                    ev.append("  BeaconGate ", style=DIM)
                    ev.append("ACTIVE", style="bold bright_green")
                if evasion.get("drip_loading_enabled"):
                    ev.append("  DripLoad ", style=DIM)
                    ev.append("ACTIVE", style="bold bright_green")
                parts.append(ev)

            # Crypto identifiers
            crypto = self._report.get("crypto", {})
            identifiers = crypto.get("identifiers", {})
            timestamps = crypto.get("timestamps", {})
            if identifiers or timestamps:
                parts.append(Text())
                parts.append(Text("    Identifiers", style="bold bright_magenta"))
                for k, v in identifiers.items():
                    t = Text()
                    t.append(f"      {k:20s} ", style=DIM)
                    t.append(str(v), style="bright_white")
                    parts.append(t)
                for k, v in timestamps.items():
                    t = Text()
                    t.append(f"      {k:20s} ", style=DIM)
                    t.append(str(v), style="bright_yellow")
                    parts.append(t)

            # TTP Summary
            ttps = self._report.get("ttps", {})
            techniques = ttps.get("techniques", [])
            if techniques:
                parts.append(Text())
                parts.append(Text("    MITRE ATT&CK Mapping", style="bold bright_red"))
                for tech in techniques[:12]:
                    t = Text()
                    t.append(f"      {tech.get('id', ''):12s}", style="bright_cyan")
                    t.append(f" {tech.get('name', '')}", style="bright_white")
                    t.append(f"  [{tech.get('tactic', '')}]", style=DIM)
                    parts.append(t)
                if len(techniques) > 12:
                    parts.append(Text(f"      ... and {len(techniques) - 12} more", style=DIM))

            return Group(*parts)
        except Exception:
            return None

    def get_results(self) -> Optional[Dict[str, Any]]:
        return self._report if self._report else None

    def cleanup(self) -> None:
        self._report.clear()

    @staticmethod
    def _basic_extract(config: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback basic extraction when IOC Central Engine is unavailable."""
        import re
        iocs: Dict[str, Any] = {
            "domains": [], "ips": [], "uris": [], "pipes": [],
            "processes": [], "network": {}, "identifiers": {}, "timestamps": {},
        }

        domains_raw = str(config.get("SETTING_DOMAINS", ""))
        if domains_raw:
            for part in (p.strip() for p in domains_raw.split(",")):
                if part.startswith("/"):
                    iocs["uris"].append(part)
                elif _is_ip(part):
                    iocs["ips"].append(part)
                elif part and not all(c == "0" for c in part):
                    iocs["domains"].append(part)

        submit = config.get("SETTING_SUBMITURI", "")
        if submit:
            iocs["uris"].append(str(submit))

        for key in ("SETTING_PIPENAME",):
            pipe = config.get(key, "")
            if pipe:
                iocs["pipes"].append(str(pipe))

        for key in ("SETTING_SPAWNTO_X86", "SETTING_SPAWNTO_X64"):
            spawn = config.get(key, "")
            if spawn and not all(c == "0" for c in str(spawn)):
                iocs["processes"].append(str(spawn))

        wm = config.get("SETTING_WATERMARK")
        if wm is not None:
            iocs["identifiers"]["watermark"] = int(wm) if isinstance(wm, (int, float)) else str(wm)

        iocs["total_iocs"] = sum(len(v) for v in iocs.values() if isinstance(v, list))
        return iocs


def _is_ip(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False
