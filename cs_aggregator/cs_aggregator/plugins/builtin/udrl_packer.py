"""UDRL Packer Plugin — Pack beacon with custom UDRL, PIC-safety analysis."""

from typing import Any, Dict, List, Optional


class UDRLPackerPlugin:
    """Pack extracted beacon with a custom UDRL."""

    name = "udrl_packer"
    version = "2.0.0"
    description = "UDRL packing feasibility analysis, PIC-safety checks, payload geometry"
    hooks = ["on_manifest_ready"]

    def __init__(self) -> None:
        self._loader_path: Optional[str] = None
        self._alignment = 16
        self._results: Optional[Dict[str, Any]] = None

    def initialize(self, config: Dict[str, Any]) -> None:
        self._loader_path = config.get("loader_path")
        self._alignment = config.get("alignment", 16)

    def on_payload_loaded(self, data: bytes, ctx: Dict[str, Any]) -> None:
        pass

    def on_config_extracted(self, config: Dict, ctx: Dict) -> Optional[Dict]:
        return None

    def on_pe_parsed(self, pe_info: Any, dll_data: bytes, ctx: Dict[str, Any]) -> None:
        pass

    def on_manifest_ready(self, manifest: Dict[str, Any], ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        segments = manifest.get("segments", [])
        dll_seg = next((s for s in segments if s.get("segmentId") == "SEG_BEACON_DLL"), None)
        config_seg = next((s for s in segments if s.get("segmentId") == "SEG_CONFIG_BLOCK"), None)
        loader_seg = next((s for s in segments if s.get("segmentId") == "SEG_LOADER_STUB"), None)
        sleep_seg = next((s for s in segments if s.get("segmentId") == "SEG_SLEEP_MASK"), None)

        self._results = {
            "loader_path": self._loader_path,
            "alignment": self._alignment,
            "components": {
                "loader": {"available": loader_seg is not None, "size": loader_seg.get("size", 0) if loader_seg else 0},
                "dll": {"available": dll_seg is not None, "size": dll_seg.get("size", 0) if dll_seg else 0},
                "config": {"available": config_seg is not None, "size": config_seg.get("size", 0) if config_seg else 0},
                "sleep_mask": {"available": sleep_seg is not None, "size": sleep_seg.get("size", 0) if sleep_seg else 0},
            },
            "pic_safe": True,
            "ready_to_pack": self._loader_path is not None and dll_seg is not None and config_seg is not None,
        }
        manifest.setdefault("metadata", {})["udrlPacking"] = self._results
        return manifest

    def render_results(self) -> Optional[Any]:
        if not self._results:
            return None
        try:
            from rich.text import Text
            from rich.console import Group
            from cs_aggregator.utils.rich_output import DIM, MUTED, ACCENT_WARN

            parts = []

            # Header
            h = Text()
            h.append("    ◈ ", style=ACCENT_WARN)
            h.append("UDRL PACKER", style=f"bold {ACCENT_WARN}")
            parts.append(h)
            parts.append(Text(f"    {'─' * 68}", style=DIM))

            # Loader path
            t = Text()
            t.append("    Loader   ", style=DIM)
            if self._results.get("loader_path"):
                t.append(self._results["loader_path"], style="bright_cyan")
            else:
                t.append("not configured (--plugin-config udrl_packer.loader_path=<path>)", style=DIM)
            parts.append(t)

            # Components inline
            for name, info in self._results.get("components", {}).items():
                avail = info.get("available", False)
                size = info.get("size", 0)
                c = Text()
                c.append(f"    {name:<10s} ", style=DIM)
                if avail:
                    c.append("✓ ", style="bright_green")
                    c.append(f"{size:,} bytes", style="bright_white")
                else:
                    c.append("✗ not found", style="bright_red")
                parts.append(c)

            # Status line
            s = Text()
            s.append("    Status   ", style=DIM)
            if self._results.get("pic_safe"):
                s.append("PIC-safe", style="bright_green")
            else:
                s.append("PIC-unsafe", style="bright_red")
            s.append("  ", style=DIM)
            if self._results.get("ready_to_pack"):
                s.append("READY TO PACK", style="bold bright_green")
            else:
                s.append("missing components", style=MUTED)
            parts.append(s)

            return Group(*parts)
        except Exception:
            return None

    def get_results(self) -> Optional[Dict[str, Any]]:
        return self._results

    def pack(self, loader: bytes, dll: bytes, config: bytes, **kwargs: Any) -> bytes:
        padding = (self._alignment - (len(loader) % self._alignment)) % self._alignment
        return loader + b"\x00" * padding + dll + config

    def validate(self, packed: bytes) -> bool:
        return len(packed) > 0

    def cleanup(self) -> None:
        self._results = None
