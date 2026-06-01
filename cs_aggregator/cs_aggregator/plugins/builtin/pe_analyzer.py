"""Universal PE Analyzer Plugin — Deep PE structure analysis with Rich output.

Sections, permissions, RWX audit, rich header, data directories, security
assessment — all rendered in a professional Rich table.
"""

import struct
from typing import Any, Dict, List, Optional


class PEAnalyzerPlugin:
    """Deep PE structure analysis for beacon DLLs."""

    name = "pe_analyzer"
    version = "2.0.0"
    description = "Deep PE analysis: sections, RWX audit, data directories, rich header, security assessment"
    hooks = ["on_pe_parsed"]

    def __init__(self) -> None:
        self._results: Dict[str, Any] = {}

    def initialize(self, config: Dict[str, Any]) -> None:
        pass

    def on_payload_loaded(self, data: bytes, ctx: Dict[str, Any]) -> None:
        pass

    def on_pe_parsed(self, pe_info: Any, dll_data: bytes, ctx: Dict[str, Any]) -> None:
        if not dll_data or len(dll_data) < 64:
            return
        analysis: Dict[str, Any] = {}
        try:
            e_lfanew = struct.unpack_from("<I", dll_data, 0x3C)[0]
            if e_lfanew + 24 > len(dll_data):
                return

            machine = struct.unpack_from("<H", dll_data, e_lfanew + 4)[0]
            num_sections = struct.unpack_from("<H", dll_data, e_lfanew + 6)[0]
            timestamp = struct.unpack_from("<I", dll_data, e_lfanew + 8)[0]
            characteristics = struct.unpack_from("<H", dll_data, e_lfanew + 22)[0]

            analysis["coff"] = {
                "machine": machine, "machine_str": "x64" if machine == 0x8664 else "x86" if machine == 0x14c else f"0x{machine:04x}",
                "num_sections": num_sections, "timestamp": timestamp,
                "characteristics": characteristics,
                "is_dll": bool(characteristics & 0x2000),
            }

            opt_magic = struct.unpack_from("<H", dll_data, e_lfanew + 24)[0]
            is_pe32plus = opt_magic == 0x20B
            ep_offset = e_lfanew + 24 + 16
            entry_point = struct.unpack_from("<I", dll_data, ep_offset)[0] if ep_offset + 4 <= len(dll_data) else 0
            analysis["optional"] = {"is_64bit": is_pe32plus, "entry_point": entry_point}

            sections = self._parse_sections(dll_data, e_lfanew, num_sections)
            analysis["sections"] = sections

            rwx = [s for s in sections if s.get("rwx")]
            analysis["security"] = {
                "rwx_count": len(rwx),
                "rwx_names": [s["name"] for s in rwx],
                "writable_executable": any(s.get("writable") and s.get("executable") for s in sections),
                "risk_level": "HIGH" if rwx else ("MEDIUM" if any(s.get("writable") and s.get("executable") for s in sections) else "LOW"),
            }

            analysis["rich_header"] = self._detect_rich_header(dll_data, e_lfanew)
            analysis["data_dirs"] = self._parse_data_directories(dll_data, e_lfanew, is_pe32plus)

        except (struct.error, ValueError, IndexError) as e:
            analysis["error"] = str(e)

        self._results = analysis
        ctx["pe_analysis"] = analysis

    def on_config_extracted(self, config: Dict, ctx: Dict) -> Optional[Dict]:
        return None

    def on_manifest_ready(self, manifest: Dict, ctx: Dict) -> Optional[Dict]:
        if self._results:
            manifest.setdefault("metadata", {})["peAnalysis"] = self._results
            return manifest
        return None

    def render_results(self) -> Optional[Any]:
        if not self._results:
            return None
        try:
            from rich.console import Group
            from rich.table import Table
            from rich.text import Text
            from rich import box
            from cs_aggregator.utils.rich_output import DIM, MUTED, ACCENT_PRIMARY

            parts = []

            # Header
            h = Text()
            h.append("    ◈ ", style=ACCENT_PRIMARY)
            h.append("PE ANALYSIS", style=f"bold {ACCENT_PRIMARY}")
            parts.append(h)
            parts.append(Text(f"    {'─' * 68}", style=DIM))

            coff = self._results.get("coff", {})
            opt = self._results.get("optional", {})
            sec = self._results.get("security", {})

            # Compact header
            t = Text()
            t.append("    Machine  ", style=DIM)
            t.append(coff.get("machine_str", "?"), style="bold bright_cyan")
            t.append(f"  EP  ", style=DIM)
            t.append(f"0x{opt.get('entry_point', 0):08x}", style="bright_white")
            t.append(f"  Sections  ", style=DIM)
            t.append(f"{coff.get('num_sections', 0)}", style="bright_white")
            t.append(f"  ", style=DIM)
            t.append("DLL" if coff.get("is_dll") else "EXE", style="bold bright_green")
            t.append(f" ({'PE32+' if opt.get('is_64bit') else 'PE32'})", style=DIM)
            parts.append(t)

            # Security
            risk = sec.get("risk_level", "?")
            risk_colors = {"HIGH": "bold red", "MEDIUM": "bold yellow", "LOW": "bold green"}
            s = Text()
            s.append("    Security ", style=DIM)
            s.append(risk, style=risk_colors.get(risk, "white"))
            if sec.get("rwx_count", 0) > 0:
                s.append(f"  ({sec['rwx_count']} RWX: {', '.join(sec.get('rwx_names', []))})", style="yellow")
            parts.append(s)

            # Sections compact table
            sections = self._results.get("sections", [])
            if sections:
                parts.append(Text())
                sec_table = Table(box=box.SIMPLE, header_style="bold", show_edge=False, padding=(0, 1))
                sec_table.add_column("Section", style="bright_white", min_width=16)
                sec_table.add_column("VSize", justify="right", style=DIM)
                sec_table.add_column("Raw", justify="right", style=DIM)
                sec_table.add_column("Perms", style="bright_cyan")
                sec_table.add_column("Flags")

                for sc in sections:
                    perms = sc.get("permissions", "---")
                    perm_style = "bold red" if sc.get("rwx") else "bright_green" if not sc.get("executable") else "yellow"
                    flags_text = Text()
                    if sc.get("is_obfuscated"):
                        flags_text.append("obfuscated ", style="bright_magenta")
                    if sc.get("contains_code"):
                        flags_text.append("code", style="bright_cyan")
                    sec_table.add_row(
                        sc["name"], f"{sc.get('virtual_size', 0):,}", f"{sc.get('raw_size', 0):,}",
                        Text(perms, style=perm_style), flags_text,
                    )
                parts.append(sec_table)

            # Data directories compact
            data_dirs = self._results.get("data_dirs", [])
            if data_dirs:
                dd_table = Table(box=box.SIMPLE, header_style="bold", show_edge=False, padding=(0, 1))
                dd_table.add_column("Directory", style="bright_white", min_width=12)
                dd_table.add_column("RVA", style=DIM)
                dd_table.add_column("Size", justify="right", style="bright_cyan")
                for dd in data_dirs:
                    dd_table.add_row(dd["name"], dd["rva"], f"{dd['size']:,}")
                parts.append(dd_table)

            return Group(*parts)
        except Exception:
            return None

    def get_results(self) -> Optional[Dict[str, Any]]:
        return self._results if self._results else None

    def cleanup(self) -> None:
        self._results.clear()

    @staticmethod
    def _parse_sections(data: bytes, pe_offset: int, num_sections: int) -> List[Dict]:
        size_of_optional = struct.unpack_from("<H", data, pe_offset + 20)[0]
        section_table = pe_offset + 24 + size_of_optional
        sections = []
        for i in range(num_sections):
            off = section_table + i * 40
            if off + 40 > len(data):
                break
            name_raw = data[off:off + 8].split(b"\x00")[0]
            is_obf = any(b > 127 for b in name_raw)
            name = f"obfuscated_{i}" if is_obf else name_raw.decode("ascii", errors="replace").strip()
            flags = struct.unpack_from("<I", data, off + 36)[0]
            r, w, x = bool(flags & 0x40000000), bool(flags & 0x80000000), bool(flags & 0x20000000)
            sections.append({
                "name": name, "is_obfuscated": is_obf,
                "virtual_size": struct.unpack_from("<I", data, off + 8)[0],
                "raw_size": struct.unpack_from("<I", data, off + 16)[0],
                "permissions": ("R" if r else "-") + ("W" if w else "-") + ("X" if x else "-"),
                "readable": r, "writable": w, "executable": x, "rwx": r and w and x,
                "contains_code": bool(flags & 0x20),
            })
        return sections

    @staticmethod
    def _detect_rich_header(data: bytes, pe_offset: int) -> Dict:
        rich_end = data.find(b"Rich", 0, pe_offset)
        return {"present": rich_end >= 0, "offset": rich_end} if rich_end >= 0 else {"present": False}

    @staticmethod
    def _parse_data_directories(data: bytes, pe_offset: int, is_pe32plus: bool) -> List[Dict]:
        names = ["Export", "Import", "Resource", "Exception", "Certificate", "BaseReloc", "Debug", "Architecture", "GlobalPtr", "TLS", "LoadConfig", "BoundImport", "IAT", "DelayImport", "CLR", "Reserved"]
        dd_offset = pe_offset + 24 + (112 if is_pe32plus else 96)
        dirs = []
        for i, name in enumerate(names):
            entry = dd_offset + i * 8
            if entry + 8 > len(data):
                break
            rva = struct.unpack_from("<I", data, entry)[0]
            size = struct.unpack_from("<I", data, entry + 4)[0]
            if rva > 0 or size > 0:
                dirs.append({"name": name, "rva": f"0x{rva:08x}", "size": size})
        return dirs
