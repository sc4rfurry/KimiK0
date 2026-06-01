"""Entropy Analyzer Plugin — Rolling entropy, anomaly detection, heatmap.

Computes per-section and rolling entropy to identify packed regions,
encrypted blocks, and anomalous zones. Produces visual heatmap output.
"""

import math
from typing import Any, Dict, List, Optional


class EntropyAnalyzerPlugin:
    """Analyze payload entropy for packed/encrypted region detection."""

    name = "entropy_analyzer"
    version = "2.0.0"
    description = "Rolling entropy analysis, anomaly zones, heatmap, packed section detection"
    hooks = ["on_payload_loaded", "on_pe_parsed"]

    def __init__(self) -> None:
        self._results: Dict[str, Any] = {}
        self._rolling_values: List[float] = []
        self._window_size = 256

    def initialize(self, config: Dict[str, Any]) -> None:
        self._window_size = config.get("window_size", 256)

    def on_payload_loaded(self, data: bytes, ctx: Dict[str, Any]) -> None:
        overall = self._shannon_entropy(data)
        self._rolling_values = self._rolling_entropy(data, self._window_size)
        anomaly_zones = self._detect_anomalies(self._rolling_values, self._window_size)

        if overall > 7.5:
            classification = "encrypted_or_compressed"
        elif overall > 6.5:
            classification = "obfuscated"
        elif overall > 4.0:
            classification = "mixed"
        else:
            classification = "plaintext"

        freq = [0] * 256
        for b in data:
            freq[b] += 1
        null_pct = (freq[0] / len(data)) * 100 if data else 0
        printable = sum(freq[i] for i in range(32, 127))
        printable_pct = (printable / len(data)) * 100 if data else 0

        self._results["payload"] = {
            "overall_entropy": round(overall, 4),
            "classification": classification,
            "size": len(data),
            "null_byte_pct": round(null_pct, 2),
            "printable_pct": round(printable_pct, 2),
            "anomaly_zones": anomaly_zones[:10],
            "rolling_summary": {
                "min": round(min(self._rolling_values) if self._rolling_values else 0, 4),
                "max": round(max(self._rolling_values) if self._rolling_values else 0, 4),
                "mean": round(sum(self._rolling_values) / len(self._rolling_values) if self._rolling_values else 0, 4),
                "samples": len(self._rolling_values),
            },
        }
        ctx["entropy_analysis"] = self._results["payload"]

    def on_pe_parsed(self, pe_info: Any, dll_data: bytes, ctx: Dict[str, Any]) -> None:
        if not pe_info or not hasattr(pe_info, "sections"):
            return
        section_entropy = []
        for sec in pe_info.sections:
            name = sec.get("name", "?")
            offset = sec.get("rawDataPointer", 0)
            size = sec.get("rawDataSize", 0)
            if size > 0 and offset + size <= len(dll_data):
                ent = self._shannon_entropy(dll_data[offset:offset + size])
                section_entropy.append({
                    "name": name, "entropy": round(ent, 4),
                    "size": size, "is_packed": ent > 7.0,
                })
        self._results["sections"] = section_entropy
        ctx["section_entropy"] = section_entropy

    def on_config_extracted(self, config: Dict, ctx: Dict) -> Optional[Dict]:
        return None

    def on_manifest_ready(self, manifest: Dict, ctx: Dict) -> Optional[Dict]:
        if self._results:
            manifest.setdefault("metadata", {})["entropyAnalysis"] = self._results
            return manifest
        return None

    def render_results(self) -> Optional[Any]:
        """Render entropy analysis with clean inline formatting."""
        if not self._results:
            return None
        try:
            from rich.console import Group
            from rich.text import Text
            from cs_aggregator.utils.rich_output import (
                render_entropy_heatmap, entropy_color, sparkline,
                _section_header, MUTED, DIM, ACCENT_SECONDARY
            )

            payload = self._results.get("payload", {})
            overall = payload.get("overall_entropy", 0)
            classification = payload.get("classification", "?")

            parts = []

            # Header
            h = Text()
            h.append("    ◈ ", style=ACCENT_SECONDARY)
            h.append("ENTROPY ANALYSIS", style=f"bold {ACCENT_SECONDARY}")
            parts.append(h)
            parts.append(Text(f"    {'─' * 68}", style=DIM))

            # Overall
            color = entropy_color(overall)
            t = Text()
            t.append("    Entropy         ", style=DIM)
            t.append(f"{overall:.4f}", style=f"bold {color}")
            t.append(f"  {sparkline([overall])}", style=color)

            class_colors = {
                "plaintext": "bright_green", "mixed": "yellow",
                "obfuscated": "bright_red", "encrypted_or_compressed": "bold red",
            }
            t.append(f"  {classification.upper()}", style=f"bold {class_colors.get(classification, 'white')}")
            parts.append(t)

            # Stats
            s = Text()
            s.append("    Null Bytes      ", style=DIM)
            s.append(f"{payload.get('null_byte_pct', 0):.1f}%", style="bright_white")
            s.append("    Printable  ", style=DIM)
            s.append(f"{payload.get('printable_pct', 0):.1f}%", style="bright_white")
            parts.append(s)

            rs = payload.get("rolling_summary", {})
            r = Text()
            r.append("    Rolling Window  ", style=DIM)
            r.append(f"min={rs.get('min', 0):.2f}  mean={rs.get('mean', 0):.2f}  max={rs.get('max', 0):.2f}", style=MUTED)
            r.append(f"  ({rs.get('samples', 0)} windows)", style=DIM)
            parts.append(r)

            # Anomalies
            anomalies = payload.get("anomaly_zones", [])
            if anomalies:
                a = Text()
                a.append(f"\n    Anomaly Zones ({len(anomalies)})", style="bold bright_yellow")
                parts.append(a)
                for az in anomalies[:5]:
                    z = Text()
                    z.append(f"      0x{az['offset_approx']:06x}", style=DIM)
                    z.append(f"  Δ={az['entropy_delta']:.2f}", style="bright_yellow")
                    z.append(f"  ({az['from_entropy']:.1f} → {az['to_entropy']:.1f})", style=DIM)
                    parts.append(z)

            # Heatmap
            parts.append(Text())
            parts.append(render_entropy_heatmap(self._rolling_values, self._window_size))

            return Group(*parts)
        except Exception:
            return None

    def get_results(self) -> Optional[Dict[str, Any]]:
        return self._results if self._results else None

    def cleanup(self) -> None:
        self._results.clear()
        self._rolling_values.clear()

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        length = len(data)
        return -sum((c / length) * math.log2(c / length) for c in freq if c > 0)

    @staticmethod
    def _rolling_entropy(data: bytes, window: int) -> List[float]:
        if len(data) < window:
            return []
        results = []
        step = max(1, window // 4)
        for i in range(0, len(data) - window, step):
            chunk = data[i:i + window]
            freq = [0] * 256
            for b in chunk:
                freq[b] += 1
            length = len(chunk)
            results.append(-sum((c / length) * math.log2(c / length) for c in freq if c > 0))
        return results

    @staticmethod
    def _detect_anomalies(rolling: List[float], window: int) -> List[Dict]:
        if len(rolling) < 3:
            return []
        anomalies = []
        for i in range(1, len(rolling)):
            delta = abs(rolling[i] - rolling[i - 1])
            if delta > 1.5:
                anomalies.append({
                    "offset_approx": i * (window // 4),
                    "entropy_delta": round(delta, 4),
                    "from_entropy": round(rolling[i - 1], 4),
                    "to_entropy": round(rolling[i], 4),
                })
        anomalies.sort(key=lambda x: x["entropy_delta"], reverse=True)
        return anomalies
