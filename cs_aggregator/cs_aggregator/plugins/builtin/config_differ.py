"""Config Differ Plugin — Operator modification analysis against CS defaults.

Automatically compares the extracted beacon config against known CobaltStrike
default values to highlight operator customizations. Also supports diffing
against a user-supplied baseline config for change tracking.
"""

from typing import Any, Dict, List, Optional, Tuple


# ─── CS 4.x Default Config Values ────────────────────────────────────────────
# Source: CS teamserver defaults + dissect.cobaltstrike defaults
CS_DEFAULTS: Dict[str, Any] = {
    "SETTING_PROTOCOL": 0,          # HTTP
    "SETTING_PORT": 80,
    "SETTING_SLEEPTIME": 60000,
    "SETTING_MAXGET": 1048576,
    "SETTING_JITTER": 0,
    "SETTING_MAXDNS": 255,
    "SETTING_USERAGENT": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; FunWebProducts)",
    "SETTING_SUBMITURI": "/submit.php?id=",
    "SETTING_SPAWNTO": "%windir%\\syswow64\\rundll32.exe",
    "SETTING_SPAWNTO_X86": "%windir%\\syswow64\\rundll32.exe",
    "SETTING_SPAWNTO_X64": "%windir%\\sysnative\\rundll32.exe",
    "SETTING_CRYPTO_SCHEME": 0,     # none
    "SETTING_PROXY_BEHAVIOR": 0,    # direct
    "SETTING_KILLDATE": 0,
    "SETTING_CLEANUP": 0,
    "SETTING_CFG_CAUTION": 0,
    "SETTING_EXIT_FUNK": 0,         # none
    "SETTING_SYSCALL_METHOD": 0,    # none
    "SETTING_GARGLE_NOOK": 0,       # sleep mask off
    "SETTING_PROCINJ_ALLOCATOR": 0, # VirtualAllocEx
    "SETTING_PROCINJ_MINALLOC": 0,
    "SETTING_PROCINJ_BOF_REUSE_MEM": 0,
    "SETTING_HTTP_NO_COOKIES": 0,
    "SETTING_BOF_ALLOCATOR": 0,
    "SETTING_BEACON_GATE": 0,
    "SETTING_RDLL_USE_DRIPLOADING": 0,
    "SETTING_RDLL_DRIPLOAD_DELAY": 0,
}

# Settings that are security-critical and worth highlighting when modified
SECURITY_CRITICAL = {
    "SETTING_SYSCALL_METHOD", "SETTING_PROCINJ_ALLOCATOR",
    "SETTING_GARGLE_NOOK", "SETTING_CLEANUP", "SETTING_EXIT_FUNK",
    "SETTING_BEACON_GATE", "SETTING_RDLL_USE_DRIPLOADING",
    "SETTING_CRYPTO_SCHEME", "SETTING_SPAWNTO_X64", "SETTING_SPAWNTO_X86",
}

# Settings that reveal operational patterns
OPSEC_INDICATORS = {
    "SETTING_PROTOCOL", "SETTING_PORT", "SETTING_SLEEPTIME",
    "SETTING_JITTER", "SETTING_USERAGENT", "SETTING_DOMAINS",
    "SETTING_SUBMITURI", "SETTING_HOST_HEADER", "SETTING_KILLDATE",
    "SETTING_WATERMARK",
}

# Decoders for human-readable labels
SETTING_DECODERS = {
    "SETTING_PROTOCOL": {0: "HTTP", 1: "DNS", 2: "SMB", 4: "TCP", 8: "HTTPS"},
    "SETTING_SYSCALL_METHOD": {0: "none", 1: "direct", 2: "indirect"},
    "SETTING_EXIT_FUNK": {0: "none", 1: "ExitThread", 2: "ExitProcess"},
    "SETTING_PROCINJ_ALLOCATOR": {0: "VirtualAllocEx", 1: "NtMapViewOfSection"},
    "SETTING_CRYPTO_SCHEME": {0: "none", 1: "AES256"},
}


def _decode(key: str, val: Any) -> str:
    """Decode a setting value to human-readable, or return raw."""
    if key in SETTING_DECODERS and isinstance(val, (int, float)):
        decoded = SETTING_DECODERS[key].get(int(val))
        if decoded:
            return f"{val} ({decoded})"
    return str(val)


class ConfigDifferPlugin:
    """Diff beacon config against CS defaults + optional baseline.

    Always produces output by diffing against hardcoded CS defaults.
    Highlights security-critical and OPSEC-relevant operator customizations.
    """

    name = "config_differ"
    version = "3.0.0"
    description = "Operator modification analysis: auto-diff vs CS defaults, security-critical highlights, OPSEC scoring"
    hooks = ["on_config_extracted"]

    def __init__(self) -> None:
        self._baseline: Optional[Dict[str, Any]] = None
        self._diff_results: Optional[Dict[str, Any]] = None

    def initialize(self, config: Dict[str, Any]) -> None:
        self._baseline = config.get("baseline")
        baseline_file = config.get("baseline_file")
        if baseline_file and not self._baseline:
            try:
                import json
                with open(baseline_file, "r") as f:
                    self._baseline = json.load(f)
            except Exception:
                pass

    def on_payload_loaded(self, data: bytes, ctx: Dict[str, Any]) -> None:
        pass

    def on_version_detected(self, version_result: Any, ctx: Dict[str, Any]) -> None:
        pass

    def on_loader_extracted(self, loader_result: Any, ctx: Dict[str, Any]) -> None:
        pass

    def on_pe_parsed(self, pe_info: Any, dll_data: bytes, ctx: Dict[str, Any]) -> None:
        pass

    def on_config_extracted(self, config: Dict[str, Any], ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Diff config against CS defaults and optional baseline."""
        # Always diff vs CS defaults
        default_diff = self._compute_diff(CS_DEFAULTS, config, "defaults")

        # Optionally diff vs user baseline
        baseline_diff = None
        if self._baseline:
            baseline_diff = self._compute_diff(self._baseline, config, "baseline")

        # Classify modifications
        security_mods = {}
        opsec_mods = {}
        for key, info in default_diff.get("changed", {}).items():
            if key in SECURITY_CRITICAL:
                security_mods[key] = info
            if key in OPSEC_INDICATORS:
                opsec_mods[key] = info

        # Add settings that exist in config but not in defaults (operator additions)
        for key, val in default_diff.get("added", {}).items():
            if key in SECURITY_CRITICAL:
                security_mods[key] = {"from": "default", "to": val}
            if key in OPSEC_INDICATORS:
                opsec_mods[key] = {"from": "default", "to": val}

        # OPSEC score: how hardened is this config?
        opsec_score = self._compute_opsec_score(config)

        self._diff_results = {
            "vs_defaults": default_diff,
            "vs_baseline": baseline_diff,
            "security_critical": security_mods,
            "opsec_indicators": opsec_mods,
            "opsec_score": opsec_score,
            "total_default_changes": default_diff["total_changes"],
        }

        ctx["config_diff"] = self._diff_results
        return None

    def on_manifest_ready(self, manifest: Dict, ctx: Dict) -> Optional[Dict]:
        if self._diff_results:
            manifest.setdefault("metadata", {})["configDiff"] = self._diff_results
            return manifest
        return None

    def render_results(self) -> Optional[Any]:
        if not self._diff_results:
            return None
        try:
            from rich.text import Text
            from rich.console import Group
            from cs_aggregator.utils.rich_output import (
                DIM, MUTED, GRADIENT, _GEM, _ARROW, _BULLET,
                _section_header, confidence_bar,
            )

            d = self._diff_results
            vs = d["vs_defaults"]
            parts: list = []

            # Header
            _section_header(
                _GEM, "CONFIG ANALYSIS",
                f"{vs['total_changes']} operator modifications",
                style=GRADIENT[3],
            )

            # OPSEC Score
            score = d.get("opsec_score", {})
            score_val = score.get("score", 0)
            s = Text("    ")
            s.append("OPSEC Score  ", style=DIM)
            s.append_text(confidence_bar(score_val, width=20))
            label_style = "#5eead4" if score_val >= 0.7 else "#fbbf24" if score_val >= 0.4 else "#f87171"
            s.append(f"  {score.get('label', '')}", style=f"bold {label_style}")
            parts.append(s)

            # Security-critical modifications
            sec_mods = d.get("security_critical", {})
            if sec_mods:
                parts.append(Text())
                h = Text("    ")
                h.append("✦ ", style="bold #ff6ec7")
                h.append("SECURITY-CRITICAL MODIFICATIONS", style="bold #ff6ec7")
                parts.append(h)

                for key, info in sec_mods.items():
                    short = key.replace("SETTING_", "").lower()
                    t = Text("      ")
                    t.append(f"{'●':>2s} ", style="#ff6ec7")
                    t.append(f"{short:<30s}", style="bright_white")
                    if isinstance(info, dict):
                        from_val = _decode(key, info.get("from", "?"))
                        to_val = _decode(key, info.get("to", "?"))
                        t.append(from_val, style="#f87171")
                        t.append(f" {_ARROW} ", style=DIM)
                        t.append(to_val, style="#5eead4")
                    else:
                        t.append(str(info), style="bright_white")
                    parts.append(t)

            # OPSEC Indicators
            ops = d.get("opsec_indicators", {})
            if ops:
                parts.append(Text())
                h = Text("    ")
                h.append("⟐ ", style=f"bold {GRADIENT[4]}")
                h.append("OPSEC INDICATORS", style=f"bold {GRADIENT[4]}")
                parts.append(h)

                for key, info in ops.items():
                    short = key.replace("SETTING_", "").lower()
                    t = Text("      ")
                    t.append(f"{_BULLET} ", style=GRADIENT[4])
                    t.append(f"{short:<30s}", style=MUTED)
                    if isinstance(info, dict):
                        to_val = _decode(key, info.get("to", "?"))
                        t.append(to_val, style="bright_white")
                    else:
                        t.append(str(info), style="bright_white")
                    parts.append(t)

            # Full diff summary (collapsed)
            parts.append(Text())
            added_count = len(vs.get("added", {}))
            changed_count = len(vs.get("changed", {}))
            unchanged_count = vs.get("unchanged_count", 0)

            summary = Text("    ")
            summary.append(f"+{added_count} ", style="bold #5eead4")
            summary.append("new  ", style=DIM)
            summary.append(f"~{changed_count} ", style="bold #fbbf24")
            summary.append("modified  ", style=DIM)
            summary.append(f"={unchanged_count} ", style=DIM)
            summary.append("unchanged", style=DIM)
            parts.append(summary)

            # OPSEC scoring breakdown
            reasons = score.get("reasons", [])
            if reasons:
                parts.append(Text())
                for reason in reasons[:8]:
                    r = Text("      ")
                    symbol = "+" if reason.startswith("+") else "-" if reason.startswith("-") else " "
                    style = "#5eead4" if symbol == "+" else "#f87171" if symbol == "-" else DIM
                    r.append(reason, style=style)
                    parts.append(r)

            # Baseline diff (if provided)
            if d.get("vs_baseline"):
                bl = d["vs_baseline"]
                if bl["total_changes"] > 0:
                    parts.append(Text())
                    bh = Text("    ")
                    bh.append("◈ ", style=f"bold {GRADIENT[1]}")
                    bh.append(f"BASELINE DIFF  ", style=f"bold {GRADIENT[1]}")
                    bh.append(f"{bl['total_changes']} changes", style=MUTED)
                    parts.append(bh)

                    for key, info in bl.get("changed", {}).items():
                        short = key.replace("SETTING_", "").lower()
                        t = Text("      ")
                        t.append(f"~ ", style="#fbbf24")
                        t.append(f"{short:<30s}", style=MUTED)
                        t.append(str(info.get("from", "?")), style="#f87171")
                        t.append(f" {_ARROW} ", style=DIM)
                        t.append(str(info.get("to", "?")), style="#5eead4")
                        parts.append(t)

            return Group(*parts)
        except Exception:
            return None

    def get_results(self) -> Optional[Dict[str, Any]]:
        return self._diff_results

    def cleanup(self) -> None:
        self._diff_results = None

    @staticmethod
    def _compute_diff(
        reference: Dict[str, Any], current: Dict[str, Any], label: str
    ) -> Dict[str, Any]:
        """Compute a structured diff between reference and current config."""
        added, removed, changed, unchanged = {}, {}, {}, {}
        all_keys = sorted(set(current.keys()) | set(reference.keys()))

        for key in all_keys:
            in_cur = key in current
            in_ref = key in reference
            if in_cur and not in_ref:
                added[key] = current[key]
            elif in_ref and not in_cur:
                removed[key] = reference[key]
            elif in_cur and in_ref:
                if str(current[key]) != str(reference[key]):
                    changed[key] = {"from": reference[key], "to": current[key]}
                else:
                    unchanged[key] = current[key]

        return {
            "label": label,
            "added": added,
            "removed": removed,
            "changed": changed,
            "unchanged_count": len(unchanged),
            "total_changes": len(added) + len(removed) + len(changed),
        }

    @staticmethod
    def _compute_opsec_score(config: Dict[str, Any]) -> Dict[str, Any]:
        """Compute an OPSEC hardening score (0.0-1.0) based on config settings.

        Evaluates syscall usage, injection technique, sleep masking,
        spawn-to customization, protocol choice, jitter, etc.
        """
        score = 0.0
        max_score = 0.0
        reasons: List[str] = []

        # Syscall method (0=none, 1=direct, 2=indirect)
        max_score += 2.0
        syscall = int(config.get("SETTING_SYSCALL_METHOD", 0))
        if syscall == 2:
            score += 2.0
            reasons.append("+ Indirect syscalls enabled")
        elif syscall == 1:
            score += 1.0
            reasons.append("+ Direct syscalls (partial evasion)")
        else:
            reasons.append("- No syscall evasion")

        # Injection allocator
        max_score += 1.5
        alloc = int(config.get("SETTING_PROCINJ_ALLOCATOR", 0))
        if alloc == 1:
            score += 1.5
            reasons.append("+ NtMapViewOfSection injection")
        else:
            reasons.append("- VirtualAllocEx injection (basic)")

        # Sleep mask
        max_score += 1.5
        gargle = int(config.get("SETTING_GARGLE_NOOK", 0))
        if gargle:
            score += 1.5
            reasons.append("+ Sleep mask enabled")
        else:
            reasons.append("- Sleep mask disabled")

        # Jitter > 0
        max_score += 1.0
        jitter = int(config.get("SETTING_JITTER", 0))
        if jitter >= 20:
            score += 1.0
            reasons.append(f"+ Jitter {jitter}% (good)")
        elif jitter > 0:
            score += 0.5
            reasons.append(f"+ Jitter {jitter}% (low)")
        else:
            reasons.append("- No jitter (deterministic callbacks)")

        # Protocol HTTPS
        max_score += 1.0
        proto = int(config.get("SETTING_PROTOCOL", 0))
        if proto == 8:
            score += 1.0
            reasons.append("+ HTTPS protocol")
        elif proto == 1:
            score += 0.5
            reasons.append("+ DNS protocol (covert)")
        else:
            reasons.append("- HTTP protocol (unencrypted)")

        # Spawn-to customized
        max_score += 1.0
        spawn64 = str(config.get("SETTING_SPAWNTO_X64", ""))
        if "rundll32" not in spawn64.lower() and spawn64:
            score += 1.0
            reasons.append(f"+ Custom spawn-to x64")
        else:
            reasons.append("- Default spawn-to (rundll32)")

        # Kill date set
        max_score += 0.5
        killdate = int(config.get("SETTING_KILLDATE", 0))
        if killdate > 0:
            score += 0.5
            reasons.append("+ Kill date configured")

        # BeaconGate
        max_score += 1.0
        bg = int(config.get("SETTING_BEACON_GATE", 0))
        if bg:
            score += 1.0
            reasons.append("+ BeaconGate enabled")

        # Drip loading
        max_score += 0.5
        drip = int(config.get("SETTING_RDLL_USE_DRIPLOADING", 0))
        if drip:
            score += 0.5
            reasons.append("+ Drip-loading enabled")

        final = score / max_score if max_score > 0 else 0.0
        if final >= 0.8:
            label = "HARDENED"
        elif final >= 0.6:
            label = "MODERATE"
        elif final >= 0.4:
            label = "BASIC"
        else:
            label = "WEAK"

        return {
            "score": round(final, 2),
            "raw_score": round(score, 1),
            "max_score": round(max_score, 1),
            "label": label,
            "reasons": reasons,
        }
