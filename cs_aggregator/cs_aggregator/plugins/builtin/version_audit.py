"""Version Feature Audit Plugin — CS version capability mapping & OPSEC advisor.

Cross-references the detected CobaltStrike version against a comprehensive
feature database, identifies which capabilities are actively used in the
payload config, and provides actionable OPSEC hardening recommendations.
"""

from typing import Any, Dict, List, Optional, Tuple

# ─── Per-Version Feature Database ─────────────────────────────────────────────
# Each feature: (introduced_version, config_key_or_None, category, description)

VERSION_FEATURES: Dict[str, Dict[str, Any]] = {
    # ── CS 4.5 ────────────────────────────────────────────────────────────
    "process_inject_hooks": {
        "introduced": "4.5", "category": "injection",
        "config_key": None,
        "name": "Process Injection Hooks",
        "description": "PROCESS_INJECT_SPAWN/EXPLICIT Aggressor hooks for custom BOF injection",
    },
    "sleep_mask_heap": {
        "introduced": "4.5", "category": "evasion",
        "config_key": "SETTING_GARGLE_NOOK",
        "name": "Sleep Mask (Heap Masking)",
        "description": "Mask/unmask Beacon heap memory during sleep to evade scanners",
    },
    "max_retry_strategy": {
        "introduced": "4.5", "category": "resilience",
        "config_key": "SETTING_MAX_RETRY_STRATEGY_ATTEMPTS",
        "name": "Max Retry Strategy",
        "description": "Exit or increase sleep after N connection failures",
    },
    # ── CS 4.6 ────────────────────────────────────────────────────────────
    "arsenal_kit": {
        "introduced": "4.6", "category": "customization",
        "config_key": None,
        "name": "Arsenal Kit (Consolidated)",
        "description": "Unified kit for Sleep Mask, Process Inject, UDRL customization",
    },
    # ── CS 4.7 ────────────────────────────────────────────────────────────
    "sleep_mask_bof": {
        "introduced": "4.7", "category": "evasion",
        "config_key": "SETTING_GARGLE_NOOK",
        "name": "Sleep Mask BOF (8KB)",
        "description": "Sleep mask as true BOF with 8KB limit, custom sleep functions",
    },
    "socks5_proxy": {
        "introduced": "4.7", "category": "pivoting",
        "config_key": None,
        "name": "SOCKS5 Proxy",
        "description": "SOCKS5 with DNS resolution and UDP support",
    },
    "bof_memory_options": {
        "introduced": "4.7", "category": "evasion",
        "config_key": "SETTING_BOF_ALLOCATOR",
        "name": "BOF Memory Options",
        "description": "Configurable BOF memory allocation (VirtualAlloc/HeapAlloc/MapViewOfFile)",
    },
    # ── CS 4.8 ────────────────────────────────────────────────────────────
    "syscall_direct": {
        "introduced": "4.8", "category": "evasion",
        "config_key": "SETTING_SYSCALL_METHOD",
        "name": "Direct Syscalls",
        "description": "Bypass API hooking via direct Nt* function execution",
        "detect_value": 1,
    },
    "syscall_indirect": {
        "introduced": "4.8", "category": "evasion",
        "config_key": "SETTING_SYSCALL_METHOD",
        "name": "Indirect Syscalls",
        "description": "Jump to instruction within Nt* function for stealth",
        "detect_value": 2,
    },
    "payload_guardrails": {
        "introduced": "4.8", "category": "opsec",
        "config_key": None,
        "name": "Payload Guardrails",
        "description": "Restrict execution by IP/username/hostname/domain",
    },
    "token_store": {
        "introduced": "4.8", "category": "post_exploitation",
        "config_key": None,
        "name": "Token Store",
        "description": "Per-Beacon token store for hot-swapping security tokens",
    },
    "sleep_mask_16kb": {
        "introduced": "4.8", "category": "evasion",
        "config_key": "SETTING_GARGLE_NOOK",
        "name": "Sleep Mask 16KB + Stack Spoofing",
        "description": "Increased sleep mask to 16KB with evasive sleep via stack spoofing (x64)",
    },
    # ── CS 4.9 ────────────────────────────────────────────────────────────
    "postex_udrl": {
        "introduced": "4.9", "category": "evasion",
        "config_key": None,
        "name": "Post-Exploitation UDRLs",
        "description": "Custom reflective loaders for mimikatz, screenshot, keylogger, etc.",
    },
    "beacon_data_store": {
        "introduced": "4.9", "category": "efficiency",
        "config_key": "SETTING_DATA_STORE_SIZE",
        "name": "Beacon Data Store",
        "description": "In-memory cache for BOFs/.NET assemblies, masked when idle",
    },
    "winhttp_support": {
        "introduced": "4.9", "category": "comms",
        "config_key": None,
        "name": "WinHTTP Library",
        "description": "WinHTTP as alternative to WinInet for HTTP(S) listeners",
    },
    "http_host_profiles": {
        "introduced": "4.9", "category": "comms",
        "config_key": None,
        "name": "Per-Host C2 Profiles",
        "description": "http-host-profiles for per-host Malleable C2 customization",
    },
    "postex_cleanup": {
        "introduced": "4.9", "category": "evasion",
        "config_key": "SETTING_CLEANUP",
        "name": "Post-Ex Memory Cleanup",
        "description": "Free reflective DLL memory after initialization",
    },
    "cfg_caution": {
        "introduced": "4.9", "category": "evasion",
        "config_key": "SETTING_CFG_CAUTION",
        "name": "CFG-Caution Mode",
        "description": "Control Flow Guard compatibility for stable injection",
    },
    # ── CS 4.10 ───────────────────────────────────────────────────────────
    "beacon_gate": {
        "introduced": "4.10", "category": "evasion",
        "config_key": "SETTING_BEACON_GATE",
        "name": "BeaconGate",
        "description": "Proxy Beacon API calls through sleep mask for call stack spoofing",
    },
    "sleepmask_vs": {
        "introduced": "4.10", "category": "customization",
        "config_key": None,
        "name": "Sleepmask-VS Template",
        "description": "Visual Studio template for custom sleep mask BOF development",
    },
    "postex_kit": {
        "introduced": "4.10", "category": "customization",
        "config_key": None,
        "name": "PostEx Kit (Overhauled)",
        "description": "Full control over post-exploitation DLL injection chain",
    },
    "c2_hot_swap": {
        "introduced": "4.10", "category": "resilience",
        "config_key": None,
        "name": "C2 Hot Swapping",
        "description": "Dynamic C2 host changes during active operations",
    },
    "bof_gate_apis": {
        "introduced": "4.10", "category": "evasion",
        "config_key": "SETTING_BEACON_GATE",
        "name": "BOF Gate APIs",
        "description": "BOFs can proxy API calls through BeaconGate",
    },
    "sleep_mask_32kb": {
        "introduced": "4.10", "category": "evasion",
        "config_key": "SETTING_GARGLE_NOOK",
        "name": "Sleep Mask 32KB Buffer",
        "description": "Increased sleep mask buffer to 32KB for complex gate logic",
    },
    # ── CS 4.11 ───────────────────────────────────────────────────────────
    "novel_sleepmask": {
        "introduced": "4.11", "category": "evasion",
        "config_key": "SETTING_GARGLE_NOOK",
        "name": "Novel Sleepmask (Auto)",
        "description": "Auto-enabled sleep mask that obfuscates Beacon + heap + self",
    },
    "obf_set_thread_context": {
        "introduced": "4.11", "category": "injection",
        "config_key": None,
        "name": "ObfSetThreadContext Injection",
        "description": "Default injection via legitimate remote image entry point spoofing",
    },
    "reflective_loader_v2": {
        "introduced": "4.11", "category": "evasion",
        "config_key": None,
        "name": "Reflective Loader v2 (sRDI)",
        "description": "Prepend/sRDI-style loader with EAF bypass and indirect syscalls",
    },
    "async_bof": {
        "introduced": "4.11", "category": "post_exploitation",
        "config_key": None,
        "name": "Async BOF Execution",
        "description": "Non-blocking BOF execution in separate threads",
    },
    "dns_over_https": {
        "introduced": "4.11", "category": "comms",
        "config_key": None,
        "name": "DNS over HTTPS (DoH)",
        "description": "Stealthy DNS-based C2 via encrypted HTTPS resolution",
    },
    "transform_obfuscate": {
        "introduced": "4.11", "category": "evasion",
        "config_key": None,
        "name": "Transform-Obfuscate",
        "description": "LZNT1 compression, RC4, XOR, Base64 payload obfuscation chain",
    },
    "drip_loading": {
        "introduced": "4.12", "category": "evasion",
        "config_key": "SETTING_RDLL_USE_DRIPLOADING",
        "name": "RDLL Drip Loading",
        "description": "Incremental memory writes with delays to defeat EDR event correlation",
    },
    # ── CS 4.12 ───────────────────────────────────────────────────────────
    "drip_load_delay": {
        "introduced": "4.12", "category": "evasion",
        "config_key": "SETTING_RDLL_DRIPLOAD_DELAY",
        "name": "Drip Load Delay",
        "description": "Configurable delay between drip-load memory write chunks",
    },
    "udc2": {
        "introduced": "4.12", "category": "comms",
        "config_key": None,
        "name": "User-Defined C2 (UDC2)",
        "description": "Custom C2 channels as BOFs — replaces legacy External C2 named pipe relay",
    },
    "rtl_clone_user_process": {
        "introduced": "4.12", "category": "injection",
        "config_key": None,
        "name": "RtlCloneUserProcess Injection",
        "description": "Process injection via undocumented NT cloning for stealthy execution",
    },
    "pivot_beacon_sleepmask": {
        "introduced": "4.12", "category": "evasion",
        "config_key": None,
        "name": "Pivot Beacon Sleep Mask",
        "description": "Sleep mask support extended to SMB/TCP pivot beacons",
    },
    "allocated_memory_v3": {
        "introduced": "4.12", "category": "evasion",
        "config_key": None,
        "name": "ALLOCATED_MEMORY v3",
        "description": "BREAKING: Updated struct for drip-loading, METHOD_MODULESTOMP for CFG compat",
    },
    "tp_injection_techniques": {
        "introduced": "4.12", "category": "injection",
        "config_key": None,
        "name": "Thread Pool Injection",
        "description": "TpDirect, TpStartRoutineStub, EarlyCascade injection techniques",
    },
    "java17_teamserver": {
        "introduced": "4.12", "category": "infrastructure",
        "config_key": None,
        "name": "Java 17+ TeamServer",
        "description": "TeamServer upgraded to Java 17 with updated dependencies",
    },
}

# ─── OPSEC Recommendations Database ──────────────────────────────────────────
OPSEC_RULES: List[Dict[str, Any]] = [
    {
        "id": "OPSEC-001", "severity": "critical", "category": "evasion",
        "check": lambda cfg: int(cfg.get("SETTING_SYSCALL_METHOD", 0)) == 0,
        "title": "No Syscall Evasion",
        "detail": "Syscalls disabled — all API calls go through ntdll hooks. EDR will intercept.",
        "fix": "Set stage.syscall_method to 'indirect' in Malleable C2 profile.",
        "min_version": "4.8",
    },
    {
        "id": "OPSEC-002", "severity": "critical", "category": "evasion",
        "check": lambda cfg: not bool(cfg.get("SETTING_GARGLE_NOOK", 0)),
        "title": "Sleep Mask Disabled",
        "detail": "Beacon memory is NOT obfuscated during sleep — trivial for memory scanners.",
        "fix": "Enable sleep mask: set stage.sleep_mask = 'true' in profile.",
        "min_version": "4.5",
    },
    {
        "id": "OPSEC-003", "severity": "high", "category": "injection",
        "check": lambda cfg: cfg.get("SETTING_SPAWNTO_X64", "").endswith("rundll32.exe"),
        "title": "Default Spawn-To Process",
        "detail": "rundll32.exe is the default — heavily monitored by EDR for injection.",
        "fix": "Change to a legitimate, less-monitored process (e.g., dllhost.exe, gpupdate.exe).",
        "min_version": "4.0",
    },
    {
        "id": "OPSEC-004", "severity": "high", "category": "opsec",
        "check": lambda cfg: int(cfg.get("SETTING_JITTER", 0)) < 10,
        "title": "Low Jitter Value",
        "detail": f"Predictable callback timing makes Beacon easy to detect via statistical analysis.",
        "fix": "Set host.jitter >= 30 in your Malleable C2 profile.",
        "min_version": "4.0",
    },
    {
        "id": "OPSEC-005", "severity": "medium", "category": "evasion",
        "check": lambda cfg: not bool(cfg.get("SETTING_CLEANUP", 0)),
        "title": "No Post-Ex Cleanup",
        "detail": "Reflective DLL memory is NOT freed after init — leaves artifacts for forensics.",
        "fix": "Set post-ex.cleanup = 'true' in Malleable C2 profile.",
        "min_version": "4.9",
    },
    {
        "id": "OPSEC-006", "severity": "medium", "category": "evasion",
        "check": lambda cfg: not bool(cfg.get("SETTING_CFG_CAUTION", 0)),
        "title": "CFG-Caution Disabled",
        "detail": "Control Flow Guard not respected — injection may crash hardened targets.",
        "fix": "Set stage.cfg_caution = 'true' for stable injection on modern Windows.",
        "min_version": "4.9",
    },
    {
        "id": "OPSEC-007", "severity": "high", "category": "comms",
        "check": lambda cfg: int(cfg.get("SETTING_PROTOCOL", 0)) == 0,
        "title": "HTTP Protocol (Unencrypted)",
        "detail": "C2 traffic is plaintext HTTP — trivial to inspect and detect.",
        "fix": "Use HTTPS (protocol=8) or DNS beacons for encrypted comms.",
        "min_version": "4.0",
    },
    {
        "id": "OPSEC-008", "severity": "low", "category": "opsec",
        "check": lambda cfg: int(cfg.get("SETTING_KILLDATE", 0)) == 0,
        "title": "No Kill Date Set",
        "detail": "Beacon has no expiration — risks long-term unauthorized access.",
        "fix": "Set a kill date to auto-terminate Beacon after engagement window.",
        "min_version": "4.0",
    },
    {
        "id": "OPSEC-009", "severity": "info", "category": "efficiency",
        "check": lambda cfg: int(cfg.get("SETTING_DATA_STORE_SIZE", 0)) == 0,
        "title": "Beacon Data Store Not Configured",
        "detail": "BOFs/.NET assemblies resent every execution — extra network traffic.",
        "fix": "Set data_store_size > 0 to cache in Beacon memory.",
        "min_version": "4.9",
    },
    {
        "id": "OPSEC-010", "severity": "high", "category": "evasion",
        "check": lambda cfg: int(cfg.get("SETTING_PROCINJ_ALLOCATOR", 0)) == 0,
        "title": "Default Injection Allocator (VirtualAllocEx)",
        "detail": "VirtualAllocEx is heavily hooked by EDR for remote allocation detection.",
        "fix": "Use NtMapViewOfSection (allocator=1) for stealthier injection.",
        "min_version": "4.5",
    },
    {
        "id": "OPSEC-011", "severity": "info", "category": "evasion",
        "check": lambda cfg: int(cfg.get("SETTING_EXIT_FUNK", 0)) == 0,
        "title": "No Exit Function",
        "detail": "Beacon has no clean exit — may leave orphaned threads.",
        "fix": "Set stage.exit_func to 'ExitThread' for clean per-thread exit.",
        "min_version": "4.0",
    },
    {
        "id": "OPSEC-012", "severity": "medium", "category": "evasion",
        "check": lambda cfg: (
            int(cfg.get("SETTING_BEACON_GATE", 0)) == 0
            and int(cfg.get("SETTING_GARGLE_NOOK", 0)) != 0
        ),
        "title": "Sleep Mask Without BeaconGate",
        "detail": "Sleep mask enabled but BeaconGate is off — API calls not proxied through mask.",
        "fix": "Enable BeaconGate for full call-stack spoofing during sleep.",
        "min_version": "4.10",
    },
    {
        "id": "OPSEC-013", "severity": "info", "category": "evasion",
        "check": lambda cfg: (
            int(cfg.get("SETTING_RDLL_USE_DRIPLOADING", 0)) != 0
            and int(cfg.get("SETTING_RDLL_DRIPLOAD_DELAY", 0)) == 0
        ),
        "title": "Drip Loading Without Delay",
        "detail": "Drip loading enabled but delay is 0ms — EDR may correlate rapid consecutive writes.",
        "fix": "Set rdll_dripload_delay to 50-200ms for temporal separation.",
        "min_version": "4.12",
    },
]

# ─── Category Metadata ───────────────────────────────────────────────────────
CATEGORY_META = {
    "evasion": ("#ff6ec7", "◈", "Evasion & Stealth"),
    "injection": ("#f87171", "⊕", "Process Injection"),
    "comms": ("#7b8cff", "◇", "Communications"),
    "post_exploitation": ("#a77de5", "✦", "Post-Exploitation"),
    "resilience": ("#5eead4", "◆", "Resilience & Recovery"),
    "efficiency": ("#fbbf24", "⟐", "Efficiency"),
    "opsec": ("#5eead4", "◈", "Operational Security"),
    "customization": ("#d35fd6", "⊕", "Customization Kits"),
    "pivoting": ("#7b8cff", "◇", "Pivoting & Tunneling"),
    "infrastructure": ("#94a3b8", "⚙", "Infrastructure"),
}


def _version_tuple(v: str) -> Tuple[int, ...]:
    """Parse '4.9.1' -> (4, 9, 1). Handles '4.9+', '4.10.x', etc."""
    import re
    parts = []
    for p in v.split("."):
        # Strip non-numeric suffixes: '9+' -> '9', 'x' -> '0'
        cleaned = re.sub(r"[^0-9]", "", p)
        try:
            parts.append(int(cleaned) if cleaned else 0)
        except ValueError:
            parts.append(0)
    return tuple(parts)


class VersionFeatureAuditPlugin:
    """CS version capability mapping, usage audit, and OPSEC advisor."""

    name = "version_audit"
    version = "1.0.0"
    description = "Version feature audit, usage analysis, and OPSEC hardening advisor"
    hooks = ["on_config_extracted"]

    def __init__(self) -> None:
        self._results: Dict[str, Any] = {}
        self._config: Dict[str, Any] = {}
        self._detected_version: str = ""

    def initialize(self, config: Dict[str, Any]) -> None:
        pass

    def on_config_extracted(self, config: Dict[str, Any], ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._config = config

        # Get detected version from pipeline context
        ver_result = ctx.get("version_detection", {})
        self._detected_version = ver_result.get("version", "") if isinstance(ver_result, dict) else ""
        if not self._detected_version:
            # Fallback: try to infer from config setting IDs
            self._detected_version = self._infer_version(config)

        self._run_audit()
        ctx["version_audit"] = self._results
        return self._results

    def _infer_version(self, config: Dict[str, Any]) -> str:
        """Infer CS version from config setting presence."""
        has_beacon_gate = "SETTING_BEACON_GATE" in config
        has_data_store = "SETTING_DATA_STORE_SIZE" in config
        has_syscall = "SETTING_SYSCALL_METHOD" in config
        has_bof_alloc = "SETTING_BOF_ALLOCATOR" in config
        has_drip = "SETTING_RDLL_USE_DRIPLOADING" in config

        if has_drip:
            return "4.11"
        if has_beacon_gate:
            return "4.10"
        if has_data_store:
            return "4.9"
        if has_syscall:
            return "4.8"
        if has_bof_alloc:
            return "4.7"
        return "4.5"

    def _run_audit(self) -> None:
        ver = self._detected_version or "4.9"
        ver_t = _version_tuple(ver)

        # 1. Categorize all features by availability
        available: List[Dict[str, Any]] = []
        unavailable: List[Dict[str, Any]] = []
        active: List[Dict[str, Any]] = []
        inactive: List[Dict[str, Any]] = []

        for fid, feat in VERSION_FEATURES.items():
            feat_ver = _version_tuple(feat["introduced"])
            is_available = ver_t >= feat_ver

            entry = {
                "id": fid,
                "name": feat["name"],
                "category": feat["category"],
                "introduced": feat["introduced"],
                "description": feat["description"],
                "available": is_available,
                "active": False,
                "config_key": feat.get("config_key"),
            }

            if is_available:
                available.append(entry)
                # Check if actively used
                cfg_key = feat.get("config_key")
                if cfg_key and cfg_key in self._config:
                    val = self._config[cfg_key]
                    detect_val = feat.get("detect_value")
                    if detect_val is not None:
                        entry["active"] = int(val) == detect_val
                    else:
                        entry["active"] = bool(int(val)) if val is not None else False
                    entry["config_value"] = val
                    if entry["active"]:
                        active.append(entry)
                    else:
                        inactive.append(entry)
                else:
                    # No config key = infrastructure/toolkit feature
                    entry["active"] = None  # Can't determine from config
                    inactive.append(entry)
            else:
                unavailable.append(entry)

        # 2. Run OPSEC checks
        opsec_findings: List[Dict[str, Any]] = []
        for rule in OPSEC_RULES:
            rule_ver = _version_tuple(rule["min_version"])
            if ver_t < rule_ver:
                continue  # Rule not applicable to this version
            try:
                triggered = rule["check"](self._config)
            except Exception:
                triggered = False
            if triggered:
                opsec_findings.append({
                    "id": rule["id"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "title": rule["title"],
                    "detail": rule["detail"],
                    "fix": rule["fix"],
                })

        # 3. Calculate scores
        total_available = len(available)
        total_active = len(active)
        feature_utilization = total_active / max(total_available, 1)

        # OPSEC score: penalize by severity
        severity_weights = {"critical": 3, "high": 2, "medium": 1, "low": 0.5, "info": 0.2}
        penalty = sum(severity_weights.get(f["severity"], 0) for f in opsec_findings)
        max_penalty = sum(severity_weights.get(r["severity"], 0) for r in OPSEC_RULES
                         if _version_tuple(r["min_version"]) <= ver_t)
        hardening_score = max(0, 1.0 - (penalty / max(max_penalty, 1)))

        # 4. Upgrade recommendations
        upgrade_benefits: List[Dict[str, Any]] = []
        for feat in unavailable:
            upgrade_benefits.append({
                "feature": feat["name"],
                "requires": feat["introduced"],
                "category": feat["category"],
                "description": feat["description"],
            })

        # Group by version
        upgrade_by_version: Dict[str, List[str]] = {}
        for ub in upgrade_benefits:
            v = ub["requires"]
            upgrade_by_version.setdefault(v, []).append(ub["feature"])

        self._results = {
            "detected_version": ver,
            "total_features": len(VERSION_FEATURES),
            "available_count": total_available,
            "active_count": total_active,
            "unavailable_count": len(unavailable),
            "feature_utilization": round(feature_utilization, 3),
            "hardening_score": round(hardening_score, 3),
            "features": {
                "available": available,
                "active": active,
                "inactive": inactive,
                "unavailable": unavailable,
            },
            "opsec_findings": opsec_findings,
            "upgrade_path": upgrade_by_version,
        }

    def get_results(self) -> Optional[Dict[str, Any]]:
        return self._results if self._results else None

    def collect_json_results(self) -> Optional[Dict[str, Any]]:
        return self._results if self._results else None

    def render_results(self) -> Any:
        if not self._results:
            return None

        from rich.text import Text
        from rich.table import Table
        from rich.panel import Panel
        from rich.console import Group
        from rich.columns import Columns
        from rich import box

        DIM = "bright_black"
        MUTED = "dim"
        GRADIENT = ["#5eead4", "#7b8cff", "#a77de5", "#d35fd6", "#ff6ec7"]

        parts: List[Any] = []
        r = self._results

        # ════════════════════════════════════════════════════════════
        #  HEADER — Version Identity + Scorecard
        # ════════════════════════════════════════════════════════════
        hdr = Text()
        hdr.append("  ◈ ", style=f"bold {GRADIENT[4]}")
        hdr.append("VERSION FEATURE AUDIT", style=f"bold {GRADIENT[4]}")
        parts.append(hdr)
        parts.append(Text(f"  {'─' * 68}", style=DIM))

        # Version identity row
        ver_line = Text("    ")
        ver_line.append("Version  ", style=DIM)
        ver_line.append(f"CobaltStrike {r['detected_version']}", style="bold bright_white")
        ver_line.append(f"  │  ", style=DIM)
        ver_line.append(f"{r['total_features']}", style=f"bold {GRADIENT[1]}")
        ver_line.append(f" features tracked", style=DIM)
        ver_line.append(f"  │  ", style=DIM)
        ver_line.append(f"{r['available_count']}", style=f"bold {GRADIENT[0]}")
        ver_line.append(f" available", style=DIM)
        parts.append(ver_line)

        # ── Dual Gauge Panel ───────────────────────────────────────
        util = r["feature_utilization"]
        hard = r["hardening_score"]

        def _render_gauge(label: str, value: float, icon: str,
                          c_good: str, c_warn: str, c_bad: str) -> Text:
            bar_w = 24
            filled = int(value * bar_w)
            c = c_good if value >= 0.6 else c_warn if value >= 0.3 else c_bad
            # Build gradient bar
            t = Text("    ")
            t.append(f"{icon} ", style=f"bold {c}")
            t.append(f"{label:<20s}", style=DIM)

            for i in range(bar_w):
                if i < filled:
                    # Gradient fill — shift hue across bar
                    idx = min(4, int(i / bar_w * 5))
                    t.append("█", style=GRADIENT[idx] if value >= 0.6 else c)
                else:
                    t.append("░", style=DIM)

            # Percentage + label
            t.append(f"  {value:.0%}", style=f"bold {c}")
            if value >= 0.8:
                t.append("  EXCELLENT", style=f"bold {c_good}")
            elif value >= 0.6:
                t.append("  GOOD", style=c_good)
            elif value >= 0.3:
                t.append("  MODERATE", style=c_warn)
            else:
                t.append("  LOW", style=f"bold {c_bad}")
            return t

        parts.append(Text())
        parts.append(_render_gauge("Feature Utilization", util, "◆",
                                   "#5eead4", "#fbbf24", "#f87171"))
        parts.append(_render_gauge("Hardening Score", hard, "◈",
                                   "#5eead4", "#fbbf24", "#f87171"))

        # Summary stat badges
        parts.append(Text())
        badge = Text("    ")
        active_count = r['active_count']
        avail = r['available_count']
        unav = r['unavailable_count']
        opsec_count = len(r["opsec_findings"])

        badge.append("  ┌─", style=DIM)
        badge.append(f" ✓ Active: ", style=DIM)
        badge.append(f"{active_count}", style=f"bold {GRADIENT[0]}")
        badge.append(f"/{avail}", style=DIM)
        badge.append(f" ─┬─", style=DIM)
        badge.append(f" ✗ Unused: ", style=DIM)
        badge.append(f"{avail - active_count}", style=f"bold {GRADIENT[1]}")
        badge.append(f" ─┬─", style=DIM)
        badge.append(f" ◇ Upgrade: ", style=DIM)
        badge.append(f"{unav}", style=f"bold {GRADIENT[3]}")
        badge.append(f" ─┬─", style=DIM)
        badge.append(f" ⚠ OPSEC: ", style=DIM)
        badge.append(f"{opsec_count}",
                     style="bold #f87171" if opsec_count > 0 else f"bold {GRADIENT[0]}")
        badge.append(" ─┘", style=DIM)
        parts.append(badge)

        # ════════════════════════════════════════════════════════════
        #  FEATURE MATRIX — Grouped by Category
        # ════════════════════════════════════════════════════════════
        parts.append(Text())
        fm_hdr = Text("  ")
        fm_hdr.append("◆ ", style=f"bold {GRADIENT[0]}")
        fm_hdr.append("FEATURE MATRIX", style=f"bold {GRADIENT[0]}")
        fm_hdr.append("  ─ Capability Status by Category", style=DIM)
        parts.append(fm_hdr)
        parts.append(Text(f"  {'─' * 68}", style=DIM))

        # Group available features by category
        by_cat: Dict[str, List[Dict]] = {}
        for feat in r["features"]["available"]:
            by_cat.setdefault(feat["category"], []).append(feat)

        # Also include unavailable for the full picture
        by_cat_unavail: Dict[str, List[Dict]] = {}
        for feat in r["features"]["unavailable"]:
            by_cat_unavail.setdefault(feat["category"], []).append(feat)

        # Category order for visual consistency
        cat_order = ["evasion", "injection", "comms", "post_exploitation",
                     "resilience", "efficiency", "opsec", "customization", "pivoting"]

        for cat in cat_order:
            avail_feats = by_cat.get(cat, [])
            unavail_feats = by_cat_unavail.get(cat, [])
            if not avail_feats and not unavail_feats:
                continue

            color, icon, label = CATEGORY_META.get(cat, (DIM, "?", cat))
            active_in_cat = sum(1 for f in avail_feats if f["active"] is True)
            total_in_cat = len(avail_feats)

            # Category header with mini utilization bar
            ch = Text("    ")
            ch.append(f"{icon} ", style=f"bold {color}")
            ch.append(f"{label}", style=f"bold {color}")
            if total_in_cat > 0:
                mini_pct = active_in_cat / total_in_cat
                mini_w = 8
                mini_fill = int(mini_pct * mini_w)
                ch.append(f"  ", style=DIM)
                ch.append("▓" * mini_fill, style=color)
                ch.append("░" * (mini_w - mini_fill), style=DIM)
                ch.append(f" {active_in_cat}/{total_in_cat}", style=DIM)
            parts.append(ch)

            # Available features
            for feat in avail_feats:
                fl = Text("      ")
                if feat["active"] is True:
                    fl.append("  ✓ ", style="bold #5eead4")
                    fl.append(f"{feat['name']:<36s}", style="bold bright_white")
                    fl.append(f" {feat['description']}", style=DIM)
                elif feat["active"] is False:
                    fl.append("  ✗ ", style="#f87171")
                    fl.append(f"{feat['name']:<36s}", style=DIM)
                    fl.append(f" {feat['description']}", style="dim italic")
                else:
                    # Infrastructure feature — can't detect from config
                    fl.append("  · ", style="#fbbf24")
                    fl.append(f"{feat['name']:<36s}", style=MUTED)
                    fl.append(f" {feat['description']}", style="dim italic")
                parts.append(fl)

            # Unavailable features (dimmed, marked with lock)
            for feat in unavail_feats:
                fl = Text("      ")
                fl.append("  ⊘ ", style=DIM)
                fl.append(f"{feat['name']:<36s}", style="dim strikethrough")
                fl.append(f" requires CS {feat['introduced']}", style=DIM)
                parts.append(fl)

        # ════════════════════════════════════════════════════════════
        #  OPSEC FINDINGS — Severity-ordered Security Advisor
        # ════════════════════════════════════════════════════════════
        findings = r.get("opsec_findings", [])
        parts.append(Text())
        if findings:
            sev_hdr = Text("  ")
            sev_hdr.append("⊕ ", style="bold #f87171")
            sev_hdr.append("OPSEC FINDINGS", style="bold #f87171")
            sev_hdr.append(f"  ─ {len(findings)} issues detected", style=DIM)
            parts.append(sev_hdr)
            parts.append(Text(f"  {'─' * 68}", style=DIM))

            SEV_COLORS = {
                "critical": "#f87171", "high": "#fbbf24",
                "medium": "#7b8cff", "low": "#5eead4", "info": DIM,
            }
            SEV_ICONS = {
                "critical": "▐█▌", "high": "▐▓▌",
                "medium": "▐▒▌", "low": "▐░▌", "info": " · ",
            }

            # Sort by severity
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sorted_findings = sorted(findings, key=lambda f: sev_order.get(f["severity"], 5))

            for f in sorted_findings:
                sc = SEV_COLORS.get(f["severity"], DIM)
                si = SEV_ICONS.get(f["severity"], " · ")

                # Finding header
                fl = Text("    ")
                fl.append(f"{si} ", style=f"bold {sc}")
                fl.append(f"{f['severity'].upper():<8s}", style=f"bold {sc}")
                fl.append(f"  {f['title']}", style="bold bright_white")
                parts.append(fl)

                # Detail line
                dl = Text("    ")
                dl.append(f"        │ ", style=DIM)
                dl.append(f"{f['detail']}", style=MUTED)
                parts.append(dl)

                # Fix recommendation
                fx = Text("    ")
                fx.append(f"        └─ ↳ ", style=GRADIENT[0])
                fx.append(f"{f['fix']}", style=f"bold {GRADIENT[0]}")
                parts.append(fx)
                parts.append(Text())  # spacing between findings
        else:
            # Clean bill of health
            clean = Text("  ")
            clean.append("◈ ", style=f"bold {GRADIENT[0]}")
            clean.append("OPSEC STATUS", style=f"bold {GRADIENT[0]}")
            clean.append("  ─ ", style=DIM)
            clean.append("ALL CLEAR", style=f"bold {GRADIENT[0]}")
            clean.append("  No issues detected", style=DIM)
            parts.append(clean)

        # ════════════════════════════════════════════════════════════
        #  UPGRADE PATH — Version Roadmap
        # ════════════════════════════════════════════════════════════
        upgrade = r.get("upgrade_path", {})
        if upgrade:
            parts.append(Text())
            up_hdr = Text("  ")
            up_hdr.append("⟐ ", style=f"bold {GRADIENT[3]}")
            up_hdr.append("UPGRADE ROADMAP", style=f"bold {GRADIENT[3]}")
            up_hdr.append(f"  ─ {sum(len(v) for v in upgrade.values())} features across "
                          f"{len(upgrade)} version(s)", style=DIM)
            parts.append(up_hdr)
            parts.append(Text(f"  {'─' * 68}", style=DIM))

            sorted_versions = sorted(upgrade.keys(), key=lambda v: _version_tuple(v))
            for i, ver in enumerate(sorted_versions):
                feats = upgrade[ver]
                is_last = (i == len(sorted_versions) - 1)

                # Version node
                connector = "└──" if is_last else "├──"
                vl = Text("    ")
                vl.append(f"  {connector} ", style=GRADIENT[3])
                vl.append(f"CS {ver}", style=f"bold {GRADIENT[1]}")
                vl.append(f"  +{len(feats)} features", style=f"bold {GRADIENT[3]}")
                parts.append(vl)

                # Feature list under version
                pipe = "   " if is_last else "│  "
                for j, fname in enumerate(feats):
                    feat_last = (j == len(feats) - 1)
                    feat_conn = "└─" if feat_last else "├─"
                    fl = Text("    ")
                    fl.append(f"  {pipe} {feat_conn} ", style=DIM)
                    fl.append(f"→ ", style=GRADIENT[3])

                    # Look up description from VERSION_FEATURES
                    desc = ""
                    for fid, fdata in VERSION_FEATURES.items():
                        if fdata["name"] == fname:
                            desc = fdata["description"]
                            break

                    fl.append(f"{fname}", style="bright_white")
                    if desc:
                        fl.append(f"  {desc}", style=DIM)
                    parts.append(fl)

        return Group(*parts)

    def cleanup(self) -> None:
        self._results = {}
        self._config = {}
        self._detected_version = ""
