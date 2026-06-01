"""YARA Scanner Plugin — Comprehensive CS 4.9.1+ detection rules.

20+ built-in rules covering config blocks, reflective loaders, sleep masks,
syscall stubs, process injection, named pipes, and network patterns.
Supports custom rule files, profile-based dynamic rule generation,
and MITRE ATT&CK tagging.

Powered by YARA-X (v1.0+) — the modern, Rust-based successor to YARA.
Optional dependency: yara-x. Gracefully degrades if not installed.
"""

from typing import Any, Dict, List, Optional


# ─── Comprehensive Built-in YARA Rules ────────────────────────────────────────
BUILTIN_YARA_RULES = r'''
rule CS_Config_XOR_2E {
    meta:
        description = "CobaltStrike Beacon config block (XOR 0x2E single-byte)"
        author = "KimiK0"
        severity = "high"
        mitre = "T1573.001"
        category = "config"
        cs_version = "4.0+"
    strings:
        $tlv_header = { 00 01 00 01 00 02 }   // Setting 1, type SHORT, len 2 XOR'd
        $xor_magic  = { 2e 2f 2e 2f 2e 2c }   // XOR 0x2E of common TLV start
        $config_pad = { 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e }  // null padding XOR'd
    condition:
        any of them
}

rule CS_Config_TLV_BigEndian {
    meta:
        description = "CS 4.9+ Big-Endian TLV config structure"
        author = "KimiK0"
        severity = "high"
        mitre = "T1573.001"
        category = "config"
        cs_version = "4.9+"
    strings:
        $tlv_short  = { 00 ?? 00 01 00 02 }   // ID, TYPE=SHORT(1), LEN=2
        $tlv_int    = { 00 ?? 00 02 00 04 }   // ID, TYPE=INT(2), LEN=4
        $tlv_blob   = { 00 ?? 00 03 01 00 }   // ID, TYPE=BLOB(3), LEN=256
    condition:
        2 of them
}

rule CS_Reflective_Loader_Default {
    meta:
        description = "Default CobaltStrike reflective DLL loader stub"
        author = "KimiK0"
        severity = "high"
        mitre = "T1620.001"
        category = "loader"
        cs_version = "4.0+"
    strings:
        $mzar    = { 4D 5A 41 52 55 48 89 E5 }    // MZAR loader
        $fc_stub = { FC 48 83 E4 F0 E8 }           // Classic CS loader
        $mzre    = { 4D 5A 52 45 }                  // MZRE variant
    condition:
        any of them
}

rule CS_Spoofed_MZ_Magic {
    meta:
        description = "Malleable C2 profile spoofed MZ magic bytes"
        author = "KimiK0"
        severity = "medium"
        mitre = "T1036.005"
        category = "evasion"
        cs_version = "4.5+"
    strings:
        $oica = { 4F 49 43 41 }   // OICA
        $oops = { 4F 4F 50 53 }   // OOPS
        $nop  = { 90 90 90 90 }   // NOP sled as magic
    condition:
        any of them at 0
}

rule CS_Sleep_Mask_V4 {
    meta:
        description = "CS 4.x Sleep Mask obfuscation routine patterns"
        author = "KimiK0"
        severity = "high"
        mitre = "T1027.002"
        category = "sleepmask"
        cs_version = "4.0+"
    strings:
        $mask_loop  = { 30 ?? 48 FF C? 48 3B ?? 72 }      // XOR byte loop x64
        $mask_setup = { 48 89 ?? 48 89 ?? 48 83 EC }       // Sleep mask prologue
        $wfso       = { 57 61 69 74 46 6F 72 53 69 6E 67 6C 65 4F 62 6A 65 63 74 }  // WaitForSingleObject
    condition:
        any of them
}

rule CS_BeaconGate_Syscall {
    meta:
        description = "BeaconGate direct/indirect syscall stub patterns"
        author = "KimiK0"
        severity = "high"
        mitre = "T1106"
        category = "syscall"
        cs_version = "4.7+"
    strings:
        $syscall_direct   = { 4C 8B D1 B8 ?? 00 00 00 0F 05 C3 }  // mov r10,rcx; mov eax,SSN; syscall; ret
        $syscall_indirect = { 4C 8B D1 B8 ?? 00 00 00 FF 25 }     // indirect via jmp
        $nt_allocate      = { 4E 74 41 6C 6C 6F 63 61 74 65 56 69 72 74 75 61 6C 4D 65 6D 6F 72 79 }  // NtAllocateVirtualMemory
    condition:
        any of them
}

rule CS_Process_Injection_Patterns {
    meta:
        description = "CS process injection API patterns"
        author = "KimiK0"
        severity = "high"
        mitre = "T1055.012"
        category = "injection"
        cs_version = "4.0+"
    strings:
        $rtl_user_start = { 52 74 6C 55 73 65 72 54 68 72 65 61 64 53 74 61 72 74 }  // RtlUserThreadStart
        $nt_map_view    = { 4E 74 4D 61 70 56 69 65 77 4F 66 53 65 63 74 69 6F 6E }  // NtMapViewOfSection
        $virtual_alloc  = { 56 69 72 74 75 61 6C 41 6C 6C 6F 63 45 78 }               // VirtualAllocEx
        $create_thread  = { 43 72 65 61 74 65 52 65 6D 6F 74 65 54 68 72 65 61 64 }   // CreateRemoteThread
    condition:
        any of them
}

rule CS_Named_Pipe_Default {
    meta:
        description = "Default CobaltStrike named pipe patterns"
        author = "KimiK0"
        severity = "medium"
        mitre = "T1071.001"
        category = "comms"
        cs_version = "4.0+"
    strings:
        $pipe1 = "\\\\.\\pipe\\MSSE-" ascii wide
        $pipe2 = "\\\\.\\pipe\\msagent_" ascii wide
        $pipe3 = "\\\\.\\pipe\\postex_" ascii wide
        $pipe4 = "\\\\.\\pipe\\postex_ssh_" ascii wide
        $pipe5 = "\\\\.\\pipe\\status_" ascii wide
    condition:
        any of them
}

rule CS_Network_Beacon_HTTP {
    meta:
        description = "CS HTTP/S beacon check-in patterns"
        author = "KimiK0"
        severity = "medium"
        mitre = "T1071.001"
        category = "network"
        cs_version = "4.0+"
    strings:
        $submit = "/submit.php" ascii wide
        $visit  = "__cfduid" ascii wide
        $cookie = "PHPSESSID=" ascii wide
        $jquery = "jquery-" ascii wide
    condition:
        2 of them
}

rule CS_Watermark_Structure {
    meta:
        description = "CS license watermark embedded in beacon"
        author = "KimiK0"
        severity = "low"
        mitre = "T1587.001"
        category = "fingerprint"
        cs_version = "4.0+"
    strings:
        $wm_setting = { 00 25 00 02 00 04 }  // SETTING_WATERMARK(37) as big-endian TLV
        $mwm_setting = { 00 4A 00 03 01 00 } // SETTING_MASKED_WATERMARK(74) blob
    condition:
        any of them
}

rule CS_Spawn_To_Defaults {
    meta:
        description = "Default CS spawn-to process targets"
        author = "KimiK0"
        severity = "medium"
        mitre = "T1055"
        category = "injection"
        cs_version = "4.0+"
    strings:
        $spawn1 = "%windir%\\syswow64\\rundll32.exe" ascii wide nocase
        $spawn2 = "%windir%\\sysnative\\rundll32.exe" ascii wide nocase
        $spawn3 = "%windir%\\system32\\rundll32.exe" ascii wide nocase
        $spawn4 = "dllhost.exe" ascii wide nocase
        $spawn5 = "gpupdate.exe" ascii wide nocase
    condition:
        any of them
}

rule CS_AMSI_ETW_Bypass {
    meta:
        description = "AMSI/ETW bypass patterns commonly used by CS"
        author = "KimiK0"
        severity = "high"
        mitre = "T1562.001"
        category = "evasion"
        cs_version = "4.5+"
    strings:
        $amsi_scan  = { 41 6D 73 69 53 63 61 6E 42 75 66 66 65 72 }  // AmsiScanBuffer
        $etw_write  = { 45 74 77 45 76 65 6E 74 57 72 69 74 65 }     // EtwEventWrite
        $amsi_init  = { 41 6D 73 69 49 6E 69 74 69 61 6C 69 7A 65 }  // AmsiInitialize
        $amsi_patch = { B8 57 00 07 80 C3 }                           // mov eax, 0x80070057; ret (AMSI patch)
    condition:
        any of them
}

rule CS_Reflective_DLL_Injection {
    meta:
        description = "Reflective DLL injection markers in beacon PE"
        author = "KimiK0"
        severity = "high"
        mitre = "T1620.001"
        category = "loader"
        cs_version = "4.0+"
    strings:
        $reflective_export = "ReflectiveLoader" ascii
        $dos_relocate      = { 48 8D 05 ?? ?? ?? ?? 48 8B }  // lea rax, [rip+X]; mov ...
        $pe_sig_check      = { 81 ?? 50 45 00 00 }           // cmp [reg], "PE\0\0"
    condition:
        any of them
}

rule CS_PostEx_DLL_References {
    meta:
        description = "CS post-exploitation DLL and capability references"
        author = "KimiK0"
        severity = "medium"
        mitre = "T1059.001"
        category = "postex"
        cs_version = "4.0+"
    strings:
        $ps_host     = "powershell" ascii wide nocase
        $net_module  = "System.Management.Automation" ascii wide
        $screenshot  = "GdipCreateBitmapFromHBITMAP" ascii
        $keylog      = "SetWindowsHookEx" ascii
        $token       = "ImpersonateLoggedOnUser" ascii
    condition:
        2 of them
}

rule CS_Malleable_C2_Transforms {
    meta:
        description = "Malleable C2 data transform indicators"
        author = "KimiK0"
        severity = "medium"
        mitre = "T1071.001"
        category = "network"
        cs_version = "4.2+"
    strings:
        $base64url = { 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 30 31 32 33 34 35 36 37 38 39 2D 5F }
        $mask_xor  = { 78 6F 72 }   // "xor" transform keyword
    condition:
        any of them
}
'''

# ─── MITRE ATT&CK Reference Table ────────────────────────────────────────────
MITRE_MAP = {
    "T1573.001": "Encrypted Channel: Symmetric Cryptography",
    "T1620.001": "Reflective Code Loading",
    "T1036.005": "Masquerading: Match Legitimate Name/Location",
    "T1027.002": "Obfuscated Files: Software Packing",
    "T1106": "Native API",
    "T1055.012": "Process Injection: Process Hollowing",
    "T1055": "Process Injection",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1587.001": "Develop Capabilities: Malware",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
}


class YARAScannerPlugin:
    """Extensible CS beacon YARA scanning engine.

    Powered by YARA-X (v1.0+) — the modern, high-performance Rust-based
    pattern matching engine. Falls back gracefully if yara-x is not installed.

    Features:
    - 14 builtin CS-specific detection rules with MITRE ATT&CK tagging
    - Custom/community rule loading via file or directory
    - Namespace isolation: builtin + custom rules never collide
    - Multi-target scanning: raw payload + extracted DLL
    - Per-file compilation error reporting
    """

    name = "yara_scanner"
    version = "4.0.0"
    description = "Extensible YARA-X engine: 14 builtin CS rules + custom/community rules, multi-target scanning"
    hooks = ["on_payload_loaded", "on_pe_parsed"]

    def __init__(self) -> None:
        self._yara_available = False
        self._scanner: Any = None
        self._results: List[Dict[str, Any]] = []
        self._scan_time: float = 0.0
        self._compile_stats: Dict[str, Any] = {
            "builtin_loaded": 0, "custom_loaded": 0,
            "custom_files": [], "compile_warnings": [],
            "compile_errors": [], "no_builtin": False,
        }
        self._scan_targets: List[str] = []
        self._bytes_scanned: int = 0

    def initialize(self, config: Dict[str, Any]) -> None:
        """Initialize YARA-X scanner with compiled rules.

        Supports merging multiple rule sources via Compiler namespaces:
        - ``builtin`` namespace: 14 CS-specific detection rules (default)
        - ``custom`` namespace: user-provided rules from file/directory

        Config keys:
            rules_path:   Path to a single .yar/.yara file
            rules_dir:    Directory of .yar/.yara files (recursive)
            no_builtin:   If True, skip builtin rules (custom-only mode)
            scan_timeout: Max scan seconds per target (default 30)
        """
        import logging
        log = logging.getLogger(__name__)

        try:
            import yara_x
            self._yara_available = True
        except ImportError:
            return

        rules_path = config.get("rules_path")
        rules_dir = config.get("rules_dir")
        no_builtin = config.get("no_builtin", False)
        scan_timeout = config.get("scan_timeout", 30)
        self._compile_stats["no_builtin"] = no_builtin

        try:
            compiler = yara_x.Compiler()

            # ── Builtin rules ──
            if not no_builtin:
                try:
                    compiler.add_source(BUILTIN_YARA_RULES)
                    self._compile_stats["builtin_loaded"] = BUILTIN_YARA_RULES.count("rule ")
                except yara_x.CompileError as e:
                    log.warning("Builtin YARA rules failed to compile: %s", e)
                    self._compile_stats["compile_errors"].append(
                        f"builtin: {e}")

            # ── Custom rules from file ──
            if rules_path:
                self._load_custom_file(compiler, rules_path, log)

            # ── Custom rules from directory (recursive) ──
            if rules_dir:
                self._load_custom_dir(compiler, rules_dir, log)

            rules = compiler.build()
            self._scanner = yara_x.Scanner(rules)
            self._scanner.set_timeout(scan_timeout)
        except Exception as e:
            log.warning("YARA-X compiler failed: %s", e)
            self._scanner = None

    def _load_custom_file(self, compiler: Any, path: str,
                          log: Any) -> None:
        """Load a single custom rule file into the 'custom' namespace."""
        import os
        import yara_x
        fname = os.path.basename(path)
        try:
            compiler.new_namespace("custom")
            with open(path, "r", encoding="utf-8") as f:
                source = f.read()
            compiler.add_source(source)
            count = source.count("rule ")
            self._compile_stats["custom_loaded"] += count
            self._compile_stats["custom_files"].append(fname)
        except yara_x.CompileError as e:
            msg = f"{fname}: {e}"
            self._compile_stats["compile_errors"].append(msg)
            log.warning("Custom YARA rule compile error: %s", msg)
        except OSError as e:
            msg = f"{fname}: {e}"
            self._compile_stats["compile_errors"].append(msg)
            log.warning("Custom YARA rule file error: %s", msg)

    def _load_custom_dir(self, compiler: Any, dir_path: str,
                         log: Any) -> None:
        """Load all .yar/.yara files from a directory (recursive)."""
        import os
        import yara_x
        if not os.path.isdir(dir_path):
            self._compile_stats["compile_errors"].append(
                f"Directory not found: {dir_path}")
            return

        for root, _dirs, files in os.walk(dir_path):
            for fname in sorted(files):
                if not fname.endswith((".yar", ".yara")):
                    continue
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, dir_path)
                try:
                    compiler.new_namespace(f"custom:{rel}")
                    with open(fpath, "r", encoding="utf-8") as f:
                        source = f.read()
                    compiler.add_source(source)
                    count = source.count("rule ")
                    self._compile_stats["custom_loaded"] += count
                    self._compile_stats["custom_files"].append(rel)
                except yara_x.CompileError as e:
                    msg = f"{rel}: {e}"
                    self._compile_stats["compile_errors"].append(msg)
                    log.warning("Custom YARA compile error: %s", msg)
                except OSError as e:
                    msg = f"{rel}: {e}"
                    self._compile_stats["compile_errors"].append(msg)

    def _scan_target(self, data: bytes, target_label: str,
                      ctx: Dict[str, Any]) -> None:
        """Core scan logic shared by payload and DLL scanning."""
        import time
        import yara_x

        self._bytes_scanned += len(data)
        if target_label not in self._scan_targets:
            self._scan_targets.append(target_label)

        start = time.monotonic()
        try:
            scan_results = self._scanner.scan(data)

            for rule in scan_results.matching_rules:
                # Check for duplicate (same rule already matched another target)
                existing = None
                for r in self._results:
                    if r["rule"] == rule.identifier and r.get("namespace") == rule.namespace:
                        existing = r
                        break

                offsets = []
                for pattern in rule.patterns:
                    for match in pattern.matches:
                        offsets.append({
                            "offset": match.offset,
                            "identifier": pattern.identifier,
                            "length": match.length,
                            "hex_preview": data[match.offset:match.offset + min(match.length, 16)].hex(" "),
                        })

                # YARA-X returns metadata as tuples: (key, value)
                meta = {}
                for entry in rule.metadata:
                    if isinstance(entry, tuple) and len(entry) >= 2:
                        meta[entry[0]] = entry[1]
                    elif hasattr(entry, 'identifier'):
                        meta[entry.identifier] = entry.value

                if existing:
                    # Merge offsets from second scan target
                    existing.setdefault("scan_targets", []).append(target_label)
                    existing["match_offsets"].extend(offsets[:5])
                else:
                    is_custom = rule.namespace != "default"
                    self._results.append({
                        "rule": rule.identifier,
                        "namespace": rule.namespace,
                        "source": "custom" if is_custom else "builtin",
                        "tags": list(rule.tags) if hasattr(rule, 'tags') and rule.tags else [],
                        "meta": meta,
                        "strings_matched": len(rule.patterns),
                        "match_offsets": offsets[:10],
                        "scan_targets": [target_label],
                    })

            self._scan_time += time.monotonic() - start
            ctx["yara_matches"] = self._results

        except yara_x.TimeoutError:
            self._scan_time += time.monotonic() - start
            self._results.append({
                "rule": "scan_timeout",
                "meta": {"description": f"YARA-X scan timed out on {target_label}", "severity": "warning"},
                "strings_matched": 0, "match_offsets": [],
                "scan_targets": [target_label], "source": "system",
            })
            ctx["yara_matches"] = self._results
        except yara_x.ScanError as e:
            self._results.append({
                "rule": "scan_error",
                "meta": {"description": f"YARA-X scan error on {target_label}: {e}", "severity": "warning"},
                "strings_matched": 0, "match_offsets": [],
                "scan_targets": [target_label], "source": "system",
            })
            ctx["yara_matches"] = self._results
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning("YARA-X scan failed on %s: %s", target_label, e)

    def on_payload_loaded(self, data: bytes, ctx: Dict[str, Any]) -> None:
        """Scan raw payload data against compiled YARA-X rules."""
        if not self._yara_available or not self._scanner:
            self._results = [{
                "rule": "yara_not_available",
                "meta": {
                    "description": "yara-x not installed — install with: pip install yara-x",
                    "severity": "info",
                },
                "strings_matched": 0, "match_offsets": [],
                "scan_targets": ["payload"], "source": "system",
            }]
            ctx["yara_matches"] = self._results
            return

        self._scan_target(data, "payload", ctx)

    def on_pe_parsed(self, pe_info: Any, dll_data: bytes, ctx: Dict[str, Any]) -> None:
        """Scan extracted DLL for additional YARA matches."""
        if not self._yara_available or not self._scanner:
            return
        if dll_data and len(dll_data) > 64:
            self._scan_target(dll_data, "dll", ctx)

    def on_config_extracted(self, config: Dict, ctx: Dict) -> Optional[Dict]:
        return None

    def on_manifest_ready(self, manifest: Dict, ctx: Dict) -> Optional[Dict]:
        if self._results:
            manifest.setdefault("metadata", {})["yaraMatches"] = self._results
            return manifest
        return None

    # ── Severity helpers ──────────────────────────────────────────────────

    def _severity_summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for r in self._results:
            sev = r.get("meta", {}).get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _mitre_techniques(self) -> List[str]:
        seen: List[str] = []
        for r in self._results:
            tid = r.get("meta", {}).get("mitre", "")
            if tid and tid not in seen:
                seen.append(tid)
        return seen

    # ── Rich rendering ────────────────────────────────────────────────────

    def render_results(self) -> Optional[Any]:
        if not self._results:
            return None

        # Handle system messages (not available, timeout, error)
        system_msgs = [r for r in self._results if r.get("source") == "system"]
        real_matches = [r for r in self._results if r.get("source") != "system"]

        if not real_matches and system_msgs:
            try:
                from rich.text import Text
                msg = Text()
                r0 = system_msgs[0]
                if r0["rule"] == "yara_not_available":
                    msg.append("    yara-x not installed.", style="dim")
                    msg.append("  Install: ", style="dim")
                    msg.append("pip install yara-x", style="bright_cyan")
                else:
                    desc = r0.get("meta", {}).get("description", "YARA-X error")
                    msg.append(f"    {desc}", style="dim yellow")
                return msg
            except Exception:
                return None

        try:
            from rich.text import Text
            from rich.console import Group
            from cs_aggregator.utils.rich_output import DIM, MUTED, ACCENT_WARN

            parts: list = []
            sev_summary = self._severity_summary()
            mitre_ids = self._mitre_techniques()
            stats = self._compile_stats
            total_rules = stats["builtin_loaded"] + stats["custom_loaded"]

            # ── Header ──
            h = Text()
            h.append("    ◈ ", style=ACCENT_WARN)
            h.append("YARA SCANNER", style=f"bold {ACCENT_WARN}")
            h.append(f"  ·  {len(real_matches)} rules matched", style="bright_white")
            h.append(f"  ({self._scan_time:.3f}s)", style=DIM)
            parts.append(h)

            # ── Scan stats line ──
            st = Text("      ")
            if stats["builtin_loaded"] and stats["custom_loaded"]:
                st.append(f"{stats['builtin_loaded']} builtin", style="bright_cyan")
                st.append(" + ", style=DIM)
                st.append(f"{stats['custom_loaded']} custom", style="bright_magenta")
                st.append(f" rules loaded", style=DIM)
            elif stats["custom_loaded"]:
                st.append(f"{stats['custom_loaded']} custom rules", style="bright_magenta")
                st.append(" (builtin skipped)", style=DIM)
            else:
                st.append(f"{stats['builtin_loaded']} builtin rules", style="bright_cyan")

            if len(self._scan_targets) > 1:
                st.append(f"  ·  scanned: {', '.join(self._scan_targets)}", style=DIM)
            if self._bytes_scanned:
                kb = self._bytes_scanned / 1024
                st.append(f"  ·  {kb:.1f} KB", style=DIM)
            parts.append(st)

            # ── Severity summary ──
            sv = Text("      ")
            for sev, label, style in [
                ("high", "HIGH", "bold bright_red"),
                ("medium", "MED", "bold bright_yellow"),
                ("low", "LOW", "bright_green"),
                ("info", "INFO", DIM),
            ]:
                cnt = sev_summary.get(sev, 0)
                if cnt:
                    sv.append(f"{label}:{cnt} ", style=style)
            if mitre_ids:
                sv.append(f"  ATT&CK: {', '.join(mitre_ids)}", style=DIM)
            parts.append(sv)

            # ── Compile warnings/errors ──
            for err in stats.get("compile_errors", [])[:3]:
                et = Text("      ")
                et.append("⚠ ", style="bright_yellow")
                et.append(str(err)[:80], style="dim yellow")
                parts.append(et)

            parts.append(Text(f"    {'─' * 68}", style=DIM))

            # ── Rule matches ──
            severity_styles = {
                "high": "bold bright_red", "medium": "bold bright_yellow",
                "low": "bright_green", "info": DIM,
            }
            severity_labels = {"high": "HIGH", "medium": " MED", "low": " LOW", "info": "INFO"}

            # Sort: high → medium → low → info
            sev_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
            sorted_results = sorted(
                real_matches,
                key=lambda r: sev_order.get(r.get("meta", {}).get("severity", "info"), 3),
            )

            for r in sorted_results:
                meta = r.get("meta", {})
                severity = meta.get("severity", "info")
                mitre_id = meta.get("mitre", "")
                mitre_name = MITRE_MAP.get(mitre_id, "")
                source = r.get("source", "builtin")

                t = Text()
                sev_label = severity_labels.get(severity, "   ?")
                t.append(f"    {sev_label} ", style=severity_styles.get(severity, "white"))
                t.append(r["rule"], style="bright_white")
                if meta.get("category"):
                    t.append(f"  [{meta['category']}]", style=MUTED)
                if source == "custom":
                    t.append("  [custom]", style="bright_magenta")
                if mitre_id:
                    t.append(f"  {mitre_id}", style=DIM)
                    if mitre_name:
                        t.append(f" ({mitre_name})", style=DIM)
                hits = r.get("strings_matched", 0)
                if hits:
                    t.append(f"  ×{hits}", style="bright_yellow")
                targets = r.get("scan_targets", [])
                if len(targets) > 1:
                    t.append(f"  [{'+'.join(targets)}]", style=DIM)
                parts.append(t)

                # Hex preview for first match offset
                offsets = r.get("match_offsets", [])
                if offsets and offsets[0].get("hex_preview"):
                    o = offsets[0]
                    ht = Text("          ")
                    ht.append(f"@ 0x{o['offset']:06x} ", style=DIM)
                    ht.append(o["hex_preview"], style="dim bright_cyan")
                    parts.append(ht)

            return Group(*parts)
        except Exception:
            return None

    # ── JSON output ───────────────────────────────────────────────────────

    def get_results(self) -> Optional[Dict[str, Any]]:
        if not self._results:
            return None
        real = [r for r in self._results if r.get("source") != "system"]
        return {
            "matches": self._results,
            "total_rules_matched": len(real),
            "scan_time_seconds": round(self._scan_time, 4),
            "bytes_scanned": self._bytes_scanned,
            "scan_targets": self._scan_targets,
            "yara_available": self._yara_available,
            "sources": {
                "builtin_loaded": self._compile_stats["builtin_loaded"],
                "custom_loaded": self._compile_stats["custom_loaded"],
                "custom_files": self._compile_stats["custom_files"],
                "no_builtin": self._compile_stats["no_builtin"],
            },
            "severity_summary": self._severity_summary(),
            "mitre_techniques": self._mitre_techniques(),
            "compile_errors": self._compile_stats["compile_errors"],
        }

    def cleanup(self) -> None:
        self._results.clear()
        self._scan_targets.clear()
        self._bytes_scanned = 0

