"""Shellcode Fingerprinter Plugin — Deep shellcode analysis for MalDev.

Uses data from ALL pipeline stages (raw bytes, parsed PE, extracted config)
to build an accurate fingerprint. Does NOT rely on plaintext string scanning
of encrypted payloads.
"""

import struct
import math

from cs_aggregator.utils.pe_utils import KNOWN_PE_MAGICS, find_pe_offset
from typing import Any, Dict, List, Optional

# Known CS profile magic bytes (stage.magic_mz_x64/x86)
CS_MAGIC_MAP = {
    "4d5a": "Standard MZ",
    "4f494341": "OICA (NOP-equivalent)",
    "4f4f5053": "OOPS (NOP-equivalent)",
    "4d5a4152": "MZAR (CS default UDRL)",
    "4e4f": "NO",
    "4d52": "MR",
}

# Known UDRL loader signatures (in the LOADER STUB region only, first ~4KB)
LOADER_SIGS = [
    (b"\xFC\x48\x83\xE4\xF0\xE8", "cs_classic", "CS Classic Reflective Loader (FC stub)"),
    (b"\x4D\x5A\x41\x52\x55\x48\x89\xE5", "cs_default_mzar", "CS Default MZAR Loader"),
    (b"\x56\x48\x89\xE6\x48\x83\xE4\xF0", "boku_loader", "BokuLoader (community UDRL)"),
    (b"\x48\x89\x5C\x24\x08\x57\x48\x83\xEC", "custom_udrl_v1", "Custom UDRL (standard prologue)"),
]


class ShellcodeFingerprintPlugin:
    """Deep shellcode analysis using multi-stage pipeline data."""

    name = "shellcode_fingerprinter"
    version = "2.0.0"
    description = "Multi-stage loader, architecture, syscall, evasion, and memory layout fingerprinting"
    hooks = ["on_payload_loaded", "on_pe_parsed", "on_config_extracted"]

    def __init__(self) -> None:
        self._results: Dict[str, Any] = {}
        self._raw_data: Optional[bytes] = None

    def initialize(self, config: Dict[str, Any]) -> None:
        pass

    # ─── Stage 1: Raw Payload ─────────────────────────────────────────────

    def on_payload_loaded(self, data: bytes, ctx: Dict[str, Any]) -> None:
        self._raw_data = data
        self._results = {
            "loader": self._classify_loader(data),
            "architecture": self._detect_architecture(data),
            "api_resolution": self._detect_api_hashing(data),
            "memory_layout": self._analyze_layout(data),
            "pic_analysis": self._check_pic_safety(data),
            # Placeholders — populated from config/PE in later hooks
            "syscalls": {"method": "unknown", "source": "pending_config"},
            "evasion": {},
            "identifiers": {},
        }
        ctx["shellcode_fingerprint"] = self._results

    # ─── Stage 2: Parsed PE ───────────────────────────────────────────────

    def on_pe_parsed(self, pe_info: Any, dll_data: bytes, ctx: Dict[str, Any]) -> None:
        if not self._results:
            return
        if pe_info is None:
            return

        pe_details = {
            "machine": getattr(pe_info, "machine_type", "unknown"),
            "sections": len(getattr(pe_info, "sections", [])),
            "imports": getattr(pe_info, "import_count", 0),
            "exports": getattr(pe_info, "export_count", 0),
            "anomalies": getattr(pe_info, "anomalies", []),
            "compile_ts": getattr(pe_info, "compile_timestamp", None),
        }
        self._results["pe_structure"] = pe_details

        # Analyze DECRYPTED DLL bytes for API resolution patterns
        if dll_data:
            self._results["api_resolution"] = self._detect_api_hashing_decrypted(dll_data)

            # Scan decrypted DLL for syscall stubs
            sc = self._scan_syscall_stubs(dll_data)
            if sc["stub_count"] > 0:
                self._results["syscalls"] = sc

            # Detect RWX sections (injection-ready)
            rwx_sections = []
            for sec in getattr(pe_info, "sections", []):
                chars = sec.get("characteristics", 0)
                if isinstance(chars, int) and (chars & 0xE0000000) == 0xE0000000:
                    rwx_sections.append(sec.get("name", "?"))
            if rwx_sections:
                self._results.setdefault("evasion", {})["rwx_sections"] = rwx_sections

    # ─── Stage 3: Config — Definitive Source of Truth ─────────────────────

    def on_config_extracted(self, config: Dict[str, Any], ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self._results:
            return None

        # Syscall method from config is DEFINITIVE
        syscall_raw = config.get("SETTING_SYSCALL_METHOD", 0)
        syscall_map = {0: "none", 1: "direct", 2: "indirect"}
        syscall_method = syscall_map.get(int(syscall_raw), f"unknown({syscall_raw})")
        self._results["syscalls"] = {
            "method": syscall_method,
            "source": "config (SETTING_SYSCALL_METHOD)",
            "stub_count": self._results.get("syscalls", {}).get("stub_count", 0),
            "syscall_instructions": self._results.get("syscalls", {}).get("syscall_instructions", 0),
        }

        # Evasion profile from config — not from string scanning
        sleep_mask = bool(config.get("SETTING_GARGLE_NOOK", 0))
        cleanup = bool(config.get("SETTING_CLEANUP", 0))
        cfg_caution = bool(config.get("SETTING_CFG_CAUTION", 0))

        # BOF allocator
        bof_alloc = config.get("SETTING_BOF_ALLOCATOR", 0)
        bof_map = {0: "VirtualAlloc", 1: "HeapAlloc", 2: "MapViewOfFile"}
        bof_method = bof_map.get(int(bof_alloc), f"unknown({bof_alloc})")

        # Process injection
        inj_alloc = config.get("SETTING_PROCINJ_ALLOCATOR", 0)
        inj_map = {0: "VirtualAllocEx", 1: "NtMapViewOfSection"}
        inj_method = inj_map.get(int(inj_alloc), f"unknown({inj_alloc})")

        # Exit function
        exit_funk = config.get("SETTING_EXIT_FUNK", 0)
        exit_map = {0: "none", 1: "ExitThread", 2: "ExitProcess"}
        exit_method = exit_map.get(int(exit_funk), f"unknown({exit_funk})")

        # Crypto
        crypto = config.get("SETTING_CRYPTO_SCHEME", 0)
        crypto_map = {0: "none", 1: "AES-256"}

        evasion = {
            "sleep_mask": sleep_mask,
            "beacon_gate": bool(config.get("SETTING_BEACON_GATE", 0)),
            "syscall_method": syscall_method,
            "cleanup": cleanup,
            "cfg_caution": cfg_caution,
            "bof_allocator": bof_method,
            "injection_allocator": inj_method,
            "exit_function": exit_method,
            "crypto": crypto_map.get(int(crypto), f"unknown({crypto})"),
        }
        # Preserve RWX sections from PE stage
        if "rwx_sections" in self._results.get("evasion", {}):
            evasion["rwx_sections"] = self._results["evasion"]["rwx_sections"]
        self._results["evasion"] = evasion

        # Identifiers
        ids = {}
        wm = config.get("SETTING_WATERMARK")
        if wm is not None:
            ids["watermark"] = int(wm) if isinstance(wm, (int, float)) else str(wm)
        masked = config.get("SETTING_MASKED_WATERMARK")
        if masked:
            ids["masked_watermark"] = str(masked)[:40]
        pk = config.get("SETTING_PUBKEY")
        if pk:
            ids["pubkey_fingerprint"] = str(pk)[:40] + "…"

        # Protocol info for fingerprinting
        proto_map = {0: "HTTP", 1: "DNS", 2: "SMB", 4: "TCP", 8: "HTTPS"}
        proto = config.get("SETTING_PROTOCOL", 0)
        ids["protocol"] = proto_map.get(int(proto), f"unknown({proto})")
        ids["port"] = int(config.get("SETTING_PORT", 0))

        self._results["identifiers"] = ids
        return None

    def on_manifest_ready(self, manifest: Dict, ctx: Dict) -> Optional[Dict]:
        if self._results:
            manifest.setdefault("metadata", {})["shellcodeFingerprint"] = self._results
            return manifest
        return None

    # ─── Render ───────────────────────────────────────────────────────────

    def render_results(self) -> Optional[Any]:
        if not self._results:
            return None
        try:
            from rich.text import Text
            from rich.console import Group
            from cs_aggregator.utils.rich_output import DIM, MUTED, ACCENT_PRIMARY, ACCENT_WARN

            parts = []

            # Header
            h = Text()
            h.append("    ◈ ", style=ACCENT_PRIMARY)
            h.append("SHELLCODE FINGERPRINT", style=f"bold {ACCENT_PRIMARY}")
            parts.append(h)
            parts.append(Text(f"    {'─' * 68}", style=DIM))

            # Loader classification - compact
            loader = self._results.get("loader", {})
            t = Text()
            t.append("    Loader   ", style=DIM)
            t.append(f"{loader.get('type', '?')}", style="bold bright_white")
            magic_hex = loader.get("magic_hex", "")
            if magic_hex:
                known = CS_MAGIC_MAP.get(magic_hex, "")
                t.append(f"  0x{magic_hex.upper()}", style="bright_cyan")
                if known:
                    t.append(f" ({known})", style=DIM)
            parts.append(t)

            # Architecture - inline
            arch = self._results.get("architecture", {})
            a = Text()
            a.append("    Arch     ", style=DIM)
            a.append(f"{arch.get('bits', '?')}-bit", style="bold bright_white")
            indicators = arch.get("indicators", [])
            if indicators:
                a.append(f"  {', '.join(indicators[:3])}", style=DIM)
            parts.append(a)

            # PE Structure - compact inline
            pe = self._results.get("pe_structure", {})
            if pe:
                p = Text()
                p.append("    PE       ", style=DIM)
                p.append(f"{pe.get('machine', '?')}", style="bright_white")
                p.append(f"  {pe.get('sections', 0)} sections", style=MUTED)
                p.append(f"  {pe.get('imports', 0)} imports", style=MUTED)
                p.append(f"  {pe.get('exports', 0)} exports", style=MUTED)
                parts.append(p)

            # Syscalls - compact
            sc = self._results.get("syscalls", {})
            method = sc.get("method", "none")
            method_styles = {"direct": "bold bright_yellow", "indirect": "bold bright_green", "none": DIM}
            s = Text()
            s.append("    Syscall  ", style=DIM)
            s.append(method.upper(), style=method_styles.get(method, "bright_white"))
            s.append(f"  via {sc.get('source', 'byte scan')}", style=DIM)
            parts.append(s)

            # Evasion - inline flags
            ev = self._results.get("evasion", {})
            e = Text()
            e.append("    Evasion  ", style=DIM)
            evasion_flags = []
            for name, key in [("SleepMask", "sleep_mask"), ("BeaconGate", "beacon_gate"),
                              ("Cleanup", "cleanup"), ("CFG-Caution", "cfg_caution")]:
                if ev.get(key, False):
                    evasion_flags.append(name)
            if evasion_flags:
                for i, flag in enumerate(evasion_flags):
                    if i > 0:
                        e.append("  ", style=DIM)
                    e.append(f"✓ {flag}", style="bright_green")
            else:
                e.append("none detected", style=DIM)
            parts.append(e)

            # Operational details - compact
            ops = []
            if ev.get("injection_allocator"):
                ops.append(f"Inject:{ev['injection_allocator']}")
            if ev.get("bof_allocator"):
                ops.append(f"BOF:{ev['bof_allocator']}")
            if ev.get("exit_function", "none") != "none":
                ops.append(f"Exit:{ev['exit_function']}")
            if ops:
                o = Text()
                o.append("    Ops      ", style=DIM)
                o.append("  ".join(ops), style=MUTED)
                parts.append(o)

            # Memory layout - compact
            layout = self._results.get("memory_layout", {})
            m = Text()
            m.append("    Memory   ", style=DIM)
            m.append(f"{layout.get('total_size', 0):,} bytes", style="bright_white")
            if layout.get("loader_end", 0) > 0:
                m.append(f"  loader:0x0-0x{layout['loader_end']:x}", style=DIM)
            parts.append(m)

            # PIC Safety - inline
            pic = self._results.get("pic_analysis", {})
            pic_safe = pic.get("is_pic_safe", True)
            pc = Text()
            pc.append("    PIC      ", style=DIM)
            if pic_safe:
                pc.append("✓ SAFE", style="bold bright_green")
            else:
                pc.append("✗ UNSAFE", style="bold bright_red")
            for note in pic.get("notes", [])[:2]:
                pc.append(f"  {note}", style=DIM)
            parts.append(pc)

            return Group(*parts)
        except Exception:
            return None

    def get_results(self) -> Optional[Dict[str, Any]]:
        return self._results if self._results else None

    def cleanup(self) -> None:
        self._results.clear()
        self._raw_data = None

    # ─── Analysis: Loader Stub (raw bytes, first ~8KB) ────────────────────

    @staticmethod
    def _classify_loader(data: bytes) -> Dict[str, Any]:
        """Classify loader using the STUB region only (first ~8KB)."""
        result: Dict[str, Any] = {}

        # Detect PE magic (may be spoofed by profile)
        magic_hex = data[:4].hex() if len(data) >= 4 else ""
        result["magic_hex"] = magic_hex

        # Find the actual DLL/PE start using centralized PE utils
        # This dynamically uses any custom magic bytes registered from profiles
        dll_offset = find_pe_offset(data, max_search=min(len(data), 8192))
        if dll_offset < 0:
            dll_offset = 0

        result["stub_size"] = dll_offset if dll_offset > 0 else 0

        # Check known loader signatures in the stub region
        stub = data[:max(dll_offset, 4096)]
        for sig, name, desc in LOADER_SIGS:
            idx = stub.find(sig)
            if idx >= 0:
                result["type"] = name
                result["description"] = desc
                result["sig_offset"] = idx
                return result

        # Classify by magic bytes
        known_magic = CS_MAGIC_MAP.get(magic_hex) or CS_MAGIC_MAP.get(magic_2)
        if known_magic:
            if dll_offset == 0:
                result["type"] = "cs_profile_loader"
                result["description"] = f"CS Loader with {known_magic} magic"
            else:
                result["type"] = "custom_udrl"
                result["description"] = f"Custom UDRL ({known_magic} magic, {dll_offset:,}B stub)"
        else:
            result["type"] = "unknown_udrl"
            result["description"] = f"Unknown loader (magic: 0x{magic_hex.upper()})"

        return result

    @staticmethod
    def _detect_architecture(data: bytes) -> Dict[str, Any]:
        """Detect architecture from instruction patterns in first 8KB."""
        scan = data[:min(len(data), 8192)]
        x64_indicators = []
        x86_indicators = []

        # x64: REX prefix density
        rex_count = sum(1 for b in scan if 0x48 <= b <= 0x4F)
        if rex_count > 50:
            x64_indicators.append("REX prefixes")
        if b"\x48\x89\xE5" in scan:
            x64_indicators.append("mov rbp,rsp")
        if b"\x48\x83\xEC" in scan:
            x64_indicators.append("sub rsp,imm8")
        if b"\x48\x8D\x05" in scan:
            x64_indicators.append("lea rax,[rip+disp]")
        if b"\x41\x57" in scan or b"\x41\x56" in scan:
            x64_indicators.append("push r15/r14")

        # x86
        if b"\x55\x89\xE5" in scan:
            x86_indicators.append("push ebp; mov ebp,esp")
        if b"\x83\xEC" in scan and not x64_indicators:
            x86_indicators.append("sub esp,imm8")

        if len(x64_indicators) >= 2:
            return {"bits": 64, "indicators": x64_indicators}
        elif x86_indicators:
            return {"bits": 32, "indicators": x86_indicators}
        return {"bits": 0, "indicators": ["inconclusive"]}

    @staticmethod
    def _detect_api_hashing(data: bytes) -> Dict[str, Any]:
        """Detect API hashing in the LOADER STUB only (first ~4KB).

        The loader is unencrypted, so hash-based resolution patterns
        are visible. The DLL body is encrypted — scanning it is useless.
        """
        stub = data[:min(len(data), 4096)]

        # ROR13: ror edi, 0x0D (x86/x64)
        if b"\xC1\xCF\x0D" in stub:
            return {"method": "ror13", "details": "ROR13 hash-based (CS/Metasploit default)"}

        # DJB2: add eax, 0x21
        if b"\x83\xC0\x21" in stub:
            return {"method": "djb2", "details": "DJB2 hash-based API resolution"}

        # API hashing via multiply-and-add (common in custom UDRLs)
        # imul reg, reg, imm32 pattern
        if b"\x69" in stub[:2048]:
            # Count imul patterns - custom UDRLs often use these
            imul_count = stub[:2048].count(b"\x69")
            if imul_count > 3:
                return {"method": "custom_hash", "details": f"Custom hash function ({imul_count} imul patterns in stub)"}

        # CRC32 init value
        if b"\xFF\xFF\xFF\xFF" in stub[:1024]:
            return {"method": "crc32", "details": "CRC32-based API resolution"}

        return {"method": "hash_based (obfuscated)", "details": "Loader uses hash-based resolution (pattern not in known database)"}

    @staticmethod
    def _detect_api_hashing_decrypted(dll_data: bytes) -> Dict[str, Any]:
        """Check decrypted DLL for API resolution evidence."""
        # In decrypted DLL, we CAN find import strings
        has_gpa = b"GetProcAddress" in dll_data
        has_ll = b"LoadLibrary" in dll_data
        has_ntdll = b"ntdll" in dll_data
        has_kernel32 = b"kernel32" in dll_data or b"KERNEL32" in dll_data

        details = []
        if has_gpa:
            details.append("GetProcAddress")
        if has_ll:
            details.append("LoadLibraryA/W")
        if has_ntdll:
            details.append("ntdll.dll")
        if has_kernel32:
            details.append("kernel32.dll")

        if has_gpa and has_ll:
            return {"method": "dynamic_import", "details": f"Runtime resolution via {', '.join(details)}"}
        elif has_gpa:
            return {"method": "import_by_name", "details": f"Direct GetProcAddress ({', '.join(details)})"}
        elif details:
            return {"method": "dynamic_load", "details": f"DLL references: {', '.join(details)}"}
        return {"method": "custom_resolution", "details": "No standard import patterns in decrypted DLL"}

    @staticmethod
    def _scan_syscall_stubs(dll_data: bytes) -> Dict[str, Any]:
        """Scan DECRYPTED DLL for syscall stub patterns."""
        # mov r10, rcx; mov eax, SSN
        stub_pattern = b"\x4C\x8B\xD1\xB8"
        syscall_instr = b"\x0F\x05"
        stub_count = dll_data.count(stub_pattern)
        sc_count = dll_data.count(syscall_instr)

        if stub_count > 0:
            method = "direct" if sc_count > stub_count // 2 else "indirect"
        else:
            method = "none"

        return {"method": method, "stub_count": stub_count, "syscall_instructions": sc_count, "source": "DLL binary scan"}

    @staticmethod
    def _analyze_layout(data: bytes) -> Dict[str, Any]:
        """Analyze memory layout — find loader/DLL boundary."""
        total = len(data)

        # Find DLL start using centralized PE utils (dynamically handles
        # any custom magic bytes registered from profiles)
        dll_offset = find_pe_offset(data, max_search=min(total, 8192))
        if dll_offset < 0:
            dll_offset = 0

        # Detect alignment
        if dll_offset > 0:
            if dll_offset % 0x1000 == 0:
                alignment = "page-aligned (0x1000)"
            elif dll_offset % 0x100 == 0:
                alignment = f"0x100-aligned"
            elif dll_offset % 0x10 == 0:
                alignment = f"0x10-aligned"
            else:
                alignment = "unaligned"
        else:
            alignment = "unknown"

        # Count null padding regions
        null_regions = 0
        in_null = False
        for i in range(0, total, 256):
            chunk = data[i:i + 256]
            if chunk == b"\x00" * 256:
                if not in_null:
                    null_regions += 1
                    in_null = True
            else:
                in_null = False

        loader_end = dll_offset if dll_offset > 0 else 0

        return {
            "total_size": total,
            "dll_offset": dll_offset,
            "loader_end": loader_end,
            "alignment": alignment,
            "null_padding_regions": null_regions,
        }

    @staticmethod
    def _check_pic_safety(data: bytes) -> Dict[str, Any]:
        """Analyze position-independent code safety in loader stub."""
        stub = data[:min(len(data), 8192)]
        notes = []
        is_safe = True

        # RIP-relative LEA (PIC-safe)
        rip_lea = stub.count(b"\x48\x8D\x05") + stub.count(b"\x48\x8D\x0D") + stub.count(b"\x48\x8D\x15")
        if rip_lea > 0:
            notes.append(f"{rip_lea} RIP-relative LEA references (PIC-safe)")

        # Indirect calls via RIP (PIC-safe)
        ind_call = stub.count(b"\xFF\x15")
        if ind_call > 0:
            notes.append(f"{ind_call} indirect calls [rip+disp] (PIC-safe)")

        # call rel32 (PIC-safe within the blob)
        call_rel = stub.count(b"\xE8")
        if call_rel > 0:
            notes.append(f"{call_rel} relative calls (PIC-safe)")

        # Absolute mov rax, imm64 patterns (potentially non-PIC)
        abs_mov = stub.count(b"\x48\xB8")
        if abs_mov > 2:
            notes.append(f"⚠ {abs_mov} mov rax,imm64 (may be non-PIC)")
            is_safe = False

        return {"is_pic_safe": is_safe, "notes": notes}
