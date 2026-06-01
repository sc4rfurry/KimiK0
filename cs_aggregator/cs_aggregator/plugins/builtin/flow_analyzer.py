"""Shellcode Flow Analyzer — Dynamic execution flow + artifact relational graph.

Uses Capstone disassembly to trace basic blocks, extract API artifacts,
detect multi-stage loading sequences, and render execution flow diagrams
and relational artifact graphs in the terminal using Rich.
"""

import struct
import hashlib
from typing import Any, Dict, List, Optional, Set, Tuple

# ─── Known API Hash Databases ────────────────────────────────────────────────
# CRC32/ROR13 hashes commonly used by CS loaders
KNOWN_API_HASHES: Dict[int, str] = {
    # ROR13 hashes (CS default)
    0x726774C: "kernel32.dll!LoadLibraryA",
    0xA779563A: "kernel32.dll!GetProcAddress",
    0x6B8029: "kernel32.dll!GetModuleHandleA",
    0xEC0E4E8E: "kernel32.dll!LoadLibraryExW",
    0x0E8AFE98: "kernel32.dll!VirtualAlloc",
    0x91AFCA54: "kernel32.dll!VirtualFree",
    0xE553A458: "kernel32.dll!VirtualProtect",
    0x7946C61B: "kernel32.dll!VirtualQuery",
    0x4FDAF6DA: "kernel32.dll!CreateFileA",
    0x1FC0EAEE: "kernel32.dll!CloseHandle",
    0xE13BEC74: "kernel32.dll!ReadFile",
    0x5BAE572D: "kernel32.dll!WriteFile",
    0x3CFA685D: "kernel32.dll!GetFileSize",
    0xC38AE110: "kernel32.dll!CreateThread",
    0xE035F044: "kernel32.dll!Sleep",
    0xB16B3F17: "kernel32.dll!ExitThread",
    0x73E2D87E: "kernel32.dll!ExitProcess",
    0xE27D6F28: "kernel32.dll!GetCurrentProcess",
    0x4FD18963: "kernel32.dll!GetCurrentThread",
    0x160D6838: "kernel32.dll!CreateProcessA",
    0x56A2B5F0: "kernel32.dll!WaitForSingleObject",
    0x0E8FB562: "ntdll.dll!NtAllocateVirtualMemory",
    0x50E92847: "ntdll.dll!NtWriteVirtualMemory",
    0xDC0D38F0: "ntdll.dll!NtCreateThreadEx",
    0x3F880E26: "ntdll.dll!NtProtectVirtualMemory",
    0x062398E4: "ntdll.dll!RtlCreateUserThread",
    0x30383E4B: "ntdll.dll!NtMapViewOfSection",
    0x0F8B7856: "ntdll.dll!NtUnmapViewOfSection",
    0xADCBCF57: "ntdll.dll!NtClose",
    0x9DBD95A6: "kernel32.dll!GetSystemInfo",
    0x876F8B31: "kernel32.dll!HeapAlloc",
    0xA56A3B36: "kernel32.dll!HeapFree",
    0xBB5F9EAD: "kernel32.dll!GetProcessHeap",
    0x9E5A41F4: "ws2_32.dll!WSAStartup",
    0xC7701394: "ws2_32.dll!connect",
    0x6174A599: "ws2_32.dll!closesocket",
    0xE0DF0FEA: "ws2_32.dll!WSASocketA",
    0x006B8029: "kernel32.dll!GetModuleHandleA",
    0xCC8E00F4: "kernel32.dll!WaitForSingleObjectEx",
    0x4C0297FA: "advapi32.dll!OpenProcessToken",
    0x77B18B82: "advapi32.dll!LookupPrivilegeValueA",
    0x0DCE8D2F: "advapi32.dll!AdjustTokenPrivileges",
}

# Stage classification patterns
STAGE_PATTERNS = {
    "api_resolver": {
        "description": "API Resolution Loop",
        "indicators": ["ror", "xor", "loop", "cmp"],
        "color": "#5eead4",
    },
    "memory_alloc": {
        "description": "Memory Allocation",
        "indicators": ["VirtualAlloc", "NtAllocateVirtualMemory", "HeapAlloc"],
        "color": "#7b8cff",
    },
    "payload_decode": {
        "description": "Payload Decryption/Decode",
        "indicators": ["xor", "sub", "rol", "ror", "rep movsb"],
        "color": "#ff6ec7",
    },
    "execution_transfer": {
        "description": "Execution Transfer",
        "indicators": ["call rax", "jmp rax", "call rbx", "ret"],
        "color": "#fbbf24",
    },
    "dll_loading": {
        "description": "DLL Loading",
        "indicators": ["LoadLibrary", "LdrLoadDll", "GetModuleHandle"],
        "color": "#a77de5",
    },
}


class BasicBlock:
    """Represents a basic block in the control flow."""
    __slots__ = ("start", "end", "size", "instructions", "successors",
                 "is_entry", "is_exit", "stage_type", "apis_called", "label")

    def __init__(self, start: int):
        self.start = start
        self.end = start
        self.size = 0
        self.instructions: List[Tuple[int, str, str]] = []  # (addr, mnemonic, op_str)
        self.successors: List[int] = []
        self.is_entry = False
        self.is_exit = False
        self.stage_type: Optional[str] = None
        self.apis_called: List[str] = []
        self.label = ""


class ShellcodeFlowAnalyzerPlugin:
    """Dynamic shellcode flow analysis with relational artifact graphs."""

    name = "flow_analyzer"
    version = "1.0.0"
    description = "Execution flow tracing, artifact extraction, relational graph, and stage analysis via Capstone"
    hooks = ["on_payload_loaded", "on_pe_parsed", "on_config_extracted"]

    def __init__(self) -> None:
        self._results: Dict[str, Any] = {}
        self._raw_data: Optional[bytes] = None
        self._dll_data: Optional[bytes] = None
        self._config: Dict[str, Any] = {}
        self._blocks: List[BasicBlock] = []
        self._artifacts: Dict[str, List[Dict[str, Any]]] = {
            "apis": [], "strings": [], "crypto": [],
            "urls": [], "dlls": [], "syscalls": [],
        }
        self._relations: List[Dict[str, Any]] = []
        self._syscall_stubs: List[Dict[str, Any]] = []
        self._anti_analysis: List[Dict[str, Any]] = []
        self._memory_map: List[Dict[str, Any]] = []
        self._opcode_stats: Dict[str, Any] = {}
        self._call_graph: List[Dict[str, Any]] = []
        self._gadgets: List[Dict[str, Any]] = []

    def initialize(self, config: Dict[str, Any]) -> None:
        pass

    # ─── Pipeline Hooks ──────────────────────────────────────────────────

    def on_payload_loaded(self, data: bytes, ctx: Dict[str, Any]) -> None:
        self._raw_data = data

    def on_version_detected(self, version_result: Any, ctx: Dict[str, Any]) -> None:
        pass

    def on_loader_extracted(self, loader_result: Any, ctx: Dict[str, Any]) -> None:
        pass

    def on_pe_parsed(self, pe_info: Any, dll_data: bytes, ctx: Dict[str, Any]) -> None:
        self._dll_data = dll_data

    def on_config_extracted(self, config: Dict[str, Any], ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._config = config
        self._run_analysis()
        return None

    def on_manifest_ready(self, manifest: Dict, ctx: Dict) -> Optional[Dict]:
        if self._results:
            manifest.setdefault("metadata", {})["flowAnalysis"] = self._results
            return manifest
        return None

    # ─── Core Analysis ───────────────────────────────────────────────────

    def _run_analysis(self) -> None:
        """Run full analysis pipeline."""
        data = self._raw_data
        if not data:
            return

        # 1. Disassemble and build basic blocks
        self._blocks = self._build_cfg(data)

        # 2. Extract artifacts from raw bytes
        self._extract_api_hashes(data)
        self._extract_strings(data)
        self._extract_crypto_constants(data)
        self._extract_dll_refs(data)

        # 3. Advanced analysis passes
        self._scan_syscall_stubs(data)
        self._detect_anti_analysis(data)
        self._build_memory_map(data)
        self._compute_opcode_stats()
        self._build_call_graph()
        self._scan_gadgets(data)

        # 4. Classify stages
        self._classify_stages()

        # 5. Build relations
        self._build_relations()

        # 6. Enrich from config
        self._enrich_from_config()

        # 7. Build results
        self._results = {
            "flow": {
                "total_blocks": len(self._blocks),
                "entry_blocks": sum(1 for b in self._blocks if b.is_entry),
                "exit_blocks": sum(1 for b in self._blocks if b.is_exit),
                "total_instructions": sum(len(b.instructions) for b in self._blocks),
                "stages": self._get_stage_summary(),
            },
            "artifacts": {
                cat: items for cat, items in self._artifacts.items() if items
            },
            "relations": self._relations,
            "execution_flow": self._get_execution_flow(),
            "syscall_stubs": self._syscall_stubs,
            "anti_analysis": self._anti_analysis,
            "memory_map": self._memory_map,
            "opcode_stats": self._opcode_stats,
            "call_graph": self._call_graph,
            "gadgets": self._gadgets,
        }

    def _build_cfg(self, data: bytes, max_insns: int = 2000) -> List[BasicBlock]:
        """Build control flow graph via Capstone disassembly."""
        try:
            import capstone
        except ImportError:
            return self._build_cfg_heuristic(data)

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True

        # Disassemble from entry point
        leaders: Set[int] = {0}
        insns_list: List[Tuple[int, int, str, str]] = []

        for insn in md.disasm(data[:min(len(data), 32768)], 0):
            if len(insns_list) >= max_insns:
                break
            insns_list.append((insn.address, insn.size, insn.mnemonic, insn.op_str))

            if insn.mnemonic in ("jmp", "je", "jne", "jz", "jnz", "jb", "jbe",
                                  "ja", "jae", "jl", "jle", "jg", "jge", "js",
                                  "jns", "jo", "jno", "jp", "jnp", "jcxz", "jecxz",
                                  "jrcxz", "loop", "loope", "loopne"):
                try:
                    target = int(insn.op_str, 16) if insn.op_str.startswith("0x") else None
                    if target is not None and 0 <= target < len(data):
                        leaders.add(target)
                except (ValueError, TypeError):
                    pass
                leaders.add(insn.address + insn.size)
            elif insn.mnemonic in ("ret", "retn", "retf", "int3", "hlt"):
                if insn.address + insn.size < len(data):
                    leaders.add(insn.address + insn.size)
            elif insn.mnemonic == "call":
                try:
                    target = int(insn.op_str, 16) if insn.op_str.startswith("0x") else None
                    if target is not None and 0 <= target < len(data):
                        leaders.add(target)
                except (ValueError, TypeError):
                    pass

        # Build blocks from leaders
        sorted_leaders = sorted(leaders)
        blocks: List[BasicBlock] = []

        for li, leader in enumerate(sorted_leaders):
            bb = BasicBlock(leader)
            next_leader = sorted_leaders[li + 1] if li + 1 < len(sorted_leaders) else float("inf")

            for addr, size, mnemonic, op_str in insns_list:
                if addr < leader:
                    continue
                if addr >= next_leader:
                    break
                bb.instructions.append((addr, mnemonic, op_str))
                bb.end = addr + size

            if bb.instructions:
                bb.size = bb.end - bb.start
                last_mn = bb.instructions[-1][1]
                last_op = bb.instructions[-1][2]

                if last_mn in ("ret", "retn", "retf", "int3", "hlt"):
                    bb.is_exit = True
                elif last_mn.startswith("j"):
                    try:
                        t = int(last_op, 16)
                        if 0 <= t < len(data):
                            bb.successors.append(t)
                    except (ValueError, TypeError):
                        pass
                    if last_mn != "jmp":
                        bb.successors.append(bb.end)
                else:
                    bb.successors.append(bb.end)

                blocks.append(bb)

        if blocks:
            blocks[0].is_entry = True

        return blocks[:200]  # Cap at 200 blocks

    def _build_cfg_heuristic(self, data: bytes) -> List[BasicBlock]:
        """Fallback CFG builder without Capstone — basic pattern scanning."""
        bb = BasicBlock(0)
        bb.is_entry = True
        bb.size = min(len(data), 256)
        bb.end = bb.size
        bb.instructions = [(0, "data", f"{bb.size} bytes (no disassembler)")]
        return [bb]

    def _extract_api_hashes(self, data: bytes) -> None:
        """Scan for known API resolution hashes in the binary."""
        for offset in range(0, min(len(data) - 4, 16384)):
            val = struct.unpack_from("<I", data, offset)[0]
            if val in KNOWN_API_HASHES:
                api = KNOWN_API_HASHES[val]
                dll, _, func = api.partition("!")
                entry = {
                    "name": func, "dll": dll, "hash": f"0x{val:08x}",
                    "offset": offset, "resolution": "hash_lookup",
                }
                if not any(a["hash"] == entry["hash"] and a["offset"] == offset
                           for a in self._artifacts["apis"]):
                    self._artifacts["apis"].append(entry)

    def _extract_strings(self, data: bytes) -> None:
        """Extract ASCII/wide strings that look like URLs, paths, or API names."""
        import re
        scan_region = data[:min(len(data), 65536)]

        # ASCII strings (6+ chars)
        for m in re.finditer(rb'[\x20-\x7e]{6,120}', scan_region):
            s = m.group().decode("ascii", errors="ignore")
            cat = self._classify_string(s)
            if cat:
                entry = {"value": s, "offset": m.start(), "category": cat, "encoding": "ascii"}
                self._artifacts["strings"].append(entry)
                if cat == "url":
                    self._artifacts["urls"].append({"url": s, "offset": m.start()})

    def _classify_string(self, s: str) -> Optional[str]:
        """Classify a string by content type."""
        sl = s.lower()
        if any(sl.startswith(p) for p in ("http://", "https://", "ftp://")):
            return "url"
        if ".dll" in sl or ".exe" in sl or ".sys" in sl:
            return "module"
        if "\\" in s and ("windows" in sl or "system32" in sl or "temp" in sl):
            return "path"
        if sl.endswith((".php", ".asp", ".aspx", ".jsp", ".cgi", ".js")):
            return "uri"
        if any(w in sl for w in ("mozilla", "user-agent", "content-type", "accept")):
            return "http_header"
        if any(w in sl for w in ("ntdll", "kernel32", "advapi32", "ws2_32", "wininet", "winhttp")):
            return "module"
        return None

    def _extract_crypto_constants(self, data: bytes) -> None:
        """Detect crypto constants (AES S-box, RC4, XOR keys)."""
        scan = data[:min(len(data), 65536)]

        # AES S-box first 8 bytes
        aes_sbox = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5])
        idx = scan.find(aes_sbox)
        if idx >= 0:
            self._artifacts["crypto"].append({
                "type": "aes_sbox", "offset": idx,
                "description": "AES S-box detected",
            })

        # XOR key patterns (repeated 4-byte sequences)
        for off in range(0, min(len(scan) - 16, 4096), 4):
            candidate = scan[off:off+4]
            if candidate == b"\x00\x00\x00\x00" or candidate == b"\xff\xff\xff\xff":
                continue
            if scan[off:off+16] == candidate * 4:
                key_hex = candidate.hex()
                if not any(c["type"] == "xor_key" and c["key"] == key_hex
                           for c in self._artifacts["crypto"]):
                    self._artifacts["crypto"].append({
                        "type": "xor_key", "offset": off,
                        "key": key_hex,
                        "description": f"Repeating XOR key 0x{key_hex}",
                    })

    def _extract_dll_refs(self, data: bytes) -> None:
        """Extract DLL name references."""
        import re
        for m in re.finditer(rb'[a-zA-Z][a-zA-Z0-9_]{2,30}\.(dll|exe|sys)', data[:65536], re.IGNORECASE):
            name = m.group().decode("ascii", errors="ignore")
            if not any(d["name"] == name for d in self._artifacts["dlls"]):
                self._artifacts["dlls"].append({
                    "name": name, "offset": m.start(),
                })

    # ─── Advanced Analysis ───────────────────────────────────────────

    def _scan_syscall_stubs(self, data: bytes) -> None:
        """Detect direct/indirect syscall stubs and extract SSNs.

        Patterns:
          Direct:   mov r10, rcx; mov eax, SSN; syscall
          Indirect: mov r10, rcx; mov eax, SSN; jmp [addr]
        """
        scan = data[:min(len(data), 65536)]
        # Pattern: 4C 8B D1 (mov r10, rcx) + B8 XX XX 00 00 (mov eax, SSN)
        i = 0
        while i < len(scan) - 12:
            if scan[i:i+3] == b"\x4c\x8b\xd1" and scan[i+3] == 0xB8:
                ssn = struct.unpack_from("<H", scan, i + 4)[0]
                # Check for syscall (0F 05) or indirect jmp
                stub_type = "unknown"
                if i + 8 < len(scan):
                    if scan[i+8:i+10] == b"\x0f\x05":
                        stub_type = "direct"
                    elif scan[i+8] in (0xFF, 0xE9, 0xEB):
                        stub_type = "indirect"
                    elif scan[i+6:i+8] == b"\x0f\x05":
                        stub_type = "direct"

                if stub_type != "unknown":
                    self._syscall_stubs.append({
                        "offset": i, "ssn": ssn, "ssn_hex": f"0x{ssn:04x}",
                        "type": stub_type,
                        "raw": scan[i:i+12].hex(),
                    })
                    i += 12
                    continue
            i += 1

    def _detect_anti_analysis(self, data: bytes) -> None:
        """Detect anti-debug, anti-VM, and timing check patterns."""
        scan = data[:min(len(data), 65536)]

        # Anti-debug patterns
        ANTI_PATTERNS = [
            # IsDebuggerPresent: 64 48 8B 04 25 60 00 (gs:[0x60] PEB access)
            (b"\x64\x48\x8b\x04\x25\x60\x00", "peb_access",
             "PEB access (anti-debug: IsDebuggerPresent check)"),
            # NtQueryInformationProcess check
            (b"\x07\x00\x00\x00",  None, None),  # skip, too generic
            # int 2d (kernel anti-debug)
            (b"\xcd\x2d", "int2d", "INT 2D anti-debug trap"),
            # cpuid (VM detection)
            (b"\x0f\xa2", "cpuid", "CPUID (potential VM detection)"),
            # rdtsc (timing check)
            (b"\x0f\x31", "rdtsc", "RDTSC timing check (anti-analysis)"),
            # in al, dx (VM detect via I/O port)
            (b"\xec", None, None),  # too generic alone
        ]

        for pattern, tag, description in ANTI_PATTERNS:
            if tag is None:
                continue
            idx = 0
            while True:
                pos = scan.find(pattern, idx)
                if pos < 0:
                    break
                self._anti_analysis.append({
                    "type": tag, "offset": pos,
                    "description": description,
                })
                idx = pos + len(pattern)

        # Check for NtQueryInformationProcess via API hash
        nqip_hashes = [0x0B268B47]  # Common hash
        for off in range(0, min(len(scan) - 4, 16384)):
            val = struct.unpack_from("<I", scan, off)[0]
            if val in nqip_hashes:
                self._anti_analysis.append({
                    "type": "nqip_hash", "offset": off,
                    "description": "NtQueryInformationProcess hash (anti-debug)",
                })

    def _build_memory_map(self, data: bytes) -> None:
        """Classify memory regions by content type."""
        import math
        REGION_SIZE = 4096
        total = len(data)

        for offset in range(0, total, REGION_SIZE):
            chunk = data[offset:offset + REGION_SIZE]
            size = len(chunk)
            if size == 0:
                continue

            # Calculate entropy
            freq = [0] * 256
            for b in chunk:
                freq[b] += 1
            ent = 0.0
            for f in freq:
                if f > 0:
                    p = f / size
                    ent -= p * math.log2(p)

            # Classify
            null_pct = chunk.count(0) / size
            if null_pct > 0.95:
                region_type = "padding"
            elif ent > 7.5:
                region_type = "encrypted"
            elif ent > 6.5:
                region_type = "compressed"
            elif ent > 4.0:
                region_type = "code"
            elif ent > 2.0:
                region_type = "data"
            else:
                region_type = "sparse"

            # Check for PE header
            if chunk[:2] == b"MZ" or chunk[:4] in (b"OICA", b"OOPS", b"MZAR"):
                region_type = "pe_header"

            self._memory_map.append({
                "offset": offset, "size": size,
                "type": region_type, "entropy": round(ent, 2),
                "null_pct": round(null_pct * 100, 1),
            })

    def _compute_opcode_stats(self) -> None:
        """Compute instruction frequency and distribution statistics."""
        if not self._blocks:
            return

        mnemonic_freq: Dict[str, int] = {}
        total_insns = 0
        branch_count = 0
        call_count = 0
        nop_count = 0
        arith_count = 0
        mem_count = 0

        BRANCH_OPS = {"jmp", "je", "jne", "jz", "jnz", "jb", "jbe", "ja", "jae",
                       "jl", "jle", "jg", "jge", "js", "jns", "loop"}
        ARITH_OPS = {"add", "sub", "mul", "imul", "div", "idiv", "xor", "or",
                      "and", "shl", "shr", "sar", "sal", "ror", "rol", "inc", "dec", "neg", "not"}
        MEM_OPS = {"mov", "lea", "push", "pop", "movzx", "movsx", "movsb",
                    "movsw", "movsd", "movsq", "stosb", "rep"}

        for bb in self._blocks:
            for _, mn, _ in bb.instructions:
                total_insns += 1
                mnemonic_freq[mn] = mnemonic_freq.get(mn, 0) + 1
                if mn in BRANCH_OPS:
                    branch_count += 1
                elif mn == "call":
                    call_count += 1
                elif mn == "nop":
                    nop_count += 1
                if mn in ARITH_OPS:
                    arith_count += 1
                if mn in MEM_OPS:
                    mem_count += 1

        # Top 15 opcodes
        sorted_ops = sorted(mnemonic_freq.items(), key=lambda x: -x[1])[:15]

        self._opcode_stats = {
            "total_instructions": total_insns,
            "unique_mnemonics": len(mnemonic_freq),
            "branch_count": branch_count,
            "call_count": call_count,
            "nop_count": nop_count,
            "arithmetic_count": arith_count,
            "memory_ops_count": mem_count,
            "branch_density": round(branch_count / max(total_insns, 1), 4),
            "call_density": round(call_count / max(total_insns, 1), 4),
            "top_opcodes": [{"mnemonic": m, "count": c,
                             "pct": round(c / max(total_insns, 1) * 100, 1)}
                            for m, c in sorted_ops],
        }

    def _build_call_graph(self) -> None:
        """Build inter-procedural call graph from disassembled blocks."""
        for bb in self._blocks:
            for addr, mn, op in bb.instructions:
                if mn != "call":
                    continue
                target = None
                target_type = "unknown"
                try:
                    if op.startswith("0x"):
                        target = int(op, 16)
                        target_type = "direct"
                    elif op.startswith("r") or op.startswith("e"):
                        target_type = "register"
                    elif "[" in op:
                        target_type = "indirect"
                except (ValueError, TypeError):
                    pass

                entry = {
                    "caller": f"0x{addr:x}",
                    "caller_block": f"0x{bb.start:x}",
                    "target": f"0x{target:x}" if target is not None else op,
                    "type": target_type,
                }
                # Resolve if target matches a known API
                for api in self._artifacts["apis"]:
                    if target is not None and abs(api["offset"] - target) < 16:
                        entry["resolved_api"] = api["name"]
                        break

                self._call_graph.append(entry)

    def _scan_gadgets(self, data: bytes) -> None:
        """Scan for ROP/JOP gadgets (ret/jmp reg terminators)."""
        try:
            import capstone
        except ImportError:
            return

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        scan = data[:min(len(data), 32768)]

        # Find ret/jmp reg locations
        RET_BYTES = {0xC3, 0xCB}
        JMP_REG = [(b"\xff\xe0", "jmp rax"), (b"\xff\xe1", "jmp rcx"),
                    (b"\xff\xe2", "jmp rdx"), (b"\xff\xe3", "jmp rbx"),
                    (b"\xff\xe6", "jmp rsi"), (b"\xff\xe7", "jmp rdi")]

        terminators: List[Tuple[int, str]] = []
        for i, b in enumerate(scan):
            if b in RET_BYTES:
                terminators.append((i, "ret"))
        for pattern, name in JMP_REG:
            idx = 0
            while True:
                pos = scan.find(pattern, idx)
                if pos < 0:
                    break
                terminators.append((pos, name))
                idx = pos + 2

        # For each terminator, try disassembling backwards (up to 20 bytes)
        seen: Set[str] = set()
        for term_off, term_name in terminators[:200]:
            for back in range(1, min(21, term_off + 1)):
                start = term_off - back
                gadget_bytes = scan[start:term_off + (2 if term_name != "ret" else 1)]
                insns = list(md.disasm(gadget_bytes, start))
                if not insns:
                    continue
                # Check if last instruction is the terminator
                last = insns[-1]
                if last.address + last.size != term_off + (2 if term_name != "ret" else 1):
                    continue
                if len(insns) < 2 or len(insns) > 5:
                    continue

                gadget_str = "; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in insns)
                if gadget_str in seen:
                    continue
                seen.add(gadget_str)

                self._gadgets.append({
                    "offset": start,
                    "instructions": gadget_str,
                    "length": len(insns),
                    "terminator": term_name,
                    "bytes": gadget_bytes.hex(),
                })

                if len(self._gadgets) >= 50:
                    return

    def _classify_stages(self) -> None:
        """Classify each basic block by its likely execution stage."""
        for bb in self._blocks:
            mnemonics = " ".join(mn for _, mn, _ in bb.instructions)
            operands = " ".join(op for _, _, op in bb.instructions)
            combined = f"{mnemonics} {operands}".lower()

            # Check API calls from artifacts
            for api in self._artifacts["apis"]:
                if bb.start <= api["offset"] < bb.end:
                    bb.apis_called.append(api["name"])

            # Stage classification
            if any(k in combined for k in ("ror", "rol")) and "cmp" in combined:
                bb.stage_type = "api_resolver"
                bb.label = "API Resolution Loop"
            elif any(a in bb.apis_called for a in ("VirtualAlloc", "NtAllocateVirtualMemory", "HeapAlloc")):
                bb.stage_type = "memory_alloc"
                bb.label = "Memory Allocation"
            elif ("xor" in combined and ("rep" in combined or "loop" in combined)):
                bb.stage_type = "payload_decode"
                bb.label = "Payload Decode"
            elif any(k in combined for k in ("call rax", "call rbx", "call rcx", "jmp rax", "jmp rbx")):
                bb.stage_type = "execution_transfer"
                bb.label = "Execution Transfer"
            elif any(a in bb.apis_called for a in ("LoadLibraryA", "LoadLibraryExW", "LdrLoadDll")):
                bb.stage_type = "dll_loading"
                bb.label = "DLL Loading"

    def _build_relations(self) -> None:
        """Build relational edges between artifacts."""
        # DLL -> API relations
        dll_set: Dict[str, List[str]] = {}
        for api in self._artifacts["apis"]:
            dll = api.get("dll", "unknown")
            dll_set.setdefault(dll, []).append(api["name"])

        for dll, funcs in dll_set.items():
            self._relations.append({
                "source": dll, "source_type": "dll",
                "target_type": "api", "targets": funcs[:10],
                "relation": "exports",
            })

        # Stage -> API relations
        for bb in self._blocks:
            if bb.stage_type and bb.apis_called:
                self._relations.append({
                    "source": bb.label or bb.stage_type,
                    "source_type": "stage",
                    "target_type": "api",
                    "targets": bb.apis_called[:5],
                    "relation": "calls",
                    "block_addr": f"0x{bb.start:x}",
                })

        # Crypto -> Stage relations
        for crypto in self._artifacts["crypto"]:
            self._relations.append({
                "source": crypto["description"],
                "source_type": "crypto",
                "target_type": "stage",
                "targets": ["Payload Decode"],
                "relation": "used_by",
            })

    def _enrich_from_config(self) -> None:
        """Add config-derived artifacts."""
        cfg = self._config
        if not cfg:
            return

        # Syscall info
        sc_method = {0: "none", 1: "direct", 2: "indirect"}.get(
            int(cfg.get("SETTING_SYSCALL_METHOD", 0)), "unknown"
        )
        if sc_method != "none":
            self._artifacts["syscalls"].append({
                "method": sc_method,
                "source": "config",
                "apis": ["NtAllocateVirtualMemory", "NtProtectVirtualMemory",
                         "NtCreateThreadEx", "NtWriteVirtualMemory"],
            })
            self._relations.append({
                "source": f"Syscall ({sc_method})",
                "source_type": "evasion",
                "target_type": "api",
                "targets": ["NtAllocateVirtualMemory", "NtCreateThreadEx"],
                "relation": "wraps",
            })

    def _get_stage_summary(self) -> List[Dict[str, Any]]:
        """Get a list of detected stages for output."""
        stages: List[Dict[str, Any]] = []
        seen: Set[str] = set()
        for bb in self._blocks:
            if bb.stage_type and bb.stage_type not in seen:
                seen.add(bb.stage_type)
                info = STAGE_PATTERNS.get(bb.stage_type, {})
                stages.append({
                    "type": bb.stage_type,
                    "description": info.get("description", bb.stage_type),
                    "block_addr": f"0x{bb.start:x}",
                    "instruction_count": len(bb.instructions),
                    "apis": bb.apis_called[:5],
                })
        return stages

    def _get_execution_flow(self) -> List[Dict[str, Any]]:
        """Build ordered execution flow with edge classification."""
        # Precompute: which blocks are targets of which blocks (for xref/back-edge)
        block_addrs = {f"0x{bb.start:x}" for bb in self._blocks}
        incoming: Dict[str, List[str]] = {}  # addr -> list of source addrs
        for bb in self._blocks:
            for s in bb.successors:
                sa = f"0x{s:x}"
                incoming.setdefault(sa, []).append(f"0x{bb.start:x}")

        flow: List[Dict[str, Any]] = []
        for bb in self._blocks[:30]:
            if not bb.instructions:
                continue

            # Classify edges
            edges: List[Dict[str, Any]] = []
            last_mn = bb.instructions[-1][1]
            for s in bb.successors:
                sa = f"0x{s:x}"
                is_back = s <= bb.start  # back-edge = target is at or before current
                if last_mn == "jmp":
                    edge_type = "unconditional"
                elif last_mn.startswith("j"):
                    # Conditional: one branch taken, one fallthrough
                    if s == bb.end:
                        edge_type = "fallthrough"
                    else:
                        edge_type = "conditional"
                elif last_mn == "call":
                    edge_type = "call"
                else:
                    edge_type = "fallthrough"
                edges.append({
                    "target": sa, "type": edge_type,
                    "is_back_edge": is_back,
                    "in_graph": sa in block_addrs,
                })

            # Build instruction listing (up to 20 per block)
            insn_list = []
            display_insns = bb.instructions[:20]
            for addr, mn, op in display_insns:
                insn_list.append({"addr": f"0x{addr:x}", "mnemonic": mn, "operands": op})

            xrefs_in = incoming.get(f"0x{bb.start:x}", [])

            entry = {
                "addr": f"0x{bb.start:x}",
                "size": bb.size,
                "insn_count": len(bb.instructions),
                "is_entry": bb.is_entry,
                "is_exit": bb.is_exit,
                "stage": bb.stage_type,
                "label": bb.label,
                "edges": edges,
                "instructions": insn_list,
                "truncated": len(bb.instructions) > 20,
                "xrefs_in": xrefs_in,
                # Keep legacy fields for JSON compat
                "successors": [f"0x{s:x}" for s in bb.successors],
                "first_insn": f"{bb.instructions[0][1]} {bb.instructions[0][2]}",
                "last_insn": f"{bb.instructions[-1][1]} {bb.instructions[-1][2]}",
            }
            if bb.apis_called:
                entry["apis"] = bb.apis_called
            flow.append(entry)
        return flow

    # ─── Render (placeholder — chunk 2) ──────────────────────────────────

    def render_results(self) -> Optional[Any]:
        """Render execution flow, relational graph, and artifacts in terminal."""
        if not self._results:
            return None
        try:
            from rich.text import Text
            from rich.tree import Tree
            from rich.table import Table
            from rich.panel import Panel
            from rich.console import Group
            from rich.columns import Columns
            from rich import box as rbox
            from cs_aggregator.utils.rich_output import (
                DIM, MUTED, GRADIENT, _GEM, _ARROW, _BULLET,
                _section_header, confidence_bar,
            )

            parts: list = []
            flow = self._results.get("flow", {})
            artifacts = self._results.get("artifacts", {})
            relations = self._results.get("relations", [])
            exec_flow = self._results.get("execution_flow", [])

            # ── Header ───────────────────────────────────────────────
            _section_header(
                _GEM, "EXECUTION FLOW ANALYSIS",
                f"{flow.get('total_blocks', 0)} blocks · "
                f"{flow.get('total_instructions', 0)} instructions",
                style=GRADIENT[0],
            )

            # ── Stage Pipeline ───────────────────────────────────────
            stages = flow.get("stages", [])
            if stages:
                pipe = Text("    ")
                for i, stg in enumerate(stages):
                    stype = stg["type"]
                    color = STAGE_PATTERNS.get(stype, {}).get("color", "#7b8cff")
                    desc = stg["description"]
                    pipe.append(f"┃ {desc} ┃", style=f"bold {color}")
                    if i < len(stages) - 1:
                        pipe.append(f" {_ARROW} ", style=DIM)
                parts.append(pipe)
                parts.append(Text())

            # ── Control Flow Graph ────────────────────────────────────
            if exec_flow:
                flow_header = Text("    ")
                flow_header.append("⟐ ", style=f"bold {GRADIENT[4]}")
                flow_header.append("CONTROL FLOW GRAPH", style=f"bold {GRADIENT[4]}")
                flow_header.append(f"  {flow.get('total_blocks', 0)} blocks", style=MUTED)

                # Count back-edges for loop indicator
                back_edges = sum(
                    1 for blk in exec_flow
                    for e in blk.get("edges", []) if e.get("is_back_edge")
                )
                if back_edges:
                    flow_header.append(f"  ↺ {back_edges} loop{'s' if back_edges > 1 else ''}", style="#fbbf24")
                parts.append(flow_header)
                parts.append(Text())

                EDGE_STYLES = {
                    "conditional": ("#fbbf24", "?"),
                    "unconditional": ("#5eead4", "→"),
                    "fallthrough": (DIM, "↓"),
                    "call": ("#ff6ec7", "⤷"),
                }

                for i, blk in enumerate(exec_flow):
                    addr = blk["addr"]
                    stage = blk.get("stage")
                    label = blk.get("label", "")
                    insn_count = blk["insn_count"]
                    color = STAGE_PATTERNS.get(stage, {}).get("color", "#7b8cff") if stage else "#7b8cff"
                    xrefs = blk.get("xrefs_in", [])

                    # ── Block top border ──
                    # Node type indicator
                    if blk.get("is_entry"):
                        node_icon = "▶"
                        node_style = "bold #5eead4"
                        border_color = "#5eead4"
                    elif blk.get("is_exit"):
                        node_icon = "■"
                        node_style = "bold #f87171"
                        border_color = "#f87171"
                    else:
                        node_icon = "◆"
                        node_style = f"bold {color}"
                        border_color = color

                    # Xref badge
                    xref_str = ""
                    if xrefs:
                        xref_str = f"  ← {','.join(xrefs)}"

                    # Top border with address + metadata
                    top = Text("      ")
                    top.append(f"╔══", style=border_color)
                    top.append(f" {node_icon} ", style=node_style)
                    top.append(f"BB {addr}", style=f"bold {border_color}")
                    top.append(f"  {insn_count} insns  {blk['size']}B", style=DIM)
                    if label:
                        top.append(f"  ⟪{label}⟫", style=f"italic {color}")
                    if label:
                        lbl_len = len(f"BB {addr}  {insn_count} insns  {blk['size']}B  {label}")
                    else:
                        lbl_len = len(f"BB {addr}  {insn_count} insns  {blk['size']}B")
                    remaining_width = max(0, 58 - lbl_len)
                    top.append("═" * min(remaining_width, 20), style=border_color)
                    top.append("╗", style=border_color)
                    parts.append(top)

                    # Xref line (if incoming references)
                    if xrefs:
                        xr = Text("      ")
                        xr.append("║", style=border_color)
                        xr.append("  xrefs: ", style=DIM)
                        for xi, xref in enumerate(xrefs[:4]):
                            xr.append(xref, style=MUTED)
                            if xi < min(len(xrefs), 4) - 1:
                                xr.append(", ", style=DIM)
                        if len(xrefs) > 4:
                            xr.append(f" +{len(xrefs)-4}", style=DIM)
                        parts.append(xr)

                    # Instructions inside the block
                    insns = blk.get("instructions", [])
                    for ins in insns:
                        il = Text("      ")
                        il.append("║", style=border_color)
                        il.append(f"  {ins['addr']:>8s}  ", style=DIM)

                        mn = ins["mnemonic"]
                        op = ins["operands"]

                        # Color-code by instruction type
                        if mn in ("call",):
                            il.append(mn, style="bold #ff6ec7")
                        elif mn in ("jmp", "je", "jne", "jz", "jnz", "jb", "jbe",
                                     "ja", "jae", "jl", "jle", "jg", "jge", "loop"):
                            il.append(mn, style="bold #fbbf24")
                        elif mn in ("ret", "retn", "int3", "hlt"):
                            il.append(mn, style="bold #f87171")
                        elif mn in ("push", "pop", "mov", "lea", "movzx"):
                            il.append(mn, style="#7b8cff")
                        elif mn in ("xor", "or", "and", "shl", "shr", "ror", "rol",
                                     "add", "sub", "inc", "dec", "not", "neg"):
                            il.append(mn, style="#a77de5")
                        elif mn in ("nop",):
                            il.append(mn, style=DIM)
                        elif mn in ("syscall",):
                            il.append(mn, style="bold #f87171")
                        else:
                            il.append(mn, style="bright_white")

                        if op:
                            il.append(f" {op}", style=DIM)
                        parts.append(il)

                    if blk.get("truncated"):
                        tr = Text("      ")
                        tr.append("║", style=border_color)
                        tr.append(f"  ... +{insn_count - len(insns)} more instructions", style=DIM)
                        parts.append(tr)

                    # APIs called (inside block)
                    apis = blk.get("apis", [])
                    if apis:
                        al = Text("      ")
                        al.append("║", style=border_color)
                        al.append("  ⤷ ", style="#ff6ec7")
                        for j, api in enumerate(apis[:3]):
                            al.append(api, style="bold #ff6ec7")
                            if j < min(len(apis), 3) - 1:
                                al.append(", ", style=DIM)
                        parts.append(al)

                    # Bottom border
                    bot = Text("      ")
                    bot.append(f"╚{'═' * 60}╝", style=border_color)
                    parts.append(bot)

                    # ── Edge arrows ──
                    edges = blk.get("edges", [])
                    if edges:
                        for edge in edges:
                            e_color, e_icon = EDGE_STYLES.get(edge["type"], (DIM, "→"))
                            el = Text("        ")
                            if edge.get("is_back_edge"):
                                el.append("↺ ", style="bold #f87171")
                                el.append("LOOP ", style="bold #f87171")
                            else:
                                el.append(f"{e_icon} ", style=e_color)
                            el.append(edge["target"], style=f"bold {e_color}")
                            el.append(f"  [{edge['type']}]", style=DIM)
                            if not edge.get("in_graph"):
                                el.append("  (out of scope)", style=DIM)
                            parts.append(el)

                    # Connector between blocks
                    if i < len(exec_flow) - 1:
                        c = Text("        ")
                        c.append("│", style=DIM)
                        parts.append(c)

                parts.append(Text())

            # ── Relational Graph ─────────────────────────────────────
            if relations:
                rg_header = Text("    ")
                rg_header.append("◈ ", style=f"bold {GRADIENT[1]}")
                rg_header.append("ARTIFACT RELATIONS", style=f"bold {GRADIENT[1]}")
                parts.append(rg_header)

                TYPE_COLORS = {
                    "dll": "#a77de5", "api": "#5eead4", "stage": "#fbbf24",
                    "crypto": "#ff6ec7", "evasion": "#7b8cff",
                }

                for rel in relations:
                    src = rel["source"]
                    src_type = rel.get("source_type", "?")
                    targets = rel.get("targets", [])
                    relation = rel.get("relation", "->")
                    src_color = TYPE_COLORS.get(src_type, MUTED)

                    r = Text("      ")
                    r.append(f"[{src_type}] ", style=f"bold {src_color}")
                    r.append(src, style=f"bold {src_color}")
                    r.append(f"  ──{relation}──▶  ", style=DIM)

                    tgt_color = TYPE_COLORS.get(rel.get("target_type", ""), MUTED)
                    for k, tgt in enumerate(targets):
                        r.append(tgt, style=tgt_color)
                        if k < len(targets) - 1:
                            r.append(", ", style=DIM)
                    parts.append(r)

                parts.append(Text())

            # ── Artifact Summary Table ───────────────────────────────
            total_artifacts = sum(len(v) for v in artifacts.values())
            if total_artifacts > 0:
                tbl_header = Text("    ")
                tbl_header.append("✦ ", style=f"bold {GRADIENT[3]}")
                tbl_header.append("EXTRACTED ARTIFACTS", style=f"bold {GRADIENT[3]}")
                tbl_header.append(f"  {total_artifacts} total", style=MUTED)
                parts.append(tbl_header)

                CAT_ICONS = {
                    "apis": ("⟐", "#5eead4"), "strings": ("◇", "#fbbf24"),
                    "crypto": ("◈", "#ff6ec7"), "dlls": ("◆", "#a77de5"),
                    "urls": ("⊕", "#7b8cff"), "syscalls": ("✦", "#f87171"),
                }

                for cat, items in artifacts.items():
                    icon, color = CAT_ICONS.get(cat, ("·", MUTED))
                    cat_line = Text(f"      {icon} ", style=f"bold {color}")
                    cat_line.append(f"{cat.upper()}", style=f"bold {color}")
                    cat_line.append(f"  ({len(items)})", style=MUTED)
                    parts.append(cat_line)

                    for item in items:
                        detail = Text("        ")
                        if cat == "apis":
                            detail.append(f"{item.get('name', '?')}", style="bright_white")
                            detail.append(f"  {item.get('hash', '')}", style=DIM)
                            detail.append(f"  @{item.get('offset', 0):#x}", style=DIM)
                        elif cat == "dlls":
                            detail.append(item.get("name", "?"), style="bright_white")
                            detail.append(f"  @{item.get('offset', 0):#x}", style=DIM)
                        elif cat == "crypto":
                            detail.append(item.get("description", "?"), style="bright_white")
                            detail.append(f"  @{item.get('offset', 0):#x}", style=DIM)
                        elif cat == "strings":
                            val = item.get("value", "")
                            if len(val) > 60:
                                val = val[:60] + "…"
                            detail.append(val, style="bright_white")
                            detail.append(f"  [{item.get('category', '')}]", style=DIM)
                        elif cat == "syscalls":
                            detail.append(f"method={item.get('method', '?')}", style="bright_white")
                            apis = item.get("apis", [])
                            if apis:
                                detail.append(f"  wraps: {', '.join(apis)}", style=DIM)
                        else:
                            detail.append(str(item)[:80], style=DIM)
                        parts.append(detail)

            # ── Syscall Stubs ────────────────────────────────────────
            stubs = self._results.get("syscall_stubs", [])
            if stubs:
                parts.append(Text())
                sh = Text("    ")
                sh.append("✦ ", style="bold #f87171")
                sh.append("SYSCALL STUBS", style="bold #f87171")
                sh.append(f"  {len(stubs)} detected", style=MUTED)
                parts.append(sh)

                for stub in stubs:
                    s = Text("      ")
                    s.append(f"SSN {stub['ssn_hex']}", style="bold bright_white")
                    s.append(f"  [{stub['type']}]", style=f"bold {'#5eead4' if stub['type'] == 'indirect' else '#fbbf24'}")
                    s.append(f"  @{stub['offset']:#x}", style=DIM)
                    s.append(f"  {stub['raw'][:16]}…", style=DIM)
                    parts.append(s)

            # ── Anti-Analysis ────────────────────────────────────────
            aa = self._results.get("anti_analysis", [])
            if aa:
                parts.append(Text())
                ah = Text("    ")
                ah.append("⚠ ", style="bold #fbbf24")
                ah.append("ANTI-ANALYSIS TECHNIQUES", style="bold #fbbf24")
                ah.append(f"  {len(aa)} detected", style=MUTED)
                parts.append(ah)

                seen_types: set = set()
                for item in aa:
                    tag = item["type"]
                    if tag in seen_types:
                        continue
                    seen_types.add(tag)
                    count = sum(1 for a in aa if a["type"] == tag)
                    a = Text("      ")
                    a.append(f"{'●':>2s} ", style="#fbbf24")
                    a.append(item["description"], style="bright_white")
                    if count > 1:
                        a.append(f"  ×{count}", style=MUTED)
                    a.append(f"  @{item['offset']:#x}", style=DIM)
                    parts.append(a)

            # ── Memory Region Map ───────────────────────────────────
            mmap = self._results.get("memory_map", [])
            if mmap:
                parts.append(Text())
                # Count regions by type
                type_counts: Dict[str, int] = {}
                ent_min = 8.0
                ent_max = 0.0
                for region in mmap:
                    rt = region["type"]
                    type_counts[rt] = type_counts.get(rt, 0) + 1
                    e = region.get("entropy", 0)
                    if e < ent_min:
                        ent_min = e
                    if e > ent_max:
                        ent_max = e

                mh = Text("    ")
                mh.append("◆ ", style=f"bold {GRADIENT[4]}")
                mh.append("MEMORY REGION MAP", style=f"bold {GRADIENT[4]}")
                mh.append(f"  {len(mmap)} regions", style=MUTED)
                mh.append(f"  entropy {ent_min:.2f}–{ent_max:.2f}", style=DIM)
                parts.append(mh)

                TYPE_CHARS = {
                    "code": ("█", "#5eead4"), "data": ("▓", "#7b8cff"),
                    "encrypted": ("█", "#ff6ec7"), "compressed": ("▒", "#fbbf24"),
                    "padding": ("░", DIM), "sparse": ("·", DIM),
                    "pe_header": ("▣", "#a77de5"),
                }

                # Region type summary bar
                for rtype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
                    ch, color = TYPE_CHARS.get(rtype, ("?", MUTED))
                    pct = count / len(mmap) * 100
                    bar_w = max(1, int(pct / 100 * 30))
                    tl = Text("      ")
                    tl.append(f"{ch} {rtype:<12s}", style=f"bold {color}")
                    tl.append("▓" * bar_w, style=color)
                    tl.append("░" * (30 - bar_w), style=DIM)
                    tl.append(f"  {count:>3d} ({pct:.0f}%)", style=MUTED)
                    parts.append(tl)

                parts.append(Text())

                # Heatmap with offset labels — 64 chars per row
                ROW_WIDTH = 64
                for row_start in range(0, len(mmap), ROW_WIDTH):
                    row_end = min(row_start + ROW_WIDTH, len(mmap))
                    offset_start = mmap[row_start]["offset"]
                    row = Text(f"      {offset_start:#08x} ")
                    for region in mmap[row_start:row_end]:
                        ch, color = TYPE_CHARS.get(region["type"], ("?", MUTED))
                        row.append(ch, style=color)
                    parts.append(row)

                # Legend
                parts.append(Text())
                legend = Text("      ")
                for rtype, (ch, color) in TYPE_CHARS.items():
                    legend.append(f"{ch} {rtype}  ", style=color)
                parts.append(legend)

            # ── Opcode Distribution ──────────────────────────────────
            ops = self._results.get("opcode_stats", {})
            if ops and ops.get("top_opcodes"):
                parts.append(Text())
                oh = Text("    ")
                oh.append("◇ ", style=f"bold {GRADIENT[3]}")
                oh.append("OPCODE DISTRIBUTION", style=f"bold {GRADIENT[3]}")
                oh.append(f"  {ops.get('total_instructions', 0)} insns", style=MUTED)
                oh.append(f"  {ops.get('unique_mnemonics', 0)} unique", style=MUTED)
                parts.append(oh)

                # Instruction class categories
                OPCODE_CLASSES = {
                    "branch": ("#fbbf24", {"jmp", "je", "jne", "jz", "jnz", "jb", "jbe",
                               "ja", "jae", "jl", "jle", "jg", "jge", "js", "jns", "loop", "jno"}),
                    "call": ("#ff6ec7", {"call"}),
                    "memory": ("#7b8cff", {"mov", "lea", "push", "pop", "movzx", "movsx",
                               "movsb", "movsw", "movsd", "movsq", "stosb", "movabs"}),
                    "arithmetic": ("#a77de5", {"add", "sub", "mul", "imul", "div", "idiv",
                                   "xor", "or", "and", "shl", "shr", "sar", "ror", "rol",
                                   "inc", "dec", "neg", "not"}),
                    "stack": ("#5eead4", {"push", "pop", "ret", "retn"}),
                    "other": (DIM, set()),
                }

                # Classify each opcode
                class_totals: Dict[str, int] = {k: 0 for k in OPCODE_CLASSES}
                for op in ops["top_opcodes"]:
                    matched = False
                    for cls_name, (_, cls_set) in OPCODE_CLASSES.items():
                        if cls_name == "other":
                            continue
                        if op["mnemonic"] in cls_set:
                            class_totals[cls_name] += op["count"]
                            matched = True
                            break
                    if not matched:
                        class_totals["other"] += op["count"]

                total = ops.get("total_instructions", 1) or 1

                # Class breakdown
                cls_line = Text("      ")
                for cls_name, (cls_color, _) in OPCODE_CLASSES.items():
                    ct = class_totals[cls_name]
                    if ct == 0:
                        continue
                    pct = ct / total * 100
                    cls_line.append(f"■ {cls_name} ", style=f"bold {cls_color}")
                    cls_line.append(f"{pct:.0f}%  ", style=MUTED)
                parts.append(cls_line)
                parts.append(Text())

                # Bar chart with gradient coloring per opcode class
                max_count = max(o["count"] for o in ops["top_opcodes"]) or 1
                for op in ops["top_opcodes"]:
                    bar_len = int((op["count"] / max_count) * 28)

                    # Determine opcode color
                    op_color = DIM
                    for cls_name, (cls_color, cls_set) in OPCODE_CLASSES.items():
                        if cls_name == "other":
                            continue
                        if op["mnemonic"] in cls_set:
                            op_color = cls_color
                            break

                    t = Text("      ")
                    t.append(f"{op['mnemonic']:<8s}", style=f"bold {op_color}")
                    t.append("█" * bar_len, style=op_color)
                    t.append("░" * (28 - bar_len), style=DIM)
                    t.append(f"  {op['count']:>4d}", style="bright_white")
                    t.append(f"  {op['pct']}%", style=MUTED)
                    parts.append(t)

                # Density summary card
                parts.append(Text())
                ds = Text("      ")
                bd = ops.get('branch_density', 0)
                cd = ops.get('call_density', 0)
                bd_color = "#f87171" if bd > 0.15 else "#fbbf24" if bd > 0.08 else "#5eead4"
                cd_color = "#f87171" if cd > 0.10 else "#fbbf24" if cd > 0.05 else "#5eead4"
                ds.append("branch ", style=DIM)
                ds.append(f"{bd:.1%}", style=f"bold {bd_color}")
                ds.append("  call ", style=DIM)
                ds.append(f"{cd:.1%}", style=f"bold {cd_color}")
                ds.append(f"  nop={ops.get('nop_count', 0)}", style=DIM)
                ds.append(f"  arith={ops.get('arithmetic_count', 0)}", style=DIM)
                ds.append(f"  mem={ops.get('memory_ops_count', 0)}", style=DIM)
                parts.append(ds)

            # ── Call Graph ───────────────────────────────────────────
            cg = self._results.get("call_graph", [])
            if cg:
                parts.append(Text())
                # Count by type
                type_counts_cg: Dict[str, int] = {}
                resolved_count = 0
                for call in cg:
                    ct = call.get("type", "unknown")
                    type_counts_cg[ct] = type_counts_cg.get(ct, 0) + 1
                    if call.get("resolved_api"):
                        resolved_count += 1

                ch_hdr = Text("    ")
                ch_hdr.append("⟐ ", style=f"bold {GRADIENT[0]}")
                ch_hdr.append("CALL GRAPH", style=f"bold {GRADIENT[0]}")
                ch_hdr.append(f"  {len(cg)} calls", style=MUTED)
                if resolved_count:
                    ch_hdr.append(f"  {resolved_count} resolved", style="#ff6ec7")
                parts.append(ch_hdr)

                # Type summary
                cg_types = Text("      ")
                CG_TYPE_COLORS = {
                    "direct": "#5eead4", "register": "#fbbf24",
                    "indirect": "#f87171", "unknown": DIM,
                }
                for ct, cnt in sorted(type_counts_cg.items(), key=lambda x: -x[1]):
                    tc = CG_TYPE_COLORS.get(ct, DIM)
                    cg_types.append(f"■ {ct} ", style=f"bold {tc}")
                    cg_types.append(f"{cnt}  ", style=MUTED)
                parts.append(cg_types)
                parts.append(Text())

                # Group calls by source block
                block_calls: Dict[str, list] = {}
                for call in cg:
                    blk = call.get("caller_block", "?")
                    block_calls.setdefault(blk, []).append(call)

                for blk_addr, calls in block_calls.items():
                    # Block header
                    bh = Text("      ")
                    bh.append(f"╔══ BB {blk_addr}", style=f"bold {GRADIENT[0]}")
                    bh.append(f"  {len(calls)} call{'s' if len(calls) != 1 else ''}", style=DIM)
                    pad = max(0, 48 - len(blk_addr))
                    bh.append("═" * min(pad, 14), style=GRADIENT[0])
                    bh.append("╗", style=GRADIENT[0])
                    parts.append(bh)

                    for call in calls:
                        cl = Text("      ")
                        cl.append("║", style=GRADIENT[0])
                        cl.append(f"  {call['caller']}  ", style=DIM)

                        ct = call.get("type", "unknown")
                        tc = CG_TYPE_COLORS.get(ct, DIM)

                        resolved = call.get("resolved_api")
                        if resolved:
                            cl.append("→ ", style="#ff6ec7")
                            cl.append(resolved, style="bold #ff6ec7")
                        else:
                            cl.append("→ ", style=tc)
                            cl.append(call["target"], style=f"bold {tc}")
                        cl.append(f"  [{ct}]", style=DIM)
                        parts.append(cl)

                    bot = Text("      ")
                    bot.append(f"╚{'═' * 52}╝", style=GRADIENT[0])
                    parts.append(bot)

            # ── ROP/JOP Gadgets ──────────────────────────────────────
            gadgets = self._results.get("gadgets", [])
            if gadgets:
                parts.append(Text())
                # Group by terminator
                ret_gadgets = [g for g in gadgets if g["terminator"] == "ret"]
                jmp_gadgets = [g for g in gadgets if g["terminator"] != "ret"]

                gh = Text("    ")
                gh.append("⊕ ", style=f"bold {GRADIENT[1]}")
                gh.append("ROP/JOP GADGETS", style=f"bold {GRADIENT[1]}")
                gh.append(f"  {len(gadgets)} found", style=MUTED)
                if ret_gadgets:
                    gh.append(f"  ROP:{len(ret_gadgets)}", style="#5eead4")
                if jmp_gadgets:
                    gh.append(f"  JOP:{len(jmp_gadgets)}", style="#fbbf24")
                parts.append(gh)

                for g in gadgets:
                    gl = Text("      ")
                    term = g["terminator"]
                    term_color = "#5eead4" if term == "ret" else "#fbbf24"

                    gl.append(f"@{g['offset']:#08x}", style=DIM)
                    gl.append(f"  [{term}]", style=f"bold {term_color}")
                    gl.append(f"  {g['length']}i  ", style=MUTED)

                    # Color each instruction in the gadget
                    insn_parts = g["instructions"].split("; ")
                    for idx, insn in enumerate(insn_parts):
                        mn = insn.split(" ")[0] if insn else ""
                        if mn in ("ret", "retf"):
                            gl.append(insn, style="bold #f87171")
                        elif mn.startswith("jmp"):
                            gl.append(insn, style="bold #fbbf24")
                        elif mn in ("pop", "push", "mov", "lea", "xchg"):
                            gl.append(insn, style="#7b8cff")
                        elif mn in ("xor", "add", "sub", "inc", "dec", "neg", "not"):
                            gl.append(insn, style="#a77de5")
                        elif mn in ("nop",):
                            gl.append(insn, style=DIM)
                        else:
                            gl.append(insn, style="bright_white")
                        if idx < len(insn_parts) - 1:
                            gl.append("; ", style=DIM)
                    parts.append(gl)

            return Group(*parts)
        except Exception:
            return None

    def get_results(self) -> Optional[Dict[str, Any]]:
        return self._results if self._results else None

    def cleanup(self) -> None:
        self._results = {}
        self._blocks = []
        self._artifacts = {"apis": [], "strings": [], "crypto": [], "urls": [], "dlls": [], "syscalls": []}
        self._relations = []
        self._syscall_stubs = []
        self._anti_analysis = []
        self._memory_map = []
        self._opcode_stats = {}
        self._call_graph = []
        self._gadgets = []
