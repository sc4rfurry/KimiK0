"""C2 Profile Parser — Malleable C2 Profile Reader for dissection hints.

Parses CobaltStrike Malleable C2 profile files to extract settings that
directly inform the dissection process:
  - magic_mz_x86/x64: custom PE magic bytes (e.g. 'OICA')
  - magic_pe: custom PE signature (e.g. 'NO')
  - stomppe: whether headers are zeroed after load
  - sleep_mask/obfuscate: encryption behavior
  - sleeptime/jitter/port: expected config values for validation
  - spawnto_x86/x64: expected values for cross-reference
  - useragent, pipename, host_stage: behavioral indicators
  - syscall_method: direct/indirect/none

Usage:
    profile = ProfileParser.parse_file("prod.profile")
    print(profile.magic_mz_x64)  # "OICA"
    print(profile.expected_config)  # {"SETTING_SLEEPTIME": 60000, ...}
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class C2Profile:
    """Parsed Malleable C2 profile with dissection-relevant settings."""

    # --- PE Header Settings ---
    magic_mz_x86: str = "MZ"
    magic_mz_x64: str = "MZ"
    magic_pe: str = "PE"
    stomppe: bool = False
    cleanup: bool = False
    obfuscate: bool = False
    sleep_mask: bool = False
    smartinject: bool = False

    # --- Global Behavior ---
    sleeptime: int = 60000
    jitter: int = 0
    data_jitter: int = 0
    useragent: str = ""
    host_stage: bool = True
    sample_name: str = ""

    # --- Networking ---
    port: int = 443
    protocol: str = "https"  # Inferred from http-get/https-certificate blocks
    domains: List[str] = field(default_factory=list)
    pipename: str = ""
    tcp_frame_header: str = ""
    smb_frame_header: str = ""

    # --- Process Injection ---
    spawnto_x86: str = ""
    spawnto_x64: str = ""
    syscall_method: Optional[str] = None  # none, direct, indirect

    # --- HTTP URIs ---
    http_get_uri: str = ""
    http_post_uri: str = ""

    # --- Stage Settings ---
    stage_name: str = ""
    module_x64: str = ""
    module_x86: str = ""
    rich_header: str = ""

    # --- Process Injection Details ---
    allocator: Optional[str] = None  # VirtualAllocEx or NtMapViewOfSection
    min_alloc: int = 0
    bof_reuse_memory: bool = False

    # --- Raw profile source ---
    raw_source: str = ""

    # --- CS 4.11/4.12 Features ---
    beacon_gate_enabled: bool = False
    beacon_gate_apis: List[str] = field(default_factory=list)
    rdll_use_driploading: bool = False
    rdll_dripload_delay: int = 0
    eaf_bypass: bool = False
    rdll_use_syscalls: bool = False
    copy_pe_header: bool = True
    sleepmask: bool = True  # Defaults to True in CS 4.11+

    @property
    def pe_magics(self) -> List[bytes]:
        """Get the PE magic bytes to search for during dissection."""
        magics = set()
        magics.add(self.magic_mz_x64.encode("ascii", errors="replace"))
        magics.add(self.magic_mz_x86.encode("ascii", errors="replace"))
        magics.add(b"MZ")  # Always include standard
        return list(magics)

    @property
    def expected_config(self) -> Dict[str, Any]:
        """Build expected config values for validation against extracted config.

        Returns a dict of SETTING_NAME -> expected_value. Only includes
        settings that have non-default values in the profile.
        """
        expected = {}

        if self.sleeptime:
            expected["SETTING_SLEEPTIME"] = self.sleeptime
        if self.jitter:
            expected["SETTING_JITTER"] = self.jitter
        if self.useragent:
            expected["SETTING_USERAGENT"] = self.useragent
        if self.spawnto_x86:
            expected["SETTING_SPAWNTO_X86"] = self.spawnto_x86
        if self.spawnto_x64:
            expected["SETTING_SPAWNTO_X64"] = self.spawnto_x64
        if self.cleanup:
            expected["SETTING_CLEANUP"] = 1
        if self.sleep_mask:
            expected["SETTING_GARGLE_NOOK"] = 1

        # Protocol mapping
        proto_map = {"http": 0, "https": 8, "dns": 1, "smb": 2, "tcp": 4}
        if self.protocol in proto_map:
            expected["SETTING_PROTOCOL"] = proto_map[self.protocol]

        # Syscall method mapping
        if self.syscall_method == "none":
            expected["SETTING_SYSCALL_METHOD"] = 0
        elif self.syscall_method == "direct":
            expected["SETTING_SYSCALL_METHOD"] = 1
        elif self.syscall_method == "indirect":
            expected["SETTING_SYSCALL_METHOD"] = 2

        # Allocator mapping
        if self.allocator == "NtMapViewOfSection":
            expected["SETTING_PROCINJ_ALLOCATOR"] = 1
        elif self.allocator == "VirtualAllocEx":
            expected["SETTING_PROCINJ_ALLOCATOR"] = 0

        if self.min_alloc:
            expected["SETTING_PROCINJ_MINALLOC"] = self.min_alloc

        return expected

    def validate_config(self, extracted_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate extracted config against expected profile values.

        Returns a dict with:
            matches: list of matching settings
            mismatches: list of (setting, expected, actual) tuples
            missing: list of settings not found in extracted config
        """
        expected = self.expected_config
        matches = []
        mismatches = []
        missing = []

        for setting, exp_val in expected.items():
            if setting not in extracted_config:
                missing.append(setting)
            else:
                actual = extracted_config[setting]
                # String comparison — normalize
                if isinstance(exp_val, str) and isinstance(actual, str):
                    if exp_val.lower().strip() in actual.lower().strip():
                        matches.append(setting)
                    else:
                        mismatches.append((setting, exp_val, actual))
                elif exp_val == actual:
                    matches.append(setting)
                else:
                    mismatches.append((setting, exp_val, actual))

        return {
            "matches": matches,
            "mismatches": mismatches,
            "missing": missing,
            "total_expected": len(expected),
            "match_rate": len(matches) / max(len(expected), 1),
        }


class ProfileParser:
    """Parser for CobaltStrike Malleable C2 profile files."""

    @staticmethod
    def parse_file(path: str) -> C2Profile:
        """Parse a .profile file from disk.

        Args:
            path: Path to the Malleable C2 profile file.

        Returns:
            C2Profile with extracted settings.
        """
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
        return ProfileParser.parse(source)

    @staticmethod
    def parse(source: str) -> C2Profile:
        """Parse profile source text.

        Handles the Malleable C2 syntax:
            set key "value";
            block { ... }
            block.subblock { ... }
        """
        profile = C2Profile(raw_source=source)

        # Strip comments
        lines = []
        for line in source.split("\n"):
            line = line.strip()
            if line.startswith("#"):
                continue
            # Strip inline comments (but not inside quotes)
            comment_pos = _find_comment(line)
            if comment_pos >= 0:
                line = line[:comment_pos].strip()
            lines.append(line)
        clean = "\n".join(lines)

        # --- Extract global 'set' directives ---
        for key, val in _extract_sets(clean):
            _apply_global_set(profile, key, val)

        # --- Extract block-level settings ---

        # stage block
        stage_block = _extract_block(clean, "stage")
        if stage_block:
            for key, val in _extract_sets(stage_block):
                _apply_stage_set(profile, key, val)

        # process-inject block
        pinj_block = _extract_block(clean, "process-inject")
        if pinj_block:
            for key, val in _extract_sets(pinj_block):
                _apply_procinj_set(profile, key, val)

        # http-get block — extract URI
        httpget_block = _extract_block(clean, "http-get")
        if httpget_block:
            for key, val in _extract_sets(httpget_block):
                if key == "uri":
                    profile.http_get_uri = val.split()[0] if val else ""

        # http-post block — extract URI
        httppost_block = _extract_block(clean, "http-post")
        if httppost_block:
            for key, val in _extract_sets(httppost_block):
                if key == "uri":
                    profile.http_post_uri = val.split()[0] if val else ""

        # https-certificate — infer protocol
        if "https-certificate" in clean:
            profile.protocol = "https"
        elif "http-get" in clean and "https-certificate" not in clean:
            # If no https cert but has http-get, might be HTTP
            # But most real profiles use HTTPS anyway
            pass

        # dns-beacon block
        dns_block = _extract_block(clean, "dns-beacon")
        if dns_block:
            profile.protocol = "dns"

        # beacon_gate block (CS 4.10+)
        bg_block = _extract_block(clean, "beacon_gate")
        if bg_block:
            profile.beacon_gate_enabled = True
            # Parse API list from the block — e.g. 'All;' or individual APIs
            api_lines = [l.strip().rstrip(";") for l in bg_block.split("\n") if l.strip() and not l.strip().startswith("set")]
            profile.beacon_gate_apis = [a for a in api_lines if a]

        return profile


# --- Internal helpers ---

def _find_comment(line: str) -> int:
    """Find the position of a '#' comment that's not inside a quoted string."""
    in_quote = False
    for i, ch in enumerate(line):
        if ch == '"':
            in_quote = not in_quote
        elif ch == '#' and not in_quote:
            return i
    return -1


def _extract_sets(text: str) -> List[tuple]:
    """Extract all 'set key "value";' directives from text."""
    pattern = r'set\s+(\w+)\s+"([^"]*)"\s*;'
    return re.findall(pattern, text)


def _extract_block(text: str, block_name: str) -> Optional[str]:
    """Extract the content of a named block: 'block_name { ... }'.

    Handles nested braces. Returns the inner content or None.
    """
    # Find the block start
    pattern = rf'\b{re.escape(block_name)}\s*\{{'
    match = re.search(pattern, text)
    if not match:
        return None

    start = match.end()
    depth = 1
    pos = start

    while pos < len(text) and depth > 0:
        if text[pos] == '{':
            depth += 1
        elif text[pos] == '}':
            depth -= 1
        pos += 1

    if depth == 0:
        return text[start:pos - 1]
    return None


def _apply_global_set(profile: C2Profile, key: str, val: str) -> None:
    """Apply a global 'set' directive to the profile."""
    key = key.lower()

    if key == "sleeptime":
        profile.sleeptime = int(val)
    elif key == "jitter":
        profile.jitter = int(val)
    elif key == "data_jitter":
        profile.data_jitter = int(val)
    elif key == "useragent":
        profile.useragent = val
    elif key == "host_stage":
        profile.host_stage = val.lower() == "true"
    elif key == "sample_name":
        profile.sample_name = val
    elif key == "pipename":
        profile.pipename = val
    elif key == "port":
        try:
            profile.port = int(val)
        except ValueError:
            pass
    elif key == "tcp_frame_header":
        profile.tcp_frame_header = val
    elif key == "smb_frame_header":
        profile.smb_frame_header = val
    elif key == "dns_idle":
        pass  # Stored in config as SETTING_DNS_IDLE
    elif key == "maxdns":
        pass  # Stored in config as SETTING_MAXDNS


def _apply_stage_set(profile: C2Profile, key: str, val: str) -> None:
    """Apply a stage block 'set' directive."""
    key = key.lower()

    if key == "magic_mz_x86":
        profile.magic_mz_x86 = val
    elif key == "magic_mz_x64":
        profile.magic_mz_x64 = val
    elif key == "magic_pe":
        profile.magic_pe = val
    elif key == "stomppe":
        profile.stomppe = val.lower() == "true"
    elif key == "cleanup":
        profile.cleanup = val.lower() == "true"
    elif key == "obfuscate":
        profile.obfuscate = val.lower() == "true"
    elif key == "sleep_mask":
        profile.sleep_mask = val.lower() == "true"
    elif key == "smartinject":
        profile.smartinject = val.lower() == "true"
    elif key == "name":
        profile.stage_name = val
    elif key == "module_x64":
        profile.module_x64 = val
    elif key == "module_x86":
        profile.module_x86 = val
    elif key == "rich_header":
        profile.rich_header = val
    elif key == "syscall_method":
        profile.syscall_method = val.lower()
    elif key == "allocator":
        profile.allocator = val
    elif key == "rdll_use_driploading":
        profile.rdll_use_driploading = val.lower() == "true"
    elif key == "rdll_dripload_delay":
        try:
            profile.rdll_dripload_delay = int(val)
        except ValueError:
            pass
    elif key == "eaf_bypass":
        profile.eaf_bypass = val.lower() == "true"
    elif key == "rdll_use_syscalls":
        profile.rdll_use_syscalls = val.lower() == "true"
    elif key == "copy_pe_header":
        profile.copy_pe_header = val.lower() == "true"
    elif key == "sleepmask":
        profile.sleepmask = val.lower() == "true"


def _apply_procinj_set(profile: C2Profile, key: str, val: str) -> None:
    """Apply a process-inject block 'set' directive."""
    key = key.lower()

    if key == "allocator":
        profile.allocator = val
    elif key == "min_alloc":
        profile.min_alloc = int(val)
    elif key == "startrwx":
        pass  # Handled via SETTING_PROCINJ_PERMS_I
    elif key == "userwx":
        pass  # Handled via SETTING_PROCINJ_PERMS
    elif key == "bof_reuse_memory":
        profile.bof_reuse_memory = val.lower() == "true"
