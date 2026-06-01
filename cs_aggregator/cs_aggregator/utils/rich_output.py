"""Rich-powered terminal output for the KimiK0 dissection engine.

Three-tier adaptive CLI:
  FULL   — Windows Terminal / modern POSIX (truecolor, Unicode box art, animations)
  BASIC  — PowerShell in ConHost / 256-color terminals (safe box, limited Unicode)
  LEGACY — CMD.exe / dumb terminals (ASCII art, 8-color fallback, no Unicode art)

Cross-platform: Windows CMD, PowerShell, Windows Terminal, macOS, Linux.
All public function signatures are backward-compatible with callers in cli.py
and all 9 builtin plugins.
"""

from __future__ import annotations

import io
import os
import sys
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple

from rich import box as rich_box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.progress import Progress
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.tree import Tree


# ── Terminal Tier ─────────────────────────────────────────────────────────────

class Tier(Enum):
    FULL   = auto()   # Windows Terminal, iTerm2, modern POSIX — truecolor + Unicode
    BASIC  = auto()   # PowerShell ConHost, 256-color — limited glyphs, safe_box
    LEGACY = auto()   # CMD.exe, dumb — ASCII only, 8-color


def _detect_tier() -> Tier:
    """Detect terminal capability tier.

    Checks (in order):
      1. Explicit override via KIMIK0_TIER env var (FULL/BASIC/LEGACY)
      2. Windows Terminal session (WT_SESSION)
      3. iTerm2 / modern POSIX (TERM_PROGRAM, COLORTERM)
      4. ConHost PowerShell heuristic (Windows + no WT_SESSION)
      5. Fallback LEGACY
    """
    override = os.environ.get("KIMIK0_TIER", "").upper()
    if override in ("FULL", "BASIC", "LEGACY"):
        return Tier[override]

    # Explicit no-color / dumb
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") in ("dumb", ""):
        return Tier.LEGACY

    is_windows = sys.platform == "win32"

    if is_windows:
        # Windows Terminal sets WT_SESSION
        if os.environ.get("WT_SESSION"):
            return Tier.FULL
        # VS Code terminal
        if os.environ.get("TERM_PROGRAM") in ("vscode",):
            return Tier.FULL
        # PowerShell in ConHost: has $PSVersionTable but no WT_SESSION
        # Detect via SESSIONNAME (console session) or default to BASIC
        return Tier.BASIC

    # POSIX
    colorterm = os.environ.get("COLORTERM", "").lower()
    term_program = os.environ.get("TERM_PROGRAM", "").lower()
    term = os.environ.get("TERM", "").lower()

    if colorterm in ("truecolor", "24bit") or term_program in ("iterm.app", "hyper", "wezterm"):
        return Tier.FULL
    if "256color" in term or "256color" in colorterm:
        return Tier.BASIC
    if term in ("xterm", "xterm-color", "screen", "tmux"):
        return Tier.BASIC

    return Tier.LEGACY


TIER: Tier = _detect_tier()


# ── Theme ─────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Theme:
    """Per-tier visual configuration."""

    # Box styles
    box_outer:  Any  # Panel borders
    box_table:  Any  # Table borders
    box_inner:  Any  # Inner segment cards

    # Whether to use Unicode block/box characters
    unicode_art: bool

    # Glyph set
    bullet:   str
    check:    str
    cross:    str
    arrow:    str
    dot:      str
    pipe:     str
    diamond:  str
    gem:      str
    star:     str
    tri:      str

    # Gauge chars
    bar_full:  str
    bar_empty: str
    spark:     str

    # Padding (top, right, bottom, left) for Panels
    panel_pad: Tuple[int, int]  # (vertical, horizontal)

    # Colors — primary accent palette
    c_primary:   str
    c_secondary: str
    c_warn:      str
    c_danger:    str
    c_success:   str
    c_dim:       str
    c_muted:     str

    # Gradient (5-stop for banners/rules)
    gradient: List[str]


def _build_theme(tier: Tier) -> Theme:
    if tier == Tier.FULL:
        return Theme(
            box_outer   = rich_box.HEAVY,
            box_table   = rich_box.SIMPLE_HEAD,
            box_inner   = rich_box.ROUNDED,
            unicode_art = True,
            bullet  = "›", check  = "✓", cross  = "✗",
            arrow   = "→", dot    = "·", pipe   = "│",
            diamond = "◆", gem    = "◈", star   = "✦", tri = "⟐",
            bar_full  = "━", bar_empty = "╌",
            spark     = "▁▂▃▄▅▆▇█",
            panel_pad = (0, 1),
            c_primary   = "#7b8cff",
            c_secondary = "#ff6ec7",
            c_warn      = "#fbbf24",
            c_danger    = "#f87171",
            c_success   = "#5eead4",
            c_dim       = "dim",
            c_muted     = "grey70",
            gradient    = ["#ff6ec7", "#d35fd6", "#a77de5", "#7b8cff", "#5eead4"],
        )
    elif tier == Tier.BASIC:
        return Theme(
            box_outer   = rich_box.SQUARE,
            box_table   = rich_box.SIMPLE,
            box_inner   = rich_box.SQUARE,
            unicode_art = True,
            bullet  = ">", check  = "OK", cross  = "XX",
            arrow   = "->",dot    = ".", pipe   = "|",
            diamond = "*", gem    = "#", star   = "+", tri = "*",
            bar_full  = "#", bar_empty = "-",
            spark     = ".:-=+*#@",
            panel_pad = (0, 1),
            c_primary   = "bright_cyan",
            c_secondary = "bright_magenta",
            c_warn      = "bright_yellow",
            c_danger    = "bright_red",
            c_success   = "bright_green",
            c_dim       = "dim",
            c_muted     = "white",
            gradient    = ["bright_magenta", "bright_cyan", "cyan",
                           "bright_blue", "bright_cyan"],
        )
    else:  # LEGACY
        return Theme(
            box_outer   = rich_box.ASCII,
            box_table   = rich_box.ASCII,
            box_inner   = rich_box.ASCII,
            unicode_art = False,
            bullet  = ">", check  = "[OK]", cross  = "[X]",
            arrow   = "->",dot    = ".", pipe   = "|",
            diamond = "*", gem    = "#", star   = "+", tri = "^",
            bar_full  = "=", bar_empty = "-",
            spark     = ".:-=+*#",
            panel_pad = (0, 1),
            c_primary   = "cyan",
            c_secondary = "magenta",
            c_warn      = "yellow",
            c_danger    = "red",
            c_success   = "green",
            c_dim       = "dim",
            c_muted     = "white",
            gradient    = ["magenta", "cyan", "cyan", "blue", "cyan"],
        )


TH: Theme = _build_theme(TIER)


# ── Console Factory ───────────────────────────────────────────────────────────

def _make_console(stderr: bool = False) -> Console:
    """Build a Console tuned for the detected terminal tier."""
    # Encoding: always UTF-8 on Windows to avoid cp1252 mojibake
    out_stream: Any = sys.stderr if stderr else sys.stdout
    if sys.platform == "win32" and hasattr(out_stream, "buffer"):
        enc = getattr(out_stream, "encoding", "").lower().replace("-", "")
        if enc != "utf8":
            out_stream = io.TextIOWrapper(
                out_stream.buffer, encoding="utf-8", errors="replace"
            )

    if TIER == Tier.FULL:
        return Console(
            file=out_stream,
            color_system="truecolor",
            highlight=False,
            legacy_windows=False,
            safe_box=False,
        )
    elif TIER == Tier.BASIC:
        return Console(
            file=out_stream,
            color_system="256",
            highlight=False,
            legacy_windows=False,  # let Rich detect — BASIC is still ConHost
            safe_box=True,
        )
    else:  # LEGACY
        return Console(
            file=out_stream,
            color_system="windows",
            highlight=False,
            legacy_windows=True,
            safe_box=True,
        )


# Public consoles (stderr for diagnostic output, stdout for piped JSON)
console        = _make_console(stderr=True)
stdout_console = _make_console(stderr=False)


# ── Backward-Compatible Symbol Aliases ────────────────────────────────────────
# Plugins and cli.py import these directly.

_BULLET  = TH.bullet
_CHECK   = TH.check
_CROSS   = TH.cross
_ARROW   = TH.arrow
_DOT     = TH.dot
_PIPE    = TH.pipe
_DIAMOND = TH.diamond
_GEM     = TH.gem

# ── Color Aliases (backward-compat) ──────────────────────────────────────────

ACCENT_PRIMARY   = TH.c_primary
ACCENT_SECONDARY = TH.c_secondary
ACCENT_WARN      = TH.c_warn
ACCENT_DANGER    = TH.c_danger
ACCENT_SUCCESS   = TH.c_success
DIM              = TH.c_dim
MUTED            = TH.c_muted
GRADIENT         = TH.gradient


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sanitize(s: str) -> str:
    """Strip non-printable / replacement characters for safe terminal display."""
    import re
    cleaned = "".join(
        c for c in s
        if c.isprintable() and c != "\ufffd" and ord(c) >= 0x20
    )
    if len(cleaned) < len(s) * 0.4 and len(s) > 2:
        hex_repr = s.encode("utf-8", errors="replace").hex()
        return f"<0x{hex_repr[:16]}>"
    cleaned = re.sub(r"\?{2,}", "?", cleaned)
    return cleaned.strip() or f"<{len(s)}B raw>"


def _term_width() -> int:
    """Return usable terminal width, clamped to [60, 200]."""
    try:
        w = console.width
        return max(60, min(200, w))
    except Exception:
        return 100


def _inner_width() -> int:
    """Width available inside a panel with padding."""
    return _term_width() - 6


# ── Banner ────────────────────────────────────────────────────────────────────

# Full Unicode big-font (ANSI shadow style)
_BANNER_FULL = """\
 ██╗  ██╗██╗███╗   ███╗██╗██╗  ██╗ ██████╗
 ██║ ██╔╝██║████╗ ████║██║██║ ██╔╝██╔═████╗
 █████╔╝ ██║██╔████╔██║██║█████╔╝ ██║██╔██║
 ██╔═██╗ ██║██║╚██╔╝██║██║██╔═██╗ ████╔╝██║
 ██║  ██╗██║██║ ╚═╝ ██║██║██║  ██╗╚██████╔╝
 ╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝"""

# Basic ASCII art for PowerShell/ConHost
_BANNER_BASIC = """\
 ##  ## ## ###  ## ## ## ##  ##  ##
 ## ##  ## ## # ## ## ## ## ##  ###
 ####   ## ##   ## ## ## ####  # ##
 ## ##  ## ##   ## ## ## ## ## ####
 ##  ## ## ##   ##  ###  ## ##  ###"""

# Pure ASCII for CMD legacy
_BANNER_LEGACY = "[ KimiK0 ] -- CobaltStrike Beacon Dissection Engine"

_BANNER_GRADIENT_STYLES = [
    "bold #ff6ec7", "bold #e165cf", "bold #c36cd8",
    "bold #a577e1", "bold #8782ea", "bold #6b8cff",
    "bold #5eead4",
]
_BANNER_BASIC_STYLES = [
    "bold bright_magenta", "bold bright_cyan", "bold cyan",
    "bold bright_blue", "bold bright_cyan",
]


def print_banner(version: str) -> None:
    """Print adaptive gradient banner with version tagline.

    FULL:   Block-font with per-line gradient colors + styled panel tagline
    BASIC:  ASCII art with color cycling
    LEGACY: Single bold line
    """
    width = _term_width()
    console.print()

    if TIER == Tier.FULL:
        lines = _BANNER_FULL.split("\n")
        for i, line in enumerate(lines):
            style = _BANNER_GRADIENT_STYLES[i % len(_BANNER_GRADIENT_STYLES)]
            console.print(Text(line, style=style), justify="center")
            time.sleep(0.015)
        console.print()

        # Tagline rule
        console.print(Rule(
            title=Text(f" {TH.tri} CS Beacon Dissection Engine  v{version} {TH.tri}",
                       style="bold #7b8cff"),
            style="#3b3b6e",
        ))

        # Subtitle in a compact panel
        sub = Text(justify="center")
        sub.append("CobaltStrike Beacon Shellcode Aggregation", style="bold #5eead4")
        sub.append("  &  ", style="dim")
        sub.append("Dissection Engine", style="bold #ff6ec7")
        console.print(Panel(
            Align.center(sub),
            box=rich_box.HEAVY,
            border_style="#2a2a4e",
            padding=(0, 4),
            expand=True,
        ))

    elif TIER == Tier.BASIC:
        lines = _BANNER_BASIC.split("\n")
        for i, line in enumerate(lines):
            style = _BANNER_BASIC_STYLES[i % len(_BANNER_BASIC_STYLES)]
            console.print(Text(line, style=style))
        console.print()
        console.print(Rule(
            title=f"CS Beacon Dissection Engine  v{version}",
            style="bright_cyan",
        ))

    else:  # LEGACY
        console.print(Text(_BANNER_LEGACY, style="bold cyan"))
        console.print(Text(f"Version {version}", style="cyan"))
        console.print(Text("=" * min(60, width), style="cyan"))

    console.print()


# ── Section Headers ───────────────────────────────────────────────────────────

def _section_header(icon: str, title: str, subtitle: str = "",
                    style: str = "") -> None:
    """Print a premium section header, tier-adaptive.

    FULL:   Gradient Rule with icon
    BASIC:  Bold Rule
    LEGACY: Plain separator line
    """
    style = style or TH.c_primary
    console.print()

    if TIER in (Tier.FULL, Tier.BASIC):
        tag = f" {icon} {title}"
        if subtitle:
            tag += f"  {TH.dot}  {subtitle}"
        console.print(Rule(title=Text(tag, style=f"bold {style}"),
                           style=style, align="left"))
    else:  # LEGACY
        header_str = f"=== {title}"
        if subtitle:
            header_str += f" | {subtitle}"
        header_str += " ==="
        console.print(Text(header_str, style="bold cyan"))


# ── Key-Value ─────────────────────────────────────────────────────────────────

def _kv(key: str, value: str, key_style: str = "",
        val_style: str = "bright_white", indent: int = 4) -> None:
    """Print a key-value pair with dot-fill alignment."""
    key_style = key_style or TH.c_dim
    t = Text()
    t.append(" " * indent)
    t.append(f"{key:.<22s} ", style=key_style)
    t.append(str(value), style=val_style)
    console.print(t)


# ── Badge ─────────────────────────────────────────────────────────────────────

def _badge(label: str, style: str = "") -> Text:
    """Create an inline badge Text."""
    style = style or TH.c_success
    t = Text()
    if TIER == Tier.FULL:
        t.append(f" {label} ", style=f"bold {style} on #1a1a2e")
    elif TIER == Tier.BASIC:
        t.append(f"[{label}]", style=f"bold {style}")
    else:
        t.append(f"[{label}]", style="bold")
    return t


# ── Sparkline ─────────────────────────────────────────────────────────────────

SPARK_CHARS = TH.spark


def sparkline(values: List[float], max_val: float = 8.0) -> str:
    """Render a Unicode sparkline from float values."""
    if not values:
        return ""
    chars = []
    n = len(SPARK_CHARS)
    for v in values:
        idx = int((v / max_val) * (n - 1))
        chars.append(SPARK_CHARS[max(0, min(idx, n - 1))])
    return "".join(chars)


# ── Entropy Color ─────────────────────────────────────────────────────────────

def entropy_color(entropy: float) -> str:
    """Map entropy value to a Rich color string."""
    if entropy < 4.0:
        return TH.c_success
    elif entropy < 6.0:
        return "green"
    elif entropy < 7.0:
        return TH.c_warn
    elif entropy < 7.5:
        return TH.c_danger
    return "bold red"


# ── Confidence Bar ────────────────────────────────────────────────────────────

def confidence_bar(value: float, width: int = 20) -> Text:
    """Gradient confidence bar.  Falls back to simple = / - for LEGACY."""
    filled  = max(0, min(width, int(value * width)))
    empty   = width - filled
    pct_str = f" {value:.0%}"

    if TIER == Tier.FULL:
        if value >= 0.9:
            colors = ["#5eead4", "#34d399", "#10b981"]
        elif value >= 0.7:
            colors = ["#fbbf24", "#f59e0b", "#d97706"]
        elif value >= 0.5:
            colors = ["#fb923c", "#f97316", "#ea580c"]
        else:
            colors = ["#f87171", "#ef4444", "#dc2626"]

        bar = Text()
        for i in range(filled):
            bar.append(TH.bar_full, style=f"bold {colors[i % len(colors)]}")
        bar.append(TH.bar_empty * empty, style=TH.c_dim)
        bar.append(pct_str, style=f"bold {colors[0]}")
        return bar

    elif TIER == Tier.BASIC:
        color = TH.c_success if value >= 0.7 else TH.c_warn if value >= 0.4 else TH.c_danger
        bar = Text()
        bar.append(TH.bar_full * filled, style=f"bold {color}")
        bar.append(TH.bar_empty * empty, style=TH.c_dim)
        bar.append(pct_str, style=f"bold {color}")
        return bar

    else:  # LEGACY
        bar = Text()
        bar.append("=" * filled + "-" * empty)
        bar.append(pct_str)
        return bar


# ── Pipeline Spinner ──────────────────────────────────────────────────────────

_STAGE_ICONS_FULL   = ["⟐", "◆", "◈", "▣", "◉", "⬡", "✦"]
_STAGE_ICONS_BASIC  = ["*", "#", "+", "o", "x", "-", ">"]
_STAGE_ICONS        = _STAGE_ICONS_FULL if TIER == Tier.FULL else _STAGE_ICONS_BASIC


class PipelineSpinner:
    """Multi-stage animated pipeline progress — tier-adaptive."""

    def __init__(self, message: str = "Analyzing payload"):
        self._message = message
        self._stage   = 0
        self._status  = None

    def __enter__(self) -> "PipelineSpinner":
        icon   = _STAGE_ICONS[0]
        style  = f"bold {TH.c_primary}"
        spin_s = f"bold {TH.c_secondary}"
        self._status = console.status(
            Text(f" {icon} {self._message}...", style=style),
            spinner="dots2" if TIER != Tier.LEGACY else "line",
            spinner_style=spin_s,
        )
        self._status.__enter__()
        return self

    def update(self, message: str) -> None:
        self._stage = (self._stage + 1) % len(_STAGE_ICONS)
        icon  = _STAGE_ICONS[self._stage]
        color = GRADIENT[self._stage % len(GRADIENT)]
        self._status.update(Text(f" {icon} {message}...", style=f"bold {color}"))

    def __exit__(self, *args: Any) -> None:
        if self._status:
            self._status.__exit__(*args)


# ── Payload Classification ────────────────────────────────────────────────────

def print_classification(classification: Dict[str, Any]) -> None:
    """Print payload classification with badge table and entropy bar."""
    _section_header(TH.gem, "PAYLOAD", "classification")

    ptype   = classification.get("type", "unknown")
    arch    = classification.get("architecture", "unknown")
    fmt     = classification.get("format", "unknown")
    size    = classification.get("fileSize", 0)
    entropy = classification.get("entropy", 0.0)
    sha256  = classification.get("hashes", {}).get("sha256", "?")
    conf    = classification.get("confidenceScore", 0.0)

    # ── Badge row ──
    badge_row = Text()
    badge_row.append_text(_badge(ptype.upper(), TH.c_primary))
    badge_row.append("  ")
    badge_row.append_text(_badge(arch, TH.c_success))
    badge_row.append("  ")
    badge_row.append_text(_badge(fmt, TH.c_secondary))
    badge_row.append(f"   {size:,} bytes", style="bright_white")
    console.print(badge_row)
    console.print()

    # ── Metrics table ──
    tbl = Table(
        box=TH.box_table,
        show_header=False,
        padding=(0, 2),
        safe_box=(TIER != Tier.FULL),
        border_style=TH.c_primary,
        expand=False,
    )
    tbl.add_column("key",  style=TH.c_muted,   width=12)
    tbl.add_column("val",  style="bright_white")

    # Entropy row with bar
    ent_c   = entropy_color(entropy)
    ent_bar = Text()
    ent_bar.append(f"{entropy:.4f} ", style=f"bold {ent_c}")
    bar_len = int(entropy / 8.0 * 20)
    if TIER == Tier.FULL:
        ent_bar.append("█" * bar_len, style=ent_c)
        ent_bar.append("░" * (20 - bar_len), style="dim")
    else:
        ent_bar.append("#" * bar_len + "-" * (20 - bar_len))
    if entropy > 7.0:
        ent_bar.append("  packed/encrypted", style="italic dim")
    elif entropy > 6.0:
        ent_bar.append("  obfuscated", style="italic dim")

    # Confidence row
    conf_bar = Text()
    conf_bar.append_text(confidence_bar(conf, width=20))

    # SHA256 row — split for readability
    sha_text = Text()
    sha_text.append(sha256[:32], style=TH.c_primary)
    sha_text.append(sha256[32:64], style=TH.c_secondary)

    tbl.add_row("Entropy", ent_bar)
    tbl.add_row("Confidence", conf_bar)
    tbl.add_row("SHA-256", sha_text)

    console.print(Panel(
        tbl,
        box=TH.box_inner,
        border_style=TH.c_primary,
        padding=TH.panel_pad,
        safe_box=(TIER != Tier.FULL),
        expand=False,
    ))


# ── Version Detection ─────────────────────────────────────────────────────────

def print_version_detection(version_info: Dict[str, Any]) -> None:
    """Print version detection with confidence gauge in a styled Panel."""
    version = version_info.get("version", "unknown")
    conf    = version_info.get("confidence", 0.0)
    method  = version_info.get("method", "unknown")
    notes   = version_info.get("notes", [])

    _section_header(TH.gem, "VERSION", f"CobaltStrike {version}",
                    style=TH.c_secondary)

    tbl = Table(
        box=TH.box_table,
        show_header=False,
        padding=(0, 2),
        safe_box=(TIER != Tier.FULL),
        expand=False,
    )
    tbl.add_column("k", style=TH.c_muted, width=14)
    tbl.add_column("v", style="bright_white")

    tbl.add_row("Detected",   Text(version, style=f"bold {TH.c_secondary}"))
    tbl.add_row("Confidence", confidence_bar(conf, width=24))
    tbl.add_row("Method",     method)

    for note in notes[:3]:
        tbl.add_row(f"  {TH.bullet}", Text(note, style="dim"))

    console.print(Panel(
        tbl,
        box=TH.box_inner,
        border_style=TH.c_secondary,
        padding=TH.panel_pad,
        safe_box=(TIER != Tier.FULL),
        expand=False,
    ))


# ── Config Decoders + Groups ──────────────────────────────────────────────────

DECODERS: Dict[str, Dict[int, str]] = {
    "SETTING_PROTOCOL":          {0: "HTTP", 1: "DNS", 2: "SMB", 4: "TCP", 8: "HTTPS"},
    "SETTING_SYSCALL_METHOD":    {0: "none", 1: "direct", 2: "indirect"},
    "SETTING_EXIT_FUNK":         {0: "none", 1: "ExitThread", 2: "ExitProcess"},
    "SETTING_PROCINJ_ALLOCATOR": {0: "VirtualAllocEx", 1: "NtMapViewOfSection"},
    "SETTING_PROXY_BEHAVIOR":    {0: "direct", 1: "IE settings", 2: "manual", 4: "block"},
    "SETTING_CRYPTO_SCHEME":     {0: "none", 1: "AES256"},
}

CONFIG_GROUPS: Dict[str, List[str]] = {
    "Network": [
        "SETTING_PROTOCOL", "SETTING_PORT", "SETTING_SLEEPTIME", "SETTING_JITTER",
        "SETTING_DOMAINS", "SETTING_SUBMITURI", "SETTING_USERAGENT",
        "SETTING_HOST_HEADER", "SETTING_PROXY_BEHAVIOR",
        "SETTING_C2_VERB_GET", "SETTING_C2_VERB_POST",
    ],
    "Identity": [
        "SETTING_WATERMARK", "SETTING_MASKED_WATERMARK", "SETTING_WATERMARKHASH",
        "SETTING_PUBKEY", "SETTING_KILLDATE",
    ],
    "Evasion": [
        "SETTING_SYSCALL_METHOD", "SETTING_GARGLE_NOOK", "SETTING_CLEANUP",
        "SETTING_CFG_CAUTION", "SETTING_EXIT_FUNK", "SETTING_CRYPTO_SCHEME",
        "SETTING_BEACON_GATE", "SETTING_BEACON_GATE_CONFIG",
        "SETTING_RDLL_USE_DRIPLOADING", "SETTING_RDLL_DRIPLOAD_DELAY",
    ],
    "Injection": [
        "SETTING_PROCINJ_ALLOCATOR", "SETTING_PROCINJ_MINALLOC",
        "SETTING_PROCINJ_PERMS", "SETTING_PROCINJ_PERMS_I",
        "SETTING_PROCINJ_BOF_REUSE_MEM", "SETTING_PROCINJ_STUB",
        "SETTING_SPAWNTO_X86", "SETTING_SPAWNTO_X64", "SETTING_SPAWNTO",
    ],
}

GROUP_STYLES: Dict[str, str] = {
    "Network":   TH.c_success,
    "Identity":  TH.c_primary,
    "Evasion":   TH.c_warn,
    "Injection": TH.c_secondary,
}

GROUP_ICONS: Dict[str, str] = {
    "Network":   TH.tri,
    "Identity":  TH.gem,
    "Evasion":   TH.diamond,
    "Injection": TH.star,
}


def _decode_setting(key: str, value: Any) -> str:
    """Human-decode known config settings to readable strings."""
    if key in DECODERS and isinstance(value, (int, float)):
        return DECODERS[key].get(int(value), f"unknown({int(value)})")
    if key == "SETTING_SLEEPTIME" and isinstance(value, (int, float)):
        secs = value / 1000
        return f"{secs:.1f}s" if secs < 60 else f"{secs / 60:.1f}m"
    if key == "SETTING_JITTER" and isinstance(value, (int, float)):
        return f"{int(value)}%"
    if key == "SETTING_KILLDATE" and isinstance(value, (int, float)) and value > 0:
        y = int(value) // 10000
        m = (int(value) % 10000) // 100
        d = int(value) % 100
        return f"{y}-{m:02d}-{d:02d}" if y > 2000 else ""
    return ""


# ── Config Table ──────────────────────────────────────────────────────────────

def print_config_table(config: Dict[str, Any], xor_key: str = "",
                       settings_count: int = 0) -> None:
    """Print config in grouped, color-coded Panel/Table layout."""
    key_disp = f"XOR 0x{xor_key.upper()}" if xor_key else "XOR unknown"
    _section_header(TH.gem, "BEACON CONFIG",
                    f"{settings_count} settings  {TH.dot}  {key_disp}")

    displayed: set = set()
    inner_w = _inner_width()

    for group_name, keys in CONFIG_GROUPS.items():
        group_items = [(k, config[k]) for k in keys if k in config]
        if not group_items:
            continue

        g_style = GROUP_STYLES.get(group_name, "bright_white")
        g_icon  = GROUP_ICONS.get(group_name, TH.diamond)

        tbl = Table(
            box=TH.box_table,
            show_header=True,
            header_style=f"bold {g_style}",
            padding=(0, 1),
            safe_box=(TIER != Tier.FULL),
            expand=True,
            width=inner_w,
        )
        tbl.add_column("Setting", style=TH.c_muted, min_width=24, max_width=32)
        tbl.add_column("Value",   style="bright_white")
        tbl.add_column("Decoded", style=f"bold {g_style}", min_width=14)

        for key, val in group_items:
            decoded  = _decode_setting(key, val)
            val_str  = str(val)
            max_vlen = max(20, inner_w - 60)
            if len(val_str) > max_vlen:
                val_str = val_str[:max_vlen] + "…"
            short_key = key.replace("SETTING_", "").lower()

            dec_text = Text(decoded)
            if decoded:
                dl = decoded.lower()
                if "indirect" in dl or "https" in decoded:
                    dec_text.stylize(f"bold {TH.c_success}")
                elif "direct" in dl or decoded in ("HTTP", "DNS"):
                    dec_text.stylize(f"bold {TH.c_warn}")
                elif decoded in ("none",):
                    dec_text.stylize("dim")

            tbl.add_row(short_key, val_str, dec_text)
            displayed.add(key)

        title_text = Text(f" {g_icon} {group_name} ", style=f"bold {g_style}")
        console.print(Panel(
            tbl,
            title=title_text,
            title_align="left",
            box=TH.box_outer,
            border_style=g_style,
            padding=(0, 0),
            safe_box=(TIER != Tier.FULL),
        ))
        console.print()

    # ── Ungrouped / Other settings ──
    remaining = sorted(k for k in config if k not in displayed)
    if remaining:
        other_tbl = Table(
            box=TH.box_table,
            show_header=False,
            padding=(0, 1),
            safe_box=(TIER != Tier.FULL),
            expand=True,
            width=inner_w,
        )
        other_tbl.add_column("Setting", style="dim", min_width=24)
        other_tbl.add_column("Value",   style="dim")

        for key in remaining:
            val     = config[key]
            val_str = str(val)
            if len(val_str) > 50:
                val_str = val_str[:50] + "…"
            decoded = _decode_setting(key, val)
            if decoded:
                val_str += f"  {TH.arrow} {decoded}"
            other_tbl.add_row(key.replace("SETTING_", "").lower(), val_str)

        console.print(Panel(
            other_tbl,
            title=Text(f" {TH.diamond} Other ({len(remaining)}) ", style="dim"),
            title_align="left",
            box=TH.box_outer,
            border_style=TH.c_muted,
            padding=(0, 0),
            safe_box=(TIER != Tier.FULL),
        ))
        console.print()


# ── Segments Summary ──────────────────────────────────────────────────────────

SEG_STYLES: Dict[str, Tuple[str, str]] = {
    "LOADER": (TH.c_warn,      TH.tri),
    "BEACON": (TH.c_success,   TH.diamond),
    "CONFIG": (TH.c_primary,   TH.gem),
    "SLEEP":  (TH.c_secondary, TH.dot),
    "POSTEX": ("#ff6ec7",      TH.star),
}


def print_segments_summary(segments: List[Dict[str, Any]]) -> None:
    """Print payload segments as visual Panel cards."""
    _section_header(TH.gem, "SEGMENTS", f"{len(segments)} components")

    total_size = sum(seg.get("size", 0) for seg in segments) or 1

    for i, seg in enumerate(segments):
        seg_id    = _sanitize(seg.get("segmentId", "?"))
        seg_type  = _sanitize(seg.get("type", ""))
        offset    = seg.get("offset", 0)
        size      = seg.get("size", 0)
        seg_ent   = seg.get("entropy", 0.0)
        sha256    = seg.get("sha256", "")
        confidence= seg.get("confidenceScore", 0.0)
        dll_refs  = seg.get("dllReferences", [])
        config    = seg.get("config", {})
        count     = seg.get("count", 0)
        bg        = seg.get("beaconGateDetected", None)

        # Pick color + icon
        color, icon = TH.c_muted, TH.dot
        for key, (c, ic) in SEG_STYLES.items():
            if key in seg_id:
                color, icon = c, ic
                break

        # Build card content as a table
        inner_w = _inner_width()
        card = Table(
            box=None,
            show_header=False,
            padding=(0, 1),
            expand=True,
            width=inner_w,
        )
        card.add_column("k", style=TH.c_muted,     width=12)
        card.add_column("v", style="bright_white",  ratio=1)

        # Offset + size
        size_str = (f"{size:,}B" if size < 1_048_576 else f"{size / 1_048_576:.1f}MB")
        card.add_row("Offset",  f"0x{offset:x}  ({size_str})")

        # Confidence
        card.add_row("Conf",    confidence_bar(confidence, width=18))

        # Entropy bar
        ent_c   = entropy_color(seg_ent)
        ent_bar = Text()
        ent_bar.append(f"{seg_ent:.4f} ", style=f"bold {ent_c}")
        bar_len = int(seg_ent / 8.0 * 18)
        spark_c = TH.spark
        ent_bar.append(spark_c[-1] * bar_len, style=ent_c)
        ent_bar.append(spark_c[0]  * (18 - bar_len), style="dim")
        if   seg_ent > 7.5: ent_bar.append("  encrypted", style=TH.c_danger)
        elif seg_ent > 6.5: ent_bar.append("  packed",    style=TH.c_warn)
        elif seg_ent > 4.0: ent_bar.append("  code/data", style=TH.c_success)
        else:                ent_bar.append("  sparse",    style="dim")
        card.add_row("Entropy", ent_bar)

        # Size proportion bar
        pct     = size / total_size
        sz_bar  = Text()
        bar_w   = max(1, int(pct * 18))
        sz_bar.append(TH.bar_full * bar_w, style=color)
        sz_bar.append(TH.bar_empty * (18 - bar_w), style="dim")
        sz_bar.append(f"  {pct:.1%}", style=TH.c_muted)
        card.add_row("Share",   sz_bar)

        # SHA256
        if sha256:
            sha_t = Text()
            sha_t.append(sha256[:32], style=TH.c_muted)
            sha_t.append("…", style="dim")
            card.add_row("SHA-256", sha_t)

        # Config count
        if config:
            card.add_row("Config",
                         Text(f"{len(config)} settings", style=f"bold {TH.c_primary}"))

        # DLL refs
        for dll in dll_refs:
            dll_name = _sanitize(dll.get("name", "?"))
            embedded = dll.get("embedded", False)
            dll_size = dll.get("size", 0)
            d_text   = Text()
            if embedded:
                d_text.append(f"{TH.arrow} {dll_name}", style=f"bold {TH.c_secondary}")
                if dll_size:
                    d_text.append(f"  {dll_size:,}B", style="dim")
                d_text.append("  [embedded]", style=TH.c_secondary)
            else:
                d_text.append(f"{TH.dot} {dll_name}", style="dim")
            card.add_row("PostEx", d_text)

        # Bare ref count
        if count > 0 and not dll_refs:
            card.add_row("Refs", Text(f"{count}", style=f"bold {color}"))

        # BeaconGate
        if bg is not None:
            bg_text = (Text(f"{TH.cross} DETECTED", style=f"bold {TH.c_danger}")
                       if bg else
                       Text(f"{TH.check} not detected", style="dim"))
            card.add_row("BeaconGate", bg_text)

        # seg_type badge in title
        title_parts = Text()
        title_parts.append(f" {icon} {seg_id} ", style=f"bold {color}")
        if seg_type:
            title_parts.append(f"[{seg_type}]", style=f"italic {color}")

        console.print(Panel(
            card,
            title=title_parts,
            title_align="left",
            box=TH.box_outer,
            border_style=color,
            padding=(0, 1),
            safe_box=(TIER != Tier.FULL),
        ))

        if i < len(segments) - 1:
            console.print(Text(f"  {TH.pipe}", style="dim"))


# ── Profile Validation ────────────────────────────────────────────────────────

def print_profile_validation(
    profile_name: str, magic_mz: str, magic_pe: str,
    stomppe: bool, sleep_mask: bool,
    match_count: int, total: int, match_pct: float,
    mismatches: List[tuple],
) -> None:
    """Print profile validation with match gauge Panel."""
    _section_header(TH.gem, "C2 PROFILE", profile_name, style=TH.c_primary)

    tbl = Table(
        box=TH.box_table,
        show_header=False,
        padding=(0, 2),
        safe_box=(TIER != Tier.FULL),
        expand=False,
    )
    tbl.add_column("k", style=TH.c_muted, width=14)
    tbl.add_column("v", style="bright_white")

    # PE magic row
    magic_t = Text()
    magic_t.append(f"MZ={magic_mz}", style=f"bold {TH.c_success}")
    magic_t.append("  ")
    magic_t.append(f"PE={magic_pe}", style=f"bold {TH.c_success}")
    if stomppe:
        magic_t.append("  ")
        magic_t.append_text(_badge("StompPE", TH.c_warn))
    if sleep_mask:
        magic_t.append("  ")
        magic_t.append_text(_badge("SleepMask", TH.c_primary))
    tbl.add_row("Magic", magic_t)

    # Match gauge
    match_t = Text()
    match_t.append_text(confidence_bar(match_pct / 100.0, width=20))
    match_t.append(f"  ({match_count}/{total})", style=TH.c_muted)
    tbl.add_row("Match", match_t)

    # Mismatches
    for item in mismatches:
        if isinstance(item, (list, tuple)) and len(item) >= 3:
            setting, expected, actual = item[0], item[1], item[2]
            mm_t = Text()
            mm_t.append(f"{TH.cross} {setting}: ", style=TH.c_danger)
            mm_t.append(f"expected={expected} ", style="dim")
            mm_t.append(f"got={actual}", style="bright_white")
            tbl.add_row("Mismatch", mm_t)

    console.print(Panel(
        tbl,
        box=TH.box_inner,
        border_style=TH.c_primary,
        padding=TH.panel_pad,
        safe_box=(TIER != Tier.FULL),
        expand=False,
    ))


# ── Pipeline Confidence Footer ────────────────────────────────────────────────

def print_pipeline_confidence(conf: float) -> None:
    """Print final pipeline confidence as a gradient-ruled footer."""
    console.print()
    conf_bar_text = confidence_bar(conf, width=32)
    if TIER in (Tier.FULL, Tier.BASIC):
        label = Text()
        label.append(f"{TH.gem} ", style=f"bold {TH.c_secondary}")
        label.append("PIPELINE CONFIDENCE  ", style="bold bright_white")
        label.append_text(conf_bar_text)
        console.print(label)
        console.print(Rule(style=TH.c_primary))
    else:
        console.print(Text(
            f"PIPELINE CONFIDENCE: {conf:.0%}", style="bold cyan"
        ))
        console.print(Text("=" * 60, style="cyan"))
    console.print()


# ── Plugin Results ────────────────────────────────────────────────────────────

def print_plugin_results(renderables: List[tuple]) -> None:
    """Print plugin results with a section header."""
    if not renderables:
        return
    _section_header(TH.gem, "ANALYSIS RESULTS",
                    f"{len(renderables)} plugins", style=TH.c_secondary)
    for _plugin_name, renderable in renderables:
        console.print(renderable)
        console.print()


# ── Warnings / Errors ─────────────────────────────────────────────────────────

def print_warnings(warnings: List[str]) -> None:
    if not warnings:
        return
    for w in warnings:
        t = Text(f"  {TH.bullet} ", style=TH.c_warn)
        t.append(w, style=TH.c_warn)
        console.print(t)


def print_errors(errors: List[str]) -> None:
    if not errors:
        return
    for e in errors:
        t = Text(f"  {TH.cross} ", style=TH.c_danger)
        t.append(e, style=TH.c_danger)
        console.print(t)


# ── Minimal Summary ───────────────────────────────────────────────────────────

def print_minimal_rich(manifest_dict: dict) -> None:
    """One-line premium summary."""
    meta           = manifest_dict.get("metadata", {})
    detected       = meta.get("csVersionDetected", {})
    classification = meta.get("payloadClassification", {})
    segments       = manifest_dict.get("segments", [])
    warnings       = meta.get("warnings", [])

    text = Text()
    text.append("CS ", style="dim")
    text.append(detected.get("version", "?"), style=f"bold {TH.c_success}")
    text.append(f"  {TH.pipe}  ", style="dim")
    text.append(
        f"{classification.get('type','?')}/{classification.get('architecture','?')}",
        style=f"bold {TH.c_primary}",
    )
    text.append(f"  {TH.pipe}  ", style="dim")
    conf = detected.get("confidence", 0.0)
    conf_c = TH.c_success if conf >= 0.9 else TH.c_warn if conf >= 0.5 else TH.c_danger
    text.append(f"conf={conf:.0%}", style=f"bold {conf_c}")
    text.append(f"  {TH.pipe}  ", style="dim")
    text.append(f"{len(segments)} segments", style="bold white")
    if warnings:
        text.append(f"  {TH.pipe}  {len(warnings)} warnings", style=f"bold {TH.c_warn}")
    console.print(text)


# ── Entropy Heatmap ───────────────────────────────────────────────────────────

def render_entropy_heatmap(rolling_values: List[float],
                           window_size: int = 256) -> Panel:
    """Render a rolling-entropy heatmap as a Rich Panel."""
    if not rolling_values:
        return Panel(Text("No entropy data", style="dim"), title="Entropy Map")

    WIDTH   = 64
    content = Text()
    spark   = TH.spark
    n_spark = len(spark)

    step    = max(1, len(rolling_values) // (WIDTH * 8))
    sampled = rolling_values[::step]

    for row_start in range(0, min(len(sampled), WIDTH * 8), WIDTH):
        row    = sampled[row_start:row_start + WIDTH]
        offset = row_start * step * (window_size // 4)
        content.append(f"0x{offset:06x} ", style="dim")
        for val in row:
            c   = entropy_color(val)
            idx = int((val / 8.0) * (n_spark - 1))
            content.append(spark[max(0, min(idx, n_spark - 1))], style=c)
        content.append("\n")

    content.append("\n")
    if TIER == Tier.FULL:
        content.append("▁▂▃ low  ",  style=TH.c_success)
        content.append("▄▅ medium  ", style=TH.c_warn)
        content.append("▆▇ high  ",  style=TH.c_danger)
        content.append("█ packed",   style="bold red")
    else:
        content.append(". low  ", style=TH.c_success)
        content.append("= medium  ", style=TH.c_warn)
        content.append("# high  ",   style=TH.c_danger)
        content.append("@ packed",   style="bold red")

    return Panel(
        content,
        title=Text(f" {TH.gem} Entropy Heatmap ", style=f"bold {TH.c_secondary}"),
        title_align="left",
        border_style=TH.c_secondary,
        box=TH.box_inner,
        padding=(1, 2),
        safe_box=(TIER != Tier.FULL),
    )
