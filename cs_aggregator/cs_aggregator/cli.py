"""CLI — Command-Line Interface for cs_aggregator.

Provides the main entry point via argparse for both:
    - python -m cs_aggregator <file>
    - cs-aggregator <file> (console script)
"""

import argparse
import io
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional

# UTF-8 encoding for stdout only — stderr is handled by rich_output.py
if sys.stdout.encoding and sys.stdout.encoding.lower().replace('-', '') != 'utf8':
    if hasattr(sys.stdout, 'buffer'):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

from cs_aggregator import __version__
from cs_aggregator.engine import DissectionPipeline


def setup_logging(verbosity: int) -> None:
    """Configure logging based on verbosity level.

    Args:
        verbosity: 0 = error only, 1 = warning, 2 = info, 3 = debug
    """
    level = logging.WARNING
    if verbosity >= 1:
        level = logging.INFO
    if verbosity >= 2:
        level = logging.DEBUG

    logging.basicConfig(
        level=level,
        format="%(levelname)-8s | %(message)s",
        stream=sys.stderr,
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="cs-aggregator",
        description="CobaltStrike Beacon Shellcode Aggregation & Dissection Engine v{}".format(
            __version__
        ),
        epilog=(
            "Examples:\n"
            "  cs-aggregator beacon.bin\n"
            "  cs-aggregator beacon.bin -o output.json -v\n"
            "  cs-aggregator beacon.bin --validate-with pefile\n"
            "  cat beacon.bin | cs-aggregator -\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "input",
        nargs="?",
        help="Path to payload file (omit or use '-' for stdin)",
    )

    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Write manifest to file instead of stdout",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v = info, -vv = debug)",
    )

    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress all non-JSON output (errors go to stderr)",
    )

    parser.add_argument(
        "--minimal",
        action="store_true",
        help="Output minimal summary instead of full manifest",
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable color output (autodetected when output is piped)",
    )

    parser.add_argument(
        "--validate-with",
        type=str,
        choices=["pefile", "dissect", "both"],
        default=None,
        help="Optional cross-validation using third-party libraries",
    )

    parser.add_argument(
        "--profile",
        type=str,
        default=None,
        metavar="PROFILE",
        help="Malleable C2 profile (.profile) to guide dissection and validate config",
    )

    parser.add_argument(
        "--reassemble",
        type=str,
        default=None,
        metavar="PAYLOAD",
        help="Reassemble a modified payload from the dissection of PAYLOAD file",
    )

    parser.add_argument(
        "--with-loader",
        type=str,
        default=None,
        metavar="LOADER",
        help="Replace loader stub with custom UDRL file",
    )

    parser.add_argument(
        "--with-sleep-mask",
        type=str,
        default=None,
        metavar="MASK",
        help="Inject/replace sleep mask with custom mask file",
    )

    parser.add_argument(
        "--with-config",
        type=str,
        default=None,
        metavar="CONFIG",
        help="Modify config block using a JSON file (requires --xor-key)",
    )

    parser.add_argument(
        "--xor-key",
        type=str,
        default=None,
        metavar="HEX",
        help="XOR key for config re-encryption (hex-encoded, e.g. '2e2e2e2e')",
    )

    parser.add_argument(
        "--output-payload",
        type=str,
        default=None,
        metavar="FILE",
        help="Write reassembled payload to FILE",
    )

    parser.add_argument(
        "--list-modules",
        action="store_true",
        help="List available pipeline modules and exit",
    )

    parser.add_argument(
        "--list-schemas",
        action="store_true",
        help="List available version schemas and exit",
    )

    parser.add_argument(
        "--version",
        action="store_true",
        help="Show version information and exit",
    )

    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        metavar="DIR",
        help="Extract all components to DIR (loader, DLL, config, sleep mask as separate files)",
    )

    parser.add_argument(
        "--config-only",
        action="store_true",
        help="Extract and print only the config block JSON (skip full dissection output)",
    )

    parser.add_argument(
        "--lenient",
        action="store_true",
        help="Continue on non-fatal errors (e.g. missing sections, partial TLV parse)",
    )

    # Plugin system
    parser.add_argument(
        "--plugins",
        type=str,
        default=None,
        metavar="NAMES",
        help="Enable specific plugins (comma-separated, e.g. 'entropy,pe'). Default: all",
    )

    parser.add_argument(
        "--list-plugins",
        action="store_true",
        help="List available plugins and exit",
    )

    parser.add_argument(
        "--plugin-dir",
        type=str,
        default=None,
        metavar="DIR",
        help="Additional directory to scan for user plugins",
    )

    parser.add_argument(
        "--run-plugin",
        type=str,
        default=None,
        metavar="NAMES",
        help="Run specific plugin(s) only (comma-separated). Shows only plugin output.",
    )

    parser.add_argument(
        "--plugin-output",
        type=str,
        default="rich",
        choices=["rich", "json", "both"],
        help="Plugin output format: rich (default), json, or both",
    )

    # IOC Central Engine export
    parser.add_argument(
        "--export-ioc",
        type=str,
        nargs="+",
        choices=["stix", "misp", "csv"],
        default=None,
        metavar="FORMAT",
        help="Export IOCs in specified format(s): stix, misp, csv",
    )

    parser.add_argument(
        "--export-yara",
        type=str,
        default=None,
        metavar="PATH",
        help="Generate and export dynamic YARA rules to file",
    )

    # YARA custom rules
    parser.add_argument(
        "--yara-rules",
        type=str,
        default=None,
        metavar="PATH",
        help="Load custom YARA rules from file (.yar/.yara) — extends builtin rules",
    )

    parser.add_argument(
        "--yara-dir",
        type=str,
        default=None,
        metavar="DIR",
        help="Load all .yar/.yara files from directory (recursive) — extends builtin rules",
    )

    parser.add_argument(
        "--yara-no-builtin",
        action="store_true",
        default=False,
        help="Skip builtin YARA rules — scan only with custom rules",
    )

    # Memory dump input mode
    parser.add_argument(
        "--memory-dump",
        type=str,
        nargs=2,
        metavar=("OFFSET", "SIZE"),
        default=None,
        help="Treat input as memory dump — extract payload from OFFSET with SIZE bytes (hex or decimal)",
    )

    # Multi-beacon extraction
    parser.add_argument(
        "--extract-all",
        action="store_true",
        help="Scan for and extract ALL embedded beacons in the input payload",
    )

    # Manual decryption key
    parser.add_argument(
        "--decryption-key",
        type=str,
        default=None,
        metavar="HEX",
        help="Manual full-payload decryption key (hex-encoded, applied before dissection)",
    )

    # Extended bruteforce key space
    parser.add_argument(
        "--extended-bruteforce",
        action="store_true",
        help="Expand XOR brute-force to 2-byte keys (0x0000–0xFFFF) — slower but catches custom keys",
    )

    # Batch mode
    parser.add_argument(
        "--batch",
        type=str,
        default=None,
        metavar="GLOB",
        help="Batch process multiple payloads (directory or glob pattern, e.g. 'payloads/*.bin')",
    )

    # Fragment reassembly mode (drip-loading)
    parser.add_argument(
        "--fragment-mode",
        type=str,
        nargs="+",
        default=None,
        metavar="FILE",
        help="Reassemble payload from multiple fragment files (drip-loading support)",
    )

    parser.add_argument(
        "--fragment-dir",
        type=str,
        default=None,
        metavar="DIR",
        help="Directory containing payload fragments to reassemble",
    )

    parser.add_argument(
        "--fragment-timeout",
        type=int,
        default=30,
        metavar="SEC",
        help="Timeout for fragment reassembly in seconds (default: 30)",
    )

    # Disassembly
    parser.add_argument(
        "--disassemble",
        action="store_true",
        help="Disassemble loader stub using Capstone engine (x86_64)",
    )

    return parser


def handle_special_actions(args: argparse.Namespace) -> bool:
    """Handle non-dissection actions (--version, --list-modules, --list-schemas).

    Returns True if the action was handled (no dissection needed).
    """
    if args.version:
        print(f"cs-aggregator v{__version__}")
        print("CobaltStrike Beacon Shellcode Aggregation & Dissection Engine")
        print("Python >= 3.11 required")
        return True

    if args.list_modules:
        print("Available pipeline modules:")
        print("  MOD_INPUT              Payload classification")
        print("  MOD_VERSION_DETECTOR   CS version detection (two-stage)")
        print("  MOD_LOADER_EXTRACTOR   Reflective loader stub extraction")
        print("  MOD_BUD_ANALYZER       Beacon User Data structure analysis")
        print("  MOD_BEACON_PARSER      Beacon DLL PE analysis (custom)")
        print("  MOD_CONFIG_EXTRACTOR   TLV config extraction & XOR decryption")
        print("  MOD_SLEEPMASK_EXTRACTOR Sleep mask detection & BeaconGate analysis")
        print("  MOD_POSTEX_EXTRACTOR   Post-exploitation DLL identification")
        print("  MOD_MANIFEST_GENERATOR JSON manifest assembly")
        print("  MOD_REASSEMBLER        Payload reassembly & modification (Phase 3)")
        print()
        print("Total: 10 modules")
        return True

    if args.list_schemas:
        from cs_aggregator.modules.version_detector import VersionDetector

        try:
            detector = VersionDetector()
            versions = detector.get_available_versions()
            print(f"Available version schemas ({len(versions)}):")
            for v in sorted(versions):
                schema = detector.get_schema(v)
                meta = schema.get("meta", {}) if schema else {}
                notes = meta.get("notes", "")
                print(f"  {v:14s}  {notes}")
        except Exception as e:
            print(f"Error loading schemas: {e}", file=sys.stderr)
            return True
        return True

    if args.list_plugins:
        from cs_aggregator.plugins import PluginManager

        plugin_dirs = [args.plugin_dir] if args.plugin_dir else []
        manager = PluginManager(plugin_dirs=plugin_dirs)
        manager.discover()

        try:
            from rich.console import Console
            from rich.table import Table
            from rich import box

            console = Console()
            table = Table(
                title="Available Plugins",
                box=box.SIMPLE_HEAVY,
                header_style="bold bright_white",
            )
            table.add_column("Name", style="bright_cyan")
            table.add_column("Version", style="dim")
            table.add_column("Source", style="bright_yellow")
            table.add_column("Hooks", style="bright_green")
            table.add_column("Description")

            for p in manager.list_plugins_table():
                table.add_row(
                    p["name"], p["version"], p["source"],
                    ", ".join(p["hooks"]), p["description"],
                )

            console.print(table)
        except ImportError:
            for p in manager.list_plugins_table():
                print(f"  {p['name']:20s} v{p['version']:8s} [{p['source']:10s}] {p['description']}")

        return True

    return False


def read_input(args: argparse.Namespace) -> Optional[bytes]:
    """Read payload data from file or stdin.

    Returns None if no input is available.
    """
    if args.input and args.input != "-":
        input_path = os.path.expanduser(args.input)
        if not os.path.isfile(input_path):
            print(f"Error: file not found: {input_path}", file=sys.stderr)
            sys.exit(1)
        try:
            with open(input_path, "rb") as f:
                return f.read()
        except OSError as e:
            print(f"Error: cannot read {input_path}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Read from stdin
        if sys.stdin.isatty():
            # No piped input and no file argument
            return None
        try:
            return sys.stdin.buffer.read()
        except OSError as e:
            print(f"Error: cannot read stdin: {e}", file=sys.stderr)
            sys.exit(1)


def colorize(text: str, color: str, no_color: bool = False) -> str:
    """Apply ANSI color to text if color is enabled.

    Args:
        text: The text to colorize.
        color: Color name (green, yellow, red, cyan, bold).
        no_color: If True, return plain text.
    """
    if no_color or not sys.stdout.isatty():
        return text

    colors = {
        "green": "\033[92m",
        "yellow": "\033[93m",
        "red": "\033[91m",
        "cyan": "\033[96m",
        "bold": "\033[1m",
        "reset": "\033[0m",
    }
    code = colors.get(color, "")
    reset = colors["reset"]
    return f"{code}{text}{reset}"


def print_minimal_summary(manifest_dict: dict, no_color: bool = False) -> None:
    """Print a minimal one-line summary of the dissection results."""
    meta = manifest_dict.get("metadata", {})
    detected = meta.get("csVersionDetected", {})
    classification = meta.get("payloadClassification", {})
    segments = manifest_dict.get("segments", [])
    warnings = meta.get("warnings", [])

    version_str = detected.get("version", "unknown")
    version_conf = detected.get("confidence", 0.0)
    payload_type = classification.get("type", "unknown")
    arch = classification.get("architecture", "unknown")

    c2_servers: List[str] = []
    for seg in segments:
        config = seg.get("config", {})
        servers = config.get("c2Servers", [])
        if servers:
            c2_servers.extend(
                f"{s.get('address', '?')}:{s.get('port', '?')}" for s in servers
            )

    parts = [
        colorize(f"[CS {version_str}]", "green", no_color),
        colorize(f"{payload_type}/{arch}", "cyan", no_color),
        colorize(f"conf={version_conf:.0%}", "yellow", no_color),
        colorize(f"{len(segments)} segments", "bold", no_color),
    ]
    if c2_servers:
        parts.append(colorize(f"C2: {', '.join(c2_servers[:3])}", "yellow", no_color))
    if warnings:
        parts.append(colorize(f"{len(warnings)} warnings", "red", no_color))

    print(" ".join(parts))


def print_full_manifest(
    manifest_dict: dict,
    output_path: Optional[str] = None,
    no_color: bool = False,
) -> None:
    """Print or write the full JSON manifest."""
    json_str = json.dumps(manifest_dict, indent=2, default=str)

    if output_path:
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(json_str)
            print(
                colorize(f"Manifest written to {output_path}", "green", no_color),
                file=sys.stderr,
            )
        except OSError as e:
            print(
                colorize(f"Error writing manifest: {e}", "red", no_color),
                file=sys.stderr,
            )
            sys.exit(1)
    else:
        # Check for warnings to print to stderr before stdout JSON
        warnings = manifest_dict.get("metadata", {}).get("warnings", [])
        if warnings:
            for w in warnings:
                print(
                    colorize(f"WARNING: {w}", "yellow", no_color),
                    file=sys.stderr,
                )

        # Print the JSON to stdout
        print(json_str)


def handle_reassembly(
    args: argparse.Namespace,
    manifest_dict: dict,
    original_data: bytes,
    no_color: bool = False,
) -> None:
    """Handle reassembly operations (--reassemble, --with-loader, etc.).

    Performs the reassembly and writes the output payload to --output-payload.
    """
    from cs_aggregator.engine import DissectionPipeline
    from cs_aggregator.utils.types import ReassemblyConfig

    # Build ReassemblyConfig from CLI flags
    loader_bytes = None
    if args.with_loader:
        loader_path = os.path.expanduser(args.with_loader)
        if not os.path.isfile(loader_path):
            print(
                colorize(f"Error: loader file not found: {loader_path}", "red", no_color),
                file=sys.stderr,
            )
            sys.exit(1)
        with open(loader_path, "rb") as f:
            loader_bytes = f.read()
        print(
            colorize(f"Loaded custom UDRL: {len(loader_bytes)} bytes", "green", no_color),
            file=sys.stderr,
        )

    sleep_mask_bytes = None
    if args.with_sleep_mask:
        mask_path = os.path.expanduser(args.with_sleep_mask)
        if not os.path.isfile(mask_path):
            print(
                colorize(f"Error: sleep mask file not found: {mask_path}", "red", no_color),
                file=sys.stderr,
            )
            sys.exit(1)
        with open(mask_path, "rb") as f:
            sleep_mask_bytes = f.read()
        print(
            colorize(f"Loaded custom sleep mask: {len(sleep_mask_bytes)} bytes", "green", no_color),
            file=sys.stderr,
        )

    modified_config = None
    xor_key_bytes = None
    if args.with_config:
        config_path = os.path.expanduser(args.with_config)
        if not os.path.isfile(config_path):
            print(
                colorize(f"Error: config file not found: {config_path}", "red", no_color),
                file=sys.stderr,
            )
            sys.exit(1)
        with open(config_path, "r", encoding="utf-8") as f:
            import json as json_lib
            modified_config = json_lib.load(f)
        print(
            colorize(f"Loaded modified config: {len(modified_config)} fields", "green", no_color),
            file=sys.stderr,
        )

        if args.xor_key:
            try:
                xor_key_bytes = bytes.fromhex(args.xor_key)
                print(
                    colorize(f"Using XOR key: {args.xor_key} ({len(xor_key_bytes)} bytes)", "green", no_color),
                    file=sys.stderr,
                )
            except ValueError:
                print(
                    colorize(f"Error: invalid hex XOR key: {args.xor_key}", "red", no_color),
                    file=sys.stderr,
                )
                sys.exit(1)
        else:
            # Try to extract XOR key from the manifest
            for seg in manifest_dict.get("segments", []):
                if seg.get("segmentId") == "SEG_CONFIG_BLOCK":
                    key_hex = seg.get("xorKey", "")
                    if key_hex:
                        xor_key_bytes = bytes.fromhex(key_hex)
                        print(
                            colorize(f"Using XOR key from manifest: {key_hex}", "green", no_color),
                            file=sys.stderr,
                        )
                    break

            if xor_key_bytes is None:
                print(
                    colorize(
                        "No XOR key found in manifest or provided via --xor-key. Config re-encryption disabled.",
                        "yellow",
                        no_color,
                    ),
                    file=sys.stderr,
                )

    # Build the manifest object from the dict (it was already dissected)
    # We need to reconstruct the Manifest object
    from cs_aggregator.utils.types import Manifest as ManifestCls

    m = ManifestCls(
        manifest_format_version=manifest_dict.get("manifestFormatVersion", "2.0"),
        metadata=manifest_dict.get("metadata", {}),
        segments=manifest_dict.get("segments", []),
    )

    config = ReassemblyConfig(
        custom_loader=loader_bytes,
        modified_dll=None,  # Keep original DLL unless modified via --with-dll (future)
        custom_sleep_mask=sleep_mask_bytes,
        modified_config=modified_config,
        xor_key=xor_key_bytes,
    )

    # Run reassembly
    print(
        colorize("Running payload reassembly...", "bold", no_color),
        file=sys.stderr,
    )

    pipeline = DissectionPipeline()
    result = pipeline.rebuild_from_original(original_data, m, config)

    if not result.success:
        print(
            colorize(f"Reassembly failed: {', '.join(result.errors)}", "red", no_color),
            file=sys.stderr,
        )
        sys.exit(1)

    # Write reassembled payload
    output_path = args.output_payload or "reassembled_payload.bin"
    try:
        with open(output_path, "wb") as f:
            f.write(result.payload)
        print(
            colorize(
                f"Reassembled payload written: {output_path} ({len(result.payload):,} bytes)",
                "green",
                no_color,
            ),
            file=sys.stderr,
        )
        if result.warnings:
            for w in result.warnings:
                print(
                    colorize(f"  Warning: {w}", "yellow", no_color),
                    file=sys.stderr,
                )
        print(
            colorize(f"SHA256: {result.sha256}", "cyan", no_color),
            file=sys.stderr,
        )
    except OSError as e:
        print(
            colorize(f"Error writing reassembled payload: {e}", "red", no_color),
            file=sys.stderr,
        )
        sys.exit(1)


def _generate_dynamic_yara(manifest: dict, raw_data: bytes, pipeline: Any) -> str:
    """Generate payload-specific YARA rules from dissection results."""
    import hashlib
    from datetime import datetime

    meta = manifest.get("metadata", {})
    config = {}
    segments = manifest.get("segments", [])

    # Extract config from manifest
    for seg in segments:
        if seg.get("segmentId") == "SEG_CONFIG_BLOCK":
            config = seg.get("config", {})
            break

    version = meta.get("version", {})
    ver_str = version.get("estimatedVersion", "unknown") if isinstance(version, dict) else "unknown"
    sha256 = hashlib.sha256(raw_data).hexdigest()
    timestamp = datetime.utcnow().strftime("%Y-%m-%d")
    source = meta.get("sourceFile", "unknown")

    lines = []
    lines.append(f"// Auto-generated YARA rules from KimiK0 CS Dissection Engine")
    lines.append(f"// Source: {source}")
    lines.append(f"// SHA256: {sha256}")
    lines.append(f"// Generated: {timestamp}")
    lines.append(f"// CS Version: {ver_str}")
    lines.append("")

    # Rule 1: Config block signature
    # Find config XOR key and generate detection bytes
    config_offset = None
    config_size = 0
    for seg in segments:
        if seg.get("segmentId") == "SEG_CONFIG_BLOCK":
            config_offset = seg.get("offset", 0)
            config_size = seg.get("size", 0)
            break

    if config_offset is not None and config_size > 16:
        # Extract first 16 bytes of config block for signature
        sig_bytes = raw_data[config_offset:config_offset + 16]
        hex_sig = " ".join(f"{b:02X}" for b in sig_bytes)
        lines.append(f"rule KimiK0_Beacon_Config_{sha256[:8]} {{")
        lines.append(f"    meta:")
        lines.append(f"        description = \"CobaltStrike Beacon config block from {source}\"")
        lines.append(f"        author = \"KimiK0 Auto-Generator\"")
        lines.append(f"        date = \"{timestamp}\"")
        lines.append(f"        cs_version = \"{ver_str}\"")
        lines.append(f"        sha256 = \"{sha256}\"")
        lines.append(f"        severity = \"high\"")
        lines.append(f"    strings:")
        lines.append(f"        $config_header = {{ {hex_sig} }}")
        lines.append(f"    condition:")
        lines.append(f"        $config_header")
        lines.append(f"}}")
        lines.append("")

    # Rule 2: Loader stub signature
    loader_offset = None
    loader_size = 0
    for seg in segments:
        if seg.get("segmentId") == "SEG_LOADER_STUB":
            loader_offset = seg.get("offset", 0)
            loader_size = seg.get("size", 0)
            break

    if loader_offset is not None and loader_size > 8:
        stub_bytes = raw_data[loader_offset:loader_offset + min(loader_size, 32)]
        hex_stub = " ".join(f"{b:02X}" for b in stub_bytes[:16])
        lines.append(f"rule KimiK0_Beacon_Loader_{sha256[:8]} {{")
        lines.append(f"    meta:")
        lines.append(f"        description = \"CobaltStrike loader stub from {source}\"")
        lines.append(f"        author = \"KimiK0 Auto-Generator\"")
        lines.append(f"        date = \"{timestamp}\"")
        lines.append(f"        cs_version = \"{ver_str}\"")
        lines.append(f"        severity = \"high\"")
        lines.append(f"    strings:")
        lines.append(f"        $loader_stub = {{ {hex_stub} }}")
        lines.append(f"    condition:")
        lines.append(f"        $loader_stub")
        lines.append(f"}}")
        lines.append("")

    # Rule 3: Network IOC rule (C2 server, user-agent, pipes)
    c2_strings = []
    if config.get("SETTING_C2_REQUEST"):
        c2_strings.append(("c2_uri", str(config["SETTING_C2_REQUEST"])))
    if config.get("SETTING_USERAGENT"):
        ua = str(config["SETTING_USERAGENT"])
        if ua and ua != "0":
            c2_strings.append(("user_agent", ua))
    if config.get("SETTING_PIPENAME"):
        pipe = str(config["SETTING_PIPENAME"])
        if pipe and pipe != "0":
            c2_strings.append(("named_pipe", pipe))
    if config.get("SETTING_SPAWNTO_X64"):
        spawn = str(config["SETTING_SPAWNTO_X64"])
        if spawn and spawn != "0" and "rundll32" not in spawn.lower():
            c2_strings.append(("spawnto_x64", spawn))

    if c2_strings:
        lines.append(f"rule KimiK0_Beacon_Network_{sha256[:8]} {{")
        lines.append(f"    meta:")
        lines.append(f"        description = \"CobaltStrike Beacon network/operational IOCs from {source}\"")
        lines.append(f"        author = \"KimiK0 Auto-Generator\"")
        lines.append(f"        date = \"{timestamp}\"")
        lines.append(f"        severity = \"medium\"")
        lines.append(f"    strings:")
        for name, val in c2_strings:
            escaped = val.replace("\\", "\\\\").replace("\"", "\\\"")
            lines.append(f"        ${name} = \"{escaped}\"")
        lines.append(f"    condition:")
        lines.append(f"        any of them")
        lines.append(f"}}")
        lines.append("")

    # Rule 4: Composite behavioral rule
    lines.append(f"rule KimiK0_Beacon_Composite_{sha256[:8]} {{")
    lines.append(f"    meta:")
    lines.append(f"        description = \"Composite CobaltStrike Beacon detection from {source}\"")
    lines.append(f"        author = \"KimiK0 Auto-Generator\"")
    lines.append(f"        date = \"{timestamp}\"")
    lines.append(f"        cs_version = \"{ver_str}\"")
    lines.append(f"        sha256 = \"{sha256}\"")
    lines.append(f"        severity = \"critical\"")
    lines.append(f"    strings:")

    # PE magic bytes
    magic = raw_data[:4]
    lines.append(f"        $magic = {{ {' '.join(f'{b:02X}' for b in magic)} }}")

    # Look for MZ/PE patterns
    pe_offset = raw_data.find(b"MZ")
    if pe_offset >= 0 and pe_offset < 0x1000:
        lines.append(f"        $mz = {{ 4D 5A }} // PE header at 0x{pe_offset:x}")

    # Common CS strings (XOR-resilient)
    lines.append(f"        $sleep_fn = {{ 48 FF 15 }} // indirect call pattern")
    lines.append(f"    condition:")
    lines.append(f"        $magic at 0 and any of ($mz, $sleep_fn)")
    lines.append(f"}}")
    lines.append("")

    return "\n".join(lines)


def _write_metadata(
    writer: Any,
    name: str,
    meta: Dict[str, Any],
    no_color: bool = False,
) -> None:
    """Write a component metadata JSON file.

    Args:
        writer: OutputWriter instance.
        name: Metadata file name (without extension).
        meta: Metadata dict to serialize.
        no_color: Whether to suppress color in output.
    """
    import json
    path = os.path.join(writer.output_dir, f"{writer.base_name}_{name}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, default=str)
    print(
        colorize(f"  Metadata:     {path}", "dim", no_color),
        file=sys.stderr,
    )


# ─── Batch Processing ─────────────────────────────────────────────────────────


def _run_batch_mode(args: argparse.Namespace) -> None:
    """Process multiple payloads via glob pattern.

    Runs the dissection pipeline independently on each matched file,
    collecting results into a JSON summary array. Errors in one file
    do not halt processing of remaining files.
    """
    import glob
    import time

    pattern = args.batch
    matched_files = sorted(glob.glob(pattern, recursive=True))

    if not matched_files:
        print(f"No files matched pattern: {pattern}", file=sys.stderr)
        sys.exit(1)

    no_color = getattr(args, 'no_color', False)
    print(
        colorize(f"cs-aggregator v{__version__} — Batch Mode", "bold", no_color),
        file=sys.stderr,
    )
    print(
        colorize(f"Processing {len(matched_files)} file(s) from: {pattern}", "cyan", no_color),
        file=sys.stderr,
    )

    results = []
    success_count = 0
    fail_count = 0
    start_total = time.monotonic()

    for i, filepath in enumerate(matched_files, 1):
        print(
            colorize(f"\n[{i}/{len(matched_files)}] {os.path.basename(filepath)}", "bold", no_color),
            file=sys.stderr,
        )

        try:
            with open(filepath, "rb") as f:
                data = f.read()

            if len(data) < 256:
                print(
                    colorize(f"  SKIP — file too small ({len(data)} bytes)", "yellow", no_color),
                    file=sys.stderr,
                )
                results.append({"file": filepath, "status": "skipped", "reason": "too_small"})
                continue

            pipeline = DissectionPipeline()
            manifest = pipeline.process(data)
            manifest_dict = {
                "manifestFormatVersion": manifest.manifest_format_version,
                "metadata": manifest.metadata,
                "segments": manifest.segments,
            }

            # Add source file info to manifest
            manifest_dict["metadata"]["sourceFile"] = filepath
            manifest_dict["metadata"]["sourceFileSize"] = len(data)

            # Write per-file output directory if --output-dir specified
            if args.output_dir:
                from cs_aggregator.utils.hashing import compute_hashes

                sha_prefix = compute_hashes(data).get("sha256", "unknown")[:8]
                ver = manifest_dict.get("metadata", {}).get("version", {}).get("detected", "unknown")
                subdir = os.path.join(args.output_dir, f"beacon_{sha_prefix}_v{ver}")
                os.makedirs(subdir, exist_ok=True)

                manifest_path = os.path.join(subdir, "manifest.json")
                with open(manifest_path, "w", encoding="utf-8") as mf:
                    json.dump(manifest_dict, mf, indent=2, default=str)

                print(
                    colorize(f"  → {manifest_path}", "green", no_color),
                    file=sys.stderr,
                )

            results.append({"file": filepath, "status": "success", "manifest": manifest_dict})
            success_count += 1

        except Exception as e:
            print(
                colorize(f"  FAIL — {e}", "red", no_color),
                file=sys.stderr,
            )
            results.append({"file": filepath, "status": "error", "error": str(e)})
            fail_count += 1

    elapsed = time.monotonic() - start_total

    # Print summary
    print(
        colorize(
            f"\n{'─' * 60}\n"
            f"Batch complete: {success_count} success, {fail_count} failed, "
            f"{len(matched_files) - success_count - fail_count} skipped  ({elapsed:.2f}s)",
            "bold", no_color,
        ),
        file=sys.stderr,
    )

    # Write batch summary to output if specified
    if args.output:
        summary = {
            "batch_pattern": pattern,
            "total_files": len(matched_files),
            "success": success_count,
            "failed": fail_count,
            "elapsed_seconds": round(elapsed, 3),
            "results": results,
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, default=str)
        print(
            colorize(f"Batch summary written to: {args.output}", "green", no_color),
            file=sys.stderr,
        )


# ─── Multi-Beacon Extraction ─────────────────────────────────────────────────


def _run_extract_all(data: bytes, args: argparse.Namespace) -> None:
    """Scan for and extract ALL embedded beacons in a payload.

    Locates all valid MZ/PE headers within the payload and runs
    the dissection pipeline on each candidate independently.
    """
    import struct

    no_color = getattr(args, 'no_color', False)

    print(
        colorize(f"cs-aggregator v{__version__} — Multi-Beacon Extraction", "bold", no_color),
        file=sys.stderr,
    )

    # Scan for all MZ headers
    candidates = []
    search_start = 0
    while True:
        mz_offset = data.find(b"MZ", search_start)
        if mz_offset == -1 or mz_offset + 64 > len(data):
            break

        # Validate: check e_lfanew points to valid PE signature
        try:
            e_lfanew = struct.unpack_from("<I", data, mz_offset + 0x3C)[0]
            pe_sig_offset = mz_offset + e_lfanew
            if pe_sig_offset + 4 <= len(data):
                pe_sig = data[pe_sig_offset:pe_sig_offset + 4]
                if pe_sig == b"PE\x00\x00":
                    # Try to get SizeOfImage for boundary
                    opt_hdr_offset = pe_sig_offset + 24
                    if opt_hdr_offset + 60 <= len(data):
                        size_of_image = struct.unpack_from("<I", data, opt_hdr_offset + 56)[0]
                        if 0 < size_of_image < 50 * 1024 * 1024:  # Sanity: < 50MB
                            candidates.append({
                                "offset": mz_offset,
                                "size_of_image": size_of_image,
                                "pe_sig_offset": pe_sig_offset,
                            })
        except (struct.error, OverflowError):
            pass

        search_start = mz_offset + 2

    if not candidates:
        print(
            colorize("No valid MZ/PE headers found in payload.", "yellow", no_color),
            file=sys.stderr,
        )
        sys.exit(1)

    print(
        colorize(f"Found {len(candidates)} candidate beacon(s):", "cyan", no_color),
        file=sys.stderr,
    )

    all_manifests = []
    for i, cand in enumerate(candidates, 1):
        offset = cand["offset"]
        end = min(offset + cand["size_of_image"], len(data))
        candidate_data = data[offset:end]

        print(
            colorize(
                f"\n  [{i}/{len(candidates)}] Offset 0x{offset:X} — {len(candidate_data):,} bytes",
                "bold", no_color,
            ),
            file=sys.stderr,
        )

        try:
            pipeline = DissectionPipeline()
            manifest = pipeline.process(candidate_data)
            manifest_dict = {
                "manifestFormatVersion": manifest.manifest_format_version,
                "metadata": manifest.metadata,
                "segments": manifest.segments,
            }
            manifest_dict["metadata"]["extractedAtOffset"] = offset
            manifest_dict["metadata"]["candidateIndex"] = i

            all_manifests.append(manifest_dict)

            ver = manifest_dict.get("metadata", {}).get("version", {}).get("detected", "?")
            conf = manifest_dict.get("metadata", {}).get("pipelineConfidence", 0)
            print(
                colorize(f"    Version: {ver}  Confidence: {conf:.0%}", "green", no_color),
                file=sys.stderr,
            )
        except Exception as e:
            print(
                colorize(f"    FAIL — {e}", "red", no_color),
                file=sys.stderr,
            )
            all_manifests.append({"offset": offset, "status": "error", "error": str(e)})

    # Output all manifests
    combined = {
        "extractionMode": "extract-all",
        "totalCandidates": len(candidates),
        "manifests": all_manifests,
    }

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(combined, f, indent=2, default=str)
        print(
            colorize(f"\nResults written to: {args.output}", "green", no_color),
            file=sys.stderr,
        )
    else:
        print(json.dumps(combined, indent=2, default=str))


def main() -> None:
    """Main entry point for the cs-aggregator CLI."""
    parser = build_parser()
    args = parser.parse_args()

    # Handle special actions (version, list, etc.)
    if handle_special_actions(args):
        sys.exit(0)

    # ─── Batch Processing Mode ─────────────────────────────────────────────
    if getattr(args, 'batch', None):
        _run_batch_mode(args)
        sys.exit(0)

    # ─── Fragment Reassembly Mode ──────────────────────────────────────────
    fragment_files = getattr(args, 'fragment_mode', None)
    fragment_dir = getattr(args, 'fragment_dir', None)

    if fragment_files or fragment_dir:
        from cs_aggregator.modules.fragment_reassembler import FragmentReassembler

        no_color = getattr(args, 'no_color', False)
        timeout = getattr(args, 'fragment_timeout', 30)
        reassembler = FragmentReassembler(timeout=timeout)

        print(
            colorize(f"cs-aggregator v{__version__} — Fragment Reassembly Mode", "bold", no_color),
            file=sys.stderr,
        )

        if fragment_dir:
            result = reassembler.reassemble_from_directory(fragment_dir)
        else:
            result = reassembler.reassemble_from_files(fragment_files)

        # Print reassembly report
        print(
            colorize(
                f"  Fragments: {result.fragments_used}  "
                f"Size: {result.total_size:,} bytes  "
                f"Gaps: {result.gaps_detected}  "
                f"Confidence: {result.confidence:.0%}  "
                f"({result.elapsed_seconds:.3f}s)",
                "cyan", no_color,
            ),
            file=sys.stderr,
        )

        for w in result.warnings:
            print(colorize(f"  ⚠ {w}", "yellow", no_color), file=sys.stderr)

        if result.total_size == 0:
            print(colorize("  No payload reassembled.", "red", no_color), file=sys.stderr)
            sys.exit(1)

        # Write reassembly report
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(result.to_dict(), f, indent=2, default=str)
            print(
                colorize(f"  Report: {args.output}", "green", no_color),
                file=sys.stderr,
            )

        # Write reassembled payload if --output-payload specified
        if getattr(args, 'output_payload', None):
            with open(args.output_payload, "wb") as f:
                f.write(result.payload)
            print(
                colorize(f"  Payload: {args.output_payload}", "green", no_color),
                file=sys.stderr,
            )

        # Continue with normal pipeline on the reassembled payload
        data = result.payload
        print(
            colorize(f"\n  Piping {len(data):,} byte reassembled payload into dissection pipeline...", "dim", no_color),
            file=sys.stderr,
        )
    else:
        # Read input normally
        data = read_input(args)
        if data is None:
            parser.print_help()
            print()
            print("Error: no input file provided and no data piped to stdin", file=sys.stderr)
            sys.exit(1)

    # ─── Multi-Beacon Extraction Mode ──────────────────────────────────────
    if getattr(args, 'extract_all', False):
        _run_extract_all(data, args)
        sys.exit(0)

    # Configure logging
    if not args.quiet:
        setup_logging(args.verbose)

    no_color = args.no_color
    use_rich_output = not no_color and not args.quiet and sys.stderr.isatty()

    if use_rich_output:
        from cs_aggregator.utils.rich_output import print_banner, console as rich_console, DIM, GRADIENT
        from rich.text import Text as _T
        print_banner(__version__)
        # Payload info line
        info = _T("  ")
        info.append("◆ ", style=f"bold {GRADIENT[4]}")
        info.append("Payload  ", style=DIM)
        info.append(f"{len(data):,} bytes", style="bold bright_white")
        if args.input:
            info.append(f"   {os.path.basename(args.input)}", style=DIM)
        rich_console.print(info)
    else:
        print(
            colorize(f"cs-aggregator v{__version__}", "bold", no_color),
            file=sys.stderr,
        )
        print(
            f"Analyzing {len(data):,} byte payload...",
            file=sys.stderr,
        )

    # Load C2 profile BEFORE pipeline (needed for magic byte registration)
    c2_profile = None
    if args.profile:
        from cs_aggregator.utils.profile_parser import ProfileParser

        profile_path = os.path.expanduser(args.profile)
        if not os.path.isfile(profile_path):
            print(
                colorize(f"Error: profile not found: {profile_path}", "red", no_color),
                file=sys.stderr,
            )
            sys.exit(1)

        try:
            c2_profile = ProfileParser.parse_file(profile_path)
            if use_rich_output:
                from cs_aggregator.utils.rich_output import console as _prc, DIM, _badge, GRADIENT
                from rich.text import Text as _T
                t = _T("  ")
                t.append("⟐ ", style=f"bold {GRADIENT[3]}")
                t.append("Profile  ", style=DIM)
                t.append(os.path.basename(profile_path), style="bold bright_white")
                t.append("   MZ=", style=DIM)
                t.append(c2_profile.magic_mz_x64, style=f"bold {GRADIENT[4]}")
                t.append("  PE=", style=DIM)
                t.append(c2_profile.magic_pe, style=f"bold {GRADIENT[4]}")
                _prc.print(t)
            else:
                print(
                    colorize(f"Loaded C2 profile: {os.path.basename(profile_path)}", "green", no_color),
                    file=sys.stderr,
                )
                print(
                    colorize(f"  PE Magic: MZ={c2_profile.magic_mz_x64}, PE={c2_profile.magic_pe}", "cyan", no_color),
                    file=sys.stderr,
                )
        except Exception as e:
            print(
                colorize(f"Profile parsing error: {e}", "red", no_color),
                file=sys.stderr,
            )
            if args.verbose >= 2:
                import traceback
                traceback.print_exc()

    # Initialize plugin system
    from cs_aggregator.plugins import PluginManager

    plugin_dirs = [args.plugin_dir] if getattr(args, 'plugin_dir', None) else []
    plugin_manager = PluginManager(plugin_dirs=plugin_dirs)
    enable_filter = None
    if getattr(args, 'plugins', None):
        enable_filter = [p.strip() for p in args.plugins.split(",")]

    plugin_manager.discover(enable_filter=enable_filter)

    # Build per-plugin config from CLI args
    plugin_config: dict = {}
    yara_cfg: dict = {}
    if getattr(args, 'yara_rules', None):
        yara_cfg['rules_path'] = args.yara_rules
    if getattr(args, 'yara_dir', None):
        yara_cfg['rules_dir'] = args.yara_dir
    if getattr(args, 'yara_no_builtin', False):
        yara_cfg['no_builtin'] = True
    if yara_cfg:
        plugin_config['yara_scanner'] = yara_cfg

    plugin_manager.initialize_all(config=plugin_config)

    if plugin_manager.enabled_plugins and not args.quiet:
        plugin_names = [p.name for p in plugin_manager.enabled_plugins]
        if use_rich_output:
            from cs_aggregator.utils.rich_output import console as _rc, DIM, MUTED, GRADIENT
            from rich.text import Text as _T
            t = _T("  ")
            t.append("◈ ", style=f"bold {GRADIENT[1]}")
            t.append("Plugins  ", style=DIM)
            t.append(f"{len(plugin_names)} active", style=f"bold {GRADIENT[4]}")
            t.append("  ", style=DIM)
            for i, pn in enumerate(plugin_names):
                t.append(pn, style=f"{GRADIENT[i % len(GRADIENT)]}")
                if i < len(plugin_names) - 1:
                    t.append(" · ", style=DIM)
            _rc.print(t)
        else:
            print(f"Plugins: {', '.join(plugin_names)}", file=sys.stderr)

    # Run the dissection pipeline
    pipeline = DissectionPipeline()
    try:
        if use_rich_output:
            from cs_aggregator.utils.rich_output import PipelineSpinner
            with PipelineSpinner("Dissecting payload"):
                manifest = pipeline.process(data, source_file=args.input, profile=c2_profile)
        else:
            manifest = pipeline.process(data, source_file=args.input, profile=c2_profile)
    except Exception as e:
        print(
            colorize(f"Pipeline error: {e}", "red", no_color),
            file=sys.stderr,
        )
        print(
            colorize(f"Use -v for detailed error information", "yellow", no_color),
            file=sys.stderr,
        )
        if args.verbose >= 2:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    # Run plugin hooks with pipeline results
    plugin_ctx: Dict[str, Any] = {"source_file": args.input}

    # on_payload_loaded
    plugin_manager.run_hook("on_payload_loaded", data=data, ctx=plugin_ctx)

    # on_pe_parsed
    if pipeline._beacon_dll_data is not None:
        plugin_manager.run_hook(
            "on_pe_parsed",
            pe_info=pipeline._pe_info,
            dll_data=pipeline._beacon_dll_data,
            ctx=plugin_ctx,
        )

    # on_config_extracted
    if pipeline._config_result is not None:
        # Propagate version detection for version-aware plugins
        if pipeline._version_result is not None:
            plugin_ctx["version_detection"] = {
                "version": pipeline._version_result.estimated_version,
                "confidence": pipeline._version_result.confidence_score,
            }
        plugin_manager.run_hook(
            "on_config_extracted",
            config=pipeline._config_result.config_json,
            ctx=plugin_ctx,
        )

    # Convert manifest to dict for display
    manifest_dict = {
        "manifestFormatVersion": manifest.manifest_format_version,
        "metadata": manifest.metadata,
        "segments": manifest.segments,
    }

    # on_manifest_ready — plugins can inject metadata
    manifest_results = plugin_manager.run_hook(
        "on_manifest_ready", manifest=manifest_dict, ctx=plugin_ctx
    )
    # Apply first non-None result
    for result in manifest_results:
        if isinstance(result, dict):
            manifest_dict = result
            break


    # Handle --profile: validate extracted config against profile (profile already loaded above)
    if c2_profile is not None:
        try:
            profile = c2_profile
            profile_path = os.path.expanduser(args.profile)

            # Embed profile metadata in manifest
            profile_meta = {
                "profileFile": os.path.basename(profile_path),
                "magic_mz_x64": profile.magic_mz_x64,
                "magic_mz_x86": profile.magic_mz_x86,
                "magic_pe": profile.magic_pe,
                "stomppe": profile.stomppe,
                "obfuscate": profile.obfuscate,
                "sleep_mask": profile.sleep_mask,
                "smartinject": profile.smartinject,
                "cleanup": profile.cleanup,
                "protocol": profile.protocol,
            }
            manifest_dict["metadata"]["c2Profile"] = profile_meta

            if not use_rich_output:
                if profile.stomppe:
                    print(
                        colorize("  StompPE: enabled (headers zeroed post-load)", "yellow", no_color),
                        file=sys.stderr,
                    )
                if profile.sleep_mask:
                    print(
                        colorize("  Sleep Mask: enabled (encrypted during sleep)", "cyan", no_color),
                        file=sys.stderr,
                    )

            # Validate extracted config against profile expectations
            extracted_config = None
            for seg in manifest_dict.get("segments", []):
                if seg.get("segmentId") == "SEG_CONFIG_BLOCK":
                    extracted_config = seg.get("config", {})
                    break

            if extracted_config:
                validation = profile.validate_config(extracted_config)
                manifest_dict["metadata"]["profileValidation"] = validation

                if not use_rich_output:
                    match_pct = validation["match_rate"] * 100
                    n_match = len(validation["matches"])
                    n_total = validation["total_expected"]
                    n_miss = len(validation["mismatches"])

                    if match_pct >= 90:
                        print(
                            colorize(f"  Profile Validation: {n_match}/{n_total} match ({match_pct:.0f}%) ✓", "green", no_color),
                            file=sys.stderr,
                        )
                    elif match_pct >= 50:
                        print(
                            colorize(f"  Profile Validation: {n_match}/{n_total} match ({match_pct:.0f}%) — {n_miss} mismatches", "yellow", no_color),
                            file=sys.stderr,
                        )
                    else:
                        print(
                            colorize(f"  Profile Validation: {n_match}/{n_total} match ({match_pct:.0f}%) ✗ — profile may not match payload", "red", no_color),
                            file=sys.stderr,
                        )

                    for setting, expected, actual in validation["mismatches"]:
                        print(
                            colorize(f"    ✗ {setting}: expected={expected}, got={actual}", "yellow", no_color),
                            file=sys.stderr,
                        )
            else:
                if not use_rich_output:
                    print(
                        colorize("  No config extracted — profile validation skipped", "yellow", no_color),
                        file=sys.stderr,
                    )

        except Exception as e:
            print(
                colorize(f"Profile validation error: {e}", "red", no_color),
                file=sys.stderr,
            )
            if args.verbose >= 2:
                import traceback
                traceback.print_exc()

    # Check if reassembly was requested
    if args.reassemble:
        # Load the original payload from the --reassemble file
        reassemble_path = os.path.expanduser(args.reassemble)
        if not os.path.isfile(reassemble_path):
            print(
                colorize(f"Error: reassembly source not found: {reassemble_path}", "red", no_color),
                file=sys.stderr,
            )
            sys.exit(1)
        with open(reassemble_path, "rb") as f:
            original_payload = f.read()
        print(
            colorize(f"Loaded original payload: {len(original_payload):,} bytes", "cyan", no_color),
            file=sys.stderr,
        )
        handle_reassembly(args, manifest_dict, original_payload, no_color)
        # Still output the manifest (dissection results)
        if args.output:
            print_full_manifest(manifest_dict, args.output, no_color)
        elif not args.minimal:
            print_full_manifest(manifest_dict, None, no_color)
        sys.exit(0)

    # Handle --config-only mode: extract and print only config JSON
    if args.config_only:
        config_json = None
        for seg in manifest_dict.get("segments", []):
            if seg.get("segmentId") == "SEG_CONFIG_BLOCK":
                config_json = seg.get("config", {})
                break
        if config_json:
            print(json.dumps(config_json, indent=2, default=str))
        else:
            print(
                colorize("No config block found in payload", "red", no_color),
                file=sys.stderr,
            )
            sys.exit(1)
        sys.exit(0)

    # Handle --output-dir: extract all components to individual files
    if args.output_dir:
        from cs_aggregator.utils.output_writer import OutputWriter

        writer = OutputWriter(args.output_dir, source_file=args.input)

        # Write manifest
        manifest_path = writer.write_manifest(manifest_dict)
        print(
            colorize(f"  Manifest:     {manifest_path}", "green", no_color),
            file=sys.stderr,
        )

        # Write summary
        summary_path = writer.write_dissection_summary(manifest_dict, data)
        print(
            colorize(f"  Summary:      {summary_path}", "green", no_color),
            file=sys.stderr,
        )

        # Extract individual components with full metadata
        extracted_count = 0
        for seg in manifest_dict.get("segments", []):
            sid = seg.get("segmentId", "")
            offset = seg.get("offset", 0)
            size = seg.get("size", 0)

            if size > 0 and offset + size <= len(data):
                component_data = data[offset:offset + size]
                hashes = {}
                try:
                    from cs_aggregator.utils.hashing import compute_hashes as ch
                    hashes = ch(component_data)
                except Exception:
                    pass

                if sid == "SEG_LOADER_STUB":
                    p = writer.write_component("loader_stub", component_data)
                    print(colorize(f"  Loader:       {p} ({size:,} bytes)", "cyan", no_color), file=sys.stderr)
                    # Loader metadata JSON
                    meta = {
                        "offset": offset, "size": size,
                        "sha256": hashes.get("sha256", ""),
                        "classification": seg.get("classification", seg.get("type", "")),
                        "bud_detected": seg.get("budDetected", False),
                        "bud_version": seg.get("budVersion", ""),
                    }
                    _write_metadata(writer, "loader_stub_metadata", meta, no_color)
                    extracted_count += 2

                elif sid == "SEG_BEACON_DLL":
                    p = writer.write_component("beacon", component_data, extension=".dll")
                    print(colorize(f"  Beacon DLL:   {p} ({size:,} bytes)", "cyan", no_color), file=sys.stderr)
                    # PE metadata JSON
                    pe_info = seg.get("peInfo", {})
                    meta = {
                        "offset": offset, "size": size,
                        "sha256": hashes.get("sha256", ""),
                        "sections": pe_info.get("sections", []),
                        "machine_type": pe_info.get("machineType", ""),
                        "compile_timestamp": pe_info.get("compileTimestamp", ""),
                    }
                    _write_metadata(writer, "beacon_pe_metadata", meta, no_color)
                    extracted_count += 2

                    # Physically extract embedded PostEx DLLs if present
                    postex_seg = next((s for s in manifest_dict.get("segments", []) if s.get("segmentId") == "SEG_POSTEX_REFS"), None)
                    if postex_seg:
                        postex_dir = os.path.join(writer.output_dir, "postex")
                        os.makedirs(postex_dir, exist_ok=True)
                        postex_meta_list = []

                        for r in postex_seg.get("dllReferences", []):
                            r_meta = {
                                "name": r.get("name"),
                                "referenceType": r.get("referenceType"),
                                "offset": r.get("offset", -1),
                                "size": r.get("size", 0),
                                "sha256": r.get("sha256", ""),
                                "entropy": r.get("entropy", 0.0),
                                "embedded": r.get("embedded", False),
                                "metadata": r.get("metadata", {}),
                            }

                            if r.get("embedded") and r.get("offset", -1) >= 0 and r.get("size", 0) > 0:
                                r_offset = r.get("offset")
                                r_size = r.get("size")
                                if r_offset + r_size <= len(component_data):
                                    try:
                                        ext_bytes = component_data[r_offset:r_offset + r_size]
                                        dll_filename = f"{r.get('name')}.dll"
                                        dll_filename = "".join(c for c in dll_filename if c.isalnum() or c in "._-")
                                        dll_path = os.path.join(postex_dir, dll_filename)
                                        with open(dll_path, "wb") as f:
                                            f.write(ext_bytes)
                                        r_meta["filePath"] = os.path.relpath(dll_path, writer.output_dir)
                                        print(colorize(f"  PostEx DLL:   {dll_path} ({r_size:,} bytes)", "cyan", no_color), file=sys.stderr)
                                        extracted_count += 1
                                    except Exception as ex:
                                        print(colorize(f"  [!] Failed to extract {r.get('name')}: {ex}", "yellow", no_color), file=sys.stderr)

                            postex_meta_list.append(r_meta)

                        if postex_meta_list:
                            meta_json_path = os.path.join(postex_dir, "metadata.json")
                            with open(meta_json_path, "w", encoding="utf-8") as f:
                                json.dump(postex_meta_list, f, indent=2, default=str)
                            print(colorize(f"  PostEx Meta:  {meta_json_path}", "cyan", no_color), file=sys.stderr)
                            extracted_count += 1

                elif sid == "SEG_SLEEP_MASK":
                    p = writer.write_component("sleep_mask", component_data)
                    print(colorize(f"  Sleep Mask:   {p} ({size:,} bytes)", "cyan", no_color), file=sys.stderr)
                    meta = {
                        "offset": offset, "size": size,
                        "sha256": hashes.get("sha256", ""),
                        "section_name": seg.get("sectionName", ""),
                        "beacongate_detected": seg.get("beaconGateDetected", False),
                    }
                    _write_metadata(writer, "sleep_mask_metadata", meta, no_color)
                    extracted_count += 2

                elif sid == "SEG_CONFIG_BLOCK":
                    config_data = seg.get("config", {})
                    if config_data:
                        p = writer.write_config(config_data)
                        print(colorize(f"  Config JSON:  {p}", "cyan", no_color), file=sys.stderr)
                        extracted_count += 1

                    # Also write encrypted + decrypted raw config bins
                    xor_key = seg.get("xorKey", "")
                    if component_data and xor_key:
                        paths = writer.write_config_block(
                            encrypted=component_data,
                            decrypted=component_data,  # Already decrypted in manifest
                            xor_key=xor_key,
                        )
                        for label, path in paths.items():
                            print(
                                colorize(f"  Config {label:10s}: {path}", "cyan", no_color),
                                file=sys.stderr,
                            )
                            extracted_count += 1

        print(
            colorize(
                f"\n  {extracted_count} files extracted to: {args.output_dir}",
                "bold", no_color,
            ),
            file=sys.stderr,
        )

    # ─── Handle --validate-with: Cross-validation against third-party parsers ──

    if getattr(args, "validate_with", None):
        try:
            from cs_aggregator.utils.cross_validator import CrossValidator

            validator = CrossValidator()
            cv_results = validator.validate(data, manifest_dict, backend=args.validate_with)

            report = validator.format_report(cv_results)
            print(report, file=sys.stderr)

            # Add to manifest metadata
            manifest_dict.setdefault("metadata", {})["crossValidation"] = [
                r.to_dict() for r in cv_results
            ]
        except Exception as e:
            print(
                colorize(f"  Cross-validation error: {e}", "red", no_color),
                file=sys.stderr,
            )

    # ─── Handle --disassemble: Capstone disassembly of loader stub ─────────

    if getattr(args, "disassemble", False):
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64

            # Find loader stub segment
            loader_data = None
            for seg in manifest_dict.get("segments", []):
                if seg.get("segmentId") == "SEG_LOADER_STUB":
                    offset = seg.get("offset", 0)
                    size = seg.get("size", 0)
                    if offset + size <= len(data):
                        loader_data = data[offset:offset + size]
                    break

            if loader_data:
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                md.detail = True

                print(
                    colorize(
                        f"\n  ◈ LOADER STUB DISASSEMBLY ({len(loader_data):,} bytes)",
                        "bold", no_color,
                    ),
                    file=sys.stderr,
                )
                print(colorize(f"  {'─' * 60}", "dim", no_color), file=sys.stderr)

                max_instructions = 200
                count = 0
                for insn in md.disasm(loader_data, 0):
                    hex_bytes = " ".join(f"{b:02X}" for b in insn.bytes)
                    line = f"  0x{insn.address:04X}:  {hex_bytes:30s}  {insn.mnemonic:8s} {insn.op_str}"
                    print(line, file=sys.stderr)
                    count += 1
                    if count >= max_instructions:
                        print(
                            colorize(
                                f"  ... ({len(loader_data)} bytes total, showing first {max_instructions} instructions)",
                                "dim", no_color,
                            ),
                            file=sys.stderr,
                        )
                        break
            else:
                print(
                    colorize("  No loader stub segment found for disassembly.", "yellow", no_color),
                    file=sys.stderr,
                )
        except ImportError:
            print(
                colorize("  Capstone not installed — install with: pip install capstone", "yellow", no_color),
                file=sys.stderr,
            )
        except Exception as e:
            print(
                colorize(f"  Disassembly error: {e}", "red", no_color),
                file=sys.stderr,
            )

    # ─── Handle --export-yara: Generate dynamic YARA rules from payload ────

    if getattr(args, "export_yara", None):
        try:
            yara_path = os.path.expanduser(args.export_yara)
            yara_rules = _generate_dynamic_yara(manifest_dict, data, pipeline)
            with open(yara_path, "w", encoding="utf-8") as yf:
                yf.write(yara_rules)
            print(
                colorize(f"  YARA rules exported: {yara_path}", "green", no_color),
                file=sys.stderr,
            )
        except Exception as e:
            print(
                colorize(f"  YARA export error: {e}", "red", no_color),
                file=sys.stderr,
            )
            if args.verbose >= 2:
                import traceback
                traceback.print_exc()

    # ─── Output Results ─────────────────────────────────────────────────────

    if args.minimal:
        if use_rich_output:
            from cs_aggregator.utils.rich_output import print_minimal_rich
            print_minimal_rich(manifest_dict)
        else:
            print_minimal_summary(manifest_dict, no_color)
    elif not args.output_dir:
        if use_rich_output and not args.output:
            # Full Rich output — vibrant interactive mode
            from cs_aggregator.utils.rich_output import (
                print_classification,
                print_version_detection,
                print_config_table,
                print_profile_validation,
                print_segments_summary,
                print_pipeline_confidence,
                print_warnings,
                print_errors,
                console as rich_console,
            )

            # Classification — merge root-level fields into the classification dict
            meta = manifest_dict.get("metadata", {})
            classification = dict(meta.get("payloadClassification", {}))
            classification["fileSize"] = meta.get("fileSize", 0)
            classification["entropy"] = meta.get("overallEntropy", 0)
            classification["hashes"] = meta.get("fileHashes", {})
            print_classification(classification)

            # Version detection
            version_info = manifest_dict.get("metadata", {}).get("csVersionDetected", {})
            print_version_detection(version_info)

            # Config table
            for seg in manifest_dict.get("segments", []):
                if seg.get("segmentId") == "SEG_CONFIG_BLOCK":
                    config_data = seg.get("config", {})
                    xor_key = seg.get("xorKey", "")
                    print_config_table(config_data, xor_key, len(config_data))
                    break

            # Profile validation
            profile_val = manifest_dict.get("metadata", {}).get("profileValidation", {})
            c2_prof = manifest_dict.get("metadata", {}).get("c2Profile", {})
            if profile_val and c2_prof:
                print_profile_validation(
                    profile_name=c2_prof.get("profileFile", ""),
                    magic_mz=c2_prof.get("magic_mz_x64", "MZ"),
                    magic_pe=c2_prof.get("magic_pe", "PE"),
                    stomppe=c2_prof.get("stomppe", False),
                    sleep_mask=c2_prof.get("sleep_mask", False),
                    match_count=len(profile_val.get("matches", [])),
                    total=profile_val.get("total_expected", 0),
                    match_pct=profile_val.get("match_rate", 0) * 100,
                    mismatches=profile_val.get("mismatches", []),
                )

            # Segments tree
            print_segments_summary(manifest_dict.get("segments", []))

            # Warnings/Errors
            warnings = manifest_dict.get("metadata", {}).get("warnings", [])
            errors = manifest_dict.get("metadata", {}).get("errors", [])
            print_warnings(warnings)
            print_errors(errors)

            # Pipeline confidence
            pipeline_conf = manifest_dict.get("metadata", {}).get("pipelineConfidence")
            if pipeline_conf is not None:
                print_pipeline_confidence(pipeline_conf)

            # ── Plugin Results Section ──
            plugin_renderables = plugin_manager.collect_renderables()
            if plugin_renderables:
                from cs_aggregator.utils.rich_output import print_plugin_results
                print_plugin_results(plugin_renderables)

        else:
            # Plain JSON output
            # Inject plugin results into manifest for JSON mode
            plugin_json = plugin_manager.collect_json_results()
            if plugin_json:
                manifest_dict.setdefault("metadata", {})["pluginResults"] = plugin_json
            print_full_manifest(manifest_dict, args.output, no_color)

    # --run-plugin standalone mode: show ONLY plugin output
    run_plugin = getattr(args, 'run_plugin', None)
    if run_plugin:
        plugin_names = [p.strip() for p in run_plugin.split(",")]
        plugin_out_mode = getattr(args, 'plugin_output', 'rich')

        # Collect results from specified plugins only
        for pname in plugin_names:
            pinfo = plugin_manager.get_plugin(pname)
            if not pinfo:
                print(f"Plugin '{pname}' not found. Use --list-plugins to see available.", file=sys.stderr)
                continue

            if plugin_out_mode in ('rich', 'both') and use_rich_output:
                render_fn = getattr(pinfo.instance, 'render_results', None)
                if render_fn:
                    renderable = render_fn()
                    if renderable:
                        from cs_aggregator.utils.rich_output import console as _prc
                        _prc.print()
                        _prc.print(renderable)

            if plugin_out_mode in ('json', 'both'):
                get_fn = getattr(pinfo.instance, 'get_results', None)
                if get_fn:
                    result = get_fn()
                    if result:
                        print(json.dumps({pname: result}, indent=2, default=str))

    # Print confidence summary to stderr (for non-rich modes)
    if not use_rich_output:
        pipeline_conf = manifest.metadata.get("pipelineConfidence")
        if pipeline_conf is not None and not args.quiet:
            print(
                colorize(
                    f"Pipeline confidence: {pipeline_conf:.0%}",
                    "green" if pipeline_conf >= 0.6 else "yellow",
                    no_color,
                ),
                file=sys.stderr,
            )

        pipeline_errors = manifest.metadata.get("errors", [])
        if pipeline_errors and not args.quiet:
            print(
                colorize(f"Pipeline errors ({len(pipeline_errors)}):", "red", no_color),
                file=sys.stderr,
            )
            for err in pipeline_errors:
                print(f"  - {err}", file=sys.stderr)

    # Cleanup plugins (always last)
    plugin_manager.cleanup_all()


if __name__ == "__main__":
    main()
