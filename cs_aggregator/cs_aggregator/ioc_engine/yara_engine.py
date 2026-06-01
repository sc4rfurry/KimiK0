"""YARA Sub-Engine — Static matching + dynamic YARA rule generation.

Powered by YARA-X (v1.0+) — the modern, Rust-based pattern matching engine.
"""

import hashlib
from typing import Any, Dict, List, Optional


class YaraEngine:
    """YARA-X scanning and dynamic rule generation from extracted artifacts."""

    def scan(self, data: bytes) -> Dict[str, Any]:
        """Scan data with built-in YARA-X rules.

        Performs a lightweight scan using YARA-X compiled rules.
        Returns a summary of matches including rule identifiers.
        """
        result: Dict[str, Any] = {"matches": [], "scan_status": "ok"}
        try:
            import yara_x

            # Compile minimal detection rules for IOC-level scanning
            rules = yara_x.compile('''
                rule CS_Config_XOR_Signature {
                    strings:
                        $xor_magic = { 2e 2f 2e 2f 2e 2c }
                    condition:
                        $xor_magic
                }
                rule CS_MZ_Header {
                    strings:
                        $mz = { 4D 5A }
                    condition:
                        $mz at 0 or $mz
                }
            ''')
            scanner = yara_x.Scanner(rules)
            scanner.set_timeout(10)
            scan_results = scanner.scan(data)

            result["yara_available"] = True
            for rule in scan_results.matching_rules:
                result["matches"].append(rule.identifier)

        except ImportError:
            result["yara_available"] = False
            result["scan_status"] = "yara-x not installed — install with: pip install yara-x"
        except Exception as e:
            result["yara_available"] = True
            result["scan_status"] = f"scan_error: {e}"
        return result

    def generate_rules(
        self, report: Dict[str, Any], config: Dict[str, Any]
    ) -> str:
        """Generate dynamic YARA rules from analysis report and config.

        Produces rules based on:
        - Extracted C2 domains and URIs
        - XOR key + config signature
        - Watermark values
        - Named pipe patterns
        - User-agent strings
        """
        rules = []
        timestamp = hashlib.md5(str(report).encode()).hexdigest()[:8]

        # Rule 1: C2 domain indicators
        network = report.get("network", {})
        domains = network.get("domains", [])
        ips = network.get("ips", [])
        if domains or ips:
            strings = []
            for i, d in enumerate(domains[:10]):
                strings.append(f'        $domain_{i} = "{d}" ascii wide')
            for i, ip in enumerate(ips[:10]):
                strings.append(f'        $ip_{i} = "{ip}" ascii wide')
            rules.append(self._build_rule(
                f"CS_C2_Indicators_{timestamp}",
                "Dynamic C2 infrastructure indicators from beacon config",
                strings,
                "any of them",
                severity="high",
                mitre="T1071.001",
            ))

        # Rule 2: Watermark detection
        crypto = report.get("crypto", {})
        identifiers = crypto.get("identifiers", {})
        wm = identifiers.get("watermark")
        if wm and isinstance(wm, int) and wm > 0:
            wm_bytes = wm.to_bytes(4, "big").hex()
            wm_hex = " ".join(wm_bytes[i:i+2] for i in range(0, len(wm_bytes), 2))
            rules.append(self._build_rule(
                f"CS_Watermark_{wm}",
                f"CobaltStrike watermark value {wm}",
                [f"        $watermark = {{ {wm_hex} }}"],
                "$watermark",
                severity="medium",
                mitre="T1587.001",
            ))

        # Rule 3: Named pipe indicators
        pipes = network.get("pipes", [])
        if pipes:
            strings = []
            for i, p in enumerate(pipes[:5]):
                strings.append(f'        $pipe_{i} = "{p}" ascii wide')
            rules.append(self._build_rule(
                f"CS_NamedPipes_{timestamp}",
                "CobaltStrike named pipe indicators from config",
                strings,
                "any of them",
                severity="medium",
                mitre="T1570",
            ))

        # Rule 4: User-agent
        c2_profile = network.get("c2_profile", {})
        ua = c2_profile.get("user_agent", "")
        if ua and len(ua) > 10:
            rules.append(self._build_rule(
                f"CS_UserAgent_{timestamp}",
                "CobaltStrike beacon user-agent string",
                [f'        $ua = "{ua[:200]}" ascii wide nocase'],
                "$ua",
                severity="low",
                mitre="T1071.001",
            ))

        if not rules:
            return "// No dynamic YARA rules generated — insufficient IOC data.\n"

        header = (
            "// Auto-generated YARA rules by KimiK0 IOC Central Engine\n"
            f"// Generated from beacon analysis report ({len(rules)} rules)\n\n"
        )
        return header + "\n\n".join(rules) + "\n"

    @staticmethod
    def _build_rule(
        name: str,
        description: str,
        strings: List[str],
        condition: str,
        severity: str = "medium",
        mitre: str = "",
    ) -> str:
        """Build a single YARA rule source block."""
        meta = [
            f'        description = "{description}"',
            '        author = "KimiK0-IOCEngine"',
            f'        severity = "{severity}"',
        ]
        if mitre:
            meta.append(f'        mitre = "{mitre}"')

        return (
            f"rule {name} {{\n"
            f"    meta:\n"
            + "\n".join(meta) + "\n"
            f"    strings:\n"
            + "\n".join(strings) + "\n"
            f"    condition:\n"
            f"        {condition}\n"
            f"}}"
        )
