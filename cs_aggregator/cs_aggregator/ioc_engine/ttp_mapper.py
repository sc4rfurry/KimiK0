"""TTP Mapper — MITRE ATT&CK technique mapping from detected IOCs."""

from typing import Any, Dict, List


# Comprehensive mapping of detected features → ATT&CK techniques
TECHNIQUE_MAP: Dict[str, Dict[str, str]] = {
    # Network
    "http_beacon": {"id": "T1071.001", "name": "Web Protocols", "tactic": "command-and-control"},
    "dns_beacon": {"id": "T1071.004", "name": "DNS", "tactic": "command-and-control"},
    "smb_pipe": {"id": "T1570", "name": "Lateral Tool Transfer", "tactic": "lateral-movement"},
    "tcp_beacon": {"id": "T1095", "name": "Non-Application Layer Protocol", "tactic": "command-and-control"},
    "proxy_manual": {"id": "T1090", "name": "Proxy", "tactic": "command-and-control"},
    # Injection
    "process_injection": {"id": "T1055", "name": "Process Injection", "tactic": "defense-evasion"},
    "reflective_loading": {"id": "T1620.001", "name": "Reflective Code Loading", "tactic": "defense-evasion"},
    "ntmap_injection": {"id": "T1055.012", "name": "Process Hollowing", "tactic": "defense-evasion"},
    # Evasion
    "sleep_mask": {"id": "T1027.002", "name": "Software Packing", "tactic": "defense-evasion"},
    "syscall_direct": {"id": "T1106", "name": "Native API", "tactic": "execution"},
    "syscall_indirect": {"id": "T1106", "name": "Native API (Indirect)", "tactic": "execution"},
    "beacon_gate": {"id": "T1055.012", "name": "BeaconGate API Proxy", "tactic": "defense-evasion"},
    "drip_loading": {"id": "T1027.013", "name": "Encrypted/Encoded File", "tactic": "defense-evasion"},
    "config_encryption": {"id": "T1573.001", "name": "Encrypted Channel: Symmetric", "tactic": "command-and-control"},
    # Persistence
    "kill_date": {"id": "T1029", "name": "Scheduled Transfer", "tactic": "exfiltration"},
    # Discovery
    "spawn_to": {"id": "T1055", "name": "Process Injection (Spawn-To)", "tactic": "defense-evasion"},
}


class TTPMapper:
    """Map detected IOCs and behaviors to MITRE ATT&CK techniques."""

    def map_from_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a consolidated IOC report and produce TTP mappings.

        Returns dict with 'techniques' list and 'tactics' summary.
        """
        techniques: List[Dict[str, str]] = []
        seen_ids: set = set()

        # Network-based TTPs
        network = report.get("network", {})
        c2 = network.get("c2_profile", {})
        protocol = c2.get("protocol", "").upper()

        if protocol in ("HTTP", "HTTPS"):
            self._add(techniques, seen_ids, "http_beacon")
        if protocol == "DNS" or network.get("dns_beacons"):
            self._add(techniques, seen_ids, "dns_beacon")
        if protocol == "SMB" or network.get("pipes"):
            self._add(techniques, seen_ids, "smb_pipe")
        if protocol == "TCP":
            self._add(techniques, seen_ids, "tcp_beacon")

        proxy = network.get("proxy", {})
        if proxy.get("behavior") == "manual":
            self._add(techniques, seen_ids, "proxy_manual")

        # Behavioral TTPs
        behavioral = report.get("behavioral", {})
        syscall = behavioral.get("syscall", {})
        method = syscall.get("method", "none")
        if method == "direct":
            self._add(techniques, seen_ids, "syscall_direct")
        elif method == "indirect":
            self._add(techniques, seen_ids, "syscall_indirect")

        injection = behavioral.get("injection", {})
        allocator = injection.get("allocator", "")
        if allocator == "NtMapViewOfSection":
            self._add(techniques, seen_ids, "ntmap_injection")
        if allocator:
            self._add(techniques, seen_ids, "process_injection")

        evasion = behavioral.get("evasion", {})
        if evasion.get("beacon_gate_enabled"):
            self._add(techniques, seen_ids, "beacon_gate")
        if evasion.get("drip_loading_enabled"):
            self._add(techniques, seen_ids, "drip_loading")

        sleep = behavioral.get("sleep_profile", {})
        if sleep.get("sleep_mask_enabled"):
            self._add(techniques, seen_ids, "sleep_mask")

        if behavioral.get("processes"):
            self._add(techniques, seen_ids, "spawn_to")

        # Crypto TTPs
        crypto = report.get("crypto", {})
        if crypto.get("keys", {}).get("xor_key"):
            self._add(techniques, seen_ids, "config_encryption")
        if crypto.get("timestamps", {}).get("kill_date"):
            self._add(techniques, seen_ids, "kill_date")

        # Always present for CS
        self._add(techniques, seen_ids, "reflective_loading")

        # Summarize by tactic
        tactics: Dict[str, int] = {}
        for t in techniques:
            tactic = t.get("tactic", "unknown")
            tactics[tactic] = tactics.get(tactic, 0) + 1

        return {
            "techniques": techniques,
            "tactics": tactics,
            "total_techniques": len(techniques),
        }

    @staticmethod
    def _add(
        techniques: List[Dict[str, str]],
        seen: set,
        key: str,
    ) -> None:
        """Add a technique if not already added."""
        if key in seen or key not in TECHNIQUE_MAP:
            return
        seen.add(key)
        techniques.append(TECHNIQUE_MAP[key].copy())
