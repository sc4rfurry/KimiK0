"""Network Sub-Engine — C2 infrastructure IOC extraction."""

import re
from typing import Any, Dict, List, Optional


class NetworkEngine:
    """Extract network-level IOCs from beacon config and DLL strings."""

    def extract(
        self, config: Dict[str, Any], dll_data: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """Extract all network IOCs."""
        result: Dict[str, Any] = {
            "domains": [],
            "ips": [],
            "uris": [],
            "pipes": [],
            "dns_beacons": [],
            "proxy": {},
            "c2_profile": {},
        }

        # C2 domains/IPs from SETTING_DOMAINS
        domains_raw = str(config.get("SETTING_DOMAINS", ""))
        if domains_raw:
            for part in (p.strip() for p in domains_raw.split(",")):
                if part.startswith("/"):
                    result["uris"].append(part)
                elif self._is_ip(part):
                    result["ips"].append(part)
                elif part and not all(c == "0" for c in part):
                    result["domains"].append(part)

        # Submit URI
        submit = config.get("SETTING_SUBMITURI", "")
        if submit:
            result["uris"].append(str(submit))

        # Host header (extra domain)
        host_header = config.get("SETTING_HOST_HEADER", "")
        if host_header and not all(c == "0" for c in str(host_header)):
            result["domains"].append(str(host_header))

        # Named pipes
        for key in ("SETTING_PIPENAME", "SETTING_PIPENAME_STAGER"):
            pipe = config.get(key, "")
            if pipe and str(pipe).strip():
                result["pipes"].append(str(pipe))

        # DNS beacon domains
        for key in (
            "SETTING_DNS_BEACON_BEACON",
            "SETTING_DNS_BEACON_GET_A",
            "SETTING_DNS_BEACON_GET_AAAA",
            "SETTING_DNS_BEACON_GET_TXT",
            "SETTING_DNS_BEACON_PUT_METADATA",
            "SETTING_DNS_BEACON_PUT_OUTPUT",
        ):
            val = config.get(key, "")
            if val and str(val).strip():
                result["dns_beacons"].append({"type": key.split("_")[-1], "value": str(val)})

        # Protocol & port
        proto_map = {0: "HTTP", 1: "DNS", 2: "SMB", 4: "TCP", 8: "HTTPS"}
        proto = config.get("SETTING_PROTOCOL", 0)
        port = config.get("SETTING_PORT", 0)
        ua = config.get("SETTING_USERAGENT", "")
        sleep_ms = config.get("SETTING_SLEEPTIME", 0)
        jitter = config.get("SETTING_JITTER", 0)

        result["c2_profile"] = {
            "protocol": proto_map.get(int(proto), f"unknown({proto})"),
            "port": int(port) if port else 0,
            "user_agent": str(ua) if ua else "",
            "sleep_ms": int(sleep_ms) if sleep_ms else 0,
            "jitter_pct": int(jitter) if jitter else 0,
        }

        # HTTP verbs
        for key, label in [
            ("SETTING_C2_VERB_GET", "http_get_verb"),
            ("SETTING_C2_VERB_POST", "http_post_verb"),
        ]:
            v = config.get(key, "")
            if v:
                result["c2_profile"][label] = str(v)

        # Proxy config
        proxy_behavior = config.get("SETTING_PROXY_BEHAVIOR", 0)
        proxy_map = {0: "direct", 1: "IE settings", 2: "manual", 4: "block"}
        result["proxy"] = {
            "behavior": proxy_map.get(int(proxy_behavior), "unknown"),
            "config": str(config.get("SETTING_PROXY_CONFIG", "")),
        }

        # SMB/TCP frame headers
        smb_frame = config.get("SETTING_SMB_FRAME_HEADER", "")
        tcp_frame = config.get("SETTING_TCP_FRAME_HEADER", "")
        if smb_frame:
            result["c2_profile"]["smb_frame_header"] = str(smb_frame)
        if tcp_frame:
            result["c2_profile"]["tcp_frame_header"] = str(tcp_frame)

        # DLL string fallback
        if dll_data:
            self._extract_from_dll(dll_data, result)

        # Deduplicate
        for key in ("domains", "ips", "uris", "pipes"):
            result[key] = list(set(result[key]))

        return result

    def _extract_from_dll(self, dll_data: bytes, result: Dict[str, Any]) -> None:
        """Extract network patterns from decrypted DLL strings."""
        try:
            strings = re.findall(rb"[\x20-\x7e]{6,256}", dll_data)
            for s in strings[:500]:
                decoded = s.decode("ascii", errors="replace")
                if re.match(r"^[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}$", decoded):
                    if not all(c == "0" for c in decoded):
                        result["domains"].append(decoded)
                elif self._is_ip(decoded):
                    result["ips"].append(decoded)
                elif decoded.startswith("/") and " " not in decoded and len(decoded) > 1:
                    result["uris"].append(decoded)
        except Exception:
            pass

    @staticmethod
    def _is_ip(s: str) -> bool:
        parts = s.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
