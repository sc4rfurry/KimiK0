"""IOC Export Engine — STIX 2.1, MISP JSON, CSV export."""

import csv
import json
import io
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List


class STIXExporter:
    """Export IOCs as STIX 2.1 JSON bundle."""

    def export(self, report: Dict[str, Any], output_path: str) -> str:
        """Export IOC report as STIX 2.1 bundle."""
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": [],
        }

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        identity_id = f"identity--{uuid.uuid4()}"

        # Identity (KimiK0 tool)
        bundle["objects"].append({
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": "KimiK0 IOC Central Engine",
            "identity_class": "system",
        })

        # Malware object (CobaltStrike Beacon)
        malware_id = f"malware--{uuid.uuid4()}"
        bundle["objects"].append({
            "type": "malware",
            "spec_version": "2.1",
            "id": malware_id,
            "created": now,
            "modified": now,
            "name": "CobaltStrike Beacon",
            "malware_types": ["backdoor", "remote-access-trojan"],
            "is_family": True,
            "created_by_ref": identity_id,
        })

        # Domain indicators
        network = report.get("network", {})
        for domain in network.get("domains", []):
            indicator_id = f"indicator--{uuid.uuid4()}"
            bundle["objects"].append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": now,
                "modified": now,
                "name": f"CS Beacon C2 Domain: {domain}",
                "indicator_types": ["malicious-activity"],
                "pattern": f"[domain-name:value = '{domain}']",
                "pattern_type": "stix",
                "valid_from": now,
                "created_by_ref": identity_id,
            })
            # Relationship
            bundle["objects"].append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid4()}",
                "created": now,
                "modified": now,
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": malware_id,
            })

        # IP indicators
        for ip in network.get("ips", []):
            bundle["objects"].append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": now,
                "modified": now,
                "name": f"CS Beacon C2 IP: {ip}",
                "indicator_types": ["malicious-activity"],
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix",
                "valid_from": now,
                "created_by_ref": identity_id,
            })

        # ATT&CK techniques
        ttps = report.get("ttps", {})
        for tech in ttps.get("techniques", []):
            bundle["objects"].append({
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": f"attack-pattern--{uuid.uuid4()}",
                "created": now,
                "modified": now,
                "name": tech.get("name", ""),
                "external_references": [{
                    "source_name": "mitre-attack",
                    "external_id": tech.get("id", ""),
                }],
            })

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2)
        return output_path


class MISPExporter:
    """Export IOCs as MISP JSON event."""

    def export(self, report: Dict[str, Any], output_path: str) -> str:
        """Export IOC report as MISP JSON event."""
        now = datetime.now(timezone.utc)
        event = {
            "Event": {
                "info": "CobaltStrike Beacon IOC Report — KimiK0",
                "date": now.strftime("%Y-%m-%d"),
                "threat_level_id": "2",
                "analysis": "2",
                "distribution": "0",
                "Attribute": [],
                "Tag": [
                    {"name": "malware:CobaltStrike"},
                    {"name": "tlp:amber"},
                ],
            }
        }

        attrs = event["Event"]["Attribute"]
        network = report.get("network", {})

        for domain in network.get("domains", []):
            attrs.append({
                "type": "domain",
                "category": "Network activity",
                "value": domain,
                "to_ids": True,
                "comment": "CS Beacon C2 domain",
            })

        for ip in network.get("ips", []):
            attrs.append({
                "type": "ip-dst",
                "category": "Network activity",
                "value": ip,
                "to_ids": True,
                "comment": "CS Beacon C2 IP",
            })

        for uri in network.get("uris", []):
            attrs.append({
                "type": "uri",
                "category": "Network activity",
                "value": uri,
                "to_ids": True,
                "comment": "CS Beacon URI",
            })

        for pipe in network.get("pipes", []):
            attrs.append({
                "type": "named pipe",
                "category": "Artifacts dropped",
                "value": pipe,
                "to_ids": True,
                "comment": "CS Beacon named pipe",
            })

        # Crypto identifiers
        crypto = report.get("crypto", {})
        identifiers = crypto.get("identifiers", {})
        wm = identifiers.get("watermark")
        if wm:
            attrs.append({
                "type": "text",
                "category": "Attribution",
                "value": str(wm),
                "to_ids": False,
                "comment": "CS Beacon watermark",
            })

        # TTPs as Galaxy clusters
        ttps = report.get("ttps", {})
        for tech in ttps.get("techniques", []):
            attrs.append({
                "type": "text",
                "category": "External analysis",
                "value": f"{tech.get('id', '')}: {tech.get('name', '')}",
                "to_ids": False,
                "comment": f"MITRE ATT&CK: {tech.get('tactic', '')}",
            })

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(event, f, indent=2)
        return output_path


class CSVExporter:
    """Export IOCs as flat CSV for SIEM ingestion."""

    def export(self, report: Dict[str, Any], output_path: str) -> str:
        """Export IOC report as CSV."""
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        rows: List[Dict[str, str]] = []

        network = report.get("network", {})
        for d in network.get("domains", []):
            rows.append({"type": "domain", "value": d, "category": "c2", "confidence": "high"})
        for ip in network.get("ips", []):
            rows.append({"type": "ip", "value": ip, "category": "c2", "confidence": "high"})
        for uri in network.get("uris", []):
            rows.append({"type": "uri", "value": uri, "category": "c2", "confidence": "medium"})
        for pipe in network.get("pipes", []):
            rows.append({"type": "named_pipe", "value": pipe, "category": "artifact", "confidence": "high"})

        behavioral = report.get("behavioral", {})
        for proc in behavioral.get("processes", []):
            rows.append({"type": "process", "value": proc, "category": "spawn_to", "confidence": "medium"})

        crypto = report.get("crypto", {})
        for k, v in crypto.get("identifiers", {}).items():
            rows.append({"type": k, "value": str(v), "category": "identifier", "confidence": "high"})

        ttps = report.get("ttps", {})
        for tech in ttps.get("techniques", []):
            rows.append({
                "type": "mitre_technique",
                "value": tech.get("id", ""),
                "category": tech.get("tactic", ""),
                "confidence": "high",
            })

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["type", "value", "category", "confidence"])
            writer.writeheader()
            writer.writerows(rows)
        return output_path
