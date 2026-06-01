"""Tests for the IOC Central Engine and its sub-engines."""

import json
import os
import tempfile
import pytest
from typing import Any, Dict


# ─── IOC Central Engine Tests ─────────────────────────────────────────────────

class TestIOCCentralEngine:
    """Test the IOC Central Engine orchestrator."""

    def test_instantiation(self):
        from cs_aggregator.ioc_engine import IOCCentralEngine
        engine = IOCCentralEngine()
        assert engine.network is not None
        assert engine.behavioral is not None
        assert engine.crypto is not None
        assert engine.yara is not None
        assert engine.ttp_mapper is not None

    def test_available_formats(self):
        from cs_aggregator.ioc_engine import IOCCentralEngine
        engine = IOCCentralEngine()
        formats = engine.get_available_formats()
        assert "stix" in formats
        assert "misp" in formats
        assert "csv" in formats

    def test_analyze_empty_config(self):
        from cs_aggregator.ioc_engine import IOCCentralEngine
        engine = IOCCentralEngine()
        result = engine.analyze(config={})
        assert "network" in result
        assert "behavioral" in result
        assert "crypto" in result
        assert "ttps" in result
        assert "total_iocs" in result

    def test_analyze_with_config(self):
        from cs_aggregator.ioc_engine import IOCCentralEngine
        engine = IOCCentralEngine()
        config = {
            "SETTING_DOMAINS": "evil.com,/submit.php",
            "SETTING_PROTOCOL": 8,
            "SETTING_PORT": 443,
            "SETTING_SLEEPTIME": 60000,
            "SETTING_JITTER": 15,
            "SETTING_SPAWNTO_X64": "%windir%\\sysnative\\rundll32.exe",
            "SETTING_WATERMARK": 391144938,
            "SETTING_SYSCALL_METHOD": 2,
        }
        result = engine.analyze(config=config)
        net = result["network"]
        assert "evil.com" in net["domains"]
        assert "/submit.php" in net["uris"]
        assert result["behavioral"]["syscall"]["method"] == "indirect"
        assert result["crypto"]["identifiers"]["watermark"] == 391144938


# ─── Network Engine Tests ─────────────────────────────────────────────────────

class TestNetworkEngine:
    """Test the Network sub-engine."""

    def test_extract_domains_ips(self):
        from cs_aggregator.ioc_engine.network_engine import NetworkEngine
        eng = NetworkEngine()
        config = {"SETTING_DOMAINS": "c2.evil.com,192.168.1.1,/path"}
        result = eng.extract(config)
        assert "c2.evil.com" in result["domains"]
        assert "192.168.1.1" in result["ips"]
        assert "/path" in result["uris"]

    def test_extract_pipes(self):
        from cs_aggregator.ioc_engine.network_engine import NetworkEngine
        eng = NetworkEngine()
        config = {"SETTING_PIPENAME": "\\\\.\\pipe\\MSSE-1234-server"}
        result = eng.extract(config)
        assert len(result["pipes"]) == 1

    def test_extract_dns_beacons(self):
        from cs_aggregator.ioc_engine.network_engine import NetworkEngine
        eng = NetworkEngine()
        config = {"SETTING_DNS_BEACON_BEACON": ".dns-c2.evil.com"}
        result = eng.extract(config)
        assert len(result["dns_beacons"]) == 1


# ─── Behavioral Engine Tests ─────────────────────────────────────────────────

class TestBehavioralEngine:
    """Test the Behavioral sub-engine."""

    def test_extract_syscall_indirect(self):
        from cs_aggregator.ioc_engine.behavioral_engine import BehavioralEngine
        eng = BehavioralEngine()
        config = {"SETTING_SYSCALL_METHOD": 2}
        result = eng.extract(config)
        assert result["syscall"]["method"] == "indirect"

    def test_extract_beacon_gate(self):
        from cs_aggregator.ioc_engine.behavioral_engine import BehavioralEngine
        eng = BehavioralEngine()
        config = {"SETTING_BEACON_GATE": 1}
        result = eng.extract(config)
        assert result["evasion"]["beacon_gate_enabled"] is True

    def test_extract_drip_loading(self):
        from cs_aggregator.ioc_engine.behavioral_engine import BehavioralEngine
        eng = BehavioralEngine()
        config = {"SETTING_RDLL_USE_DRIPLOADING": 1, "SETTING_RDLL_DRIPLOAD_DELAY": 100}
        result = eng.extract(config)
        assert result["evasion"]["drip_loading_enabled"] is True
        assert result["evasion"]["drip_delay_ms"] == 100

    def test_extract_spawn_to(self):
        from cs_aggregator.ioc_engine.behavioral_engine import BehavioralEngine
        eng = BehavioralEngine()
        config = {"SETTING_SPAWNTO_X64": "dllhost.exe"}
        result = eng.extract(config)
        assert "dllhost.exe" in result["processes"]


# ─── Crypto Engine Tests ─────────────────────────────────────────────────────

class TestCryptoEngine:
    """Test the Crypto sub-engine."""

    def test_extract_watermark(self):
        from cs_aggregator.ioc_engine.crypto_engine import CryptoEngine
        eng = CryptoEngine()
        config = {"SETTING_WATERMARK": 305419896}
        result = eng.extract(config)
        assert result["identifiers"]["watermark"] == 305419896

    def test_extract_killdate(self):
        from cs_aggregator.ioc_engine.crypto_engine import CryptoEngine
        eng = CryptoEngine()
        config = {"SETTING_KILLDATE": 20261231}
        result = eng.extract(config)
        assert result["timestamps"]["kill_date"] == "2026-12-31"

    def test_extract_xor_key_from_ctx(self):
        from cs_aggregator.ioc_engine.crypto_engine import CryptoEngine
        eng = CryptoEngine()
        result = eng.extract({}, {"xor_key": "2e2e2e2e"})
        assert result["keys"]["xor_key"] == "2e2e2e2e"
        assert result["keys"]["xor_key_length"] == 4


# ─── TTP Mapper Tests ────────────────────────────────────────────────────────

class TestTTPMapper:
    """Test the TTP mapper."""

    def test_map_http_beacon(self):
        from cs_aggregator.ioc_engine.ttp_mapper import TTPMapper
        mapper = TTPMapper()
        report = {"network": {"c2_profile": {"protocol": "HTTPS"}, "pipes": []}}
        result = mapper.map_from_report(report)
        ids = {t["id"] for t in result["techniques"]}
        assert "T1071.001" in ids  # Web Protocols

    def test_map_syscall_indirect(self):
        from cs_aggregator.ioc_engine.ttp_mapper import TTPMapper
        mapper = TTPMapper()
        report = {"behavioral": {"syscall": {"method": "indirect"}, "processes": [], "injection": {}, "evasion": {}, "sleep_profile": {}}}
        result = mapper.map_from_report(report)
        ids = {t["id"] for t in result["techniques"]}
        assert "T1106" in ids  # Native API


# ─── YARA Engine Tests ───────────────────────────────────────────────────────

class TestYaraEngine:
    """Test the YARA sub-engine."""

    def test_generate_rules_with_domains(self):
        from cs_aggregator.ioc_engine.yara_engine import YaraEngine
        eng = YaraEngine()
        report = {"network": {"domains": ["evil.com"], "ips": [], "pipes": [], "c2_profile": {}}}
        rules = eng.generate_rules(report, {})
        assert "evil.com" in rules
        assert "rule CS_C2_Indicators" in rules

    def test_generate_rules_with_watermark(self):
        from cs_aggregator.ioc_engine.yara_engine import YaraEngine
        eng = YaraEngine()
        report = {"crypto": {"identifiers": {"watermark": 305419896}, "keys": {}}}
        rules = eng.generate_rules(report, {})
        assert "rule CS_Watermark_305419896" in rules

    def test_generate_rules_empty(self):
        from cs_aggregator.ioc_engine.yara_engine import YaraEngine
        eng = YaraEngine()
        rules = eng.generate_rules({}, {})
        assert "No dynamic YARA rules" in rules


# ─── Exporter Tests ──────────────────────────────────────────────────────────

class TestExporters:
    """Test all three export formats."""

    @pytest.fixture
    def sample_report(self):
        return {
            "network": {"domains": ["evil.com"], "ips": ["1.2.3.4"], "uris": ["/submit"], "pipes": []},
            "behavioral": {"processes": ["dllhost.exe"], "syscall": {"method": "indirect"}, "injection": {}, "evasion": {}, "sleep_profile": {}},
            "crypto": {"identifiers": {"watermark": 12345}, "timestamps": {}, "keys": {}},
            "ttps": {"techniques": [{"id": "T1071.001", "name": "Web Protocols", "tactic": "c2"}]},
            "total_iocs": 5,
        }

    def test_stix_export(self, sample_report, tmp_path):
        from cs_aggregator.ioc_engine.exporters import STIXExporter
        exp = STIXExporter()
        path = str(tmp_path / "test.stix.json")
        result = exp.export(sample_report, path)
        assert os.path.exists(result)
        with open(result) as f:
            bundle = json.load(f)
        assert bundle["type"] == "bundle"
        assert len(bundle["objects"]) > 0

    def test_misp_export(self, sample_report, tmp_path):
        from cs_aggregator.ioc_engine.exporters import MISPExporter
        exp = MISPExporter()
        path = str(tmp_path / "test.misp.json")
        result = exp.export(sample_report, path)
        assert os.path.exists(result)
        with open(result) as f:
            event = json.load(f)
        assert "Event" in event
        assert len(event["Event"]["Attribute"]) > 0

    def test_csv_export(self, sample_report, tmp_path):
        from cs_aggregator.ioc_engine.exporters import CSVExporter
        exp = CSVExporter()
        path = str(tmp_path / "test.csv")
        result = exp.export(sample_report, path)
        assert os.path.exists(result)
        with open(result) as f:
            lines = f.readlines()
        assert len(lines) > 1  # Header + at least 1 row
        assert "domain" in lines[1]
