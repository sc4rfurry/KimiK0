"""Tests for the C2 profile parser module."""

import pytest
from cs_aggregator.utils.profile_parser import ProfileParser, C2Profile


SAMPLE_PROFILE = '''
# Global settings
set sleeptime "60000";
set jitter "37";
set useragent "Mozilla/5.0 (Windows NT 10.0)";
set host_stage "false";

http-get {
    set uri "/jquery-3.7.1.min.js";

    client {
        header "Accept" "text/html";
        metadata {
            base64url;
            header "Cookie";
        }
    }
}

http-post {
    set uri "/wp-admin/admin-ajax.php";
}

stage {
    set magic_mz_x64 "OICA";
    set magic_mz_x86 "OICA";
    set magic_pe "NO";
    set stomppe "true";
    set cleanup "true";
    set obfuscate "true";
    set sleep_mask "true";
    set smartinject "true";
    set name "srv.dll";
    set module_x64 "xpsservices.dll";
}

process-inject {
    set allocator "NtMapViewOfSection";
    set min_alloc "17500";
    set userwx "false";
    set startrwx "false";
    set bof_reuse_memory "true";
}
'''


class TestProfileParser:
    """Test Malleable C2 profile parsing."""

    def test_parse_global_settings(self):
        profile = ProfileParser.parse(SAMPLE_PROFILE)
        assert profile.sleeptime == 60000
        assert profile.jitter == 37
        assert "Mozilla/5.0" in profile.useragent
        assert profile.host_stage is False

    def test_parse_stage_settings(self):
        profile = ProfileParser.parse(SAMPLE_PROFILE)
        assert profile.magic_mz_x64 == "OICA"
        assert profile.magic_mz_x86 == "OICA"
        assert profile.magic_pe == "NO"
        assert profile.stomppe is True
        assert profile.cleanup is True
        assert profile.obfuscate is True
        assert profile.sleep_mask is True
        assert profile.smartinject is True
        assert profile.stage_name == "srv.dll"
        assert profile.module_x64 == "xpsservices.dll"

    def test_parse_procinj_settings(self):
        profile = ProfileParser.parse(SAMPLE_PROFILE)
        assert profile.allocator == "NtMapViewOfSection"
        assert profile.min_alloc == 17500
        assert profile.bof_reuse_memory is True

    def test_parse_http_uris(self):
        profile = ProfileParser.parse(SAMPLE_PROFILE)
        assert profile.http_get_uri == "/jquery-3.7.1.min.js"
        assert profile.http_post_uri == "/wp-admin/admin-ajax.php"

    def test_pe_magics_property(self):
        profile = ProfileParser.parse(SAMPLE_PROFILE)
        magics = profile.pe_magics
        assert b"OICA" in magics
        assert b"MZ" in magics

    def test_expected_config(self):
        profile = ProfileParser.parse(SAMPLE_PROFILE)
        expected = profile.expected_config
        assert expected["SETTING_SLEEPTIME"] == 60000
        assert expected["SETTING_JITTER"] == 37
        assert expected["SETTING_CLEANUP"] == 1
        assert expected["SETTING_GARGLE_NOOK"] == 1  # sleep_mask
        assert expected["SETTING_PROCINJ_ALLOCATOR"] == 1  # NtMapViewOfSection
        assert expected["SETTING_PROCINJ_MINALLOC"] == 17500
        assert "Mozilla/5.0" in expected.get("SETTING_USERAGENT", "")

    def test_validate_config_all_match(self):
        profile = ProfileParser.parse(SAMPLE_PROFILE)
        extracted = {
            "SETTING_SLEEPTIME": 60000,
            "SETTING_JITTER": 37,
            "SETTING_USERAGENT": "Mozilla/5.0 (Windows NT 10.0) Chrome/125",
            "SETTING_CLEANUP": 1,
            "SETTING_GARGLE_NOOK": 1,
            "SETTING_PROTOCOL": 8,
            "SETTING_PROCINJ_ALLOCATOR": 1,
            "SETTING_PROCINJ_MINALLOC": 17500,
        }
        result = profile.validate_config(extracted)
        assert len(result["mismatches"]) == 0
        assert result["match_rate"] >= 0.9

    def test_validate_config_with_mismatch(self):
        profile = ProfileParser.parse(SAMPLE_PROFILE)
        extracted = {
            "SETTING_SLEEPTIME": 30000,  # Wrong!
            "SETTING_JITTER": 37,
            "SETTING_CLEANUP": 1,
        }
        result = profile.validate_config(extracted)
        assert len(result["mismatches"]) >= 1
        mismatch_settings = [m[0] for m in result["mismatches"]]
        assert "SETTING_SLEEPTIME" in mismatch_settings

    def test_validate_config_with_missing(self):
        profile = ProfileParser.parse(SAMPLE_PROFILE)
        extracted = {}  # Empty — nothing matches
        result = profile.validate_config(extracted)
        assert len(result["missing"]) > 0
        assert result["match_rate"] == 0.0

    def test_parse_comments_stripped(self):
        source = '''
        set sleeptime "5000";  # This is a comment
        # Full line comment
        set jitter "10";
        '''
        profile = ProfileParser.parse(source)
        assert profile.sleeptime == 5000
        assert profile.jitter == 10

    def test_parse_empty_profile(self):
        profile = ProfileParser.parse("")
        assert profile.magic_mz_x64 == "MZ"  # Defaults
        assert profile.sleeptime == 60000

    def test_parse_real_profile(self):
        """Test against the real prod.profile if available."""
        import os
        profile_path = r'd:\GzG\KimiK0\Payload\Profiles\prod.profile'
        if os.path.isfile(profile_path):
            profile = ProfileParser.parse_file(profile_path)
            assert profile.magic_mz_x64 == "OICA"
            assert profile.magic_pe == "NO"
            assert profile.stomppe is True
            assert profile.sleep_mask is True
            assert profile.sleeptime == 60000
            assert profile.jitter == 37
            assert profile.allocator == "NtMapViewOfSection"
            assert profile.min_alloc == 17500
