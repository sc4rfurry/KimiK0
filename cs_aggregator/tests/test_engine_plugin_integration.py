"""Tests for engine-plugin integration — verifying hook dispatch works end-to-end."""

import pytest
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

from cs_aggregator.engine import DissectionPipeline
from cs_aggregator.plugins.manager import PluginManager


class TestEnginePluginIntegration:
    """Test that the engine dispatches hooks to the plugin manager."""

    def test_pipeline_accepts_plugin_manager(self):
        """Test that DissectionPipeline accepts a plugin_manager parameter."""
        pm = PluginManager()
        pipeline = DissectionPipeline(plugin_manager=pm)
        assert pipeline._plugin_manager is pm

    def test_pipeline_without_plugin_manager(self):
        """Test that DissectionPipeline works without a plugin_manager."""
        pipeline = DissectionPipeline()
        assert pipeline._plugin_manager is None

    def test_dispatch_hook_with_manager(self):
        """Test that _dispatch_hook calls plugin manager's run_hook."""
        pm = MagicMock(spec=PluginManager)
        pipeline = DissectionPipeline(plugin_manager=pm)
        pipeline._dispatch_hook("on_payload_loaded", data=b"test", ctx={})
        pm.run_hook.assert_called_once_with("on_payload_loaded", data=b"test", ctx={})

    def test_dispatch_hook_without_manager(self):
        """Test that _dispatch_hook is a no-op without plugin manager."""
        pipeline = DissectionPipeline()
        # Should not raise
        pipeline._dispatch_hook("on_payload_loaded", data=b"test", ctx={})

    def test_dispatch_hook_exception_handling(self):
        """Test that hook dispatch failures don't crash the pipeline."""
        pm = MagicMock(spec=PluginManager)
        pm.run_hook.side_effect = RuntimeError("Plugin crashed!")
        pipeline = DissectionPipeline(plugin_manager=pm)
        # Should not raise — exceptions are caught
        pipeline._dispatch_hook("on_payload_loaded", data=b"test", ctx={})


class TestPluginManagerDuplicate:
    """Test that the duplicate get_plugin bug is fixed (B2)."""

    def test_get_plugin_requires_enabled_and_initialized(self):
        """Only enabled+initialized plugins are returned by get_plugin."""
        pm = PluginManager()
        mock_instance = MagicMock()
        mock_instance.name = "test"
        mock_instance.version = "1.0"
        mock_instance.description = "test"
        mock_instance.hooks = ["on_payload_loaded"]
        from cs_aggregator.plugins.manager import PluginInfo
        info = PluginInfo(mock_instance, source="test")
        info.enabled = False  # Disabled
        info.initialized = True
        pm._plugins.append(info)
        result = pm.get_plugin("test")
        assert result is None  # Should NOT return disabled plugin


class TestPluginProtocolHooks:
    """Test that the DissectionPlugin protocol has all required hooks."""

    def test_protocol_has_all_hooks(self):
        from cs_aggregator.plugins.base import DissectionPlugin
        # Check that all 6 hook methods exist
        for hook in [
            "on_payload_loaded",
            "on_version_detected",
            "on_loader_extracted",
            "on_config_extracted",
            "on_pe_parsed",
            "on_manifest_ready",
        ]:
            assert hasattr(DissectionPlugin, hook), f"Missing hook: {hook}"
