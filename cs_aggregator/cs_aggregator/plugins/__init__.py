"""Plugin system for the KimiK0 Dissection Engine.

Provides a Protocol-based plugin architecture with dynamic discovery,
lifecycle management, and hook-based execution.

Usage:
    from cs_aggregator.plugins import PluginManager

    manager = PluginManager()
    manager.discover()
    manager.initialize_all(config={})
    manager.run_hook("on_payload_loaded", data=payload_bytes, ctx={})
    manager.cleanup_all()
"""

from cs_aggregator.plugins.base import DissectionPlugin, PackerPlugin
from cs_aggregator.plugins.manager import PluginManager
from cs_aggregator.plugins.hooks import HookPoint

__all__ = ["DissectionPlugin", "PackerPlugin", "PluginManager", "HookPoint"]
