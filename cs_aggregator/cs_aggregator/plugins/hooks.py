"""Hook point definitions for the plugin system.

Each hook corresponds to a stage in the dissection pipeline.
Plugins declare which hooks they subscribe to.
"""

from enum import Enum


class HookPoint(str, Enum):
    """Pipeline hook points where plugins can inject behavior."""

    ON_PAYLOAD_LOADED = "on_payload_loaded"
    ON_VERSION_DETECTED = "on_version_detected"
    ON_LOADER_EXTRACTED = "on_loader_extracted"
    ON_PE_PARSED = "on_pe_parsed"
    ON_CONFIG_EXTRACTED = "on_config_extracted"
    ON_MANIFEST_READY = "on_manifest_ready"

    @classmethod
    def all_hooks(cls) -> list:
        return [h.value for h in cls]
