"""Plugin contracts using Python Protocols for structural subtyping.

Plugins implement these Protocols without inheriting from them. This
keeps plugins decoupled and lightweight — any class with the right
method signatures satisfies the contract.
"""

from typing import Any, Dict, List, Optional, runtime_checkable, Protocol


@runtime_checkable
class DissectionPlugin(Protocol):
    """Contract all dissection/analysis plugins must satisfy.

    Plugins declare which hooks they subscribe to via the `hooks` attribute.
    Only subscribed hooks will be called.

    Attributes:
        name: Unique plugin identifier (e.g. "entropy_analyzer").
        version: Semver string (e.g. "1.0.0").
        description: One-line human-readable description.
        hooks: List of HookPoint names this plugin subscribes to.
    """

    name: str
    version: str
    description: str
    hooks: List[str]

    def initialize(self, config: Dict[str, Any]) -> None:
        """Called once after discovery, before any hooks fire."""
        ...

    def on_payload_loaded(self, data: bytes, ctx: Dict[str, Any]) -> None:
        """Called after Stage 1 — raw payload bytes available."""
        ...

    def on_version_detected(
        self, version_result: Any, ctx: Dict[str, Any]
    ) -> None:
        """Called after Stage 2 — version detection result available."""
        ...

    def on_loader_extracted(
        self, loader_result: Any, ctx: Dict[str, Any]
    ) -> None:
        """Called after Stage 3 — loader extraction result available."""
        ...

    def on_config_extracted(
        self, config: Dict[str, Any], ctx: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Called after Stage 5 — config settings available."""
        ...

    def on_pe_parsed(
        self, pe_info: Any, dll_data: bytes, ctx: Dict[str, Any]
    ) -> None:
        """Called after Stage 4 — PE info and DLL bytes available."""
        ...

    def on_manifest_ready(
        self, manifest: Dict[str, Any], ctx: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Called after Stage 7 — complete manifest available."""
        ...

    def render_results(self) -> Optional[Any]:
        """Return a Rich renderable (Panel, Table, Tree, Text) for CLI display.

        Called after all hooks have completed. The renderable is printed
        to the terminal as a dedicated plugin output section.

        Returns:
            A Rich renderable object, or None if no results to display.
        """
        ...

    def get_results(self) -> Optional[Dict[str, Any]]:
        """Return plugin results as a JSON-serializable dict.

        Used for --plugin-output json mode and manifest injection.

        Returns:
            Results dict, or None if no results.
        """
        ...

    def cleanup(self) -> None:
        """Called at pipeline end for resource cleanup."""
        ...


@runtime_checkable
class PackerPlugin(Protocol):
    """Contract for UDRL packer plugins."""

    name: str
    version: str
    description: str

    def pack(
        self,
        loader: bytes,
        dll: bytes,
        config: bytes,
        **kwargs: Any,
    ) -> bytes:
        """Pack components into a single payload."""
        ...

    def validate(self, packed: bytes) -> bool:
        """Validate a packed payload for structural integrity."""
        ...
