"""Plugin Manager — Discovery, lifecycle, and execution.

Discovers plugins from:
1. Built-in plugins (cs_aggregator.plugins.builtin.*)
2. User plugin directories (~/.kimik0/plugins/)
3. Entry points (importlib.metadata, group: cs_aggregator.plugins)

Each plugin is validated against the Protocol contract before loading.
All hook execution is isolated in try/except — one crash doesn't kill the pipeline.
"""

import importlib
import logging
import pkgutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from cs_aggregator.plugins.base import DissectionPlugin, PackerPlugin
from cs_aggregator.plugins.hooks import HookPoint

logger = logging.getLogger(__name__)


class PluginInfo:
    """Metadata wrapper for a loaded plugin instance."""

    def __init__(self, instance: Any, source: str = "builtin"):
        self.instance = instance
        self.name: str = getattr(instance, "name", "unknown")
        self.version: str = getattr(instance, "version", "0.0.0")
        self.description: str = getattr(instance, "description", "")
        self.hooks: List[str] = getattr(instance, "hooks", [])
        self.source = source  # "builtin", "user", "entrypoint"
        self.enabled = True
        self.initialized = False
        self.errors: List[str] = []

    def __repr__(self) -> str:
        status = "✓" if self.initialized else "○"
        return f"PluginInfo({status} {self.name} v{self.version}, hooks={self.hooks})"


class PluginManager:
    """Orchestrates plugin discovery, validation, lifecycle, and hook execution.

    Usage:
        manager = PluginManager()
        manager.discover()
        manager.initialize_all(config={})
        results = manager.run_hook("on_payload_loaded", data=payload, ctx={})
        manager.cleanup_all()
    """

    def __init__(self, plugin_dirs: Optional[List[str]] = None):
        """Initialize the plugin manager.

        Args:
            plugin_dirs: Additional directories to scan for plugins.
        """
        self._plugins: List[PluginInfo] = []
        self._plugin_dirs = plugin_dirs or []
        self._hook_registry: Dict[str, List[PluginInfo]] = {
            hook.value: [] for hook in HookPoint
        }

    @property
    def plugins(self) -> List[PluginInfo]:
        """All discovered plugins."""
        return self._plugins

    @property
    def enabled_plugins(self) -> List[PluginInfo]:
        """Only enabled plugins."""
        return [p for p in self._plugins if p.enabled]

    def discover(self, enable_filter: Optional[List[str]] = None) -> int:
        """Discover and register all available plugins.

        Args:
            enable_filter: If provided, only enable plugins with these names.

        Returns:
            Number of plugins discovered.
        """
        # 1. Built-in plugins
        self._discover_builtin()

        # 2. User plugin directories
        for d in self._plugin_dirs:
            self._discover_directory(d)

        # 3. Entry points (from installed packages)
        self._discover_entry_points()

        # Apply filter
        if enable_filter is not None:
            for p in self._plugins:
                p.enabled = p.name in enable_filter

        # Build hook registry
        self._rebuild_hook_registry()

        logger.info(
            "Plugin discovery: %d plugins found, %d enabled",
            len(self._plugins),
            len(self.enabled_plugins),
        )
        return len(self._plugins)

    def _discover_builtin(self) -> None:
        """Discover built-in plugins from cs_aggregator.plugins.builtin."""
        try:
            import cs_aggregator.plugins.builtin as builtin_pkg

            package_path = Path(builtin_pkg.__file__).parent
            for importer, modname, ispkg in pkgutil.iter_modules([str(package_path)]):
                if modname.startswith("_"):
                    continue
                try:
                    module = importlib.import_module(
                        f"cs_aggregator.plugins.builtin.{modname}"
                    )
                    # Look for a class ending in "Plugin"
                    for attr_name in dir(module):
                        if attr_name.endswith("Plugin") and not attr_name.startswith("_"):
                            cls = getattr(module, attr_name)
                            if isinstance(cls, type) and self._validate_plugin(cls):
                                instance = cls()
                                self._register(instance, source="builtin")
                except Exception as e:
                    logger.warning("Failed to load builtin plugin %s: %s", modname, e)
        except ImportError:
            logger.debug("No builtin plugins package found")

    def _discover_directory(self, directory: str) -> None:
        """Discover plugins from a filesystem directory."""
        dir_path = Path(directory).expanduser()
        if not dir_path.is_dir():
            return

        for py_file in dir_path.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            try:
                import importlib.util

                spec = importlib.util.spec_from_file_location(
                    f"user_plugin_{py_file.stem}", str(py_file)
                )
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)

                    for attr_name in dir(module):
                        if attr_name.endswith("Plugin"):
                            cls = getattr(module, attr_name)
                            if isinstance(cls, type) and self._validate_plugin(cls):
                                instance = cls()
                                self._register(instance, source="user")
            except Exception as e:
                logger.warning("Failed to load user plugin %s: %s", py_file.name, e)

    def _discover_entry_points(self) -> None:
        """Discover plugins registered via Python entry points."""
        try:
            from importlib.metadata import entry_points

            eps = entry_points(group="cs_aggregator.plugins")
            for ep in eps:
                try:
                    plugin_class = ep.load()
                    if self._validate_plugin(plugin_class):
                        instance = plugin_class()
                        self._register(instance, source="entrypoint")
                except Exception as e:
                    logger.warning("Failed to load entry point plugin %s: %s", ep.name, e)
        except Exception:
            logger.debug("Entry point discovery failed")

    def _validate_plugin(self, cls: Type) -> bool:
        """Validate a plugin class satisfies the DissectionPlugin protocol."""
        required_attrs = ["name", "version", "hooks", "initialize", "cleanup"]
        for attr in required_attrs:
            if not hasattr(cls, attr):
                return False
        return True

    def _register(self, instance: Any, source: str = "builtin") -> None:
        """Register a plugin instance."""
        # Check for duplicate names
        for existing in self._plugins:
            if existing.name == getattr(instance, "name", ""):
                logger.warning(
                    "Duplicate plugin name '%s' from %s (already loaded from %s)",
                    existing.name, source, existing.source,
                )
                return

        info = PluginInfo(instance, source=source)
        self._plugins.append(info)
        logger.debug("Registered plugin: %s v%s (%s)", info.name, info.version, source)

    def _rebuild_hook_registry(self) -> None:
        """Rebuild the hook → plugin mapping."""
        self._hook_registry = {hook.value: [] for hook in HookPoint}
        for plugin in self.enabled_plugins:
            for hook_name in plugin.hooks:
                if hook_name in self._hook_registry:
                    self._hook_registry[hook_name].append(plugin)

    def initialize_all(self, config: Optional[Dict[str, Any]] = None) -> None:
        """Initialize all enabled plugins.

        Args:
            config: Global config dict. Each plugin receives
                config.get(plugin.name, {}) as its config.
        """
        config = config or {}
        for plugin in self.enabled_plugins:
            try:
                plugin_config = config.get(plugin.name, {})
                plugin.instance.initialize(plugin_config)
                plugin.initialized = True
                logger.debug("Initialized plugin: %s", plugin.name)
            except Exception as e:
                plugin.errors.append(f"initialize: {e}")
                logger.warning("Plugin %s initialization failed: %s", plugin.name, e)

    def run_hook(self, hook_name: str, **kwargs: Any) -> List[Any]:
        """Execute a hook across all subscribed plugins.

        Each plugin is called in isolation — exceptions are caught and logged.

        Args:
            hook_name: Hook point name (e.g. "on_payload_loaded").
            **kwargs: Hook-specific arguments passed to each plugin.

        Returns:
            List of non-None return values from plugins.
        """
        results: List[Any] = []
        subscribers = self._hook_registry.get(hook_name, [])

        for plugin in subscribers:
            if not plugin.initialized or not plugin.enabled:
                continue
            try:
                method = getattr(plugin.instance, hook_name, None)
                if method and callable(method):
                    result = method(**kwargs)
                    if result is not None:
                        results.append(result)
            except Exception as e:
                plugin.errors.append(f"{hook_name}: {e}")
                logger.warning(
                    "Plugin %s hook %s failed: %s", plugin.name, hook_name, e
                )

        return results

    def cleanup_all(self) -> None:
        """Cleanup all initialized plugins."""
        for plugin in self._plugins:
            if plugin.initialized:
                try:
                    plugin.instance.cleanup()
                except Exception as e:
                    logger.debug("Plugin %s cleanup failed: %s", plugin.name, e)

    def list_plugins_table(self) -> List[Dict[str, Any]]:
        """Return plugin info as a list of dicts for display."""
        return [
            {
                "name": p.name,
                "version": p.version,
                "description": p.description,
                "source": p.source,
                "enabled": p.enabled,
                "initialized": p.initialized,
                "hooks": p.hooks,
                "errors": p.errors,
            }
            for p in self._plugins
        ]

    def get_plugin(self, name: str) -> Optional["PluginInfo"]:
        """Get a specific plugin by name.

        Returns:
            PluginInfo if found, None otherwise.
        """
        for p in self._plugins:
            if p.name == name and p.enabled and p.initialized:
                return p
        return None

    def collect_renderables(self) -> List[tuple]:
        """Collect Rich renderables from all plugins that have results.

        Returns:
            List of (plugin_name, renderable) tuples.
        """
        results = []
        for plugin in self.enabled_plugins:
            if not plugin.initialized:
                continue
            try:
                render_fn = getattr(plugin.instance, "render_results", None)
                if render_fn and callable(render_fn):
                    renderable = render_fn()
                    if renderable is not None:
                        results.append((plugin.name, renderable))
            except Exception as e:
                plugin.errors.append(f"render_results: {e}")
                logger.debug("Plugin %s render failed: %s", plugin.name, e)
        return results

    def collect_json_results(self) -> Dict[str, Any]:
        """Collect JSON results from all plugins.

        Returns:
            Dict mapping plugin_name -> results_dict.
        """
        results = {}
        for plugin in self.enabled_plugins:
            if not plugin.initialized:
                continue
            try:
                get_fn = getattr(plugin.instance, "get_results", None)
                if get_fn and callable(get_fn):
                    data = get_fn()
                    if data is not None:
                        results[plugin.name] = data
            except Exception as e:
                plugin.errors.append(f"get_results: {e}")
                logger.debug("Plugin %s get_results failed: %s", plugin.name, e)
        return results

