"""
Plugin Loader Service

Dynamically loads and manages VulnScan plugins.
"""
import os
import sys
import importlib.util
import inspect
import logging
from typing import Dict, List, Optional, Type, Any
from pathlib import Path

# Add SDK to path
SDK_PATH = os.path.join(os.path.dirname(__file__), '../../sdk/python')
sys.path.insert(0, SDK_PATH)

from vulnscan_sdk import BasePlugin

logger = logging.getLogger(__name__)


class PluginLoader:
    """
    Plugin loader that discovers and loads plugins from plugin directories.

    Supports:
    - Dynamic plugin discovery
    - Plugin validation
    - Plugin metadata extraction
    - Plugin instance management
    """

    def __init__(self, plugin_dirs: Optional[List[str]] = None):
        """
        Initialize plugin loader.

        Args:
            plugin_dirs: List of directories to search for plugins
        """
        self.plugin_dirs = plugin_dirs or [
            os.path.join(os.path.dirname(__file__), '../plugins'),
        ]

        self.plugins: Dict[str, Type[BasePlugin]] = {}
        self.plugin_instances: Dict[str, BasePlugin] = {}

        logger.info(f"Plugin loader initialized with directories: {self.plugin_dirs}")

    def discover_plugins(self) -> List[str]:
        """
        Discover all available plugins in plugin directories.

        Returns:
            List of discovered plugin names
        """
        discovered = []

        for plugin_dir in self.plugin_dirs:
            if not os.path.exists(plugin_dir):
                logger.warning(f"Plugin directory does not exist: {plugin_dir}")
                continue

            logger.info(f"Scanning for plugins in: {plugin_dir}")

            # Walk through plugin directory
            for root, dirs, files in os.walk(plugin_dir):
                for file in files:
                    if file.endswith('_plugin.py') and not file.startswith('__'):
                        plugin_path = os.path.join(root, file)
                        plugin_name = self._load_plugin_from_file(plugin_path)

                        if plugin_name:
                            discovered.append(plugin_name)

        logger.info(f"Discovered {len(discovered)} plugins: {discovered}")
        return discovered

    def _load_plugin_from_file(self, file_path: str) -> Optional[str]:
        """
        Load a plugin from a Python file.

        Args:
            file_path: Path to plugin file

        Returns:
            Plugin name if loaded successfully, None otherwise
        """
        try:
            # Generate module name from file path
            module_name = f"plugin_{Path(file_path).stem}_{id(file_path)}"

            # Load module
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            if not spec or not spec.loader:
                logger.error(f"Failed to load spec for {file_path}")
                return None

            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

            # Find BasePlugin subclasses
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, BasePlugin) and obj is not BasePlugin:
                    # Found a plugin class
                    plugin_class = obj

                    # Validate plugin
                    if not self._validate_plugin_class(plugin_class):
                        continue

                    # Store plugin class
                    plugin_name = plugin_class.name
                    self.plugins[plugin_name] = plugin_class

                    logger.info(f"Loaded plugin: {plugin_name} v{plugin_class.version} from {file_path}")
                    return plugin_name

        except Exception as e:
            logger.error(f"Failed to load plugin from {file_path}: {e}", exc_info=True)

        return None

    def _validate_plugin_class(self, plugin_class: Type[BasePlugin]) -> bool:
        """
        Validate a plugin class.

        Args:
            plugin_class: Plugin class to validate

        Returns:
            True if valid
        """
        try:
            # Check required attributes
            if not hasattr(plugin_class, 'name') or plugin_class.name == "base-plugin":
                logger.warning(f"Plugin {plugin_class} missing valid 'name' attribute")
                return False

            if not hasattr(plugin_class, 'version') or plugin_class.version == "0.0.0":
                logger.warning(f"Plugin {plugin_class.name} missing valid 'version' attribute")
                return False

            # Check execute method exists
            if not hasattr(plugin_class, 'execute'):
                logger.warning(f"Plugin {plugin_class.name} missing 'execute' method")
                return False

            return True

        except Exception as e:
            logger.error(f"Plugin validation error: {e}")
            return False

    def get_plugin(self, plugin_name: str) -> Optional[Type[BasePlugin]]:
        """
        Get a plugin class by name.

        Args:
            plugin_name: Plugin name

        Returns:
            Plugin class or None if not found
        """
        return self.plugins.get(plugin_name)

    def get_plugin_instance(self, plugin_name: str) -> Optional[BasePlugin]:
        """
        Get a plugin instance (creates if doesn't exist).

        Args:
            plugin_name: Plugin name

        Returns:
            Plugin instance or None if plugin not found
        """
        # Return existing instance if available
        if plugin_name in self.plugin_instances:
            return self.plugin_instances[plugin_name]

        # Get plugin class
        plugin_class = self.get_plugin(plugin_name)
        if not plugin_class:
            logger.error(f"Plugin not found: {plugin_name}")
            return None

        # Create instance
        try:
            instance = plugin_class()
            self.plugin_instances[plugin_name] = instance
            return instance
        except Exception as e:
            logger.error(f"Failed to create plugin instance for {plugin_name}: {e}")
            return None

    def list_plugins(self) -> List[Dict[str, Any]]:
        """
        List all loaded plugins with their metadata.

        Returns:
            List of plugin metadata dictionaries
        """
        result = []

        for plugin_name, plugin_class in self.plugins.items():
            try:
                # Get instance to access metadata
                instance = self.get_plugin_instance(plugin_name)
                if instance:
                    metadata = instance.get_metadata()
                    result.append(metadata)
            except Exception as e:
                logger.error(f"Failed to get metadata for {plugin_name}: {e}")

        return result

    def reload_plugins(self):
        """Reload all plugins (clears cache and re-discovers)."""
        logger.info("Reloading all plugins...")
        self.plugins.clear()
        self.plugin_instances.clear()
        self.discover_plugins()


# Global plugin loader instance
_plugin_loader: Optional[PluginLoader] = None


def get_plugin_loader() -> PluginLoader:
    """
    Get global plugin loader instance (singleton).

    Returns:
        Plugin loader instance
    """
    global _plugin_loader

    if _plugin_loader is None:
        _plugin_loader = PluginLoader()
        _plugin_loader.discover_plugins()

    return _plugin_loader


# Test the loader
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    loader = PluginLoader()
    plugins = loader.discover_plugins()

    print(f"\n{'='*60}")
    print(f"Plugin Loader Test")
    print(f"{'='*60}\n")

    print(f"Discovered {len(plugins)} plugins:\n")

    for plugin_info in loader.list_plugins():
        print(f"  - {plugin_info['name']} v{plugin_info['version']}")
        print(f"    Type: {plugin_info['type']}")
        print(f"    Description: {plugin_info['description']}")
        print(f"    Requires Auth: {plugin_info['requires_authentication']}")
        print()
