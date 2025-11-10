"""
Plugin Registry Service

Registers and manages plugins in the database.
"""
import logging
from sqlalchemy.orm import Session
from typing import List, Dict, Any

from backend.models import Plugin
from backend.services.plugin_loader import get_plugin_loader

logger = logging.getLogger(__name__)


class PluginRegistry:
    """
    Manages plugin registration in the database.

    Syncs discovered plugins with the database Plugin table.
    """

    def __init__(self, db: Session):
        """
        Initialize plugin registry.

        Args:
            db: Database session
        """
        self.db = db
        self.loader = get_plugin_loader()

    def sync_plugins(self) -> int:
        """
        Sync discovered plugins to database.

        - Adds new plugins
        - Updates existing plugins
        - Marks removed plugins as disabled

        Returns:
            Number of plugins synced
        """
        logger.info("Syncing plugins to database...")

        # Get all discovered plugins
        discovered_plugins = self.loader.list_plugins()
        discovered_names = {p['name'] for p in discovered_plugins}

        synced_count = 0

        # Add/update discovered plugins
        for plugin_meta in discovered_plugins:
            try:
                self._register_plugin(plugin_meta)
                synced_count += 1
            except Exception as e:
                logger.error(f"Failed to register plugin {plugin_meta['name']}: {e}")

        # Disable plugins that are no longer discovered
        all_db_plugins = self.db.query(Plugin).all()
        for db_plugin in all_db_plugins:
            if db_plugin.name not in discovered_names and db_plugin.is_enabled:
                logger.info(f"Disabling removed plugin: {db_plugin.name}")
                db_plugin.is_enabled = False

        self.db.commit()

        logger.info(f"Synced {synced_count} plugins to database")
        return synced_count

    def _register_plugin(self, plugin_meta: Dict[str, Any]):
        """
        Register a single plugin in database.

        Args:
            plugin_meta: Plugin metadata dictionary
        """
        # Check if plugin exists
        existing = self.db.query(Plugin).filter(Plugin.name == plugin_meta['name']).first()

        if existing:
            # Update existing plugin
            existing.display_name = plugin_meta['name'].replace('-', ' ').title()
            existing.description = plugin_meta.get('description', '')
            existing.version = plugin_meta['version']
            existing.author = plugin_meta.get('author', 'Unknown')
            existing.vendor = plugin_meta.get('vendor')
            existing.asset_types = plugin_meta.get('supported_asset_types', [])
            existing.requires_authentication = plugin_meta.get('requires_authentication', False)
            existing.is_intrusive = plugin_meta.get('is_intrusive', False)
            existing.is_enabled = True

            logger.info(f"Updated plugin: {existing.name} v{existing.version}")

        else:
            # Create new plugin
            new_plugin = Plugin(
                name=plugin_meta['name'],
                display_name=plugin_meta['name'].replace('-', ' ').title(),
                description=plugin_meta.get('description', ''),
                version=plugin_meta['version'],
                author=plugin_meta.get('author', 'Unknown'),
                vendor=plugin_meta.get('vendor'),
                asset_types=plugin_meta.get('supported_asset_types', []),
                requires_authentication=plugin_meta.get('requires_authentication', False),
                is_intrusive=plugin_meta.get('is_intrusive', False),
                is_enabled=True,
                is_verified=False  # Manual verification required
            )

            self.db.add(new_plugin)
            logger.info(f"Registered new plugin: {new_plugin.name} v{new_plugin.version}")

    def get_enabled_plugins(self) -> List[Plugin]:
        """
        Get all enabled plugins from database.

        Returns:
            List of enabled Plugin objects
        """
        return self.db.query(Plugin).filter(Plugin.is_enabled == True).all()

    def get_plugin_by_name(self, name: str) -> Plugin:
        """
        Get plugin by name from database.

        Args:
            name: Plugin name

        Returns:
            Plugin object or None
        """
        return self.db.query(Plugin).filter(Plugin.name == name).first()


def init_plugins(db: Session) -> int:
    """
    Initialize plugins on application startup.

    Args:
        db: Database session

    Returns:
        Number of plugins registered
    """
    try:
        registry = PluginRegistry(db)
        return registry.sync_plugins()
    except Exception as e:
        logger.error(f"Plugin initialization failed: {e}", exc_info=True)
        return 0
