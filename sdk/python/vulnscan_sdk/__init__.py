"""
VulnScan SDK - Plugin Development Kit

This SDK provides interfaces and utilities for developing VulnScan plugins.
"""

__version__ = "0.1.0"

from .base_plugin import (
    BasePlugin,
    PluginType,
    PluginResult,
    PluginFinding,
    PluginAsset,
    PluginConfig,
    FindingSeverity
)

__all__ = [
    "BasePlugin",
    "PluginType",
    "PluginResult",
    "PluginFinding",
    "PluginAsset",
    "PluginConfig",
    "FindingSeverity",
]
