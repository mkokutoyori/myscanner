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

# Import helpers (with optional dependencies)
try:
    from .ssh_helper import SSHHelper, SSHConnectionError, SSHExecutionError
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False

try:
    from .winrm_helper import WinRMHelper, WinRMConnectionError, WinRMExecutionError
    WINRM_AVAILABLE = True
except ImportError:
    WINRM_AVAILABLE = False

__all__ = [
    "BasePlugin",
    "PluginType",
    "PluginResult",
    "PluginFinding",
    "PluginAsset",
    "PluginConfig",
    "FindingSeverity",
]

# Add helpers to __all__ if available
if SSH_AVAILABLE:
    __all__.extend(["SSHHelper", "SSHConnectionError", "SSHExecutionError"])

if WINRM_AVAILABLE:
    __all__.extend(["WinRMHelper", "WinRMConnectionError", "WinRMExecutionError"])
