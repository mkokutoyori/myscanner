"""
VulnScan SDK - Base Plugin Class

This module provides the abstract base class for all VulnScan plugins.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from enum import Enum
from pydantic import BaseModel, Field
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class PluginType(str, Enum):
    """Plugin type enumeration"""
    DISCOVERY = "discovery"
    VULNERABILITY = "vulnerability"
    CONFIGURATION = "configuration"
    COMPLIANCE = "compliance"
    PENTEST = "pentest"


class FindingSeverity(str, Enum):
    """Finding severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PluginFinding(BaseModel):
    """Standard finding format returned by plugins"""
    title: str = Field(..., description="Brief title of the finding")
    description: str = Field(..., description="Detailed description")
    severity: FindingSeverity = Field(..., description="Severity level")

    # Optional fields
    cve_ids: List[str] = Field(default_factory=list, description="List of CVE IDs")
    cwe_ids: List[str] = Field(default_factory=list, description="List of CWE IDs")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="CVSS score")

    affected_service: Optional[str] = Field(None, description="Affected service name")
    affected_port: Optional[int] = Field(None, description="Affected port number")

    evidence: Optional[str] = Field(None, description="Evidence/proof of finding")
    remediation: Optional[str] = Field(None, description="Remediation steps")
    remediation_priority: int = Field(default=0, description="Remediation priority (0-100)")

    # Additional metadata
    references: List[str] = Field(default_factory=list, description="External references")
    tags: List[str] = Field(default_factory=list, description="Tags for categorization")
    raw_data: Dict[str, Any] = Field(default_factory=dict, description="Raw scanner output")


class PluginAsset(BaseModel):
    """Asset discovered or updated by plugin"""
    ip_address: str = Field(..., description="IP address")
    hostname: Optional[str] = Field(None, description="Hostname")
    mac_address: Optional[str] = Field(None, description="MAC address")

    os_family: Optional[str] = Field(None, description="OS family (Linux, Windows, etc.)")
    os_version: Optional[str] = Field(None, description="OS version")
    vendor: Optional[str] = Field(None, description="Vendor (Cisco, Microsoft, etc.)")
    model: Optional[str] = Field(None, description="Device model")

    open_ports: List[int] = Field(default_factory=list, description="Open ports")
    services: Dict[str, Any] = Field(default_factory=dict, description="Services by port")

    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class PluginResult(BaseModel):
    """Result returned by plugin execution"""
    success: bool = Field(..., description="Whether execution was successful")

    # Findings and assets
    findings: List[PluginFinding] = Field(default_factory=list, description="Findings discovered")
    assets: List[PluginAsset] = Field(default_factory=list, description="Assets discovered/updated")

    # Execution metadata
    execution_time: float = Field(default=0.0, description="Execution time in seconds")
    error_message: Optional[str] = Field(None, description="Error message if failed")

    # Statistics
    stats: Dict[str, Any] = Field(default_factory=dict, description="Execution statistics")

    # Raw output (optional)
    raw_output: Optional[str] = Field(None, description="Raw output from scanner")


class PluginConfig(BaseModel):
    """Base configuration for plugins"""
    timeout: int = Field(default=1800, description="Execution timeout in seconds")
    verbose: bool = Field(default=False, description="Verbose logging")
    dry_run: bool = Field(default=False, description="Dry run mode (no actual scanning)")

    # Credential references (Vault paths)
    credential_path: Optional[str] = Field(None, description="Vault path to credentials")

    # Additional config
    extra: Dict[str, Any] = Field(default_factory=dict, description="Plugin-specific config")


class BasePlugin(ABC):
    """
    Abstract base class for all VulnScan plugins.

    All plugins must inherit from this class and implement the execute() method.

    Example:
        class MyPlugin(BasePlugin):
            name = "my-plugin"
            version = "1.0.0"
            description = "My custom plugin"

            def execute(self, target, config):
                # Your plugin logic here
                findings = []
                # ... scan logic ...
                return PluginResult(
                    success=True,
                    findings=findings
                )
    """

    # Plugin metadata (must be defined by subclass)
    name: str = "base-plugin"
    version: str = "0.0.0"
    description: str = "Base plugin class"
    author: str = "Unknown"

    plugin_type: PluginType = PluginType.DISCOVERY
    vendor: Optional[str] = None  # e.g., "cisco", "linux", "windows"

    requires_authentication: bool = False
    is_intrusive: bool = False
    is_safe: bool = True

    # Supported target types
    supported_asset_types: List[str] = []

    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize plugin.

        Args:
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger(f"plugin.{self.name}")
        self._validate_metadata()

    def _validate_metadata(self):
        """Validate plugin metadata"""
        if not self.name or self.name == "base-plugin":
            raise ValueError("Plugin must define a unique name")
        if not self.version or self.version == "0.0.0":
            raise ValueError("Plugin must define a version")

    @abstractmethod
    def execute(
        self,
        target: str,
        config: Optional[PluginConfig] = None,
        credentials: Optional[Dict[str, Any]] = None
    ) -> PluginResult:
        """
        Execute the plugin against a target.

        Args:
            target: Target to scan (IP, hostname, CIDR, etc.)
            config: Plugin configuration
            credentials: Credentials dictionary (retrieved from Vault)

        Returns:
            PluginResult with findings and assets

        Raises:
            Exception: If execution fails
        """
        pass

    def validate_target(self, target: str) -> bool:
        """
        Validate that target is in correct format.

        Args:
            target: Target string

        Returns:
            True if valid
        """
        # Basic validation - can be overridden
        return bool(target and len(target) > 0)

    def get_metadata(self) -> Dict[str, Any]:
        """
        Get plugin metadata.

        Returns:
            Dictionary with plugin metadata
        """
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "type": self.plugin_type.value,
            "vendor": self.vendor,
            "requires_authentication": self.requires_authentication,
            "is_intrusive": self.is_intrusive,
            "is_safe": self.is_safe,
            "supported_asset_types": self.supported_asset_types
        }

    def __repr__(self) -> str:
        return f"<Plugin: {self.name} v{self.version}>"
