"""
Hello World Plugin Example

This is a simple example plugin that demonstrates the VulnScan SDK.
It performs a basic "scan" and returns a demo finding.
"""
import sys
import os

# Add SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from vulnscan_sdk import (
    BasePlugin,
    PluginType,
    PluginResult,
    PluginFinding,
    PluginAsset,
    PluginConfig,
    FindingSeverity
)
from typing import Dict, Any, Optional
import time


class HelloWorldPlugin(BasePlugin):
    """
    A simple Hello World plugin for demonstration purposes.

    This plugin doesn't perform real scanning - it just demonstrates
    the plugin structure and how to return findings and assets.
    """

    # Plugin metadata
    name = "hello-world"
    version = "1.0.0"
    description = "Simple Hello World demonstration plugin"
    author = "VulnScan Team"

    plugin_type = PluginType.DISCOVERY
    vendor = None

    requires_authentication = False
    is_intrusive = False
    is_safe = True

    supported_asset_types = ["host", "unknown"]

    def execute(
        self,
        target: str,
        config: Optional[PluginConfig] = None,
        credentials: Optional[Dict[str, Any]] = None
    ) -> PluginResult:
        """
        Execute the Hello World "scan".

        This just returns a demo finding and asset to demonstrate the format.
        """
        start_time = time.time()

        self.logger.info(f"Hello World plugin executing against target: {target}")

        # Validate target
        if not self.validate_target(target):
            return PluginResult(
                success=False,
                error_message="Invalid target format"
            )

        # Create a demo finding
        findings = [
            PluginFinding(
                title="Hello World Finding",
                description=f"This is a demonstration finding from the Hello World plugin. Target: {target}",
                severity=FindingSeverity.INFO,
                evidence=f"Plugin successfully executed against {target}",
                remediation="This is just a demo - no remediation needed!",
                tags=["demo", "hello-world"],
                raw_data={"target": target, "timestamp": time.time()}
            )
        ]

        # Create a demo asset
        assets = [
            PluginAsset(
                ip_address=target if self._is_ip(target) else "192.0.2.1",
                hostname=target if not self._is_ip(target) else None,
                os_family="Unknown",
                metadata={
                    "scanned_by": "hello-world-plugin",
                    "demo": True
                }
            )
        ]

        execution_time = time.time() - start_time

        self.logger.info(f"Hello World plugin completed in {execution_time:.2f}s")

        return PluginResult(
            success=True,
            findings=findings,
            assets=assets,
            execution_time=execution_time,
            stats={
                "targets_scanned": 1,
                "findings_discovered": len(findings),
                "assets_discovered": len(assets)
            }
        )

    def _is_ip(self, target: str) -> bool:
        """Simple check if target looks like an IP address"""
        parts = target.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False


# Demo usage
if __name__ == "__main__":
    import logging

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Create plugin instance
    plugin = HelloWorldPlugin()

    print(f"\n{'='*60}")
    print(f"Plugin: {plugin.name} v{plugin.version}")
    print(f"Description: {plugin.description}")
    print(f"Author: {plugin.author}")
    print(f"{'='*60}\n")

    # Execute against a target
    target = "192.0.2.1"
    print(f"Executing plugin against target: {target}\n")

    config = PluginConfig(verbose=True)
    result = plugin.execute(target, config)

    # Display results
    print(f"\n{'='*60}")
    print(f"Execution Result:")
    print(f"{'='*60}")
    print(f"Success: {result.success}")
    print(f"Execution Time: {result.execution_time:.2f}s")
    print(f"Findings: {len(result.findings)}")
    print(f"Assets: {len(result.assets)}")

    if result.findings:
        print(f"\nFindings:")
        for i, finding in enumerate(result.findings, 1):
            print(f"  {i}. [{finding.severity.value.upper()}] {finding.title}")
            print(f"     {finding.description}")

    if result.assets:
        print(f"\nAssets:")
        for i, asset in enumerate(result.assets, 1):
            print(f"  {i}. {asset.ip_address} ({asset.hostname or 'no hostname'})")

    print(f"\n{'='*60}\n")
