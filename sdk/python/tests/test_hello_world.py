"""
Test Hello World Plugin

Basic tests for the Hello World example plugin.
"""
import sys
import os
import pytest

# Add SDK and examples to path
SDK_PATH = os.path.join(os.path.dirname(__file__), '..')
sys.path.insert(0, SDK_PATH)
sys.path.insert(0, os.path.join(SDK_PATH, 'examples'))

from examples.hello_world_plugin import HelloWorldPlugin
from vulnscan_sdk import FindingSeverity


class TestHelloWorldPlugin:
    """Test suite for Hello World plugin"""

    def test_plugin_metadata(self):
        """Test plugin has correct metadata"""
        plugin = HelloWorldPlugin()

        assert plugin.name == "hello-world"
        assert plugin.version == "1.0.0"
        assert plugin.description != ""
        assert plugin.author != ""

    def test_plugin_execute(self):
        """Test plugin execution"""
        plugin = HelloWorldPlugin()
        result = plugin.execute("192.0.2.1")

        assert result.success is True
        assert len(result.findings) > 0
        assert result.execution_time > 0

    def test_finding_format(self):
        """Test finding has correct format"""
        plugin = HelloWorldPlugin()
        result = plugin.execute("192.0.2.1")

        finding = result.findings[0]
        assert finding.title != ""
        assert finding.description != ""
        assert finding.severity == FindingSeverity.INFO

    def test_asset_format(self):
        """Test asset has correct format"""
        plugin = HelloWorldPlugin()
        result = plugin.execute("192.0.2.1")

        assert len(result.assets) > 0
        asset = result.assets[0]
        assert asset.ip_address == "192.0.2.1"

    def test_hostname_target(self):
        """Test with hostname instead of IP"""
        plugin = HelloWorldPlugin()
        result = plugin.execute("example.com")

        assert result.success is True
        assert len(result.assets) > 0

    def test_get_metadata(self):
        """Test get_metadata method"""
        plugin = HelloWorldPlugin()
        metadata = plugin.get_metadata()

        assert "name" in metadata
        assert "version" in metadata
        assert "type" in metadata
        assert metadata["name"] == "hello-world"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
