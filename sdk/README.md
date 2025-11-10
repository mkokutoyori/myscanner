# VulnScan Plugin SDK

**Version:** 0.1.0

The VulnScan Plugin SDK provides a simple and powerful interface for developing custom security scanning plugins for the VulnScan Platform.

## Features

- **Simple API** - Write plugins in under 200 lines of Python
- **Standardized Findings** - Consistent finding format across all plugins
- **SSH Helper** - Built-in SSH client for remote system access
- **Type Safety** - Pydantic models for validation
- **Extensible** - Support for any vendor or asset type

## Quick Start

### 1. Install SDK

```bash
# Add SDK to Python path
export PYTHONPATH="${PYTHONPATH}:/path/to/vulnscan/sdk/python"

# Or install dependencies
pip install pydantic paramiko
```

### 2. Create Your First Plugin

```python
from vulnscan_sdk import (
    BasePlugin,
    PluginType,
    PluginResult,
    PluginFinding,
    FindingSeverity
)

class MyPlugin(BasePlugin):
    # Plugin metadata
    name = "my-plugin"
    version = "1.0.0"
    description = "My custom security plugin"
    author = "Your Name"

    plugin_type = PluginType.VULNERABILITY
    requires_authentication = False

    def execute(self, target, config=None, credentials=None):
        # Your scanning logic here
        findings = []

        # Example finding
        findings.append(PluginFinding(
            title="Example Vulnerability",
            description="This is an example finding",
            severity=FindingSeverity.MEDIUM,
            remediation="Fix the issue by doing X"
        ))

        return PluginResult(
            success=True,
            findings=findings
        )
```

### 3. Test Your Plugin

```python
if __name__ == "__main__":
    plugin = MyPlugin()
    result = plugin.execute("192.168.1.1")

    print(f"Found {len(result.findings)} issues")
    for finding in result.findings:
        print(f"  - [{finding.severity}] {finding.title}")
```

## SDK Reference

### BasePlugin

All plugins must inherit from `BasePlugin` and implement the `execute()` method.

#### Required Attributes

```python
class MyPlugin(BasePlugin):
    name = "my-plugin"          # Unique plugin identifier
    version = "1.0.0"            # Semantic version
    description = "..."          # Brief description
    author = "Your Name"         # Plugin author
```

#### Optional Attributes

```python
plugin_type = PluginType.DISCOVERY        # Plugin type
vendor = "cisco"                           # Vendor name (optional)
requires_authentication = False            # Requires credentials?
is_intrusive = False                       # Makes changes to target?
is_safe = True                             # Safe to run?
supported_asset_types = ["linux", "host"]  # Asset types
```

#### Execute Method

```python
def execute(
    self,
    target: str,                          # Target IP/hostname
    config: Optional[PluginConfig] = None, # Plugin configuration
    credentials: Optional[Dict] = None     # Credentials from Vault
) -> PluginResult:
    """
    Execute the plugin against a target.

    Returns:
        PluginResult with findings and assets
    """
    pass
```

### PluginResult

Return value of `execute()` method.

```python
PluginResult(
    success=True,                    # Execution succeeded?
    findings=[...],                  # List of PluginFinding objects
    assets=[...],                    # List of PluginAsset objects
    execution_time=10.5,             # Execution time in seconds
    error_message="...",             # Error message if failed
    stats={"checks": 10},            # Custom statistics
    raw_output="..."                 # Raw scanner output (optional)
)
```

### PluginFinding

Represents a security finding.

```python
PluginFinding(
    title="SSH Root Login Enabled",
    description="Detailed description of the issue",
    severity=FindingSeverity.HIGH,    # CRITICAL, HIGH, MEDIUM, LOW, INFO

    # Optional fields
    cve_ids=["CVE-2021-1234"],
    cwe_ids=["CWE-287"],
    cvss_score=7.5,

    affected_service="sshd",
    affected_port=22,

    evidence="PermitRootLogin yes",   # Proof of finding
    remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config",
    remediation_priority=80,           # 0-100

    references=["https://example.com/doc"],
    tags=["ssh", "authentication"],
    raw_data={"key": "value"}
)
```

### PluginAsset

Represents a discovered or updated asset.

```python
PluginAsset(
    ip_address="192.168.1.1",
    hostname="server01",
    mac_address="00:11:22:33:44:55",

    os_family="Linux",
    os_version="Ubuntu 22.04 LTS",
    vendor="Cisco",
    model="ISR 4331",

    open_ports=[22, 80, 443],
    services={
        "22": {"name": "ssh", "version": "OpenSSH 8.2"},
        "80": {"name": "http", "version": "nginx 1.18"}
    },

    metadata={"location": "datacenter-1"}
)
```

### PluginConfig

Configuration passed to plugins.

```python
PluginConfig(
    timeout=1800,                # Execution timeout (seconds)
    verbose=False,               # Verbose logging
    dry_run=False,               # Dry run mode
    credential_path="ssh/server1", # Vault path to credentials
    extra={"custom_option": "value"}
)
```

## SSH Helper

For plugins that need SSH access, use the `SSHHelper` class.

```python
from vulnscan_sdk.ssh_helper import SSHHelper

# In your plugin's execute() method
ssh = SSHHelper(self.logger)

try:
    # Connect
    ssh.connect(
        host=target,
        username=credentials['username'],
        password=credentials.get('password'),
        private_key=credentials.get('private_key')
    )

    # Execute command
    exit_code, stdout, stderr = ssh.execute_command("whoami")

    # Upload file
    ssh.upload_file("/local/file", "/remote/file")

    # Download file
    ssh.download_file("/remote/file", "/local/file")

finally:
    ssh.disconnect()
```

### Context Manager

```python
with SSHHelper() as ssh:
    ssh.connect(host=target, username="admin", password="pass")
    exit_code, output, errors = ssh.execute_command("uname -a")
    print(output)
# Automatically disconnects
```

## Examples

### Example 1: Simple Port Checker

```python
import socket
from vulnscan_sdk import *

class PortCheckerPlugin(BasePlugin):
    name = "port-checker"
    version = "1.0.0"
    description = "Check if common ports are open"

    def execute(self, target, config=None, credentials=None):
        findings = []
        common_ports = [21, 22, 23, 80, 443, 3389]

        for port in common_ports:
            if self._is_port_open(target, port):
                severity = FindingSeverity.INFO

                # Flag risky services
                if port in [21, 23]:  # FTP, Telnet
                    severity = FindingSeverity.HIGH

                findings.append(PluginFinding(
                    title=f"Port {port} Open",
                    description=f"Port {port} is accessible",
                    severity=severity,
                    affected_port=port
                ))

        return PluginResult(
            success=True,
            findings=findings
        )

    def _is_port_open(self, host, port, timeout=2):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
```

### Example 2: SSH Config Audit

```python
from vulnscan_sdk import *
from vulnscan_sdk.ssh_helper import SSHHelper

class SSHConfigPlugin(BasePlugin):
    name = "ssh-config-audit"
    version = "1.0.0"
    description = "Audit SSH server configuration"
    requires_authentication = True

    def execute(self, target, config=None, credentials=None):
        findings = []
        ssh = SSHHelper(self.logger)

        try:
            ssh.connect(
                host=target,
                username=credentials['username'],
                password=credentials.get('password')
            )

            # Check root login
            _, config_output, _ = ssh.execute_command(
                "grep '^PermitRootLogin' /etc/ssh/sshd_config"
            )

            if 'yes' in config_output.lower():
                findings.append(PluginFinding(
                    title="SSH Root Login Enabled",
                    description="SSH allows direct root login",
                    severity=FindingSeverity.HIGH,
                    affected_port=22,
                    evidence=config_output,
                    remediation="Set 'PermitRootLogin no'"
                ))

        finally:
            ssh.disconnect()

        return PluginResult(success=True, findings=findings)
```

## Plugin Types

```python
from vulnscan_sdk import PluginType

PluginType.DISCOVERY       # Network/asset discovery
PluginType.VULNERABILITY   # Vulnerability scanning
PluginType.CONFIGURATION   # Configuration auditing
PluginType.COMPLIANCE      # Compliance checking
PluginType.PENTEST         # Penetration testing
```

## Severity Levels

```python
from vulnscan_sdk import FindingSeverity

FindingSeverity.CRITICAL   # Immediate action required
FindingSeverity.HIGH       # Should be fixed soon
FindingSeverity.MEDIUM     # Should be addressed
FindingSeverity.LOW        # Minor issue
FindingSeverity.INFO       # Informational
```

## Plugin Deployment

### 1. File Structure

Place your plugin in:
```
backend/plugins/<vendor>/<plugin_name>_plugin.py
```

Example:
```
backend/plugins/linux/linux_plugin.py
backend/plugins/cisco/cisco_plugin.py
backend/plugins/windows/windows_plugin.py
```

### 2. Auto-Discovery

Plugins are automatically discovered on application startup if they:
- Are named `*_plugin.py`
- Inherit from `BasePlugin`
- Have valid `name` and `version` attributes

### 3. Database Registration

Plugins are automatically registered in the database when discovered.

## Testing Your Plugin

```bash
# Run plugin standalone
python backend/plugins/linux/linux_plugin.py

# Run with VulnScan API
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Scan",
    "scan_type": "vulnerability",
    "targets": ["192.168.1.1"],
    "plugin_name": "your-plugin-name"
  }'
```

## Best Practices

1. **Error Handling** - Always catch exceptions and return appropriate `PluginResult`
2. **Timeouts** - Respect the `config.timeout` parameter
3. **Logging** - Use `self.logger` for debugging
4. **Credentials** - Never log credentials, use Vault references
5. **Safe Mode** - Check `config.dry_run` before making changes
6. **Clean Up** - Always close connections and free resources

## Troubleshooting

### Plugin not discovered

- Check file is named `*_plugin.py`
- Verify it inherits from `BasePlugin`
- Check logs: `docker-compose logs api`

### Import errors

- Ensure SDK is in Python path
- Install required dependencies
- Check Python version (3.11+ required)

### SSH connection failed

- Verify credentials in Vault
- Check firewall rules
- Test SSH manually: `ssh user@host`

## Support

- **Documentation:** `/sdk/README.md` (this file)
- **Examples:** `/sdk/python/examples/`
- **Source:** `/sdk/python/vulnscan_sdk/`

## License

MIT License - See LICENSE file for details.
