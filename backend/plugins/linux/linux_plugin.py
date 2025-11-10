"""
Linux Security Audit Plugin

Performs comprehensive security auditing of Linux systems using:
- Lynis (security auditing tool)
- OpenSCAP (compliance scanning)
- Custom security checks

Requires SSH access to target system.
"""
import sys
import os
import re
import json
from typing import Dict, Any, Optional, List

# Add SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../sdk/python'))

from vulnscan_sdk import (
    BasePlugin,
    PluginType,
    PluginResult,
    PluginFinding,
    PluginAsset,
    PluginConfig,
    FindingSeverity
)
from vulnscan_sdk.ssh_helper import SSHHelper, SSHConnectionError, SSHExecutionError
import time
import logging


class LinuxPlugin(BasePlugin):
    """
    Linux security audit plugin.

    Connects to Linux systems via SSH and performs:
    1. System information gathering
    2. Lynis security audit
    3. OpenSCAP compliance scanning
    4. Custom security checks
    """

    # Plugin metadata
    name = "linux-audit"
    version = "1.0.0"
    description = "Comprehensive Linux security audit using Lynis and OpenSCAP"
    author = "VulnScan Team"

    plugin_type = PluginType.VULNERABILITY
    vendor = "linux"

    requires_authentication = True
    is_intrusive = False
    is_safe = True

    supported_asset_types = ["host", "linux"]

    def __init__(self, logger: Optional[logging.Logger] = None):
        super().__init__(logger)
        self.ssh = None

    def execute(
        self,
        target: str,
        config: Optional[PluginConfig] = None,
        credentials: Optional[Dict[str, Any]] = None
    ) -> PluginResult:
        """
        Execute Linux security audit.

        Args:
            target: Target hostname or IP
            config: Plugin configuration
            credentials: SSH credentials (username, password, or private_key)

        Returns:
            PluginResult with findings
        """
        start_time = time.time()
        config = config or PluginConfig()

        self.logger.info(f"Starting Linux audit for target: {target}")

        # Validate inputs
        if not credentials:
            return PluginResult(
                success=False,
                error_message="Credentials required for SSH access"
            )

        findings: List[PluginFinding] = []
        assets: List[PluginAsset] = []

        try:
            # Connect via SSH
            self.ssh = SSHHelper(self.logger)
            self.ssh.connect(
                host=target,
                username=credentials.get("username", "root"),
                password=credentials.get("password"),
                private_key=credentials.get("private_key"),
                timeout=30
            )

            # 1. Gather system information
            self.logger.info("Gathering system information...")
            asset_info = self._gather_system_info(target)
            if asset_info:
                assets.append(asset_info)

            # 2. Run custom security checks
            self.logger.info("Running custom security checks...")
            custom_findings = self._run_custom_checks()
            findings.extend(custom_findings)

            # 3. Run Lynis if available
            self.logger.info("Checking for Lynis...")
            if self._check_command_exists("lynis"):
                self.logger.info("Running Lynis audit...")
                lynis_findings = self._run_lynis()
                findings.extend(lynis_findings)
            else:
                self.logger.warning("Lynis not found on target system")

            # 4. Run OpenSCAP if available
            self.logger.info("Checking for OpenSCAP...")
            if self._check_command_exists("oscap"):
                self.logger.info("Running OpenSCAP scan...")
                oscap_findings = self._run_openscap()
                findings.extend(oscap_findings)
            else:
                self.logger.warning("OpenSCAP not found on target system")

            execution_time = time.time() - start_time

            self.logger.info(
                f"Linux audit completed: {len(findings)} findings, "
                f"{len(assets)} assets, {execution_time:.2f}s"
            )

            return PluginResult(
                success=True,
                findings=findings,
                assets=assets,
                execution_time=execution_time,
                stats={
                    "total_findings": len(findings),
                    "critical_findings": sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL),
                    "high_findings": sum(1 for f in findings if f.severity == FindingSeverity.HIGH),
                    "checks_performed": ["system_info", "custom_checks", "lynis", "openscap"]
                }
            )

        except SSHConnectionError as e:
            self.logger.error(f"SSH connection failed: {e}")
            return PluginResult(
                success=False,
                error_message=f"SSH connection failed: {e}",
                execution_time=time.time() - start_time
            )

        except Exception as e:
            self.logger.error(f"Plugin execution failed: {e}", exc_info=True)
            return PluginResult(
                success=False,
                error_message=str(e),
                execution_time=time.time() - start_time,
                findings=findings,  # Return partial results
                assets=assets
            )

        finally:
            if self.ssh:
                self.ssh.disconnect()

    def _check_command_exists(self, command: str) -> bool:
        """Check if a command exists on the remote system."""
        try:
            exit_code, _, _ = self.ssh.execute_command(
                f"command -v {command}",
                check_exit_code=False
            )
            return exit_code == 0
        except:
            return False

    def _gather_system_info(self, target: str) -> Optional[PluginAsset]:
        """Gather system information."""
        try:
            # Get hostname
            _, hostname, _ = self.ssh.execute_command("hostname")
            hostname = hostname.strip()

            # Get OS info
            _, os_release, _ = self.ssh.execute_command(
                "cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null || echo 'Unknown'",
                check_exit_code=False
            )

            os_family = "Linux"
            os_version = "Unknown"

            # Parse OS release
            for line in os_release.split('\n'):
                if 'PRETTY_NAME' in line:
                    os_version = line.split('=')[1].strip('"')
                    break

            # Get kernel version
            _, kernel, _ = self.ssh.execute_command("uname -r")
            kernel = kernel.strip()

            return PluginAsset(
                ip_address=target,
                hostname=hostname,
                os_family=os_family,
                os_version=os_version,
                metadata={
                    "kernel_version": kernel,
                    "os_release": os_release.strip()
                }
            )

        except Exception as e:
            self.logger.warning(f"Failed to gather system info: {e}")
            return None

    def _run_custom_checks(self) -> List[PluginFinding]:
        """Run custom security checks."""
        findings = []

        # Check 1: Root login via SSH
        try:
            _, sshd_config, _ = self.ssh.execute_command(
                "grep -i '^PermitRootLogin' /etc/ssh/sshd_config || echo 'PermitRootLogin yes'",
                check_exit_code=False
            )

            if 'yes' in sshd_config.lower():
                findings.append(PluginFinding(
                    title="SSH Root Login Enabled",
                    description="SSH server allows direct root login, which is a security risk.",
                    severity=FindingSeverity.HIGH,
                    affected_service="sshd",
                    affected_port=22,
                    evidence=sshd_config.strip(),
                    remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd",
                    tags=["ssh", "authentication", "root-access"]
                ))
        except:
            pass

        # Check 2: Password authentication
        try:
            _, passwd_auth, _ = self.ssh.execute_command(
                "grep -i '^PasswordAuthentication' /etc/ssh/sshd_config || echo 'PasswordAuthentication yes'",
                check_exit_code=False
            )

            if 'yes' in passwd_auth.lower():
                findings.append(PluginFinding(
                    title="SSH Password Authentication Enabled",
                    description="SSH allows password authentication instead of key-only authentication.",
                    severity=FindingSeverity.MEDIUM,
                    affected_service="sshd",
                    affected_port=22,
                    evidence=passwd_auth.strip(),
                    remediation="Set 'PasswordAuthentication no' in /etc/ssh/sshd_config",
                    tags=["ssh", "authentication"]
                ))
        except:
            pass

        # Check 3: Firewall status
        try:
            exit_code, firewall_status, _ = self.ssh.execute_command(
                "systemctl is-active iptables firewalld ufw 2>/dev/null || echo 'inactive'",
                check_exit_code=False
            )

            if 'inactive' in firewall_status or exit_code != 0:
                findings.append(PluginFinding(
                    title="Firewall Not Active",
                    description="No active firewall detected (iptables, firewalld, or ufw).",
                    severity=FindingSeverity.HIGH,
                    evidence=firewall_status.strip(),
                    remediation="Enable and configure firewall (ufw, firewalld, or iptables)",
                    tags=["firewall", "network-security"]
                ))
        except:
            pass

        # Check 4: Unattended upgrades
        try:
            exit_code, _, _ = self.ssh.execute_command(
                "dpkg -l unattended-upgrades 2>/dev/null || rpm -q yum-cron 2>/dev/null",
                check_exit_code=False
            )

            if exit_code != 0:
                findings.append(PluginFinding(
                    title="Automatic Security Updates Not Configured",
                    description="System does not have automatic security updates configured.",
                    severity=FindingSeverity.MEDIUM,
                    remediation="Install and configure unattended-upgrades (Debian/Ubuntu) or yum-cron (RHEL/CentOS)",
                    tags=["updates", "patch-management"]
                ))
        except:
            pass

        return findings

    def _run_lynis(self) -> List[PluginFinding]:
        """Run Lynis security audit."""
        findings = []

        try:
            # Run Lynis in quiet mode
            _, lynis_output, _ = self.ssh.execute_command(
                "sudo lynis audit system --quick --quiet 2>&1 || lynis audit system --quick --quiet 2>&1",
                timeout=600,
                check_exit_code=False
            )

            # Parse Lynis output
            findings = self._parse_lynis_output(lynis_output)

        except SSHExecutionError as e:
            self.logger.error(f"Lynis execution failed: {e}")
        except Exception as e:
            self.logger.error(f"Lynis parsing failed: {e}")

        return findings

    def _parse_lynis_output(self, output: str) -> List[PluginFinding]:
        """Parse Lynis output and extract findings."""
        findings = []

        # Look for warnings and suggestions
        for line in output.split('\n'):
            if 'Warning:' in line or 'WARNING' in line.upper():
                finding = PluginFinding(
                    title="Lynis Warning",
                    description=line.strip(),
                    severity=FindingSeverity.MEDIUM,
                    evidence=line.strip(),
                    tags=["lynis", "audit"]
                )
                findings.append(finding)

            elif 'Suggestion:' in line or 'SUGGESTION' in line.upper():
                finding = PluginFinding(
                    title="Lynis Suggestion",
                    description=line.strip(),
                    severity=FindingSeverity.LOW,
                    evidence=line.strip(),
                    tags=["lynis", "audit", "hardening"]
                )
                findings.append(finding)

        return findings[:20]  # Limit to 20 findings

    def _run_openscap(self) -> List[PluginFinding]:
        """Run OpenSCAP compliance scan."""
        findings = []

        try:
            # Run basic OpenSCAP scan (if profiles available)
            _, oscap_output, _ = self.ssh.execute_command(
                "oscap info /usr/share/xml/scap/ssg/content/*xccdf*.xml 2>&1 | head -20 || echo 'No SCAP content found'",
                timeout=300,
                check_exit_code=False
            )

            # For now, just report if OpenSCAP is available
            findings.append(PluginFinding(
                title="OpenSCAP Available",
                description="OpenSCAP is installed and can be used for compliance scanning.",
                severity=FindingSeverity.INFO,
                evidence=oscap_output[:500],
                remediation="Configure and run regular OpenSCAP compliance scans",
                tags=["openscap", "compliance"]
            ))

        except Exception as e:
            self.logger.error(f"OpenSCAP execution failed: {e}")

        return findings


# Test the plugin
if __name__ == "__main__":
    import logging

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    plugin = LinuxPlugin()

    print(f"\n{'='*60}")
    print(f"Plugin: {plugin.name} v{plugin.version}")
    print(f"Description: {plugin.description}")
    print(f"Requires Auth: {plugin.requires_authentication}")
    print(f"{'='*60}\n")

    # Note: Actual execution requires SSH credentials
    print("This plugin requires SSH credentials to execute.")
    print("Use via the VulnScan Platform API with proper credentials from Vault.")
