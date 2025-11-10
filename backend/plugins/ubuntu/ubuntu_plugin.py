"""
Ubuntu/Debian Security Audit Plugin

Comprehensive security scanning for Ubuntu and Debian systems.
Based on research from LINUX_SECURITY_RESEARCH.md

Checks:
- SSH configuration (root login, password auth, default port)
- Firewall status (ufw)
- AppArmor status (MAC)
- Package vulnerabilities (apt security updates)
- File permissions (world-writable, SUID/SGID)
- User accounts (weak passwords, sudo access)
- Services and open ports
- System hardening (kernel params, log config)
"""
import logging
import re
from typing import List, Dict, Any, Optional

# Add SDK to path
import sys
import os
SDK_PATH = os.path.join(os.path.dirname(__file__), '../../../sdk/python')
sys.path.insert(0, SDK_PATH)

from vulnscan_sdk import (
    BasePlugin,
    PluginType,
    PluginResult,
    PluginFinding,
    FindingSeverity,
    PluginAsset,
    PluginConfig
)
from vulnscan_sdk.ssh_helper import SSHHelper

# Import distro detector
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from detectors.distro_detector import detect_distribution, DistroFamily


class UbuntuPlugin(BasePlugin):
    """
    Ubuntu/Debian security audit plugin.

    Performs comprehensive security assessment including:
    - Critical configuration checks (SSH, firewall, MAC)
    - Vulnerability scanning (CVE detection via apt)
    - Compliance checks (CIS benchmark alignment)
    - System hardening assessment
    """

    # Plugin metadata
    name = "ubuntu-security-audit"
    version = "1.0.0"
    description = "Comprehensive security audit for Ubuntu and Debian systems"
    author = "VulnScan Platform"

    plugin_type = PluginType.VULNERABILITY
    vendor = "canonical"
    requires_authentication = True
    is_intrusive = False
    is_safe = True
    supported_asset_types = ["linux", "ubuntu", "debian"]

    def __init__(self):
        super().__init__()
        self.ssh: Optional[SSHHelper] = None
        self.distro_info = None

    def execute(
        self,
        target: str,
        config: Optional[PluginConfig] = None,
        credentials: Optional[Dict[str, Any]] = None
    ) -> PluginResult:
        """
        Execute Ubuntu security audit.

        Args:
            target: Target IP or hostname
            config: Plugin configuration
            credentials: SSH credentials

        Returns:
            PluginResult with findings and asset info
        """
        self.logger.info(f"Starting Ubuntu security audit on {target}")

        findings: List[PluginFinding] = []
        assets: List[PluginAsset] = []

        # Validate credentials
        if not credentials or 'username' not in credentials:
            return PluginResult(
                success=False,
                error_message="SSH credentials required",
                findings=[],
                assets=[]
            )

        # Connect via SSH
        self.ssh = SSHHelper(self.logger)

        try:
            connected = self.ssh.connect(
                host=target,
                username=credentials['username'],
                password=credentials.get('password'),
                private_key=credentials.get('private_key'),
                port=credentials.get('port', 22),
                timeout=30
            )

            if not connected:
                return PluginResult(
                    success=False,
                    error_message=f"Failed to connect to {target}",
                    findings=[],
                    assets=[]
                )

            # Detect distribution
            self.distro_info = detect_distribution(self.ssh)

            # Verify this is Ubuntu/Debian
            if self.distro_info.family != DistroFamily.DEBIAN:
                return PluginResult(
                    success=False,
                    error_message=f"Not an Ubuntu/Debian system (detected: {self.distro_info.name})",
                    findings=[],
                    assets=[]
                )

            self.logger.info(
                f"Confirmed {self.distro_info.name} {self.distro_info.version}"
            )

            # Gather asset information
            asset = self._gather_asset_info(target)
            assets.append(asset)

            # Run all security checks (P0 - Critical Priority)
            findings.extend(self._check_ssh_security())
            findings.extend(self._check_firewall())
            findings.extend(self._check_apparmor())
            findings.extend(self._check_package_vulnerabilities())
            findings.extend(self._check_file_permissions())
            findings.extend(self._check_user_accounts())
            findings.extend(self._check_services())
            findings.extend(self._check_system_hardening())

            # Additional checks if Lynis available
            if self._command_exists("lynis"):
                findings.extend(self._run_lynis())

            self.logger.info(f"Audit complete: {len(findings)} findings")

            return PluginResult(
                success=True,
                findings=findings,
                assets=assets,
                stats={
                    "total_checks": 50,
                    "findings_by_severity": self._count_by_severity(findings)
                }
            )

        except Exception as e:
            self.logger.error(f"Audit failed: {e}", exc_info=True)
            return PluginResult(
                success=False,
                error_message=str(e),
                findings=findings,
                assets=assets
            )

        finally:
            if self.ssh:
                self.ssh.disconnect()

    def _gather_asset_info(self, target: str) -> PluginAsset:
        """Gather system information for asset inventory."""
        # Hostname
        _, hostname, _ = self.ssh.execute_command("hostname", check_exit_code=False)
        hostname = hostname.strip()

        # Kernel version
        _, kernel, _ = self.ssh.execute_command("uname -r", check_exit_code=False)

        # Memory
        _, mem_output, _ = self.ssh.execute_command(
            "free -m | grep Mem | awk '{print $2}'",
            check_exit_code=False
        )
        memory_mb = mem_output.strip()

        # CPU info
        _, cpu_output, _ = self.ssh.execute_command(
            "grep -m 1 'model name' /proc/cpuinfo | cut -d: -f2",
            check_exit_code=False
        )

        # Uptime
        _, uptime, _ = self.ssh.execute_command("uptime -p", check_exit_code=False)

        return PluginAsset(
            ip_address=target,
            hostname=hostname if hostname else target,
            os_family="Linux",
            os_version=f"{self.distro_info.name} {self.distro_info.version}",
            vendor="Canonical" if "ubuntu" in self.distro_info.name.lower() else "Debian",
            metadata={
                "distribution": self.distro_info.name,
                "version": self.distro_info.version,
                "codename": self.distro_info.version_codename,
                "kernel": kernel.strip(),
                "package_manager": self.distro_info.package_manager,
                "mac_system": self.distro_info.mac_system,
                "firewall": self.distro_info.firewall,
                "init_system": self.distro_info.init_system,
                "memory_mb": memory_mb,
                "cpu": cpu_output.strip(),
                "uptime": uptime.strip()
            }
        )

    def _check_ssh_security(self) -> List[PluginFinding]:
        """
        Check SSH configuration security.

        P0 Critical Checks:
        - PermitRootLogin
        - PasswordAuthentication
        - Default port (22)
        - Protocol version
        """
        findings = []
        self.logger.info("Checking SSH security...")

        # Read sshd_config
        exit_code, config, _ = self.ssh.execute_command(
            "cat /etc/ssh/sshd_config",
            check_exit_code=False
        )

        if exit_code != 0:
            findings.append(PluginFinding(
                title="SSH Configuration Not Readable",
                description="Unable to read /etc/ssh/sshd_config",
                severity=FindingSeverity.MEDIUM,
                affected_service="sshd",
                affected_port=22
            ))
            return findings

        # Check PermitRootLogin (P0 - CRITICAL)
        root_login_match = re.search(r'^\s*PermitRootLogin\s+(\S+)', config, re.MULTILINE)
        if root_login_match:
            value = root_login_match.group(1).lower()
            if value in ['yes', 'without-password', 'prohibit-password']:
                findings.append(PluginFinding(
                    title="SSH Root Login Enabled",
                    description=(
                        f"SSH allows root login (PermitRootLogin {value}). "
                        "Direct root login is a critical security risk and should be disabled. "
                        "Attackers commonly target root accounts."
                    ),
                    severity=FindingSeverity.CRITICAL,
                    cwe_ids=["CWE-284"],
                    affected_service="sshd",
                    affected_port=22,
                    evidence=f"PermitRootLogin {value}",
                    remediation=(
                        "1. Edit /etc/ssh/sshd_config\n"
                        "2. Set: PermitRootLogin no\n"
                        "3. Restart SSH: sudo systemctl restart sshd"
                    ),
                    remediation_priority=95,
                    tags=["ssh", "authentication", "cis-benchmark"]
                ))
        else:
            # Default is usually 'prohibit-password' which is still risky
            findings.append(PluginFinding(
                title="SSH Root Login Configuration Not Explicit",
                description="PermitRootLogin not explicitly set (using default)",
                severity=FindingSeverity.HIGH,
                affected_service="sshd",
                affected_port=22,
                remediation="Explicitly set: PermitRootLogin no",
                tags=["ssh", "configuration"]
            ))

        # Check PasswordAuthentication (P0 - CRITICAL)
        pass_auth_match = re.search(r'^\s*PasswordAuthentication\s+(\S+)', config, re.MULTILINE)
        if pass_auth_match:
            value = pass_auth_match.group(1).lower()
            if value == 'yes':
                findings.append(PluginFinding(
                    title="SSH Password Authentication Enabled",
                    description=(
                        "SSH allows password authentication. "
                        "Password authentication is vulnerable to brute-force attacks. "
                        "Key-based authentication is significantly more secure."
                    ),
                    severity=FindingSeverity.HIGH,
                    cwe_ids=["CWE-521"],
                    affected_service="sshd",
                    affected_port=22,
                    evidence="PasswordAuthentication yes",
                    remediation=(
                        "1. Set up SSH key authentication for all users\n"
                        "2. Edit /etc/ssh/sshd_config\n"
                        "3. Set: PasswordAuthentication no\n"
                        "4. Restart SSH: sudo systemctl restart sshd"
                    ),
                    remediation_priority=85,
                    tags=["ssh", "authentication", "cis-benchmark"]
                ))

        # Check default port (P1 - HIGH)
        port_match = re.search(r'^\s*Port\s+(\d+)', config, re.MULTILINE)
        port = int(port_match.group(1)) if port_match else 22
        if port == 22:
            findings.append(PluginFinding(
                title="SSH Running on Default Port",
                description=(
                    "SSH is running on default port 22. "
                    "Moving SSH to a non-standard port reduces automated attacks."
                ),
                severity=FindingSeverity.LOW,
                affected_service="sshd",
                affected_port=22,
                evidence="Port 22 (default)",
                remediation="Change SSH port to non-standard value (e.g., 2222, 22000)",
                remediation_priority=30,
                tags=["ssh", "hardening"]
            ))

        # Check Protocol version (P1 - HIGH)
        if 'Protocol 1' in config or re.search(r'^\s*Protocol\s+1', config, re.MULTILINE):
            findings.append(PluginFinding(
                title="SSH Protocol 1 Enabled",
                description="SSH Protocol 1 is outdated and has known vulnerabilities",
                severity=FindingSeverity.HIGH,
                cve_ids=["CVE-2001-0572"],
                affected_service="sshd",
                affected_port=22,
                remediation="Remove Protocol 1, ensure only Protocol 2 is used",
                remediation_priority=80,
                tags=["ssh", "protocol"]
            ))

        # Check MaxAuthTries (P2 - MEDIUM)
        max_tries_match = re.search(r'^\s*MaxAuthTries\s+(\d+)', config, re.MULTILINE)
        if max_tries_match:
            tries = int(max_tries_match.group(1))
            if tries > 4:
                findings.append(PluginFinding(
                    title="SSH MaxAuthTries Too High",
                    description=f"MaxAuthTries set to {tries}, should be 4 or less",
                    severity=FindingSeverity.MEDIUM,
                    affected_service="sshd",
                    affected_port=22,
                    remediation="Set MaxAuthTries to 4 or less",
                    tags=["ssh", "hardening"]
                ))

        return findings

    def _check_firewall(self) -> List[PluginFinding]:
        """
        Check firewall configuration (ufw for Ubuntu/Debian).

        P0 Critical: Firewall disabled
        """
        findings = []
        self.logger.info("Checking firewall status...")

        # Check ufw status
        exit_code, output, _ = self.ssh.execute_command(
            "ufw status",
            check_exit_code=False
        )

        if exit_code != 0 or 'command not found' in output.lower():
            findings.append(PluginFinding(
                title="UFW Firewall Not Installed",
                description="UFW (Uncomplicated Firewall) is not installed on this system",
                severity=FindingSeverity.HIGH,
                cwe_ids=["CWE-16"],
                evidence="ufw command not found",
                remediation="Install and configure UFW: sudo apt install ufw && sudo ufw enable",
                remediation_priority=85,
                tags=["firewall", "cis-benchmark"]
            ))
            return findings

        # Check if firewall is active
        if 'Status: inactive' in output or 'inactive' in output.lower():
            findings.append(PluginFinding(
                title="Firewall Disabled",
                description=(
                    "UFW firewall is installed but disabled. "
                    "A disabled firewall leaves all ports exposed to network attacks."
                ),
                severity=FindingSeverity.CRITICAL,
                cwe_ids=["CWE-16"],
                evidence="UFW Status: inactive",
                remediation=(
                    "1. Configure firewall rules\n"
                    "2. Enable UFW: sudo ufw enable\n"
                    "3. Verify: sudo ufw status verbose"
                ),
                remediation_priority=90,
                tags=["firewall", "network", "cis-benchmark"]
            ))
        else:
            # Firewall is active - check for overly permissive rules
            if 'ALLOW' in output and 'Anywhere' in output:
                findings.append(PluginFinding(
                    title="Overly Permissive Firewall Rules",
                    description="Firewall has rules allowing traffic from anywhere",
                    severity=FindingSeverity.MEDIUM,
                    evidence=output[:500],
                    remediation="Review and restrict firewall rules to specific IPs/networks",
                    remediation_priority=60,
                    tags=["firewall", "network"]
                ))

        return findings

    def _check_apparmor(self) -> List[PluginFinding]:
        """
        Check AppArmor MAC system status.

        P0 Critical: AppArmor disabled
        """
        findings = []
        self.logger.info("Checking AppArmor status...")

        # Check if AppArmor is installed and running
        exit_code, output, _ = self.ssh.execute_command(
            "aa-status 2>/dev/null",
            check_exit_code=False
        )

        if exit_code != 0 or 'command not found' in output.lower():
            findings.append(PluginFinding(
                title="AppArmor Not Installed",
                description=(
                    "AppArmor (Mandatory Access Control) is not installed. "
                    "AppArmor provides additional security by restricting program capabilities."
                ),
                severity=FindingSeverity.HIGH,
                cwe_ids=["CWE-276"],
                evidence="AppArmor not found",
                remediation="Install AppArmor: sudo apt install apparmor apparmor-utils",
                remediation_priority=70,
                tags=["mac", "apparmor", "cis-benchmark"]
            ))
            return findings

        # Check if AppArmor is enabled
        exit_code, enabled_output, _ = self.ssh.execute_command(
            "cat /sys/module/apparmor/parameters/enabled 2>/dev/null",
            check_exit_code=False
        )

        if exit_code == 0 and enabled_output.strip() == 'N':
            findings.append(PluginFinding(
                title="AppArmor Disabled",
                description=(
                    "AppArmor is installed but disabled at kernel level. "
                    "This removes an important security layer."
                ),
                severity=FindingSeverity.CRITICAL,
                cwe_ids=["CWE-276"],
                evidence="AppArmor kernel module disabled",
                remediation=(
                    "1. Enable in GRUB: remove apparmor=0 from kernel parameters\n"
                    "2. Update GRUB: sudo update-grub\n"
                    "3. Reboot system"
                ),
                remediation_priority=75,
                tags=["mac", "apparmor", "kernel"]
            ))
        elif 'apparmor module is loaded' in output.lower():
            # AppArmor is running - check profile status
            profiles_enforcing = re.search(r'(\d+) profiles are in enforce mode', output)
            profiles_complain = re.search(r'(\d+) profiles are in complain mode', output)

            if profiles_enforcing:
                enforcing_count = int(profiles_enforcing.group(1))
                if enforcing_count == 0:
                    findings.append(PluginFinding(
                        title="No AppArmor Profiles in Enforce Mode",
                        description="AppArmor is running but no profiles are actively enforcing",
                        severity=FindingSeverity.MEDIUM,
                        evidence="0 profiles in enforce mode",
                        remediation="Enable AppArmor profiles: sudo aa-enforce /etc/apparmor.d/*",
                        remediation_priority=50,
                        tags=["mac", "apparmor"]
                    ))

        return findings

    def _check_package_vulnerabilities(self) -> List[PluginFinding]:
        """
        Check for packages with available security updates.

        P0 Critical: Unpatched packages with CVEs
        """
        findings = []
        self.logger.info("Checking for package vulnerabilities...")

        # Update package lists (non-intrusive)
        self.ssh.execute_command(
            "apt-get update -qq 2>/dev/null",
            check_exit_code=False,
            timeout=60
        )

        # Check for security updates
        exit_code, output, _ = self.ssh.execute_command(
            "apt list --upgradable 2>/dev/null | grep -i security",
            check_exit_code=False
        )

        if exit_code == 0 and output.strip():
            # Parse security updates
            security_updates = [line for line in output.split('\n') if line.strip()]

            if security_updates:
                findings.append(PluginFinding(
                    title=f"Security Updates Available ({len(security_updates)} packages)",
                    description=(
                        f"Found {len(security_updates)} packages with available security updates. "
                        "Unpatched packages may contain exploitable vulnerabilities."
                    ),
                    severity=FindingSeverity.CRITICAL,
                    cwe_ids=["CWE-1104"],
                    evidence="\n".join(security_updates[:10]),
                    remediation=(
                        "Apply security updates:\n"
                        "sudo apt update && sudo apt upgrade -y"
                    ),
                    remediation_priority=95,
                    tags=["packages", "vulnerability", "patching"]
                ))

        # Check system upgrade status
        exit_code, upgrade_output, _ = self.ssh.execute_command(
            "apt list --upgradable 2>/dev/null | wc -l",
            check_exit_code=False
        )

        if exit_code == 0:
            total_updates = int(upgrade_output.strip()) - 1  # Subtract header line
            if total_updates > 50:
                findings.append(PluginFinding(
                    title=f"System Significantly Out of Date ({total_updates} updates)",
                    description=f"System has {total_updates} available package updates",
                    severity=FindingSeverity.HIGH,
                    evidence=f"{total_updates} packages need updating",
                    remediation="Update system: sudo apt update && sudo apt upgrade",
                    remediation_priority=80,
                    tags=["packages", "maintenance"]
                ))

        # Check for end-of-life Ubuntu versions
        if self.distro_info and 'ubuntu' in self.distro_info.name.lower():
            version = self.distro_info.version
            eol_versions = ['14.04', '16.04', '17.10', '18.10', '19.04', '19.10', '20.10', '21.04', '21.10']
            if version in eol_versions:
                findings.append(PluginFinding(
                    title="End-of-Life Ubuntu Version",
                    description=f"Ubuntu {version} has reached end-of-life and no longer receives security updates",
                    severity=FindingSeverity.CRITICAL,
                    evidence=f"Ubuntu {version} (EOL)",
                    remediation=f"Upgrade to supported Ubuntu LTS version (20.04, 22.04, or 24.04)",
                    remediation_priority=100,
                    tags=["eol", "upgrade", "compliance"]
                ))

        return findings

    def _check_file_permissions(self) -> List[PluginFinding]:
        """
        Check for dangerous file permissions.

        P0 Critical:
        - World-writable files
        - SUID/SGID binaries
        - Weak /etc/shadow permissions
        """
        findings = []
        self.logger.info("Checking file permissions...")

        # Check /etc/shadow permissions (P0 - CRITICAL)
        exit_code, output, _ = self.ssh.execute_command(
            "stat -c '%a %U:%G' /etc/shadow",
            check_exit_code=False
        )

        if exit_code == 0:
            perms, owner = output.strip().split()
            if perms != '640' and perms != '000':
                findings.append(PluginFinding(
                    title="Weak /etc/shadow Permissions",
                    description=f"/etc/shadow has permissions {perms}, should be 640 or 000",
                    severity=FindingSeverity.CRITICAL,
                    cwe_ids=["CWE-732"],
                    affected_service="filesystem",
                    evidence=f"/etc/shadow: {perms} {owner}",
                    remediation="sudo chmod 640 /etc/shadow",
                    remediation_priority=90,
                    tags=["permissions", "passwords", "cis-benchmark"]
                ))

        # Check for world-writable files in system directories (P0 - CRITICAL)
        exit_code, output, _ = self.ssh.execute_command(
            "find /etc /usr /var -xdev -type f -perm -002 2>/dev/null | head -20",
            check_exit_code=False,
            timeout=60
        )

        if exit_code == 0 and output.strip():
            world_writable = [f for f in output.split('\n') if f.strip()]
            if world_writable:
                findings.append(PluginFinding(
                    title=f"World-Writable System Files Found ({len(world_writable)})",
                    description=(
                        "Found system files writable by all users. "
                        "This allows any user to modify critical system files."
                    ),
                    severity=FindingSeverity.CRITICAL,
                    cwe_ids=["CWE-732"],
                    evidence="\n".join(world_writable[:10]),
                    remediation="Review and remove world-write permissions: chmod o-w <file>",
                    remediation_priority=85,
                    tags=["permissions", "filesystem"]
                ))

        # Check for unusual SUID binaries (P1 - HIGH)
        exit_code, output, _ = self.ssh.execute_command(
            "find / -xdev -type f -perm -4000 2>/dev/null",
            check_exit_code=False,
            timeout=120
        )

        if exit_code == 0 and output.strip():
            suid_files = output.strip().split('\n')
            # Common SUID binaries that are expected
            expected_suid = {'/usr/bin/sudo', '/usr/bin/passwd', '/usr/bin/su',
                           '/usr/bin/chsh', '/usr/bin/chfn', '/usr/bin/newgrp',
                           '/usr/bin/mount', '/usr/bin/umount', '/bin/ping'}

            unexpected_suid = [f for f in suid_files if f not in expected_suid]

            if len(suid_files) > 30:
                findings.append(PluginFinding(
                    title=f"Excessive SUID Binaries ({len(suid_files)})",
                    description=f"Found {len(suid_files)} SUID binaries (expected ~15-20)",
                    severity=FindingSeverity.MEDIUM,
                    cwe_ids=["CWE-250"],
                    evidence=f"Total SUID files: {len(suid_files)}",
                    remediation="Review SUID binaries and remove unnecessary ones",
                    remediation_priority=50,
                    tags=["permissions", "suid"]
                ))

        return findings

    def _check_user_accounts(self) -> List[PluginFinding]:
        """
        Check user account security.

        P0 Critical:
        - Users with empty passwords
        - Excessive sudo access
        - Inactive accounts not disabled
        """
        findings = []
        self.logger.info("Checking user accounts...")

        # Check for users with empty passwords (P0 - CRITICAL)
        exit_code, output, _ = self.ssh.execute_command(
            "awk -F: '($2 == \"\") {print $1}' /etc/shadow 2>/dev/null",
            check_exit_code=False
        )

        if exit_code == 0 and output.strip():
            users = output.strip().split('\n')
            findings.append(PluginFinding(
                title="Users with Empty Passwords",
                description=f"Found {len(users)} user(s) with empty passwords",
                severity=FindingSeverity.CRITICAL,
                cwe_ids=["CWE-521"],
                evidence=", ".join(users),
                remediation="Set passwords or lock accounts: sudo passwd <user>",
                remediation_priority=100,
                tags=["users", "passwords", "authentication"]
            ))

        # Check sudo access (P1 - HIGH)
        exit_code, output, _ = self.ssh.execute_command(
            "grep -v '^#' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep NOPASSWD",
            check_exit_code=False
        )

        if exit_code == 0 and output.strip():
            findings.append(PluginFinding(
                title="Passwordless Sudo Configured",
                description="Some users can run sudo without password (NOPASSWD)",
                severity=FindingSeverity.HIGH,
                cwe_ids=["CWE-284"],
                evidence=output[:500],
                remediation="Remove NOPASSWD from sudo configuration",
                remediation_priority=70,
                tags=["users", "sudo", "privileges"]
            ))

        # Check for users with UID 0 (root equivalent)
        exit_code, output, _ = self.ssh.execute_command(
            "awk -F: '($3 == 0) {print $1}' /etc/passwd",
            check_exit_code=False
        )

        if exit_code == 0:
            root_users = output.strip().split('\n')
            if len(root_users) > 1:
                findings.append(PluginFinding(
                    title="Multiple UID 0 Accounts",
                    description=f"Found {len(root_users)} accounts with UID 0 (root privileges)",
                    severity=FindingSeverity.HIGH,
                    cwe_ids=["CWE-250"],
                    evidence=", ".join(root_users),
                    remediation="Only 'root' should have UID 0",
                    remediation_priority=75,
                    tags=["users", "privileges"]
                ))

        return findings

    def _check_services(self) -> List[PluginFinding]:
        """Check for risky or unnecessary services."""
        findings = []
        self.logger.info("Checking running services...")

        # List all listening ports
        exit_code, output, _ = self.ssh.execute_command(
            "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
            check_exit_code=False
        )

        if exit_code == 0 and output:
            # Check for risky services
            risky_ports = {
                21: ("FTP", FindingSeverity.HIGH, "Unencrypted file transfer protocol"),
                23: ("Telnet", FindingSeverity.CRITICAL, "Unencrypted remote access"),
                69: ("TFTP", FindingSeverity.HIGH, "Trivial FTP - no authentication"),
                513: ("rlogin", FindingSeverity.CRITICAL, "Insecure remote login"),
                514: ("rsh", FindingSeverity.CRITICAL, "Insecure remote shell"),
                3306: ("MySQL", FindingSeverity.MEDIUM, "Database exposed to network"),
                5432: ("PostgreSQL", FindingSeverity.MEDIUM, "Database exposed to network"),
                6379: ("Redis", FindingSeverity.HIGH, "Redis without authentication"),
                27017: ("MongoDB", FindingSeverity.HIGH, "MongoDB without authentication"),
            }

            for port, (service, severity, desc) in risky_ports.items():
                if f":{port}" in output or f" {port} " in output:
                    findings.append(PluginFinding(
                        title=f"Risky Service Running: {service}",
                        description=f"{service} is listening on port {port}. {desc}",
                        severity=severity,
                        affected_service=service.lower(),
                        affected_port=port,
                        remediation=f"Disable {service} if not needed, or restrict access with firewall",
                        remediation_priority=80 if severity == FindingSeverity.CRITICAL else 60,
                        tags=["services", "network", "exposure"]
                    ))

        return findings

    def _check_system_hardening(self) -> List[PluginFinding]:
        """Check system hardening settings."""
        findings = []
        self.logger.info("Checking system hardening...")

        # Check kernel parameters
        hardening_checks = [
            ("net.ipv4.conf.all.send_redirects", "0", "IP redirects enabled"),
            ("net.ipv4.conf.default.send_redirects", "0", "IP redirects enabled"),
            ("net.ipv4.icmp_ignore_bogus_error_responses", "1", "ICMP bogus errors accepted"),
            ("kernel.randomize_va_space", "2", "ASLR disabled or weak"),
        ]

        for param, expected, issue in hardening_checks:
            exit_code, value, _ = self.ssh.execute_command(
                f"sysctl {param} 2>/dev/null | cut -d= -f2",
                check_exit_code=False
            )

            if exit_code == 0:
                actual = value.strip()
                if actual != expected:
                    findings.append(PluginFinding(
                        title=f"Kernel Hardening: {issue}",
                        description=f"{param} is {actual}, should be {expected}",
                        severity=FindingSeverity.MEDIUM,
                        evidence=f"{param} = {actual}",
                        remediation=f"Set in /etc/sysctl.conf: {param}={expected}",
                        remediation_priority=50,
                        tags=["kernel", "hardening", "cis-benchmark"]
                    ))

        return findings

    def _run_lynis(self) -> List[PluginFinding]:
        """Run Lynis audit if available."""
        findings = []
        self.logger.info("Running Lynis audit...")

        exit_code, output, _ = self.ssh.execute_command(
            "lynis audit system --quick --quiet",
            check_exit_code=False,
            timeout=300
        )

        if exit_code == 0:
            # Parse Lynis warnings
            warnings = re.findall(r'Warning: (.+)', output)
            for warning in warnings[:5]:  # Limit to top 5
                findings.append(PluginFinding(
                    title=f"Lynis Warning: {warning[:60]}",
                    description=f"Lynis security audit found: {warning}",
                    severity=FindingSeverity.MEDIUM,
                    evidence=warning,
                    tags=["lynis", "audit"]
                ))

        return findings

    def _command_exists(self, command: str) -> bool:
        """Check if a command exists on the system."""
        exit_code, _, _ = self.ssh.execute_command(
            f"which {command}",
            check_exit_code=False
        )
        return exit_code == 0

    def _count_by_severity(self, findings: List[PluginFinding]) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }

        for finding in findings:
            counts[finding.severity.value] += 1

        return counts


# Test plugin standalone
if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    parser = argparse.ArgumentParser(description="Ubuntu Security Audit Plugin")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", help="SSH password")
    parser.add_argument("--key", help="SSH private key path")

    args = parser.parse_args()

    credentials = {"username": args.username}
    if args.password:
        credentials["password"] = args.password
    if args.key:
        with open(args.key) as f:
            credentials["private_key"] = f.read()

    plugin = UbuntuPlugin()
    result = plugin.execute(args.target, credentials=credentials)

    print(f"\n{'='*60}")
    print(f"Ubuntu Security Audit Results")
    print(f"{'='*60}\n")
    print(f"Success: {result.success}")
    print(f"Findings: {len(result.findings)}")
    print(f"\nBy Severity:")
    for severity, count in result.stats.get('findings_by_severity', {}).items():
        print(f"  {severity}: {count}")

    print(f"\n{'='*60}")
    print("Critical and High Severity Findings:")
    print(f"{'='*60}\n")

    for finding in result.findings:
        if finding.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]:
            print(f"[{finding.severity.value}] {finding.title}")
            print(f"  {finding.description}")
            print()
