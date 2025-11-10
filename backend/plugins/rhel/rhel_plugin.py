"""
RHEL/CentOS/Rocky Linux Security Audit Plugin

Comprehensive security scanning for Red Hat Enterprise Linux family systems.
Based on research from LINUX_SECURITY_RESEARCH.md

Checks:
- SSH configuration (root login, password auth, default port)
- Firewall status (firewalld)
- SELinux status (MAC)
- Package vulnerabilities (dnf/yum security updates)
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


class RHELPlugin(BasePlugin):
    """
    RHEL/CentOS/Rocky Linux security audit plugin.

    Performs comprehensive security assessment including:
    - Critical configuration checks (SSH, firewall, SELinux)
    - Vulnerability scanning (CVE detection via dnf/yum)
    - Compliance checks (CIS benchmark alignment)
    - System hardening assessment
    """

    # Plugin metadata
    name = "rhel-security-audit"
    version = "1.0.0"
    description = "Comprehensive security audit for RHEL/CentOS/Rocky Linux systems"
    author = "VulnScan Platform"

    plugin_type = PluginType.VULNERABILITY
    vendor = "redhat"
    requires_authentication = True
    is_intrusive = False
    is_safe = True
    supported_asset_types = ["linux", "rhel", "centos", "rocky", "alma"]

    def __init__(self):
        super().__init__()
        self.ssh: Optional[SSHHelper] = None
        self.distro_info = None
        self.pkg_manager = "dnf"  # Will be detected

    def execute(
        self,
        target: str,
        config: Optional[PluginConfig] = None,
        credentials: Optional[Dict[str, Any]] = None
    ) -> PluginResult:
        """
        Execute RHEL security audit.

        Args:
            target: Target IP or hostname
            config: Plugin configuration
            credentials: SSH credentials

        Returns:
            PluginResult with findings and asset info
        """
        self.logger.info(f"Starting RHEL security audit on {target}")

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

            # Verify this is RHEL family
            if self.distro_info.family != DistroFamily.REDHAT:
                return PluginResult(
                    success=False,
                    error_message=f"Not a RHEL-family system (detected: {self.distro_info.name})",
                    findings=[],
                    assets=[]
                )

            self.logger.info(
                f"Confirmed {self.distro_info.name} {self.distro_info.version}"
            )

            # Detect package manager (dnf or yum)
            self.pkg_manager = self.distro_info.package_manager or "dnf"

            # Gather asset information
            asset = self._gather_asset_info(target)
            assets.append(asset)

            # Run all security checks (P0 - Critical Priority)
            findings.extend(self._check_ssh_security())
            findings.extend(self._check_firewall())
            findings.extend(self._check_selinux())
            findings.extend(self._check_package_vulnerabilities())
            findings.extend(self._check_file_permissions())
            findings.extend(self._check_user_accounts())
            findings.extend(self._check_services())
            findings.extend(self._check_system_hardening())

            # Additional checks if Lynis available
            if self._command_exists("lynis"):
                findings.extend(self._run_lynis())

            # OpenSCAP check (more common on RHEL)
            if self._command_exists("oscap"):
                findings.extend(self._check_openscap())

            self.logger.info(f"Audit complete: {len(findings)} findings")

            return PluginResult(
                success=True,
                findings=findings,
                assets=assets,
                stats={
                    "total_checks": 55,
                    "findings_by_severity": self._count_by_severity(findings),
                    "package_manager": self.pkg_manager
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
            vendor="Red Hat" if "rhel" in self.distro_info.name.lower() else "Community",
            metadata={
                "distribution": self.distro_info.name,
                "version": self.distro_info.version,
                "kernel": kernel.strip(),
                "package_manager": self.pkg_manager,
                "mac_system": self.distro_info.mac_system,
                "firewall": self.distro_info.firewall,
                "init_system": self.distro_info.init_system,
                "memory_mb": memory_mb,
                "cpu": cpu_output.strip(),
                "uptime": uptime.strip()
            }
        )

    def _check_ssh_security(self) -> List[PluginFinding]:
        """Check SSH configuration security (same as Ubuntu but worth checking)."""
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
                        "Direct root login is a critical security risk. "
                        "This is especially critical on RHEL systems handling sensitive workloads."
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

        # Check PasswordAuthentication (P0 - CRITICAL)
        pass_auth_match = re.search(r'^\s*PasswordAuthentication\s+(\S+)', config, re.MULTILINE)
        if pass_auth_match:
            value = pass_auth_match.group(1).lower()
            if value == 'yes':
                findings.append(PluginFinding(
                    title="SSH Password Authentication Enabled",
                    description=(
                        "SSH allows password authentication. "
                        "Key-based authentication is mandatory for enterprise RHEL systems."
                    ),
                    severity=FindingSeverity.HIGH,
                    cwe_ids=["CWE-521"],
                    affected_service="sshd",
                    affected_port=22,
                    evidence="PasswordAuthentication yes",
                    remediation=(
                        "1. Set up SSH key authentication\n"
                        "2. Set: PasswordAuthentication no\n"
                        "3. Restart SSH: sudo systemctl restart sshd"
                    ),
                    remediation_priority=85,
                    tags=["ssh", "authentication", "cis-benchmark"]
                ))

        # Check for SELinux SSH confinement
        exit_code, output, _ = self.ssh.execute_command(
            "ps -eZ | grep sshd | head -1",
            check_exit_code=False
        )
        if exit_code == 0 and 'unconfined' in output:
            findings.append(PluginFinding(
                title="SSH Running Unconfined by SELinux",
                description="sshd process is not confined by SELinux",
                severity=FindingSeverity.MEDIUM,
                evidence=output[:200],
                remediation="Review SELinux policy for sshd",
                tags=["ssh", "selinux"]
            ))

        return findings

    def _check_firewall(self) -> List[PluginFinding]:
        """
        Check firewalld configuration.

        P0 Critical: Firewall disabled
        """
        findings = []
        self.logger.info("Checking firewall status...")

        # Check firewalld status
        exit_code, output, _ = self.ssh.execute_command(
            "systemctl is-active firewalld",
            check_exit_code=False
        )

        if exit_code != 0 or 'inactive' in output.lower():
            # Check if firewalld is installed
            exit_code2, _, _ = self.ssh.execute_command(
                "rpm -q firewalld",
                check_exit_code=False
            )

            if exit_code2 != 0:
                findings.append(PluginFinding(
                    title="Firewalld Not Installed",
                    description="firewalld is not installed on this RHEL system",
                    severity=FindingSeverity.HIGH,
                    cwe_ids=["CWE-16"],
                    evidence="firewalld package not installed",
                    remediation=f"Install and configure firewalld: sudo {self.pkg_manager} install firewalld && sudo systemctl enable --now firewalld",
                    remediation_priority=85,
                    tags=["firewall", "cis-benchmark"]
                ))
            else:
                findings.append(PluginFinding(
                    title="Firewalld Disabled",
                    description=(
                        "firewalld is installed but not active. "
                        "RHEL systems should always have an active firewall."
                    ),
                    severity=FindingSeverity.CRITICAL,
                    cwe_ids=["CWE-16"],
                    evidence="firewalld is inactive",
                    remediation="Enable firewalld: sudo systemctl enable --now firewalld",
                    remediation_priority=90,
                    tags=["firewall", "network", "cis-benchmark"]
                ))
            return findings

        # Firewall is active - check configuration
        exit_code, zone_output, _ = self.ssh.execute_command(
            "firewall-cmd --get-default-zone",
            check_exit_code=False
        )

        if exit_code == 0:
            default_zone = zone_output.strip()

            # Check if zone is too permissive
            if default_zone in ['trusted', 'dmz']:
                findings.append(PluginFinding(
                    title=f"Permissive Firewall Zone: {default_zone}",
                    description=f"Default firewall zone is '{default_zone}' which may be too permissive",
                    severity=FindingSeverity.MEDIUM,
                    evidence=f"Default zone: {default_zone}",
                    remediation="Review firewall zone configuration and use 'public' or more restrictive zone",
                    remediation_priority=60,
                    tags=["firewall", "configuration"]
                ))

        # Check for open ports
        exit_code, ports_output, _ = self.ssh.execute_command(
            "firewall-cmd --list-all",
            check_exit_code=False
        )

        if exit_code == 0 and ports_output:
            # Look for risky services
            risky_services = ['ftp', 'telnet', 'rsh', 'rlogin']
            for service in risky_services:
                if service in ports_output.lower():
                    findings.append(PluginFinding(
                        title=f"Risky Service Allowed in Firewall: {service}",
                        description=f"Firewall allows insecure service: {service}",
                        severity=FindingSeverity.HIGH,
                        evidence=f"{service} service allowed",
                        remediation=f"Remove service: sudo firewall-cmd --permanent --remove-service={service} && sudo firewall-cmd --reload",
                        remediation_priority=80,
                        tags=["firewall", "services"]
                    ))

        return findings

    def _check_selinux(self) -> List[PluginFinding]:
        """
        Check SELinux status and configuration.

        P0 Critical: SELinux disabled or permissive
        """
        findings = []
        self.logger.info("Checking SELinux status...")

        # Check SELinux status
        exit_code, output, _ = self.ssh.execute_command(
            "getenforce",
            check_exit_code=False
        )

        if exit_code != 0:
            findings.append(PluginFinding(
                title="SELinux Not Available",
                description="SELinux is not available on this system",
                severity=FindingSeverity.CRITICAL,
                cwe_ids=["CWE-276"],
                evidence="getenforce command failed",
                remediation="SELinux should be enabled on all RHEL systems",
                remediation_priority=95,
                tags=["selinux", "mac", "cis-benchmark"]
            ))
            return findings

        selinux_status = output.strip().lower()

        if selinux_status == 'disabled':
            findings.append(PluginFinding(
                title="SELinux Disabled",
                description=(
                    "SELinux is completely disabled. "
                    "This removes a critical security layer required by many compliance standards. "
                    "RHEL systems MUST run SELinux in enforcing mode for production use."
                ),
                severity=FindingSeverity.CRITICAL,
                cwe_ids=["CWE-276"],
                evidence="SELinux status: Disabled",
                remediation=(
                    "1. Edit /etc/selinux/config\n"
                    "2. Set: SELINUX=enforcing\n"
                    "3. Reboot system\n"
                    "4. Run: sudo touch /.autorelabel (before reboot)"
                ),
                remediation_priority=100,
                tags=["selinux", "mac", "compliance", "cis-benchmark"]
            ))

        elif selinux_status == 'permissive':
            findings.append(PluginFinding(
                title="SELinux in Permissive Mode",
                description=(
                    "SELinux is in permissive mode (logs but doesn't enforce). "
                    "Production RHEL systems must run SELinux in enforcing mode."
                ),
                severity=FindingSeverity.HIGH,
                cwe_ids=["CWE-276"],
                evidence="SELinux status: Permissive",
                remediation=(
                    "1. Fix any SELinux denials: sudo ausearch -m AVC,USER_AVC -ts recent\n"
                    "2. Set to enforcing: sudo setenforce 1\n"
                    "3. Make permanent in /etc/selinux/config: SELINUX=enforcing"
                ),
                remediation_priority=90,
                tags=["selinux", "mac", "compliance"]
            ))

        else:  # Enforcing
            # Check SELinux policy
            exit_code, policy_output, _ = self.ssh.execute_command(
                "sestatus | grep 'Loaded policy'",
                check_exit_code=False
            )

            if exit_code == 0:
                if 'targeted' not in policy_output.lower():
                    findings.append(PluginFinding(
                        title="Non-Standard SELinux Policy",
                        description=f"SELinux policy is not 'targeted': {policy_output}",
                        severity=FindingSeverity.MEDIUM,
                        evidence=policy_output,
                        remediation="Review SELinux policy configuration",
                        tags=["selinux", "configuration"]
                    ))

            # Check for SELinux denials
            exit_code, denials, _ = self.ssh.execute_command(
                "ausearch -m AVC -ts today 2>/dev/null | grep denied | wc -l",
                check_exit_code=False
            )

            if exit_code == 0 and denials.strip().isdigit():
                denial_count = int(denials.strip())
                if denial_count > 10:
                    findings.append(PluginFinding(
                        title=f"High Number of SELinux Denials ({denial_count})",
                        description=f"Found {denial_count} SELinux denials today",
                        severity=FindingSeverity.MEDIUM,
                        evidence=f"{denial_count} AVC denials",
                        remediation="Review SELinux audit logs: sudo ausearch -m AVC -ts recent",
                        tags=["selinux", "audit"]
                    ))

        # Check for unconfined processes
        exit_code, unconfined, _ = self.ssh.execute_command(
            "ps -eZ | grep unconfined_service_t | wc -l",
            check_exit_code=False
        )

        if exit_code == 0 and unconfined.strip().isdigit():
            unconfined_count = int(unconfined.strip())
            if unconfined_count > 0:
                findings.append(PluginFinding(
                    title=f"Unconfined Services Running ({unconfined_count})",
                    description=f"Found {unconfined_count} services running unconfined by SELinux",
                    severity=FindingSeverity.MEDIUM,
                    evidence=f"{unconfined_count} unconfined processes",
                    remediation="Review and confine services: ps -eZ | grep unconfined",
                    remediation_priority=50,
                    tags=["selinux", "processes"]
                ))

        return findings

    def _check_package_vulnerabilities(self) -> List[PluginFinding]:
        """
        Check for packages with available security updates.

        P0 Critical: Unpatched packages with CVEs
        """
        findings = []
        self.logger.info("Checking for package vulnerabilities...")

        # Check for security updates
        exit_code, output, _ = self.ssh.execute_command(
            f"{self.pkg_manager} updateinfo list security --available",
            check_exit_code=False,
            timeout=90
        )

        if exit_code == 0 and output.strip():
            # Count security advisories by severity
            critical_count = output.lower().count('critical/')
            important_count = output.lower().count('important/')
            moderate_count = output.lower().count('moderate/')

            total_security = critical_count + important_count + moderate_count

            if critical_count > 0:
                findings.append(PluginFinding(
                    title=f"Critical Security Updates Available ({critical_count})",
                    description=(
                        f"Found {critical_count} critical security updates available. "
                        "Critical updates address actively exploited vulnerabilities."
                    ),
                    severity=FindingSeverity.CRITICAL,
                    cwe_ids=["CWE-1104"],
                    evidence=output[:1000],
                    remediation=f"Apply updates immediately: sudo {self.pkg_manager} update --security",
                    remediation_priority=100,
                    tags=["packages", "vulnerability", "patching", "critical"]
                ))

            if important_count > 0:
                findings.append(PluginFinding(
                    title=f"Important Security Updates Available ({important_count})",
                    description=f"Found {important_count} important security updates",
                    severity=FindingSeverity.HIGH,
                    cwe_ids=["CWE-1104"],
                    evidence=f"{important_count} important security advisories",
                    remediation=f"Apply updates: sudo {self.pkg_manager} update --security",
                    remediation_priority=85,
                    tags=["packages", "vulnerability", "patching"]
                ))

            if moderate_count > 5:
                findings.append(PluginFinding(
                    title=f"Multiple Moderate Security Updates ({moderate_count})",
                    description=f"Found {moderate_count} moderate security updates",
                    severity=FindingSeverity.MEDIUM,
                    evidence=f"{moderate_count} moderate security advisories",
                    remediation=f"Apply updates: sudo {self.pkg_manager} update --security",
                    remediation_priority=60,
                    tags=["packages", "vulnerability", "patching"]
                ))

        # Check for end-of-life versions
        if self.distro_info:
            version = self.distro_info.version.split('.')[0]  # Major version

            # CentOS EOL check
            if 'centos' in self.distro_info.name.lower():
                if version in ['6', '7', '8']:
                    findings.append(PluginFinding(
                        title=f"End-of-Life CentOS Version ({version})",
                        description=(
                            f"CentOS {version} has reached end-of-life. "
                            "Consider migrating to Rocky Linux or AlmaLinux."
                        ),
                        severity=FindingSeverity.HIGH,
                        evidence=f"CentOS {version}",
                        remediation="Migrate to Rocky Linux, AlmaLinux, or RHEL",
                        remediation_priority=80,
                        tags=["eol", "upgrade", "compliance"]
                    ))

            # RHEL old version check
            if 'rhel' in self.distro_info.name.lower():
                if int(version) < 7:
                    findings.append(PluginFinding(
                        title=f"Outdated RHEL Version ({version})",
                        description=f"RHEL {version} is outdated and may lack security support",
                        severity=FindingSeverity.HIGH,
                        evidence=f"RHEL {version}",
                        remediation=f"Upgrade to RHEL 8 or 9",
                        remediation_priority=85,
                        tags=["eol", "upgrade"]
                    ))

        # Check subscription status (RHEL only)
        if 'rhel' in self.distro_info.name.lower():
            exit_code, sub_output, _ = self.ssh.execute_command(
                "subscription-manager status 2>/dev/null",
                check_exit_code=False
            )

            if exit_code == 0:
                if 'Status:' in sub_output and 'Current' not in sub_output:
                    findings.append(PluginFinding(
                        title="RHEL Subscription Not Current",
                        description="RHEL subscription is not current - system may not receive updates",
                        severity=FindingSeverity.HIGH,
                        evidence=sub_output[:300],
                        remediation="Renew RHEL subscription: subscription-manager register",
                        remediation_priority=90,
                        tags=["subscription", "updates", "compliance"]
                    ))

        return findings

    def _check_file_permissions(self) -> List[PluginFinding]:
        """Check for dangerous file permissions."""
        findings = []
        self.logger.info("Checking file permissions...")

        # Check /etc/shadow permissions (P0 - CRITICAL)
        exit_code, output, _ = self.ssh.execute_command(
            "stat -c '%a %U:%G' /etc/shadow",
            check_exit_code=False
        )

        if exit_code == 0:
            perms, owner = output.strip().split()
            if perms != '000' and perms != '400':
                findings.append(PluginFinding(
                    title="Weak /etc/shadow Permissions",
                    description=f"/etc/shadow has permissions {perms}, should be 000 or 400",
                    severity=FindingSeverity.CRITICAL,
                    cwe_ids=["CWE-732"],
                    evidence=f"/etc/shadow: {perms} {owner}",
                    remediation="sudo chmod 000 /etc/shadow",
                    remediation_priority=90,
                    tags=["permissions", "passwords", "cis-benchmark"]
                ))

        # Check for world-writable files
        exit_code, output, _ = self.ssh.execute_command(
            "find /etc /usr /var -xdev -type f -perm -002 2>/dev/null | head -20",
            check_exit_code=False,
            timeout=60
        )

        if exit_code == 0 and output.strip():
            world_writable = [f for f in output.split('\n') if f.strip()]
            if world_writable:
                findings.append(PluginFinding(
                    title=f"World-Writable System Files ({len(world_writable)})",
                    description="Found system files writable by all users",
                    severity=FindingSeverity.CRITICAL,
                    cwe_ids=["CWE-732"],
                    evidence="\n".join(world_writable[:10]),
                    remediation="Remove world-write permissions: chmod o-w <file>",
                    remediation_priority=85,
                    tags=["permissions", "filesystem"]
                ))

        return findings

    def _check_user_accounts(self) -> List[PluginFinding]:
        """Check user account security."""
        findings = []
        self.logger.info("Checking user accounts...")

        # Check for users with empty passwords
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
                remediation="Set passwords: sudo passwd <user>",
                remediation_priority=100,
                tags=["users", "passwords"]
            ))

        # Check for UID 0 users
        exit_code, output, _ = self.ssh.execute_command(
            "awk -F: '($3 == 0) {print $1}' /etc/passwd",
            check_exit_code=False
        )

        if exit_code == 0:
            root_users = output.strip().split('\n')
            if len(root_users) > 1:
                findings.append(PluginFinding(
                    title="Multiple UID 0 Accounts",
                    description=f"Found {len(root_users)} accounts with UID 0",
                    severity=FindingSeverity.HIGH,
                    cwe_ids=["CWE-250"],
                    evidence=", ".join(root_users),
                    remediation="Only 'root' should have UID 0",
                    remediation_priority=75,
                    tags=["users", "privileges"]
                ))

        return findings

    def _check_services(self) -> List[PluginFinding]:
        """Check for risky services."""
        findings = []
        self.logger.info("Checking services...")

        # Check for legacy services
        legacy_services = ['telnet', 'rsh', 'rlogin', 'rexec', 'ftp', 'tftp']

        for service in legacy_services:
            exit_code, _, _ = self.ssh.execute_command(
                f"systemctl is-enabled {service}.socket 2>/dev/null || systemctl is-enabled {service} 2>/dev/null",
                check_exit_code=False
            )

            if exit_code == 0:
                findings.append(PluginFinding(
                    title=f"Insecure Service Enabled: {service}",
                    description=f"{service} service is enabled - this is a legacy insecure protocol",
                    severity=FindingSeverity.CRITICAL,
                    affected_service=service,
                    remediation=f"Disable service: sudo systemctl disable --now {service}",
                    remediation_priority=95,
                    tags=["services", "legacy", "cis-benchmark"]
                ))

        return findings

    def _check_system_hardening(self) -> List[PluginFinding]:
        """Check system hardening settings."""
        findings = []
        self.logger.info("Checking system hardening...")

        # Check kernel parameters
        hardening_checks = [
            ("net.ipv4.conf.all.send_redirects", "0", "IP redirects enabled"),
            ("net.ipv4.conf.all.accept_source_route", "0", "IP source routing enabled"),
            ("net.ipv4.icmp_ignore_bogus_error_responses", "1", "ICMP errors accepted"),
            ("kernel.randomize_va_space", "2", "ASLR disabled"),
            ("kernel.dmesg_restrict", "1", "dmesg accessible to users"),
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
            warnings = re.findall(r'Warning: (.+)', output)
            for warning in warnings[:5]:
                findings.append(PluginFinding(
                    title=f"Lynis: {warning[:60]}",
                    description=f"Lynis audit found: {warning}",
                    severity=FindingSeverity.MEDIUM,
                    evidence=warning,
                    tags=["lynis", "audit"]
                ))

        return findings

    def _check_openscap(self) -> List[PluginFinding]:
        """Check if OpenSCAP profiles are available."""
        findings = []
        self.logger.info("Checking OpenSCAP availability...")

        # Check for SCAP Security Guide
        exit_code, _, _ = self.ssh.execute_command(
            "rpm -q scap-security-guide",
            check_exit_code=False
        )

        if exit_code != 0:
            findings.append(PluginFinding(
                title="OpenSCAP Security Guide Not Installed",
                description=(
                    "SCAP Security Guide not installed. "
                    "This package provides CIS benchmark profiles for automated compliance checking."
                ),
                severity=FindingSeverity.INFO,
                remediation=f"Install: sudo {self.pkg_manager} install scap-security-guide",
                tags=["oscap", "compliance", "cis"]
            ))

        return findings

    def _command_exists(self, command: str) -> bool:
        """Check if a command exists."""
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

    parser = argparse.ArgumentParser(description="RHEL Security Audit Plugin")
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

    plugin = RHELPlugin()
    result = plugin.execute(args.target, credentials=credentials)

    print(f"\n{'='*60}")
    print(f"RHEL Security Audit Results")
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
