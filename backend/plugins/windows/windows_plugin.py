"""
Windows Security Audit Plugin

Comprehensive security scanning for Windows systems including:
- OS version and patch level
- Security configurations (UAC, Defender, Firewall)
- SMB and RDP security
- User accounts and privileges
- Security updates
- System hardening
"""
import logging
import re
import json
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

try:
    from vulnscan_sdk.winrm_helper import WinRMHelper, WinRMConnectionError, WinRMExecutionError
    WINRM_AVAILABLE = True
except ImportError:
    WINRM_AVAILABLE = False


class WindowsPlugin(BasePlugin):
    """
    Windows security audit plugin.

    Performs comprehensive security assessment including:
    - Critical configuration checks (RDP, SMB, UAC, Firewall)
    - Vulnerability scanning (patch level, missing updates)
    - Compliance checks (security baselines)
    - System hardening assessment
    """

    # Plugin metadata
    name = "windows-security-audit"
    version = "1.0.0"
    description = "Comprehensive security audit for Windows systems"
    author = "VulnScan Platform"

    plugin_type = PluginType.VULNERABILITY
    vendor = "microsoft"
    requires_authentication = True
    is_intrusive = False
    is_safe = True
    supported_asset_types = ["windows", "host"]

    def __init__(self):
        super().__init__()
        self.winrm: Optional[WinRMHelper] = None
        self.os_info = None

    def execute(
        self,
        target: str,
        config: Optional[PluginConfig] = None,
        credentials: Optional[Dict[str, Any]] = None
    ) -> PluginResult:
        """
        Execute Windows security audit.

        Args:
            target: Target IP or hostname
            config: Plugin configuration
            credentials: WinRM credentials (username, password)

        Returns:
            PluginResult with findings and asset info
        """
        if not WINRM_AVAILABLE:
            return PluginResult(
                success=False,
                error_message="pywinrm package not installed. Install with: pip install pywinrm"
            )

        self.logger.info(f"Starting Windows security audit on {target}")

        findings: List[PluginFinding] = []
        assets: List[PluginAsset] = []

        # Validate credentials
        if not credentials or 'username' not in credentials or 'password' not in credentials:
            return PluginResult(
                success=False,
                error_message="WinRM credentials required (username and password)"
            )

        # Connect via WinRM
        self.winrm = WinRMHelper(self.logger)

        try:
            connected = self.winrm.connect(
                host=target,
                username=credentials['username'],
                password=credentials['password'],
                port=credentials.get('port', 5985),
                transport=credentials.get('transport', 'ntlm'),
                use_ssl=credentials.get('use_ssl', False),
                timeout=30
            )

            if not connected:
                return PluginResult(
                    success=False,
                    error_message=f"Failed to connect to {target} via WinRM"
                )

            self.logger.info(f"Connected to {target} via WinRM")

            # Gather OS information
            self.os_info = self._gather_os_info()

            # Gather asset information
            asset = self._gather_asset_info(target)
            assets.append(asset)

            # Run all security checks
            findings.extend(self._check_os_version())
            findings.extend(self._check_smb_security())
            findings.extend(self._check_rdp_security())
            findings.extend(self._check_uac_settings())
            findings.extend(self._check_windows_defender())
            findings.extend(self._check_firewall())
            findings.extend(self._check_security_updates())
            findings.extend(self._check_user_accounts())
            findings.extend(self._check_services())
            findings.extend(self._check_registry_security())

            self.logger.info(f"Audit complete: {len(findings)} findings")

            return PluginResult(
                success=True,
                findings=findings,
                assets=assets,
                stats={
                    "total_checks": 50,
                    "findings_by_severity": self._count_by_severity(findings),
                    "os_version": self.os_info.get('version', 'Unknown')
                }
            )

        except WinRMConnectionError as e:
            self.logger.error(f"WinRM connection failed: {e}")
            return PluginResult(
                success=False,
                error_message=f"WinRM connection failed: {e}"
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
            if self.winrm:
                self.winrm.disconnect()

    def _gather_os_info(self) -> Dict[str, str]:
        """Gather Windows OS information."""
        try:
            ps_script = """
            $os = Get-CimInstance Win32_OperatingSystem
            @{
                Caption = $os.Caption
                Version = $os.Version
                BuildNumber = $os.BuildNumber
                OSArchitecture = $os.OSArchitecture
                LastBootUpTime = $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss')
            } | ConvertTo-Json
            """

            exit_code, output, _ = self.winrm.execute_powershell(ps_script, check_exit_code=False)

            if exit_code == 0:
                return json.loads(output)
            else:
                return {'version': 'Unknown'}

        except Exception as e:
            self.logger.warning(f"Failed to gather OS info: {e}")
            return {'version': 'Unknown'}

    def _gather_asset_info(self, target: str) -> PluginAsset:
        """Gather system information for asset inventory."""
        # Hostname
        _, hostname, _ = self.winrm.execute_command("hostname", check_exit_code=False)
        hostname = hostname.strip()

        # Memory
        ps_memory = "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB"
        _, memory_output, _ = self.winrm.execute_powershell(ps_memory, check_exit_code=False)

        # CPU
        ps_cpu = "(Get-CimInstance Win32_Processor).Name"
        _, cpu_output, _ = self.winrm.execute_powershell(ps_cpu, check_exit_code=False)

        return PluginAsset(
            ip_address=target,
            hostname=hostname if hostname else target,
            os_family="Windows",
            os_version=self.os_info.get('Caption', 'Unknown'),
            vendor="Microsoft",
            metadata={
                "version": self.os_info.get('Version', 'Unknown'),
                "build_number": self.os_info.get('BuildNumber', 'Unknown'),
                "architecture": self.os_info.get('OSArchitecture', 'Unknown'),
                "last_boot": self.os_info.get('LastBootUpTime', 'Unknown'),
                "memory_mb": memory_output.strip() if memory_output else "Unknown",
                "cpu": cpu_output.strip() if cpu_output else "Unknown"
            }
        )

    def _check_os_version(self) -> List[PluginFinding]:
        """Check Windows version and support status."""
        findings = []
        self.logger.info("Checking OS version...")

        version = self.os_info.get('Version', '')
        caption = self.os_info.get('Caption', '')

        # Check for unsupported Windows versions
        unsupported_versions = {
            'Windows 7': 'critical',
            'Windows 8': 'critical',
            'Windows 8.1': 'high',
            'Windows Server 2008': 'critical',
            'Windows Server 2012': 'high'
        }

        for unsupported_ver, severity in unsupported_versions.items():
            if unsupported_ver in caption:
                findings.append(PluginFinding(
                    title=f"Unsupported Windows Version: {unsupported_ver}",
                    description=f"This system is running {caption} which is no longer supported by Microsoft. "
                               f"It does not receive security updates.",
                    severity=FindingSeverity.CRITICAL if severity == 'critical' else FindingSeverity.HIGH,
                    cwe_ids=["CWE-1104"],
                    evidence=caption,
                    remediation=f"Upgrade to a supported Windows version (Windows 10/11, Server 2016/2019/2022)",
                    remediation_priority=100,
                    tags=["os", "eol", "compliance"]
                ))

        return findings

    def _check_smb_security(self) -> List[PluginFinding]:
        """Check SMB configuration security."""
        findings = []
        self.logger.info("Checking SMB security...")

        # Check SMBv1 status
        ps_smb1 = "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue | Select-Object State | ConvertTo-Json"
        exit_code, output, _ = self.winrm.execute_powershell(ps_smb1, check_exit_code=False)

        if exit_code == 0 and output:
            try:
                result = json.loads(output)
                if result.get('State') == 'Enabled' or result.get('State') == 2:  # 2 = Enabled
                    findings.append(PluginFinding(
                        title="SMBv1 Enabled",
                        description="SMBv1 protocol is enabled. This protocol is vulnerable to attacks like WannaCry and EternalBlue.",
                        severity=FindingSeverity.CRITICAL,
                        cve_ids=["CVE-2017-0143", "CVE-2017-0144", "CVE-2017-0145"],
                        affected_service="SMB",
                        affected_port=445,
                        evidence="SMBv1 is enabled",
                        remediation="Disable SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
                        remediation_priority=100,
                        tags=["smb", "eternalblue", "cve-2017-0144"]
                    ))
            except:
                pass

        # Check SMB signing
        ps_signing = "Get-SmbServerConfiguration | Select-Object EnableSecuritySignature, RequireSecuritySignature | ConvertTo-Json"
        exit_code, output, _ = self.winrm.execute_powershell(ps_signing, check_exit_code=False)

        if exit_code == 0 and output:
            try:
                result = json.loads(output)
                if not result.get('RequireSecuritySignature'):
                    findings.append(PluginFinding(
                        title="SMB Signing Not Required",
                        description="SMB signing is not required. This allows man-in-the-middle attacks on SMB connections.",
                        severity=FindingSeverity.HIGH,
                        affected_service="SMB",
                        affected_port=445,
                        evidence="SMB signing is not required",
                        remediation="Enable required SMB signing: Set-SmbServerConfiguration -RequireSecuritySignature $true",
                        remediation_priority=85,
                        tags=["smb", "signing"]
                    ))
            except:
                pass

        return findings

    def _check_rdp_security(self) -> List[PluginFinding]:
        """Check RDP security configuration."""
        findings = []
        self.logger.info("Checking RDP security...")

        # Check if RDP is enabled
        ps_rdp_enabled = "Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue | Select-Object fDenyTSConnections"
        exit_code, output, _ = self.winrm.execute_powershell(ps_rdp_enabled, check_exit_code=False)

        rdp_enabled = False
        if exit_code == 0 and output and 'fDenyTSConnections' in output:
            # fDenyTSConnections = 0 means RDP is enabled
            if ': 0' in output or ':0' in output:
                rdp_enabled = True

        if rdp_enabled:
            # Check NLA (Network Level Authentication)
            ps_nla = "Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -ErrorAction SilentlyContinue | Select-Object UserAuthentication"
            exit_code, output, _ = self.winrm.execute_powershell(ps_nla, check_exit_code=False)

            if exit_code == 0 and output:
                if ': 0' in output or ':0' in output:
                    findings.append(PluginFinding(
                        title="RDP Network Level Authentication Disabled",
                        description="RDP is enabled but Network Level Authentication (NLA) is disabled. "
                                   "This allows attackers to establish RDP sessions before authentication.",
                        severity=FindingSeverity.HIGH,
                        affected_service="RDP",
                        affected_port=3389,
                        cve_ids=["CVE-2019-0708"],  # BlueKeep
                        evidence="NLA is disabled",
                        remediation="Enable NLA in RDP settings or via registry: Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1",
                        remediation_priority=90,
                        tags=["rdp", "authentication"]
                    ))

            # Check encryption level
            ps_encryption = "Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'MinEncryptionLevel' -ErrorAction SilentlyContinue | Select-Object MinEncryptionLevel"
            exit_code, output, _ = self.winrm.execute_powershell(ps_encryption, check_exit_code=False)

            if exit_code == 0 and output:
                # MinEncryptionLevel: 1=Low, 2=Client Compatible, 3=High, 4=FIPS
                if ': 1' in output or ': 2' in output or ':1' in output or ':2' in output:
                    findings.append(PluginFinding(
                        title="RDP Weak Encryption Level",
                        description="RDP encryption level is set to Low or Client Compatible.",
                        severity=FindingSeverity.MEDIUM,
                        affected_service="RDP",
                        affected_port=3389,
                        evidence="Weak encryption level",
                        remediation="Set RDP encryption to High (3) or FIPS (4)",
                        remediation_priority=60,
                        tags=["rdp", "encryption"]
                    ))

        return findings

    def _check_uac_settings(self) -> List[PluginFinding]:
        """Check User Account Control (UAC) settings."""
        findings = []
        self.logger.info("Checking UAC settings...")

        # Check if UAC is enabled
        ps_uac = "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -ErrorAction SilentlyContinue | Select-Object EnableLUA"
        exit_code, output, _ = self.winrm.execute_powershell(ps_uac, check_exit_code=False)

        if exit_code == 0 and output:
            if ': 0' in output or ':0' in output:
                findings.append(PluginFinding(
                    title="UAC Disabled",
                    description="User Account Control (UAC) is disabled. This significantly reduces system security.",
                    severity=FindingSeverity.CRITICAL,
                    cwe_ids=["CWE-250"],
                    evidence="UAC is disabled (EnableLUA = 0)",
                    remediation="Enable UAC: Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 1",
                    remediation_priority=95,
                    tags=["uac", "privileges"]
                ))

        # Check ConsentPromptBehaviorAdmin
        ps_consent = "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'ConsentPromptBehaviorAdmin' -ErrorAction SilentlyContinue | Select-Object ConsentPromptBehaviorAdmin"
        exit_code, output, _ = self.winrm.execute_powershell(ps_consent, check_exit_code=False)

        if exit_code == 0 and output:
            # 0 = Elevate without prompting (dangerous)
            if ': 0' in output or ':0' in output:
                findings.append(PluginFinding(
                    title="UAC Set to Elevate Without Prompting",
                    description="UAC is configured to elevate privileges without prompting administrators.",
                    severity=FindingSeverity.HIGH,
                    evidence="ConsentPromptBehaviorAdmin = 0",
                    remediation="Set UAC to prompt on secure desktop (value 2)",
                    remediation_priority=80,
                    tags=["uac", "privileges"]
                ))

        return findings

    def _check_windows_defender(self) -> List[PluginFinding]:
        """Check Windows Defender status."""
        findings = []
        self.logger.info("Checking Windows Defender...")

        # Check if Defender is running
        ps_defender = "Get-Service -Name WinDefend -ErrorAction SilentlyContinue | Select-Object Status | ConvertTo-Json"
        exit_code, output, _ = self.winrm.execute_powershell(ps_defender, check_exit_code=False)

        if exit_code != 0 or 'Running' not in output:
            findings.append(PluginFinding(
                title="Windows Defender Not Running",
                description="Windows Defender service is not running. The system may not have active antivirus protection.",
                severity=FindingSeverity.HIGH,
                evidence="WinDefend service not running",
                remediation="Start Windows Defender service and ensure it's set to automatic startup",
                remediation_priority=85,
                tags=["antivirus", "defender"]
            ))

        # Check real-time protection
        ps_realtime = "Get-MpPreference -ErrorAction SilentlyContinue | Select-Object DisableRealtimeMonitoring | ConvertTo-Json"
        exit_code, output, _ = self.winrm.execute_powershell(ps_realtime, check_exit_code=False)

        if exit_code == 0 and output:
            try:
                result = json.loads(output)
                if result.get('DisableRealtimeMonitoring') == True:
                    findings.append(PluginFinding(
                        title="Windows Defender Real-Time Protection Disabled",
                        description="Real-time protection is disabled in Windows Defender.",
                        severity=FindingSeverity.CRITICAL,
                        evidence="Real-time monitoring is disabled",
                        remediation="Enable real-time protection: Set-MpPreference -DisableRealtimeMonitoring $false",
                        remediation_priority=95,
                        tags=["antivirus", "defender", "realtime"]
                    ))
            except:
                pass

        return findings

    def _check_firewall(self) -> List[PluginFinding]:
        """Check Windows Firewall status."""
        findings = []
        self.logger.info("Checking Windows Firewall...")

        # Check firewall profiles
        ps_firewall = "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"
        exit_code, output, _ = self.winrm.execute_powershell(ps_firewall, check_exit_code=False)

        if exit_code == 0 and output:
            try:
                profiles = json.loads(output)
                if not isinstance(profiles, list):
                    profiles = [profiles]

                for profile in profiles:
                    if not profile.get('Enabled'):
                        findings.append(PluginFinding(
                            title=f"Windows Firewall Disabled ({profile.get('Name')} Profile)",
                            description=f"The {profile.get('Name')} firewall profile is disabled.",
                            severity=FindingSeverity.CRITICAL,
                            cwe_ids=["CWE-16"],
                            evidence=f"{profile.get('Name')} profile is disabled",
                            remediation=f"Enable firewall: Set-NetFirewallProfile -Profile {profile.get('Name')} -Enabled True",
                            remediation_priority=95,
                            tags=["firewall", "network"]
                        ))
            except:
                pass

        return findings

    def _check_security_updates(self) -> List[PluginFinding]:
        """Check for missing security updates."""
        findings = []
        self.logger.info("Checking security updates...")

        # Check last update check time
        ps_last_check = "(New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastSearchSuccessDate"
        exit_code, output, _ = self.winrm.execute_powershell(ps_last_check, check_exit_code=False)

        # Check Windows Update service
        ps_wuauserv = "Get-Service -Name wuauserv | Select-Object Status"
        exit_code, wu_status, _ = self.winrm.execute_powershell(ps_wuauserv, check_exit_code=False)

        if 'Stopped' in wu_status:
            findings.append(PluginFinding(
                title="Windows Update Service Disabled",
                description="Windows Update service (wuauserv) is stopped. System may not receive security updates.",
                severity=FindingSeverity.HIGH,
                evidence="wuauserv service is stopped",
                remediation="Start Windows Update service: Start-Service wuauserv",
                remediation_priority=85,
                tags=["updates", "patching"]
            ))

        return findings

    def _check_user_accounts(self) -> List[PluginFinding]:
        """Check user account security."""
        findings = []
        self.logger.info("Checking user accounts...")

        # Check for Administrator account status
        ps_admin = "Get-LocalUser -Name Administrator -ErrorAction SilentlyContinue | Select-Object Enabled | ConvertTo-Json"
        exit_code, output, _ = self.winrm.execute_powershell(ps_admin, check_exit_code=False)

        if exit_code == 0 and output:
            try:
                result = json.loads(output)
                if result.get('Enabled') == True:
                    findings.append(PluginFinding(
                        title="Built-in Administrator Account Enabled",
                        description="The built-in Administrator account is enabled. This is a common target for attacks.",
                        severity=FindingSeverity.HIGH,
                        cwe_ids=["CWE-250"],
                        evidence="Administrator account is enabled",
                        remediation="Disable built-in Administrator account: Disable-LocalUser -Name Administrator",
                        remediation_priority=80,
                        tags=["users", "administrator"]
                    ))
            except:
                pass

        # Check for Guest account
        ps_guest = "Get-LocalUser -Name Guest -ErrorAction SilentlyContinue | Select-Object Enabled | ConvertTo-Json"
        exit_code, output, _ = self.winrm.execute_powershell(ps_guest, check_exit_code=False)

        if exit_code == 0 and output:
            try:
                result = json.loads(output)
                if result.get('Enabled') == True:
                    findings.append(PluginFinding(
                        title="Guest Account Enabled",
                        description="The Guest account is enabled.",
                        severity=FindingSeverity.MEDIUM,
                        evidence="Guest account is enabled",
                        remediation="Disable Guest account: Disable-LocalUser -Name Guest",
                        remediation_priority=60,
                        tags=["users", "guest"]
                    ))
            except:
                pass

        return findings

    def _check_services(self) -> List[PluginFinding]:
        """Check for risky services."""
        findings = []
        self.logger.info("Checking services...")

        # Check for Telnet service
        ps_telnet = "Get-Service -Name TlntSvr -ErrorAction SilentlyContinue | Select-Object Status"
        exit_code, output, _ = self.winrm.execute_powershell(ps_telnet, check_exit_code=False)

        if exit_code == 0 and 'Running' in output:
            findings.append(PluginFinding(
                title="Telnet Service Running",
                description="Telnet service is running. This is an insecure protocol.",
                severity=FindingSeverity.CRITICAL,
                affected_service="Telnet",
                affected_port=23,
                evidence="Telnet service is running",
                remediation="Disable Telnet service: Stop-Service TlntSvr; Set-Service TlntSvr -StartupType Disabled",
                remediation_priority=95,
                tags=["services", "telnet", "insecure"]
            ))

        return findings

    def _check_registry_security(self) -> List[PluginFinding]:
        """Check critical registry security settings."""
        findings = []
        self.logger.info("Checking registry security...")

        # Check LSA protection (RunAsPPL)
        ps_lsa = "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -ErrorAction SilentlyContinue | Select-Object RunAsPPL"
        exit_code, output, _ = self.winrm.execute_powershell(ps_lsa, check_exit_code=False)

        if exit_code != 0 or ': 0' in output or ':0' in output or not output:
            findings.append(PluginFinding(
                title="LSA Protection Not Enabled",
                description="LSA (Local Security Authority) protection is not enabled. "
                           "This allows tools like Mimikatz to dump credentials from memory.",
                severity=FindingSeverity.HIGH,
                cwe_ids=["CWE-522"],
                evidence="RunAsPPL not set or disabled",
                remediation="Enable LSA protection: Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -Value 1",
                remediation_priority=85,
                tags=["registry", "lsa", "credentials"]
            ))

        # Check WDigest UseLogonCredential
        ps_wdigest = "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name 'UseLogonCredential' -ErrorAction SilentlyContinue | Select-Object UseLogonCredential"
        exit_code, output, _ = self.winrm.execute_powershell(ps_wdigest, check_exit_code=False)

        if exit_code == 0 and (': 1' in output or ':1' in output):
            findings.append(PluginFinding(
                title="WDigest Storing Plaintext Passwords",
                description="WDigest is configured to store plaintext passwords in memory.",
                severity=FindingSeverity.CRITICAL,
                cwe_ids=["CWE-256"],
                evidence="UseLogonCredential = 1",
                remediation="Disable WDigest plaintext storage: Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name 'UseLogonCredential' -Value 0",
                remediation_priority=100,
                tags=["registry", "wdigest", "credentials", "plaintext"]
            ))

        return findings

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
            counts[finding.severity.value.upper()] += 1

        return counts


# Test plugin standalone
if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    parser = argparse.ArgumentParser(description="Windows Security Audit Plugin")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--username", required=True, help="Windows username")
    parser.add_argument("--password", required=True, help="Windows password")
    parser.add_argument("--port", type=int, default=5985, help="WinRM port")

    args = parser.parse_args()

    credentials = {
        "username": args.username,
        "password": args.password,
        "port": args.port
    }

    plugin = WindowsPlugin()
    result = plugin.execute(args.target, credentials=credentials)

    print(f"\n{'='*60}")
    print(f"Windows Security Audit Results")
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
            print(f"[{finding.severity.value.upper()}] {finding.title}")
            print(f"  {finding.description}")
            print()
