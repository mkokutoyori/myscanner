"""
Microsoft Services Security Audit Plugin

Scans Microsoft services for security vulnerabilities:
- IIS (Internet Information Services)
- SQL Server
- Exchange Server
- SharePoint
"""
import logging
import json
import re
from typing import List, Dict, Any, Optional
import sys
import os

SDK_PATH = os.path.join(os.path.dirname(__file__), '../../../sdk/python')
sys.path.insert(0, SDK_PATH)

from vulnscan_sdk import (
    BasePlugin, PluginType, PluginResult, PluginFinding,
    FindingSeverity, PluginAsset, PluginConfig
)

try:
    from vulnscan_sdk.winrm_helper import WinRMHelper
    WINRM_AVAILABLE = True
except ImportError:
    WINRM_AVAILABLE = False


class MicrosoftServicesPlugin(BasePlugin):
    """Microsoft Services (IIS, SQL, Exchange) security audit plugin."""

    name = "microsoft-services-audit"
    version = "1.0.0"
    description = "Security audit for Microsoft services (IIS, SQL Server, Exchange)"
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

    def execute(
        self,
        target: str,
        config: Optional[PluginConfig] = None,
        credentials: Optional[Dict[str, Any]] = None
    ) -> PluginResult:
        if not WINRM_AVAILABLE:
            return PluginResult(success=False, error_message="pywinrm not installed")

        self.logger.info(f"Starting Microsoft services audit on {target}")
        findings: List[PluginFinding] = []

        if not credentials:
            return PluginResult(success=False, error_message="Credentials required")

        self.winrm = WinRMHelper(self.logger)

        try:
            self.winrm.connect(
                host=target,
                username=credentials['username'],
                password=credentials['password'],
                port=credentials.get('port', 5985)
            )

            # Check each service
            findings.extend(self._check_iis())
            findings.extend(self._check_sql_server())
            findings.extend(self._check_exchange())
            findings.extend(self._check_sharepoint())

            return PluginResult(
                success=True,
                findings=findings,
                stats={"total_findings": len(findings)}
            )

        except Exception as e:
            self.logger.error(f"Services audit failed: {e}")
            return PluginResult(success=False, error_message=str(e), findings=findings)
        finally:
            if self.winrm:
                self.winrm.disconnect()

    def _check_iis(self) -> List[PluginFinding]:
        """Check IIS security."""
        findings = []
        self.logger.info("Checking IIS...")

        # Check if IIS is installed
        ps_iis = "Get-Service -Name W3SVC -ErrorAction SilentlyContinue | Select-Object Status"
        exit_code, output, _ = self.winrm.execute_powershell(ps_iis, check_exit_code=False)

        if exit_code != 0 or 'Running' not in output:
            return findings

        # Check default web site
        ps_default = "Get-Website -Name 'Default Web Site' -ErrorAction SilentlyContinue | Select-Object State"
        exit_code, output, _ = self.winrm.execute_powershell(ps_default, check_exit_code=False)

        if exit_code == 0 and 'Started' in output:
            findings.append(PluginFinding(
                title="IIS Default Website Running",
                description="The default IIS website is running. This may expose sensitive information.",
                severity=FindingSeverity.MEDIUM,
                affected_service="IIS",
                affected_port=80,
                evidence="Default Web Site is running",
                remediation="Stop and remove the default website if not needed",
                remediation_priority=50,
                tags=["iis", "web", "default-config"]
            ))

        # Check directory browsing
        ps_browse = "Get-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -PSPath 'IIS:\' -ErrorAction SilentlyContinue | Select-Object Value"
        exit_code, output, _ = self.winrm.execute_powershell(ps_browse, check_exit_code=False)

        if exit_code == 0 and 'True' in output:
            findings.append(PluginFinding(
                title="IIS Directory Browsing Enabled",
                description="Directory browsing is enabled, allowing attackers to view directory contents.",
                severity=FindingSeverity.MEDIUM,
                affected_service="IIS",
                evidence="Directory browsing enabled",
                remediation="Disable directory browsing: Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value False",
                remediation_priority=60,
                tags=["iis", "web", "directory-browsing"]
            ))

        # Check for WebDAV
        ps_webdav = "Get-WindowsFeature -Name Web-DAV-Publishing -ErrorAction SilentlyContinue | Select-Object Installed"
        exit_code, output, _ = self.winrm.execute_powershell(ps_webdav, check_exit_code=False)

        if exit_code == 0 and 'True' in output:
            findings.append(PluginFinding(
                title="IIS WebDAV Enabled",
                description="WebDAV is enabled and may be vulnerable to CVE-2017-7269 (buffer overflow).",
                severity=FindingSeverity.HIGH,
                cve_ids=["CVE-2017-7269"],
                affected_service="IIS WebDAV",
                evidence="WebDAV feature is installed",
                remediation="Disable WebDAV if not required: Uninstall-WindowsFeature Web-DAV-Publishing",
                remediation_priority=80,
                tags=["iis", "webdav", "cve-2017-7269"]
            ))

        return findings

    def _check_sql_server(self) -> List[PluginFinding]:
        """Check SQL Server security."""
        findings = []
        self.logger.info("Checking SQL Server...")

        # Check if SQL Server is running
        ps_sql = "Get-Service -Name MSSQLSERVER -ErrorAction SilentlyContinue | Select-Object Status"
        exit_code, output, _ = self.winrm.execute_powershell(ps_sql, check_exit_code=False)

        if exit_code != 0 or 'Running' not in output:
            return findings

        # Check if sa account is enabled (requires sqlcmd)
        ps_sa = "sqlcmd -Q \"SELECT name, is_disabled FROM sys.sql_logins WHERE name = 'sa'\" -ErrorAction SilentlyContinue"
        exit_code, output, _ = self.winrm.execute_powershell(ps_sa, check_exit_code=False)

        if exit_code == 0 and output:
            if 'sa' in output and '0' in output:  # 0 means enabled
                findings.append(PluginFinding(
                    title="SQL Server 'sa' Account Enabled",
                    description="The 'sa' account is enabled. This is a high-value target for attackers.",
                    severity=FindingSeverity.HIGH,
                    affected_service="SQL Server",
                    affected_port=1433,
                    evidence="sa account is enabled",
                    remediation="Disable sa account: ALTER LOGIN sa DISABLE",
                    remediation_priority=85,
                    tags=["sql-server", "sa-account", "authentication"]
                ))

        # Check SQL Server authentication mode
        ps_auth = "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\MSSQL*.MSSQLSERVER\\MSSQLServer' -Name LoginMode -ErrorAction SilentlyContinue | Select-Object LoginMode"
        exit_code, output, _ = self.winrm.execute_powershell(ps_auth, check_exit_code=False)

        if exit_code == 0 and output:
            # LoginMode 2 = Mixed Mode (SQL + Windows)
            if ': 2' in output or ':2' in output:
                findings.append(PluginFinding(
                    title="SQL Server Mixed Mode Authentication",
                    description="SQL Server uses Mixed Mode authentication. Windows Authentication only is more secure.",
                    severity=FindingSeverity.MEDIUM,
                    affected_service="SQL Server",
                    evidence="Mixed mode authentication enabled",
                    remediation="Use Windows Authentication Mode only if possible",
                    remediation_priority=60,
                    tags=["sql-server", "authentication"]
                ))

        # Check for xp_cmdshell
        ps_cmdshell = "sqlcmd -Q \"SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM sys.configurations WHERE name = 'xp_cmdshell'\" -ErrorAction SilentlyContinue"
        exit_code, output, _ = self.winrm.execute_powershell(ps_cmdshell, check_exit_code=False)

        if exit_code == 0 and '1' in output:
            findings.append(PluginFinding(
                title="SQL Server xp_cmdshell Enabled",
                description="xp_cmdshell is enabled, allowing OS command execution from SQL Server.",
                severity=FindingSeverity.CRITICAL,
                cwe_ids=["CWE-78"],
                affected_service="SQL Server",
                evidence="xp_cmdshell is enabled",
                remediation="Disable xp_cmdshell: EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE",
                remediation_priority=95,
                tags=["sql-server", "xp_cmdshell", "command-execution"]
            ))

        return findings

    def _check_exchange(self) -> List[PluginFinding]:
        """Check Exchange Server security."""
        findings = []
        self.logger.info("Checking Exchange Server...")

        # Check if Exchange is installed
        ps_exchange = "Get-Service -Name MSExchangeServiceHost -ErrorAction SilentlyContinue | Select-Object Status"
        exit_code, output, _ = self.winrm.execute_powershell(ps_exchange, check_exit_code=False)

        if exit_code != 0:
            return findings

        # Get Exchange version
        ps_version = "Get-Command Exsetup.exe -ErrorAction SilentlyContinue | ForEach-Object {$_.FileVersionInfo} | Select-Object ProductVersion"
        exit_code, version_output, _ = self.winrm.execute_powershell(ps_version, check_exit_code=False)

        # Check for ProxyLogon/ProxyShell vulnerabilities
        findings.append(PluginFinding(
            title="Exchange Server Requires Security Patch Verification",
            description="Exchange Server detected. Verify it's patched against ProxyLogon (CVE-2021-26855 series) and ProxyShell vulnerabilities.",
            severity=FindingSeverity.CRITICAL,
            cve_ids=["CVE-2021-26855", "CVE-2021-26857", "CVE-2021-26858", "CVE-2021-27065",
                     "CVE-2021-34473", "CVE-2021-34523", "CVE-2021-31207"],
            affected_service="Exchange Server",
            affected_port=443,
            evidence=f"Exchange Server detected, version: {version_output[:100] if version_output else 'Unknown'}",
            remediation="Apply latest Exchange Security Updates. Use Microsoft Exchange On-Premises Mitigation Tool. https://aka.ms/ExchangeEOMT",
            remediation_priority=100,
            tags=["exchange", "proxylogon", "proxyshell"]
        ))

        # Check OWA external access
        ps_owa = "Get-OwaVirtualDirectory -ErrorAction SilentlyContinue | Where-Object {$_.ExternalUrl -ne $null} | Select-Object Name, ExternalUrl"
        exit_code, output, _ = self.winrm.execute_powershell(ps_owa, check_exit_code=False)

        if exit_code == 0 and output and 'http://' in output.lower():
            findings.append(PluginFinding(
                title="Exchange OWA Using HTTP",
                description="Outlook Web Access is configured with HTTP (not HTTPS).",
                severity=FindingSeverity.HIGH,
                affected_service="Exchange OWA",
                affected_port=80,
                evidence="OWA ExternalUrl uses HTTP",
                remediation="Configure OWA to use HTTPS only",
                remediation_priority=85,
                tags=["exchange", "owa", "encryption"]
            ))

        return findings

    def _check_sharepoint(self) -> List[PluginFinding]:
        """Check SharePoint security."""
        findings = []
        self.logger.info("Checking SharePoint...")

        # Check if SharePoint is installed
        ps_sp = "Get-Service -Name SPTimerV4 -ErrorAction SilentlyContinue | Select-Object Status"
        exit_code, output, _ = self.winrm.execute_powershell(ps_sp, check_exit_code=False)

        if exit_code != 0:
            return findings

        findings.append(PluginFinding(
            title="SharePoint Server Detected",
            description="SharePoint Server is installed. Ensure it's fully patched and follows security best practices.",
            severity=FindingSeverity.INFO,
            affected_service="SharePoint",
            evidence="SharePoint Timer Service detected",
            remediation="Keep SharePoint updated. Review permissions, disable anonymous access, enable MFA, review add-ins.",
            tags=["sharepoint", "configuration"]
        ))

        return findings


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    print("Microsoft Services Security Audit Plugin")
    print("Use via VulnScan Platform API with proper credentials.")
