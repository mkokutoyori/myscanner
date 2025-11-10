"""
Active Directory Security Audit Plugin

Scans Active Directory environments for security vulnerabilities including:
- LDAP/LDAPS security
- Kerberos vulnerabilities (Kerberoasting, AS-REP Roasting)
- Password policies
- Privileged accounts and groups
- Delegation issues
- GPO security
"""
import logging
import json
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
    from vulnscan_sdk.winrm_helper import WinRMHelper, WinRMConnectionError
    WINRM_AVAILABLE = True
except ImportError:
    WINRM_AVAILABLE = False


class ActiveDirectoryPlugin(BasePlugin):
    """Active Directory security audit plugin."""

    name = "active-directory-security-audit"
    version = "1.0.0"
    description = "Active Directory security audit for domain controllers"
    author = "VulnScan Platform"
    plugin_type = PluginType.VULNERABILITY
    vendor = "microsoft"
    requires_authentication = True
    is_intrusive = False
    is_safe = True
    supported_asset_types = ["windows", "domain-controller"]

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

        self.logger.info(f"Starting AD security audit on {target}")
        findings: List[PluginFinding] = []
        assets: List[PluginAsset] = []

        if not credentials or 'username' not in credentials:
            return PluginResult(success=False, error_message="Credentials required")

        self.winrm = WinRMHelper(self.logger)

        try:
            self.winrm.connect(
                host=target,
                username=credentials['username'],
                password=credentials['password'],
                port=credentials.get('port', 5985)
            )

            # Check if this is a Domain Controller
            ps_dc_check = "Get-Service -Name NTDS -ErrorAction SilentlyContinue | Select-Object Status"
            exit_code, output, _ = self.winrm.execute_powershell(ps_dc_check, check_exit_code=False)

            if exit_code != 0 or 'Running' not in output:
                return PluginResult(success=False, error_message="Not a Domain Controller")

            # Gather asset info
            _, hostname, _ = self.winrm.execute_command("hostname", check_exit_code=False)
            ps_domain = "(Get-ADDomain -ErrorAction SilentlyContinue).DNSRoot"
            _, domain, _ = self.winrm.execute_powershell(ps_domain, check_exit_code=False)

            assets.append(PluginAsset(
                ip_address=target,
                hostname=hostname.strip(),
                os_family="Windows",
                vendor="Microsoft",
                metadata={"role": "Domain Controller", "domain": domain.strip()}
            ))

            # Run AD security checks
            findings.extend(self._check_ldap_security())
            findings.extend(self._check_kerberos_security())
            findings.extend(self._check_password_policies())
            findings.extend(self._check_privileged_accounts())
            findings.extend(self._check_delegation())
            findings.extend(self._check_gpo_security())

            return PluginResult(
                success=True,
                findings=findings,
                assets=assets,
                stats={"total_findings": len(findings)}
            )

        except Exception as e:
            self.logger.error(f"AD audit failed: {e}")
            return PluginResult(success=False, error_message=str(e), findings=findings, assets=assets)
        finally:
            if self.winrm:
                self.winrm.disconnect()

    def _check_ldap_security(self) -> List[PluginFinding]:
        """Check LDAP/LDAPS configuration."""
        findings = []
        self.logger.info("Checking LDAP security...")

        # Check LDAP signing
        ps_signing = "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name 'LDAPServerIntegrity' -ErrorAction SilentlyContinue | Select-Object LDAPServerIntegrity"
        exit_code, output, _ = self.winrm.execute_powershell(ps_signing, check_exit_code=False)

        if exit_code == 0 and output:
            # 0 = None, 1 = Negotiate signing, 2 = Require signing
            if ':0' in output or ': 0' in output or ':1' in output or ': 1' in output:
                findings.append(PluginFinding(
                    title="LDAP Signing Not Required",
                    description="LDAP signing is not required. This allows man-in-the-middle attacks on LDAP traffic.",
                    severity=FindingSeverity.HIGH,
                    affected_service="LDAP",
                    affected_port=389,
                    evidence=f"LDAPServerIntegrity not set to 2 (require signing)",
                    remediation="Set LDAP signing to required: Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name 'LDAPServerIntegrity' -Value 2",
                    remediation_priority=85,
                    tags=["ldap", "signing", "mitm"]
                ))

        # Check LDAP channel binding
        ps_channel = "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name 'LdapEnforceChannelBinding' -ErrorAction SilentlyContinue | Select-Object LdapEnforceChannelBinding"
        exit_code, output, _ = self.winrm.execute_powershell(ps_channel, check_exit_code=False)

        if exit_code != 0 or ':0' in output or ': 0' in output or not output:
            findings.append(PluginFinding(
                title="LDAP Channel Binding Not Enforced",
                description="LDAP channel binding is not enforced, allowing relay attacks.",
                severity=FindingSeverity.HIGH,
                cve_ids=["CVE-2017-8563"],
                affected_service="LDAP",
                remediation="Enable LDAP channel binding: Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name 'LdapEnforceChannelBinding' -Value 2",
                remediation_priority=85,
                tags=["ldap", "channel-binding"]
            ))

        return findings

    def _check_kerberos_security(self) -> List[PluginFinding]:
        """Check Kerberos security."""
        findings = []
        self.logger.info("Checking Kerberos security...")

        # Check for accounts with PreAuth not required
        ps_preauth = "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth -ErrorAction SilentlyContinue | Select-Object SamAccountName | ConvertTo-Json"
        exit_code, output, _ = self.winrm.execute_powershell(ps_preauth, check_exit_code=False)

        if exit_code == 0 and output and output.strip() not in ['', '[]', 'null']:
            findings.append(PluginFinding(
                title="AS-REP Roasting Vulnerable Accounts Found",
                description="Accounts with 'Do not require Kerberos preauthentication' enabled are vulnerable to AS-REP Roasting.",
                severity=FindingSeverity.CRITICAL,
                evidence=output[:500],
                remediation="Disable 'Do not require Kerberos preauthentication' for all accounts",
                remediation_priority=95,
                tags=["kerberos", "as-rep-roasting", "T1558.004"]
            ))

        # Check for weak SPNs
        ps_spn = "Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName -ErrorAction SilentlyContinue | Measure-Object | Select-Object Count"
        exit_code, output, _ = self.winrm.execute_powershell(ps_spn, check_exit_code=False)

        if exit_code == 0 and output:
            count_match = re.search(r':\s*(\d+)', output)
            if count_match and int(count_match.group(1)) > 0:
                findings.append(PluginFinding(
                    title=f"Kerberoasting Risk - {count_match.group(1)} Service Accounts",
                    description=f"Found {count_match.group(1)} accounts with SPNs that may be vulnerable to Kerberoasting.",
                    severity=FindingSeverity.HIGH,
                    evidence=f"{count_match.group(1)} accounts with SPNs",
                    remediation="Ensure all service accounts use strong passwords (25+ characters) or use gMSAs",
                    remediation_priority=85,
                    tags=["kerberos", "kerberoasting", "T1558.003"]
                ))

        return findings

    def _check_password_policies(self) -> List[PluginFinding]:
        """Check domain password policies."""
        findings = []
        self.logger.info("Checking password policies...")

        ps_policy = "Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue | Select-Object MinPasswordLength, PasswordHistoryCount, MaxPasswordAge | ConvertTo-Json"
        exit_code, output, _ = self.winrm.execute_powershell(ps_policy, check_exit_code=False)

        if exit_code == 0 and output:
            try:
                policy = json.loads(output)
                min_length = policy.get('MinPasswordLength', 0)
                if min_length < 14:
                    findings.append(PluginFinding(
                        title=f"Weak Minimum Password Length ({min_length})",
                        description=f"Domain password policy requires only {min_length} characters. Recommended: 14+ characters.",
                        severity=FindingSeverity.HIGH,
                        cwe_ids=["CWE-521"],
                        evidence=f"MinPasswordLength: {min_length}",
                        remediation="Set minimum password length to 14: Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 14",
                        remediation_priority=85,
                        tags=["password-policy", "compliance"]
                    ))

                history = policy.get('PasswordHistoryCount', 0)
                if history < 24:
                    findings.append(PluginFinding(
                        title=f"Insufficient Password History ({history})",
                        description=f"Password history is set to {history}. Recommended: 24+.",
                        severity=FindingSeverity.MEDIUM,
                        evidence=f"PasswordHistoryCount: {history}",
                        remediation="Set password history to 24: Set-ADDefaultDomainPasswordPolicy -PasswordHistoryCount 24",
                        remediation_priority=60,
                        tags=["password-policy"]
                    ))
            except:
                pass

        return findings

    def _check_privileged_accounts(self) -> List[PluginFinding]:
        """Check privileged account security."""
        findings = []
        self.logger.info("Checking privileged accounts...")

        # Check Domain Admins
        ps_da = "Get-ADGroupMember -Identity 'Domain Admins' -ErrorAction SilentlyContinue | Measure-Object | Select-Object Count"
        exit_code, output, _ = self.winrm.execute_powershell(ps_da, check_exit_code=False)

        if exit_code == 0 and output:
            count_match = re.search(r':\s*(\d+)', output)
            if count_match and int(count_match.group(1)) > 5:
                findings.append(PluginFinding(
                    title=f"Excessive Domain Admins ({count_match.group(1)})",
                    description=f"Domain Admins group has {count_match.group(1)} members. Limit to essential accounts only.",
                    severity=FindingSeverity.HIGH,
                    cwe_ids=["CWE-250"],
                    evidence=f"{count_match.group(1)} Domain Admins",
                    remediation="Remove unnecessary accounts from Domain Admins group",
                    remediation_priority=80,
                    tags=["privileged-accounts", "domain-admins"]
                ))

        # Check for service accounts in privileged groups
        ps_svc = "Get-ADGroupMember -Identity 'Domain Admins' -ErrorAction SilentlyContinue | Where-Object {$_.SamAccountName -like '*svc*' -or $_.SamAccountName -like '*service*'} | Select-Object SamAccountName"
        exit_code, output, _ = self.winrm.execute_powershell(ps_svc, check_exit_code=False)

        if exit_code == 0 and output and output.strip() not in ['', 'null']:
            findings.append(PluginFinding(
                title="Service Accounts in Domain Admins",
                description="Service accounts found in Domain Admins group. This is a critical security risk.",
                severity=FindingSeverity.CRITICAL,
                evidence=output[:300],
                remediation="Remove service accounts from Domain Admins. Use gMSAs with minimal privileges.",
                remediation_priority=100,
                tags=["privileged-accounts", "service-accounts"]
            ))

        return findings

    def _check_delegation(self) -> List[PluginFinding]:
        """Check Kerberos delegation issues."""
        findings = []
        self.logger.info("Checking Kerberos delegation...")

        # Check unconstrained delegation
        ps_unconstrained = "Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation -ErrorAction SilentlyContinue | Select-Object Name | ConvertTo-Json"
        exit_code, output, _ = self.winrm.execute_powershell(ps_unconstrained, check_exit_code=False)

        if exit_code == 0 and output and output.strip() not in ['', '[]', 'null']:
            findings.append(PluginFinding(
                title="Unconstrained Delegation Enabled",
                description="Accounts with unconstrained delegation can impersonate any user to any service. This is a critical security risk.",
                severity=FindingSeverity.CRITICAL,
                cwe_ids=["CWE-269"],
                evidence=output[:500],
                remediation="Replace unconstrained delegation with constrained delegation or resource-based constrained delegation",
                remediation_priority=100,
                tags=["delegation", "unconstrained", "T1134"]
            ))

        return findings

    def _check_gpo_security(self) -> List[PluginFinding]:
        """Check GPO security."""
        findings = []
        self.logger.info("Checking GPO security...")

        # Check for GPP passwords (MS14-025)
        ps_gpp = "Get-ChildItem -Path '\\\\$env:USERDNSDOMAIN\\SYSVOL\\$env:USERDNSDOMAIN\\Policies' -Recurse -Include '*.xml' -ErrorAction SilentlyContinue | Select-String -Pattern 'cpassword' | Measure-Object | Select-Object Count"
        exit_code, output, _ = self.winrm.execute_powershell(ps_gpp, check_exit_code=False)

        if exit_code == 0 and output:
            count_match = re.search(r':\s*(\d+)', output)
            if count_match and int(count_match.group(1)) > 0:
                findings.append(PluginFinding(
                    title="GPP Passwords Found (MS14-025)",
                    description=f"Found {count_match.group(1)} instances of cpassword in GPO XML files. These can be easily decrypted.",
                    severity=FindingSeverity.CRITICAL,
                    cve_ids=["CVE-2014-1812"],
                    evidence=f"{count_match.group(1)} GPP password instances",
                    remediation="Remove all cpassword entries from GPO XML files. Use LAPS for local admin passwords.",
                    remediation_priority=100,
                    tags=["gpo", "gpp-passwords", "ms14-025"]
                ))

        return findings


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    print("Active Directory Security Audit Plugin")
    print("Use via VulnScan Platform API with proper credentials.")
