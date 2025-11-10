"""
Discovery Scanner
Implements network discovery using masscan and nmap
"""
import nmap
import subprocess
import json
import logging
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from datetime import datetime

from backend.models import Asset, Finding, Scan, ScanAsset, AssetType, FindingSeverity
from backend.core.config import settings

logger = logging.getLogger(__name__)


def execute_discovery_scan(scan_id: int, db: Session) -> Dict[str, Any]:
    """
    Execute discovery scan using masscan for fast port discovery
    followed by nmap for detailed service detection

    Args:
        scan_id: ID of the scan
        db: Database session

    Returns:
        Dictionary with scan results
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise ValueError(f"Scan {scan_id} not found")

    results = {
        "assets_discovered": 0,
        "findings_count": 0,
        "hosts": []
    }

    # For POC, use nmap directly (masscan requires root and may not be available)
    # In production, use masscan for initial discovery, then nmap for deep scan
    logger.info(f"Starting discovery scan for targets: {scan.targets}")

    for target in scan.targets:
        logger.info(f"Scanning target: {target}")

        try:
            # Use python-nmap for POC
            nm = nmap.PortScanner()

            # Perform scan with service detection
            # Arguments: -sV (service detection), -O (OS detection), -T4 (timing)
            nm.scan(
                hosts=target,
                arguments=f"-sV -T{settings.NMAP_TIMING.replace('T', '')} --top-ports 1000"
            )

            # Process results for each host
            for host in nm.all_hosts():
                logger.info(f"Processing host: {host}")

                host_data = nm[host]
                hostname = host_data.hostname() if host_data.hostname() else None

                # Detect OS
                os_family = None
                os_version = None
                vendor = None

                if 'osmatch' in host_data and len(host_data['osmatch']) > 0:
                    os_match = host_data['osmatch'][0]
                    os_family = os_match.get('name', 'Unknown')
                    os_version = os_match.get('accuracy', 'Unknown')

                # Extract open ports and services
                open_ports = []
                services = {}

                if 'tcp' in host_data:
                    for port, port_data in host_data['tcp'].items():
                        if port_data['state'] == 'open':
                            open_ports.append(port)
                            services[str(port)] = {
                                'service': port_data.get('name', 'unknown'),
                                'product': port_data.get('product', ''),
                                'version': port_data.get('version', ''),
                                'extrainfo': port_data.get('extrainfo', '')
                            }

                # Determine asset type based on services
                asset_type = determine_asset_type(services, os_family)

                # Create or update asset
                asset = db.query(Asset).filter(Asset.ip_address == host).first()

                if asset:
                    # Update existing asset
                    asset.hostname = hostname
                    asset.asset_type = asset_type
                    asset.os_family = os_family
                    asset.os_version = os_version
                    asset.vendor = vendor
                    asset.open_ports = open_ports
                    asset.services = services
                    asset.last_seen = datetime.utcnow()
                    asset.is_active = True
                else:
                    # Create new asset
                    asset = Asset(
                        ip_address=host,
                        hostname=hostname,
                        asset_type=asset_type,
                        os_family=os_family,
                        os_version=os_version,
                        vendor=vendor,
                        open_ports=open_ports,
                        services=services,
                        is_active=True
                    )
                    db.add(asset)

                db.commit()
                db.refresh(asset)

                # Associate asset with scan
                scan_asset = ScanAsset(scan_id=scan.id, asset_id=asset.id)
                db.add(scan_asset)
                db.commit()

                results["assets_discovered"] += 1
                results["hosts"].append({
                    "ip": host,
                    "hostname": hostname,
                    "open_ports": len(open_ports),
                    "services": len(services)
                })

                # Create findings for interesting discoveries
                findings = analyze_services(asset, services, scan.id, db)
                results["findings_count"] += len(findings)

                logger.info(f"Host {host}: {len(open_ports)} open ports, {len(findings)} findings")

        except Exception as e:
            logger.error(f"Error scanning target {target}: {str(e)}", exc_info=True)
            # Continue with next target

    logger.info(f"Discovery scan completed: {results['assets_discovered']} assets, {results['findings_count']} findings")

    return results


def determine_asset_type(services: Dict[str, Any], os_family: Optional[str]) -> AssetType:
    """
    Determine asset type based on discovered services and OS

    Args:
        services: Dictionary of services
        os_family: Detected OS family

    Returns:
        AssetType enum
    """
    # Check for database services
    db_ports = {'1433', '1521', '3306', '5432', '27017'}
    if any(port in services for port in db_ports):
        return AssetType.DATABASE

    # Check for web services
    web_ports = {'80', '443', '8080', '8443'}
    if any(port in services for port in web_ports):
        return AssetType.WEB_APPLICATION

    # Check for Windows services
    windows_ports = {'135', '139', '445', '3389'}
    if any(port in services for port in windows_ports):
        return AssetType.WINDOWS

    # Check for SSH (Linux)
    if '22' in services:
        return AssetType.LINUX

    # Check for network device indicators
    network_ports = {'23', '161', '162', '830'}  # Telnet, SNMP, NETCONF
    if any(port in services for port in network_ports):
        return AssetType.NETWORK_DEVICE

    # Check OS family
    if os_family:
        os_lower = os_family.lower()
        if 'windows' in os_lower:
            return AssetType.WINDOWS
        elif 'linux' in os_lower or 'unix' in os_lower:
            return AssetType.LINUX
        elif any(vendor in os_lower for vendor in ['cisco', 'juniper', 'huawei', 'palo alto']):
            return AssetType.NETWORK_DEVICE

    return AssetType.HOST


def analyze_services(asset: Asset, services: Dict[str, Any], scan_id: int, db: Session) -> List[Finding]:
    """
    Analyze discovered services and create findings for potential vulnerabilities

    Args:
        asset: Asset object
        services: Dictionary of services
        scan_id: Scan ID
        db: Database session

    Returns:
        List of created findings
    """
    findings = []

    # Check for common vulnerabilities
    for port, service_data in services.items():
        service_name = service_data.get('service', '').lower()
        version = service_data.get('version', '')

        # Telnet (unencrypted)
        if service_name == 'telnet':
            finding = Finding(
                scan_id=scan_id,
                asset_id=asset.id,
                title="Unencrypted Telnet Service Detected",
                description=f"Telnet service is running on port {port}. Telnet transmits data in plaintext, including credentials.",
                severity=FindingSeverity.HIGH,
                affected_service='telnet',
                affected_port=int(port),
                remediation="Disable Telnet and use SSH instead for secure remote access.",
                plugin_name='discovery',
                cve_ids=[],
                cwe_ids=['CWE-319']
            )
            db.add(finding)
            findings.append(finding)

        # FTP (unencrypted)
        if service_name == 'ftp':
            finding = Finding(
                scan_id=scan_id,
                asset_id=asset.id,
                title="Unencrypted FTP Service Detected",
                description=f"FTP service is running on port {port}. FTP transmits credentials and data in plaintext.",
                severity=FindingSeverity.MEDIUM,
                affected_service='ftp',
                affected_port=int(port),
                remediation="Disable FTP and use SFTP or FTPS instead.",
                plugin_name='discovery',
                cve_ids=[],
                cwe_ids=['CWE-319']
            )
            db.add(finding)
            findings.append(finding)

        # SMBv1 (vulnerable)
        if service_name == 'microsoft-ds' and '445' in services:
            finding = Finding(
                scan_id=scan_id,
                asset_id=asset.id,
                title="SMB Service Detected (Potential SMBv1)",
                description=f"SMB service detected on port {port}. SMBv1 is vulnerable to EternalBlue and other attacks.",
                severity=FindingSeverity.HIGH,
                affected_service='smb',
                affected_port=int(port),
                remediation="Disable SMBv1 and ensure only SMBv2/SMBv3 are enabled.",
                plugin_name='discovery',
                cve_ids=['CVE-2017-0144'],
                cwe_ids=['CWE-20']
            )
            db.add(finding)
            findings.append(finding)

        # Outdated SSH versions
        if service_name == 'ssh' and version:
            if 'openssh' in version.lower():
                # Extract version number
                import re
                match = re.search(r'(\d+\.\d+)', version)
                if match:
                    ver = float(match.group(1))
                    if ver < 7.4:
                        finding = Finding(
                            scan_id=scan_id,
                            asset_id=asset.id,
                            title="Outdated SSH Server Version",
                            description=f"SSH server version {version} is outdated and may contain known vulnerabilities.",
                            severity=FindingSeverity.MEDIUM,
                            affected_service='ssh',
                            affected_port=int(port),
                            remediation="Update SSH server to the latest version.",
                            plugin_name='discovery',
                            evidence=version
                        )
                        db.add(finding)
                        findings.append(finding)

        # RDP exposed
        if service_name == 'ms-wbt-server' or port == '3389':
            finding = Finding(
                scan_id=scan_id,
                asset_id=asset.id,
                title="RDP Service Exposed",
                description=f"Remote Desktop Protocol (RDP) is exposed on port {port}. RDP is frequently targeted for brute-force attacks.",
                severity=FindingSeverity.MEDIUM,
                affected_service='rdp',
                affected_port=int(port),
                remediation="Restrict RDP access to specific IP addresses, use VPN, enable NLA, and implement strong passwords.",
                plugin_name='discovery'
            )
            db.add(finding)
            findings.append(finding)

    db.commit()

    return findings


def run_masscan(targets: List[str], rate: int = 1000) -> Dict[str, List[int]]:
    """
    Run masscan for fast port discovery (requires root privileges)

    Args:
        targets: List of target IP ranges
        rate: Scan rate (packets per second)

    Returns:
        Dictionary mapping IP addresses to lists of open ports
    """
    # Note: This is a placeholder. Masscan requires root privileges
    # In production, run this in a privileged container
    logger.warning("Masscan not implemented in POC - using nmap instead")
    return {}
