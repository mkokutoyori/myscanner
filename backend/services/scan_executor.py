"""
Scan Executor Service

Executes vulnerability scans using plugins.
For POC: Synchronous execution.
For Production: This logic should move to Celery tasks.
"""
import logging
from typing import Dict, Any
from sqlalchemy.orm import Session
from datetime import datetime

from backend.models import Scan, Asset, Finding, Credential, AssetType, FindingSeverity

logger = logging.getLogger(__name__)


def execute_vulnerability_scan_sync(scan_id: int, db: Session) -> Dict[str, Any]:
    """
    Execute a vulnerability scan synchronously (POC only).

    Args:
        scan_id: ID of scan to execute
        db: Database session

    Returns:
        Dictionary with execution results

    Raises:
        Exception: If scan execution fails
    """
    logger.info(f"Starting vulnerability scan {scan_id}")

    # Get scan
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise Exception(f"Scan {scan_id} not found")

    # Get credential
    credential_id = scan.plugin_config.get("credential_id")
    if not credential_id:
        raise Exception("No credential_id in scan config")

    credential = db.query(Credential).filter(Credential.id == credential_id).first()
    if not credential:
        raise Exception(f"Credential {credential_id} not found")

    # Retrieve credential secrets
    from backend.api.credentials import _get_credential_secrets_internal
    secrets = _get_credential_secrets_internal(credential)

    # Prepare credential dict for plugin
    plugin_credentials = {
        "username": secrets.get("username"),
        "password": secrets.get("password"),
        "private_key": secrets.get("private_key"),
    }

    # Load plugins
    from backend.services.plugin_loader import PluginLoader
    loader = PluginLoader()
    loader.discover_plugins()

    assets_scanned = 0
    findings_created = 0

    # Scan each target
    for target in scan.targets:
        logger.info(f"Scanning target {target}")

        try:
            # Determine which plugin to use
            plugin_name = scan.plugin_name
            plugin_instance = None

            if not plugin_name and scan.plugin_config.get("auto_detect_distro"):
                # Auto-detect distribution
                logger.info(f"Auto-detecting distribution for {target}")
                plugin_name = _detect_and_select_plugin(target, plugin_credentials, loader)

            if plugin_name:
                plugin_instance = loader.get_plugin_instance(plugin_name)

            if not plugin_instance:
                logger.error(f"No plugin available for target {target}")
                continue

            logger.info(f"Using plugin {plugin_name} for {target}")

            # Execute plugin
            result = plugin_instance.execute(
                target=target,
                credentials=plugin_credentials
            )

            if not result.success:
                logger.error(f"Plugin execution failed for {target}: {result.error_message}")
                continue

            # Store/update asset
            asset = _store_or_update_asset(target, result, db)
            assets_scanned += 1

            # Store findings
            for finding in result.findings:
                db_finding = Finding(
                    scan_id=scan.id,
                    asset_id=asset.id,
                    title=finding.title,
                    description=finding.description,
                    severity=finding.severity,
                    cve_ids=finding.cve_ids or [],
                    cwe_ids=finding.cwe_ids or [],
                    cvss_score=finding.cvss_score,
                    affected_service=finding.affected_service,
                    affected_port=finding.affected_port,
                    evidence=finding.evidence,
                    remediation=finding.remediation,
                    remediation_priority=finding.remediation_priority,
                    plugin_name=plugin_name,
                    tags=finding.tags or []
                )
                db.add(db_finding)
                findings_created += 1

            db.commit()
            logger.info(f"Stored {len(result.findings)} findings for {target}")

        except Exception as e:
            logger.error(f"Error scanning target {target}: {e}", exc_info=True)
            db.rollback()
            continue

    logger.info(f"Scan {scan_id} completed: {assets_scanned} assets, {findings_created} findings")

    return {
        "assets_scanned": assets_scanned,
        "findings_created": findings_created
    }


def _detect_and_select_plugin(target: str, credentials: Dict[str, Any], loader: PluginLoader) -> str:
    """
    Auto-detect Linux distribution and select appropriate plugin.

    Args:
        target: Target IP or hostname
        credentials: SSH credentials
        loader: Plugin loader instance

    Returns:
        Plugin name to use

    Raises:
        Exception: If detection fails
    """
    from backend.plugins.detectors.distro_detector import detect_distribution, DistroFamily
    from vulnscan_sdk.ssh_helper import SSHHelper

    ssh = SSHHelper(logger)

    try:
        # Connect via SSH
        connected = ssh.connect(
            host=target,
            username=credentials.get("username"),
            password=credentials.get("password"),
            private_key=credentials.get("private_key"),
            timeout=30
        )

        if not connected:
            raise Exception(f"Failed to connect to {target}")

        # Detect distribution
        distro_info = detect_distribution(ssh)

        # Select plugin based on distribution family
        if distro_info.family == DistroFamily.DEBIAN:
            return "ubuntu-security-audit"
        elif distro_info.family == DistroFamily.REDHAT:
            return "rhel-security-audit"
        else:
            raise Exception(f"No plugin available for distribution family: {distro_info.family.value}")

    finally:
        ssh.disconnect()


def _store_or_update_asset(target: str, result, db: Session) -> Asset:
    """
    Store or update asset information from scan result.

    Args:
        target: Target IP or hostname
        result: Plugin execution result
        db: Database session

    Returns:
        Asset object
    """
    # Get asset info from result
    if result.assets and len(result.assets) > 0:
        asset_info = result.assets[0]
    else:
        asset_info = None

    # Check if asset exists
    asset = db.query(Asset).filter(Asset.ip_address == target).first()

    if asset:
        # Update existing asset
        if asset_info:
            asset.hostname = asset_info.hostname or asset.hostname
            asset.os_family = asset_info.os_family or asset.os_family
            asset.os_version = asset_info.os_version or asset.os_version
            asset.vendor = asset_info.vendor or asset.vendor
            asset.asset_metadata = asset_info.metadata or asset.asset_metadata
        asset.last_seen = datetime.utcnow()
        asset.is_active = True
    else:
        # Create new asset
        asset = Asset(
            ip_address=target,
            hostname=asset_info.hostname if asset_info else None,
            asset_type=AssetType.LINUX,  # We know it's Linux from the plugin
            os_family=asset_info.os_family if asset_info else "Linux",
            os_version=asset_info.os_version if asset_info else None,
            vendor=asset_info.vendor if asset_info else None,
            asset_metadata=asset_info.metadata if asset_info else {},
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            is_active=True
        )
        db.add(asset)

    db.commit()
    db.refresh(asset)

    return asset


def _get_credential_secrets_internal(credential: Credential) -> Dict[str, Any]:
    """
    Internal function to get credential secrets (used by scan executor).

    Args:
        credential: Credential object

    Returns:
        Dictionary of secrets
    """
    import base64
    import json
    from cryptography.fernet import Fernet
    from backend.core.config import settings

    # Try Vault first
    if credential.vault_path:
        try:
            from backend.services.vault_service import get_credential_secrets
            return get_credential_secrets(credential.vault_path)
        except:
            pass

    # Fallback: decrypt from DB
    if credential.encrypted_secrets:
        key = base64.urlsafe_b64encode(settings.SECRET_KEY[:32].encode().ljust(32)[:32])
        fernet = Fernet(key)

        try:
            decrypted = fernet.decrypt(credential.encrypted_secrets.encode())
            secrets = json.loads(decrypted.decode())
            return secrets
        except Exception as e:
            raise Exception(f"Failed to decrypt secrets: {str(e)}")

    raise Exception("No secrets available")


# Make this function available to credentials API
def get_credential_secrets_for_api(credential: Credential) -> Dict[str, Any]:
    """Wrapper for API to get credential secrets"""
    return _get_credential_secrets_internal(credential)
