"""
SQLAlchemy ORM Models
Defines database schema for assets, scans, findings, etc.
"""
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean,
    ForeignKey, JSON, Enum as SQLEnum, Float
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
import enum
from .database import Base


# Enums
class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str, enum.Enum):
    DISCOVERY = "discovery"
    VULNERABILITY = "vulnerability"
    AUTHENTICATED = "authenticated"
    CONFIGURATION = "configuration"
    INTRUSIVE = "intrusive"
    EXPLOIT = "exploit"


class FindingSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AssetType(str, enum.Enum):
    HOST = "host"
    NETWORK_DEVICE = "network_device"
    DATABASE = "database"
    WEB_APPLICATION = "web_application"
    ACTIVE_DIRECTORY = "active_directory"
    WINDOWS = "windows"
    LINUX = "linux"
    UNKNOWN = "unknown"


class ApprovalStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


# Models
class Asset(Base):
    """Represents a discovered asset (host, device, application, etc.)"""
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), index=True, nullable=False)  # Support IPv6
    hostname = Column(String(255), index=True, nullable=True)
    mac_address = Column(String(17), nullable=True)
    asset_type = Column(SQLEnum(AssetType), default=AssetType.UNKNOWN)

    # Asset details
    os_family = Column(String(100), nullable=True)
    os_version = Column(String(255), nullable=True)
    vendor = Column(String(255), nullable=True)
    model = Column(String(255), nullable=True)

    # Network information
    open_ports = Column(JSON, default=list)  # List of open ports
    services = Column(JSON, default=dict)  # Port -> service mapping

    # Metadata
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), onupdate=func.now())
    is_active = Column(Boolean, default=True)
    tags = Column(JSON, default=list)
    metadata = Column(JSON, default=dict)  # Additional flexible data

    # Relationships
    scans = relationship("Scan", back_populates="assets", secondary="scan_assets")
    findings = relationship("Finding", back_populates="asset")
    credentials = relationship("Credential", back_populates="asset")


class Scan(Base):
    """Represents a scan job"""
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    scan_type = Column(SQLEnum(ScanType), nullable=False)
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING, index=True)

    # Scan configuration
    targets = Column(JSON, nullable=False)  # IP ranges, hostnames, etc.
    plugin_name = Column(String(100), nullable=True)
    plugin_config = Column(JSON, default=dict)

    # Timing
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Results
    total_assets = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)

    # Celery task tracking
    celery_task_id = Column(String(255), nullable=True, index=True)

    # User tracking
    created_by = Column(String(255), nullable=True)

    # Approval (for intrusive scans)
    requires_approval = Column(Boolean, default=False)
    approval_status = Column(SQLEnum(ApprovalStatus), nullable=True)
    approved_by = Column(String(255), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    assets = relationship("Asset", back_populates="scans", secondary="scan_assets")
    findings = relationship("Finding", back_populates="scan")


class ScanAsset(Base):
    """Association table between Scans and Assets"""
    __tablename__ = "scan_assets"

    scan_id = Column(Integer, ForeignKey("scans.id"), primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), primary_key=True)
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())


class Finding(Base):
    """Represents a security finding (vulnerability, misconfiguration, etc.)"""
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)

    # References
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)

    # Finding details
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(SQLEnum(FindingSeverity), nullable=False, index=True)

    # Vulnerability identifiers
    cve_ids = Column(JSON, default=list)  # List of CVE IDs
    cwe_ids = Column(JSON, default=list)  # List of CWE IDs
    cvss_score = Column(Float, nullable=True)

    # Technical details
    affected_service = Column(String(255), nullable=True)
    affected_port = Column(Integer, nullable=True)
    evidence = Column(Text, nullable=True)  # Proof of finding

    # Remediation
    remediation = Column(Text, nullable=True)
    remediation_priority = Column(Integer, default=0)

    # Status
    is_false_positive = Column(Boolean, default=False)
    is_resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    # Metadata
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())
    plugin_name = Column(String(100), nullable=True)
    raw_data = Column(JSON, default=dict)  # Original scanner output

    # Relationships
    scan = relationship("Scan", back_populates="findings")
    asset = relationship("Asset", back_populates="findings")


class Credential(Base):
    """Stores references to credentials in Vault (NOT the actual credentials!)"""
    __tablename__ = "credentials"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, unique=True)
    description = Column(Text, nullable=True)

    # Asset association
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)

    # Credential type
    credential_type = Column(String(50), nullable=False)  # ssh, winrm, snmp, db, etc.

    # Vault reference (NOT the actual credentials!)
    vault_path = Column(String(500), nullable=False)

    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    created_by = Column(String(255), nullable=True)

    # Relationships
    asset = relationship("Asset", back_populates="credentials")


class AuditLog(Base):
    """Immutable audit log for all actions"""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    # User information
    user_id = Column(String(255), nullable=False, index=True)
    user_email = Column(String(255), nullable=True)

    # Action details
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(100), nullable=False)
    resource_id = Column(String(255), nullable=True)

    # Request details
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)

    # Result
    success = Column(Boolean, nullable=False)
    error_message = Column(Text, nullable=True)

    # Additional context
    details = Column(JSON, default=dict)


class Plugin(Base):
    """Registry of available plugins"""
    __tablename__ = "plugins"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, unique=True, index=True)
    display_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    version = Column(String(50), nullable=False)

    # Plugin metadata
    author = Column(String(255), nullable=True)
    vendor = Column(String(100), nullable=True)  # cisco, juniper, linux, windows, etc.
    asset_types = Column(JSON, default=list)  # List of supported asset types

    # Configuration
    requires_authentication = Column(Boolean, default=False)
    is_intrusive = Column(Boolean, default=False)
    config_schema = Column(JSON, default=dict)  # JSON schema for plugin config

    # Status
    is_enabled = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)  # Signed/verified plugin

    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


# Create indices for common queries
from sqlalchemy import Index

Index('idx_finding_severity_asset', Finding.severity, Finding.asset_id)
Index('idx_scan_status_created', Scan.status, Scan.created_at)
Index('idx_asset_type_active', Asset.asset_type, Asset.is_active)
