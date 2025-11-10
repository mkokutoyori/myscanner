"""
Assets API endpoints
Manage discovered assets (hosts, devices, applications, etc.)
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime

from backend.models import get_db, Asset, AssetType, Finding, FindingSeverity

router = APIRouter()


# Pydantic schemas for request/response
class AssetResponse(BaseModel):
    """Asset response schema"""
    id: int
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    asset_type: AssetType
    os_family: Optional[str] = None
    os_version: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    open_ports: List[int] = []
    services: dict = {}
    first_seen: datetime
    last_seen: Optional[datetime] = None
    is_active: bool
    tags: List[str] = []
    finding_count: Optional[int] = None
    critical_findings: Optional[int] = None

    class Config:
        from_attributes = True


class AssetListResponse(BaseModel):
    """Paginated asset list response"""
    total: int
    page: int
    page_size: int
    assets: List[AssetResponse]


class AssetCreate(BaseModel):
    """Create asset request"""
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    asset_type: AssetType = AssetType.UNKNOWN


@router.get("/assets", response_model=AssetListResponse)
async def list_assets(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    asset_type: Optional[AssetType] = None,
    is_active: Optional[bool] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    List all assets with pagination and filters

    - **page**: Page number (starting from 1)
    - **page_size**: Number of items per page (max 100)
    - **asset_type**: Filter by asset type
    - **is_active**: Filter by active status
    - **search**: Search by IP, hostname, or vendor
    """
    query = db.query(Asset)

    # Apply filters
    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)

    if is_active is not None:
        query = query.filter(Asset.is_active == is_active)

    if search:
        query = query.filter(
            or_(
                Asset.ip_address.ilike(f"%{search}%"),
                Asset.hostname.ilike(f"%{search}%"),
                Asset.vendor.ilike(f"%{search}%")
            )
        )

    # Count total
    total = query.count()

    # Paginate
    assets = query.order_by(desc(Asset.last_seen)).offset((page - 1) * page_size).limit(page_size).all()

    # Enrich with finding counts
    asset_responses = []
    for asset in assets:
        finding_count = db.query(Finding).filter(Finding.asset_id == asset.id).count()
        critical_findings = db.query(Finding).filter(
            Finding.asset_id == asset.id,
            Finding.severity == FindingSeverity.CRITICAL
        ).count()

        asset_dict = {
            "id": asset.id,
            "ip_address": asset.ip_address,
            "hostname": asset.hostname,
            "mac_address": asset.mac_address,
            "asset_type": asset.asset_type,
            "os_family": asset.os_family,
            "os_version": asset.os_version,
            "vendor": asset.vendor,
            "model": asset.model,
            "open_ports": asset.open_ports or [],
            "services": asset.services or {},
            "first_seen": asset.first_seen,
            "last_seen": asset.last_seen,
            "is_active": asset.is_active,
            "tags": asset.tags or [],
            "finding_count": finding_count,
            "critical_findings": critical_findings
        }
        asset_responses.append(AssetResponse(**asset_dict))

    return AssetListResponse(
        total=total,
        page=page,
        page_size=page_size,
        assets=asset_responses
    )


@router.get("/assets/{asset_id}", response_model=AssetResponse)
async def get_asset(asset_id: int, db: Session = Depends(get_db)):
    """
    Get asset by ID
    """
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    finding_count = db.query(Finding).filter(Finding.asset_id == asset.id).count()
    critical_findings = db.query(Finding).filter(
        Finding.asset_id == asset.id,
        Finding.severity == FindingSeverity.CRITICAL
    ).count()

    asset_dict = {
        "id": asset.id,
        "ip_address": asset.ip_address,
        "hostname": asset.hostname,
        "mac_address": asset.mac_address,
        "asset_type": asset.asset_type,
        "os_family": asset.os_family,
        "os_version": asset.os_version,
        "vendor": asset.vendor,
        "model": asset.model,
        "open_ports": asset.open_ports or [],
        "services": asset.services or {},
        "first_seen": asset.first_seen,
        "last_seen": asset.last_seen,
        "is_active": asset.is_active,
        "tags": asset.tags or [],
        "finding_count": finding_count,
        "critical_findings": critical_findings
    }

    return AssetResponse(**asset_dict)


@router.post("/assets", response_model=AssetResponse, status_code=201)
async def create_asset(asset_data: AssetCreate, db: Session = Depends(get_db)):
    """
    Create a new asset manually
    """
    # Check if asset already exists
    existing = db.query(Asset).filter(Asset.ip_address == asset_data.ip_address).first()
    if existing:
        raise HTTPException(status_code=409, detail="Asset with this IP already exists")

    asset = Asset(**asset_data.dict())
    db.add(asset)
    db.commit()
    db.refresh(asset)

    asset_dict = {
        "id": asset.id,
        "ip_address": asset.ip_address,
        "hostname": asset.hostname,
        "mac_address": asset.mac_address,
        "asset_type": asset.asset_type,
        "os_family": asset.os_family,
        "os_version": asset.os_version,
        "vendor": asset.vendor,
        "model": asset.model,
        "open_ports": asset.open_ports or [],
        "services": asset.services or {},
        "first_seen": asset.first_seen,
        "last_seen": asset.last_seen,
        "is_active": asset.is_active,
        "tags": asset.tags or [],
        "finding_count": 0,
        "critical_findings": 0
    }

    return AssetResponse(**asset_dict)


@router.delete("/assets/{asset_id}", status_code=204)
async def delete_asset(asset_id: int, db: Session = Depends(get_db)):
    """
    Delete an asset (soft delete - marks as inactive)
    """
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    asset.is_active = False
    db.commit()

    return None


@router.get("/assets/stats/summary")
async def get_asset_stats(db: Session = Depends(get_db)):
    """
    Get asset statistics summary
    """
    total_assets = db.query(Asset).filter(Asset.is_active == True).count()

    assets_by_type = {}
    for asset_type in AssetType:
        count = db.query(Asset).filter(
            Asset.asset_type == asset_type,
            Asset.is_active == True
        ).count()
        assets_by_type[asset_type.value] = count

    total_findings = db.query(Finding).count()
    critical_findings = db.query(Finding).filter(Finding.severity == FindingSeverity.CRITICAL).count()
    high_findings = db.query(Finding).filter(Finding.severity == FindingSeverity.HIGH).count()

    return {
        "total_assets": total_assets,
        "assets_by_type": assets_by_type,
        "total_findings": total_findings,
        "critical_findings": critical_findings,
        "high_findings": high_findings
    }
