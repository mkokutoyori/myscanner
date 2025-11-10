"""
Scans API endpoints
Manage vulnerability scans and discovery operations
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

from backend.models import (
    get_db, Scan, ScanStatus, ScanType, ApprovalStatus
)
from backend.core.config import settings

router = APIRouter()


# Pydantic schemas
class ScanCreate(BaseModel):
    """Create scan request"""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    scan_type: ScanType
    targets: List[str] = Field(..., min_items=1, description="IP addresses, ranges, or hostnames")
    plugin_name: Optional[str] = None
    plugin_config: Dict[str, Any] = {}


class ScanResponse(BaseModel):
    """Scan response schema"""
    id: int
    name: str
    description: Optional[str]
    scan_type: ScanType
    status: ScanStatus
    targets: List[str]
    plugin_name: Optional[str]
    plugin_config: Dict[str, Any]
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    total_assets: int
    total_findings: int
    error_message: Optional[str]
    celery_task_id: Optional[str]
    created_by: Optional[str]
    requires_approval: bool
    approval_status: Optional[ApprovalStatus]
    approved_by: Optional[str]
    approved_at: Optional[datetime]

    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    """Paginated scan list response"""
    total: int
    page: int
    page_size: int
    scans: List[ScanResponse]


class ScanApproval(BaseModel):
    """Scan approval request"""
    approved: bool
    comments: Optional[str] = None


@router.post("/scans", response_model=ScanResponse, status_code=201)
async def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Create and optionally start a new scan

    - **name**: Human-readable scan name
    - **scan_type**: Type of scan (discovery, vulnerability, etc.)
    - **targets**: List of targets (IP addresses, ranges, hostnames)
    - **plugin_name**: Optional plugin to use for scanning
    - **plugin_config**: Plugin-specific configuration

    For intrusive or exploit scans, approval is required before execution.
    """
    # Create scan object
    scan = Scan(
        name=scan_data.name,
        description=scan_data.description,
        scan_type=scan_data.scan_type,
        targets=scan_data.targets,
        plugin_name=scan_data.plugin_name,
        plugin_config=scan_data.plugin_config,
        created_by="system"  # TODO: Get from auth
    )

    # Check if approval is required
    requires_approval = (
        scan_data.scan_type in [ScanType.INTRUSIVE, ScanType.EXPLOIT] and
        settings.REQUIRE_APPROVAL_INTRUSIVE
    )

    scan.requires_approval = requires_approval

    if requires_approval:
        scan.approval_status = ApprovalStatus.PENDING
        scan.status = ScanStatus.PENDING
    else:
        scan.status = ScanStatus.PENDING
        # Queue the scan
        # TODO: Integrate with Celery
        # from backend.workers.tasks import execute_scan
        # task = execute_scan.delay(scan.id)
        # scan.celery_task_id = task.id

    db.add(scan)
    db.commit()
    db.refresh(scan)

    return scan


@router.get("/scans", response_model=ScanListResponse)
async def list_scans(
    page: int = 1,
    page_size: int = 50,
    status: Optional[ScanStatus] = None,
    scan_type: Optional[ScanType] = None,
    db: Session = Depends(get_db)
):
    """
    List all scans with pagination and filters

    - **page**: Page number (starting from 1)
    - **page_size**: Number of items per page (max 100)
    - **status**: Filter by scan status
    - **scan_type**: Filter by scan type
    """
    query = db.query(Scan)

    if status:
        query = query.filter(Scan.status == status)

    if scan_type:
        query = query.filter(Scan.scan_type == scan_type)

    total = query.count()
    scans = query.order_by(desc(Scan.created_at)).offset((page - 1) * page_size).limit(page_size).all()

    return ScanListResponse(
        total=total,
        page=page,
        page_size=page_size,
        scans=scans
    )


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """
    Get scan by ID
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return scan


@router.post("/scans/{scan_id}/approve", response_model=ScanResponse)
async def approve_scan(
    scan_id: int,
    approval: ScanApproval,
    db: Session = Depends(get_db)
):
    """
    Approve or reject a scan that requires approval

    - **approved**: True to approve, False to reject
    - **comments**: Optional approval comments
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if not scan.requires_approval:
        raise HTTPException(status_code=400, detail="Scan does not require approval")

    if scan.approval_status != ApprovalStatus.PENDING:
        raise HTTPException(status_code=400, detail="Scan already processed")

    if approval.approved:
        scan.approval_status = ApprovalStatus.APPROVED
        scan.approved_by = "admin"  # TODO: Get from auth
        scan.approved_at = datetime.utcnow()

        # Start the scan
        # TODO: Integrate with Celery
        # from backend.workers.tasks import execute_scan
        # task = execute_scan.delay(scan.id)
        # scan.celery_task_id = task.id
        scan.status = ScanStatus.PENDING
    else:
        scan.approval_status = ApprovalStatus.REJECTED
        scan.status = ScanStatus.CANCELLED

    db.commit()
    db.refresh(scan)

    return scan


@router.delete("/scans/{scan_id}", status_code=204)
async def cancel_scan(scan_id: int, db: Session = Depends(get_db)):
    """
    Cancel a running or pending scan
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED]:
        raise HTTPException(status_code=400, detail="Cannot cancel completed scan")

    # TODO: Cancel Celery task
    # if scan.celery_task_id:
    #     from backend.workers.celery_app import celery_app
    #     celery_app.control.revoke(scan.celery_task_id, terminate=True)

    scan.status = ScanStatus.CANCELLED
    db.commit()

    return None


@router.post("/scans/discovery", response_model=ScanResponse, status_code=201)
async def create_discovery_scan(
    targets: List[str] = Field(..., description="IP ranges or hostnames to scan"),
    name: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Convenience endpoint to create a discovery scan (masscan -> nmap)

    This is the primary POC endpoint that demonstrates the discovery pipeline.
    """
    scan_name = name or f"Discovery Scan - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"

    scan = Scan(
        name=scan_name,
        description="Automated network discovery using masscan and nmap",
        scan_type=ScanType.DISCOVERY,
        targets=targets,
        plugin_name="discovery",
        plugin_config={
            "masscan_rate": settings.MASSCAN_RATE,
            "nmap_timing": settings.NMAP_TIMING
        },
        status=ScanStatus.PENDING,
        requires_approval=False,
        created_by="system"  # TODO: Get from auth
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Queue the scan
    # TODO: Integrate with Celery worker
    # from backend.workers.tasks import execute_discovery_scan
    # task = execute_discovery_scan.delay(scan.id)
    # scan.celery_task_id = task.id
    # db.commit()

    return scan


@router.get("/scans/stats/summary")
async def get_scan_stats(db: Session = Depends(get_db)):
    """
    Get scan statistics summary
    """
    total_scans = db.query(Scan).count()

    scans_by_status = {}
    for status in ScanStatus:
        count = db.query(Scan).filter(Scan.status == status).count()
        scans_by_status[status.value] = count

    scans_by_type = {}
    for scan_type in ScanType:
        count = db.query(Scan).filter(Scan.scan_type == scan_type).count()
        scans_by_type[scan_type.value] = count

    pending_approvals = db.query(Scan).filter(
        Scan.approval_status == ApprovalStatus.PENDING
    ).count()

    return {
        "total_scans": total_scans,
        "scans_by_status": scans_by_status,
        "scans_by_type": scans_by_type,
        "pending_approvals": pending_approvals
    }
