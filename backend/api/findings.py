"""
Findings API endpoints
Manage security findings and vulnerabilities
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

from backend.models import get_db, Finding, FindingSeverity, Asset

router = APIRouter()


# Pydantic schemas
class FindingResponse(BaseModel):
    """Finding response schema"""
    id: int
    scan_id: int
    asset_id: int
    asset_ip: Optional[str] = None
    asset_hostname: Optional[str] = None
    title: str
    description: str
    severity: FindingSeverity
    cve_ids: List[str]
    cwe_ids: List[str]
    cvss_score: Optional[float]
    affected_service: Optional[str]
    affected_port: Optional[int]
    evidence: Optional[str]
    remediation: Optional[str]
    remediation_priority: int
    is_false_positive: bool
    is_resolved: bool
    resolved_at: Optional[datetime]
    discovered_at: datetime
    plugin_name: Optional[str]

    class Config:
        from_attributes = True


class FindingListResponse(BaseModel):
    """Paginated finding list response"""
    total: int
    page: int
    page_size: int
    findings: List[FindingResponse]


@router.get("/findings", response_model=FindingListResponse)
async def list_findings(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    severity: Optional[FindingSeverity] = None,
    asset_id: Optional[int] = None,
    scan_id: Optional[int] = None,
    is_resolved: Optional[bool] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    List all findings with pagination and filters

    - **page**: Page number (starting from 1)
    - **page_size**: Number of items per page (max 100)
    - **severity**: Filter by severity
    - **asset_id**: Filter by asset
    - **scan_id**: Filter by scan
    - **is_resolved**: Filter by resolution status
    - **search**: Search in title and description
    """
    query = db.query(Finding).join(Asset)

    # Apply filters
    if severity:
        query = query.filter(Finding.severity == severity)

    if asset_id:
        query = query.filter(Finding.asset_id == asset_id)

    if scan_id:
        query = query.filter(Finding.scan_id == scan_id)

    if is_resolved is not None:
        query = query.filter(Finding.is_resolved == is_resolved)

    if search:
        query = query.filter(
            or_(
                Finding.title.ilike(f"%{search}%"),
                Finding.description.ilike(f"%{search}%")
            )
        )

    # Count total
    total = query.count()

    # Paginate
    findings = query.order_by(desc(Finding.discovered_at)).offset((page - 1) * page_size).limit(page_size).all()

    # Enrich with asset info
    finding_responses = []
    for finding in findings:
        asset = db.query(Asset).filter(Asset.id == finding.asset_id).first()
        finding_dict = {
            "id": finding.id,
            "scan_id": finding.scan_id,
            "asset_id": finding.asset_id,
            "asset_ip": asset.ip_address if asset else None,
            "asset_hostname": asset.hostname if asset else None,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
            "cve_ids": finding.cve_ids or [],
            "cwe_ids": finding.cwe_ids or [],
            "cvss_score": finding.cvss_score,
            "affected_service": finding.affected_service,
            "affected_port": finding.affected_port,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
            "remediation_priority": finding.remediation_priority,
            "is_false_positive": finding.is_false_positive,
            "is_resolved": finding.is_resolved,
            "resolved_at": finding.resolved_at,
            "discovered_at": finding.discovered_at,
            "plugin_name": finding.plugin_name
        }
        finding_responses.append(FindingResponse(**finding_dict))

    return FindingListResponse(
        total=total,
        page=page,
        page_size=page_size,
        findings=finding_responses
    )


@router.get("/findings/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: int, db: Session = Depends(get_db)):
    """
    Get finding by ID
    """
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    asset = db.query(Asset).filter(Asset.id == finding.asset_id).first()

    finding_dict = {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "asset_id": finding.asset_id,
        "asset_ip": asset.ip_address if asset else None,
        "asset_hostname": asset.hostname if asset else None,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "cve_ids": finding.cve_ids or [],
        "cwe_ids": finding.cwe_ids or [],
        "cvss_score": finding.cvss_score,
        "affected_service": finding.affected_service,
        "affected_port": finding.affected_port,
        "evidence": finding.evidence,
        "remediation": finding.remediation,
        "remediation_priority": finding.remediation_priority,
        "is_false_positive": finding.is_false_positive,
        "is_resolved": finding.is_resolved,
        "resolved_at": finding.resolved_at,
        "discovered_at": finding.discovered_at,
        "plugin_name": finding.plugin_name
    }

    return FindingResponse(**finding_dict)


@router.patch("/findings/{finding_id}/resolve")
async def resolve_finding(finding_id: int, db: Session = Depends(get_db)):
    """
    Mark a finding as resolved
    """
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.is_resolved = True
    finding.resolved_at = datetime.utcnow()
    db.commit()

    return {"message": "Finding marked as resolved"}


@router.patch("/findings/{finding_id}/false-positive")
async def mark_false_positive(finding_id: int, db: Session = Depends(get_db)):
    """
    Mark a finding as false positive
    """
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.is_false_positive = True
    db.commit()

    return {"message": "Finding marked as false positive"}


@router.get("/findings/stats/summary")
async def get_finding_stats(db: Session = Depends(get_db)):
    """
    Get finding statistics summary
    """
    total_findings = db.query(Finding).count()
    unresolved_findings = db.query(Finding).filter(Finding.is_resolved == False).count()

    findings_by_severity = {}
    for severity in FindingSeverity:
        count = db.query(Finding).filter(
            Finding.severity == severity,
            Finding.is_resolved == False,
            Finding.is_false_positive == False
        ).count()
        findings_by_severity[severity.value] = count

    return {
        "total_findings": total_findings,
        "unresolved_findings": unresolved_findings,
        "findings_by_severity": findings_by_severity
    }
