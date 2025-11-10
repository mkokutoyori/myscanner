"""
Celery Tasks
Main task definitions for scanning operations
"""
from celery import Task
from backend.workers.celery_app import celery_app
from backend.models import Session, Scan, ScanStatus
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class DatabaseTask(Task):
    """Base task with database session management"""
    _db = None

    @property
    def db(self):
        if self._db is None:
            from backend.models.database import SessionLocal
            self._db = SessionLocal()
        return self._db

    def after_return(self, *args, **kwargs):
        if self._db is not None:
            self._db.close()
            self._db = None


@celery_app.task(base=DatabaseTask, bind=True, name="execute_scan")
def execute_scan(self, scan_id: int):
    """
    Execute a scan based on its type and configuration

    Args:
        scan_id: ID of the scan to execute

    Returns:
        dict: Scan results
    """
    logger.info(f"Starting scan {scan_id}")

    # Get scan from database
    scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        logger.error(f"Scan {scan_id} not found")
        return {"error": "Scan not found"}

    # Update scan status
    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.utcnow()
    self.db.commit()

    try:
        # Route to appropriate scanner based on scan type
        from backend.workers.discovery import execute_discovery_scan
        from backend.models import ScanType

        if scan.scan_type == ScanType.DISCOVERY:
            result = execute_discovery_scan(scan_id, self.db)
        else:
            # TODO: Implement other scan types
            result = {"error": f"Scan type {scan.scan_type} not yet implemented"}

        # Update scan status
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        scan.total_assets = result.get("assets_discovered", 0)
        scan.total_findings = result.get("findings_count", 0)
        self.db.commit()

        logger.info(f"Scan {scan_id} completed successfully")
        return result

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {str(e)}", exc_info=True)
        scan.status = ScanStatus.FAILED
        scan.completed_at = datetime.utcnow()
        scan.error_message = str(e)
        self.db.commit()

        raise


@celery_app.task(name="test_task")
def test_task(message: str = "Hello from Celery!"):
    """
    Simple test task to verify Celery is working
    """
    logger.info(f"Test task executed: {message}")
    return {"message": message, "status": "success"}
