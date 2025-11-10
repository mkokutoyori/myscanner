"""
Celery Application Configuration
Defines the Celery app for distributed task processing
"""
from celery import Celery
from backend.core.config import settings
import logging

logger = logging.getLogger(__name__)

# Create Celery app
celery_app = Celery(
    "vulnscan_workers",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["backend.workers.tasks", "backend.workers.discovery"]
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=settings.SCAN_WORKER_TIMEOUT,
    task_soft_time_limit=settings.SCAN_WORKER_TIMEOUT - 300,  # 5 min before hard limit
    worker_prefetch_multiplier=1,  # One task at a time per worker
    worker_max_tasks_per_child=50,  # Restart worker after 50 tasks (prevent memory leaks)
    result_expires=86400,  # Results expire after 24 hours
)

logger.info("Celery app initialized")
