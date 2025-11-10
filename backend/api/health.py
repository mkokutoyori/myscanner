"""
Health check endpoints
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from backend.models import get_db
from backend.core.config import settings
import redis

router = APIRouter()


@router.get("/health")
async def health_check(db: Session = Depends(get_db)):
    """
    Health check endpoint
    Returns status of all critical services
    """
    services = {
        "api": "healthy",
        "database": "unknown",
        "redis": "unknown",
        "vault": "unknown"
    }

    # Check database
    try:
        db.execute("SELECT 1")
        services["database"] = "healthy"
    except Exception as e:
        services["database"] = f"unhealthy: {str(e)}"

    # Check Redis
    try:
        r = redis.from_url(settings.REDIS_URL)
        r.ping()
        services["redis"] = "healthy"
    except Exception as e:
        services["redis"] = f"unhealthy: {str(e)}"

    # Check Vault (optional for POC)
    try:
        import hvac
        client = hvac.Client(url=settings.VAULT_ADDR, token=settings.VAULT_TOKEN)
        if client.sys.is_initialized():
            services["vault"] = "healthy"
        else:
            services["vault"] = "not initialized"
    except Exception as e:
        services["vault"] = f"unhealthy: {str(e)}"

    # Overall status
    overall_healthy = all(
        status == "healthy" for key, status in services.items()
        if key in ["api", "database", "redis"]  # Vault is optional
    )

    return {
        "status": "healthy" if overall_healthy else "degraded",
        "services": services,
        "version": settings.APP_VERSION
    }


@router.get("/ready")
async def readiness_check(db: Session = Depends(get_db)):
    """
    Readiness check for Kubernetes
    Returns 200 if service is ready to accept traffic
    """
    try:
        db.execute("SELECT 1")
        return {"status": "ready"}
    except Exception as e:
        return {"status": "not ready", "error": str(e)}


@router.get("/alive")
async def liveness_check():
    """
    Liveness check for Kubernetes
    Returns 200 if service is alive
    """
    return {"status": "alive"}
