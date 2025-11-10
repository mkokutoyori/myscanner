"""
Main FastAPI Application
Entry point for the VulnScan Platform API
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging
import time

from backend.core.config import settings
from backend.models import init_db
from backend.api import assets, scans, findings, plugins, health

# Configure logging
logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle events for the application"""
    # Startup
    logger.info("Starting VulnScan Platform API...")
    logger.info("Initializing database...")
    init_db()
    logger.info("Database initialized successfully")

    yield

    # Shutdown
    logger.info("Shutting down VulnScan Platform API...")


# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Open-source vulnerability scanning and audit platform",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    """Add X-Process-Time header to all responses"""
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response


# Exception handlers
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    logger.error(f"Global exception handler caught: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": str(exc) if settings.DEBUG else "An error occurred"
        }
    )


# Include routers
app.include_router(health.router, prefix=settings.API_V1_PREFIX, tags=["health"])
app.include_router(assets.router, prefix=settings.API_V1_PREFIX, tags=["assets"])
app.include_router(scans.router, prefix=settings.API_V1_PREFIX, tags=["scans"])
app.include_router(findings.router, prefix=settings.API_V1_PREFIX, tags=["findings"])
app.include_router(plugins.router, prefix=settings.API_V1_PREFIX, tags=["plugins"])


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint - API information"""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "operational",
        "docs": "/docs",
        "api_v1": settings.API_V1_PREFIX
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )
