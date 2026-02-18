"""FastAPI application main entry point."""
import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.settings import settings
from app.routers import events, lo2, modsec
from app.schemas import HealthResponse

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup
    logger.info("Starting AI-Driven Log Sentinel API...")
    
    # Resolve and log model paths
    from app.services.model_loader import model_loader
    modsec_dir = model_loader._resolve_path(settings.MODSEC_MODEL_DIR)
    lo2_dir = model_loader._resolve_path(settings.LO2_MODEL_DIR)
    
    logger.info(f"ModSec model directory: {modsec_dir.absolute()}")
    logger.info(f"LO2 model directory: {lo2_dir.absolute()}")
    
    # Check if model directories exist
    if not modsec_dir.exists():
        logger.warning(f"⚠️ ModSec model directory not found: {modsec_dir.absolute()}")
    if not lo2_dir.exists():
        logger.warning(f"⚠️ LO2 model directory not found: {lo2_dir.absolute()}")
    
    # Pre-load models for faster first request (performance optimization)
    try:
        model_loader.get_modsec_model()
        logger.info("ModSec model pre-loaded successfully")
    except Exception as e:
        logger.warning(f"Could not pre-load ModSec model: {e}")
    try:
        model_loader.get_lo2_log_models()
        logger.info("LO2 log models pre-loaded successfully")
    except Exception as e:
        logger.warning(f"Could not pre-load LO2 log models: {e}")
    try:
        model_loader.get_lo2_metric_models()
        logger.info("LO2 metric models pre-loaded successfully")
    except Exception as e:
        logger.warning(f"Could not pre-load LO2 metric models: {e}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down API...")


# Create FastAPI app
app = FastAPI(
    title="AI-Driven Log Sentinel API",
    description="Mini-SIEM system for threat detection and anomaly detection",
    version="1.0.0",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(modsec.router)
app.include_router(lo2.router)
app.include_router(events.router)


@app.get("/health", response_model=HealthResponse, tags=["health"])
async def health_check() -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse(status="ok")


@app.get("/", tags=["root"])
async def root():
    """Root endpoint with API information."""
    return {
        "name": "AI-Driven Log Sentinel API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=True,
        log_level=settings.LOG_LEVEL.lower()
    )
