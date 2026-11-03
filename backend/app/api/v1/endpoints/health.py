"""Health-check and system status endpoints."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter
from sqlalchemy import text

from app.core.config import get_settings
from app.database.session import AsyncSessionLocal
from app.scanners.probe import probe_all_scanners
from app.schemas.schemas import (
    HealthResponse,
    ScannersStatusResponse,
    ScannerStatus,
)

router = APIRouter(tags=["health"])
settings = get_settings()


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Public health-check endpoint.
    Returns application status, database connectivity, and scanner availability.
    """
    db_status = "ok"
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
    except Exception as exc:
        db_status = f"error: {exc}"

    scanners = probe_all_scanners()
    scanner_availability = {s.name: s.available for s in scanners}

    return HealthResponse(
        status="ok",
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        database=db_status,
        timestamp=datetime.now(timezone.utc),
        scanner_availability=scanner_availability,
    )


@router.get("/health/scanners", response_model=ScannersStatusResponse)
async def scanners_status():
    """Detailed scanner availability with version strings."""
    scanners = probe_all_scanners()
    return ScannersStatusResponse(
        scanners=[
            ScannerStatus(
                name=s.name,
                available=s.available,
                version=s.version,
                path=s.path,
                description=s.description,
                category=s.category,
            )
            for s in scanners
        ],
        timestamp=datetime.now(timezone.utc),
    )
