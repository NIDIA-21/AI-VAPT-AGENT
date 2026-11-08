"""API v1 router — aggregates all endpoint routers."""
from fastapi import APIRouter

from app.api.v1.endpoints import (
    health,
    dashboard,
    targets,
    assessments,
    scope,
    agent,
    scanners,
    findings,
    approvals,
    reports,
)

api_router = APIRouter()

api_router.include_router(health.router)
api_router.include_router(dashboard.router)
api_router.include_router(targets.router)
api_router.include_router(scope.router)
api_router.include_router(assessments.router)
api_router.include_router(agent.router)
api_router.include_router(scanners.router, prefix="/scanners", tags=["Scanners"])
api_router.include_router(findings.router, prefix="/findings", tags=["Findings"])
api_router.include_router(approvals.router, prefix="/approvals", tags=["Approvals"])
api_router.include_router(reports.router, prefix="/reports", tags=["Reports"])
