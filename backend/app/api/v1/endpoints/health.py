"""Health check endpoint."""
from fastapi import APIRouter

from app.core.config import get_settings

router = APIRouter(tags=["Health"])
settings = get_settings()


@router.get("/health")
def health_check() -> dict:
    return {"status": "ok", "app": settings.APP_NAME, "environment": settings.ENVIRONMENT}
