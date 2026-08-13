"""Dashboard statistics endpoint."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.schemas.stats import StatsResponse
from app.services.stats_service import StatsService

router = APIRouter(tags=["Stats"])


@router.get("/stats", response_model=StatsResponse)
def get_stats(db: Session = Depends(get_db)) -> StatsResponse:
    return StatsService(db).get_stats()
