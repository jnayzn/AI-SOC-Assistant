"""POST /analyze endpoint -- the core triage feature."""
from fastapi import APIRouter, BackgroundTasks, Depends
from sqlalchemy.orm import Session

from app.api.v1.endpoints.intelowl import run_analysis_enrichment_bg
from app.core.config import get_settings
from app.database.session import get_db
from app.models.user import User
from app.schemas.analysis import AnalysisResponse, AnalyzeRequest
from app.services.analysis_service import AnalysisService
from app.utils.dependencies import get_current_user

router = APIRouter(tags=["Analyze"])


@router.post("/analyze", response_model=AnalysisResponse)
def analyze_content(
    payload: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> AnalysisResponse:
    service = AnalysisService(db)
    user_id = current_user.id if current_user else None
    analysis = service.analyze(payload, user_id=user_id)
    # Non-blocking IntelOwl threat-intel enrichment: each extracted IOC is
    # submitted to IntelOwl in a background task so the triage response is not
    # delayed. Self-disables when INTELOWL_API_TOKEN is not configured.
    if get_settings().intelowl_configured:
        background_tasks.add_task(run_analysis_enrichment_bg, analysis.id)
    return AnalysisResponse.model_validate(analysis)
