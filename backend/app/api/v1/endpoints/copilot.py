"""AI SOC Copilot chat endpoint. Additive: does not modify any existing
analyze/history/stats/auth/knowledge endpoint or route."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.schemas.copilot import CopilotChatRequest, CopilotChatResponse
from app.services.copilot_service import CopilotService

router = APIRouter(tags=["Copilot"])


@router.post("/copilot/chat", response_model=CopilotChatResponse)
def copilot_chat(payload: CopilotChatRequest, db: Session = Depends(get_db)) -> CopilotChatResponse:
    return CopilotService(db).chat(payload)
