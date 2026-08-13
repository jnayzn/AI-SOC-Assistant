"""Aggregates all v1 endpoint routers."""
from fastapi import APIRouter

from app.api.v1.endpoints import analyze, auth, copilot, health, history, intelowl, knowledge, mitre_playbooks, stats

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(analyze.router)
api_router.include_router(history.router)
api_router.include_router(stats.router)
api_router.include_router(auth.router)
api_router.include_router(knowledge.router)
api_router.include_router(copilot.router)
api_router.include_router(intelowl.router)
api_router.include_router(mitre_playbooks.router)
