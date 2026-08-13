"""FastAPI application entrypoint."""
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.exceptions import register_exception_handlers
from app.core.logging_config import configure_logging
from app.core.rate_limiter import RateLimitMiddleware
from app.core.security_headers import SecurityHeadersMiddleware
from app.database.base import Base
from app.database.migrations import run_light_migrations
from app.database.session import engine

settings = get_settings()
configure_logging(settings.DEBUG)
logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "Production-grade AI web application that analyzes phishing emails, SOC alerts, "
        "and security logs using an LLM to classify threats, assess risk, and recommend actions."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Middleware executes bottom-up on the request path in Starlette, so adding
# these after CORS keeps CORS as the outermost layer (required for correct
# preflight/error-response header handling).
app.add_middleware(RateLimitMiddleware, requests_per_minute=settings.RATE_LIMIT_PER_MINUTE)
app.add_middleware(SecurityHeadersMiddleware)
# Compresses large JSON responses (e.g. history pages, PDF-adjacent payloads,
# MITRE matrix) transparently; negotiated via the client's Accept-Encoding.
app.add_middleware(GZipMiddleware, minimum_size=1024)

register_exception_handlers(app)
app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.on_event("startup")
def on_startup() -> None:
    # For production, prefer Alembic migrations (`alembic upgrade head`) over
    # create_all. This create_all call is a convenience fallback for local dev.
    Base.metadata.create_all(bind=engine)
    # Additive, idempotent column backfill for existing deployments/volumes
    # (create_all does not alter tables that already exist).
    run_light_migrations(engine)

    if settings.has_insecure_secret_key:
        if settings.ENVIRONMENT.lower() in ("production", "prod"):
            # Never allow the shipped placeholder secret to sign real JWTs in
            # production -- it is public (committed in .env.example) so every
            # token would be forgeable.
            raise RuntimeError(
                "SECRET_KEY is still the insecure default. Set a long random "
                "SECRET_KEY in your production .env before starting the app."
            )
        logger.warning(
            "SECRET_KEY is still the insecure default placeholder. This is "
            "fine for local development, but must be changed before any "
            "deployment reachable outside your machine."
        )

    logger.info("%s started in %s mode.", settings.APP_NAME, settings.ENVIRONMENT)


@app.get("/")
def root() -> dict:
    return {"message": settings.APP_NAME, "docs": "/docs", "api": settings.API_V1_PREFIX}
