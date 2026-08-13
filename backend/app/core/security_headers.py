"""Security-hardening HTTP response headers middleware (Chantier Q).

Additive: does not change any existing route, auth flow, or response body.
Adds standard defensive headers recommended for production web APIs.
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.core.config import get_settings

settings = get_settings()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        # Only advertise HSTS when not running in local/dev mode, since it
        # requires HTTPS and would otherwise break local http:// testing.
        if settings.ENVIRONMENT.lower() in ("production", "prod"):
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response
