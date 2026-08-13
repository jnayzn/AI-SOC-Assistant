"""Simple in-memory sliding-window rate limiter middleware.

For production/multi-instance deployments, back this with Redis instead of
an in-process dict (see README Future Improvements).
"""
import time
from collections import defaultdict, deque

from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import get_settings

settings = get_settings()


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, requests_per_minute: int | None = None):
        super().__init__(app)
        self.limit = requests_per_minute or settings.RATE_LIMIT_PER_MINUTE
        self.window_seconds = 60
        self._hits: dict[str, deque] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):
        if request.url.path in ("/api/v1/health", "/docs", "/openapi.json", "/redoc"):
            return await call_next(request)

        client_key = request.client.host if request.client else "unknown"
        now = time.monotonic()
        hits = self._hits[client_key]

        while hits and now - hits[0] > self.window_seconds:
            hits.popleft()

        if len(hits) >= self.limit:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded. Please slow down."},
            )

        hits.append(now)
        return await call_next(request)
