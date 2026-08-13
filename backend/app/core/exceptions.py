"""Custom application exceptions and FastAPI exception handlers."""
import logging

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


class AppError(Exception):
    """Base application error with an HTTP status code."""

    def __init__(self, message: str, status_code: int = status.HTTP_400_BAD_REQUEST):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class LLMResponseError(AppError):
    """Raised when the LLM response cannot be parsed into the expected schema."""

    def __init__(self, message: str = "The AI model returned an invalid response."):
        super().__init__(message, status_code=status.HTTP_502_BAD_GATEWAY)


class PromptInjectionDetected(AppError):
    """Raised when submitted content looks like a prompt-injection/jailbreak attempt."""

    def __init__(self, message: str = "Submitted content was rejected by safety filters."):
        super().__init__(message, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)


class NotFoundError(AppError):
    def __init__(self, message: str = "Resource not found."):
        super().__init__(message, status_code=status.HTTP_404_NOT_FOUND)


class UnauthorizedError(AppError):
    def __init__(self, message: str = "Not authenticated."):
        super().__init__(message, status_code=status.HTTP_401_UNAUTHORIZED)


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
        logger.warning("AppError on %s: %s", request.url.path, exc.message)
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        logger.info("Validation error on %s: %s", request.url.path, exc.errors())
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": "Invalid request payload.", "errors": exc.errors()},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled exception on %s", request.url.path)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error."},
        )
