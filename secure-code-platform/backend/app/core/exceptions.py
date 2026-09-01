"""
Custom exception hierarchy.

Services raise these domain-specific exceptions instead of HTTPException
directly — that keeps the service layer framework-agnostic (a service
shouldn't know it's being called from HTTP) and gives a single place
(`register_exception_handlers`) that maps domain errors to HTTP responses.
"""
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse


class AppError(Exception):
    """Base class for all domain errors. status_code is the HTTP code it maps to."""
    status_code = status.HTTP_400_BAD_REQUEST
    default_message = "Something went wrong"

    def __init__(self, message: str | None = None):
        self.message = message or self.default_message
        super().__init__(self.message)


class NotFoundError(AppError):
    status_code = status.HTTP_404_NOT_FOUND
    default_message = "Resource not found"


class AlreadyExistsError(AppError):
    status_code = status.HTTP_409_CONFLICT
    default_message = "Resource already exists"


class InvalidCredentialsError(AppError):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_message = "Invalid email or password"


class UnauthorizedError(AppError):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_message = "Authentication required"


class ForbiddenError(AppError):
    status_code = status.HTTP_403_FORBIDDEN
    default_message = "You do not have permission to perform this action"


class EmailNotVerifiedError(AppError):
    status_code = status.HTTP_403_FORBIDDEN
    default_message = "Please verify your email before continuing"


class InvalidTokenError(AppError):
    status_code = status.HTTP_400_BAD_REQUEST
    default_message = "Invalid or expired token"


class ValidationFailedError(AppError):
    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    default_message = "Validation failed"


class FileTooLargeError(AppError):
    status_code = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
    default_message = "Uploaded file exceeds the maximum allowed size"


class UnsupportedFileTypeError(AppError):
    status_code = status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
    default_message = "File type is not supported"


class EngineExecutionError(AppError):
    status_code = status.HTTP_502_BAD_GATEWAY
    default_message = "A scan engine failed to execute"


class RateLimitExceededError(AppError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    default_message = "Too many requests — please slow down"


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def handle_app_error(request: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"success": False, "error": {"message": exc.message, "type": exc.__class__.__name__}},
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        # Last-resort handler so the API never leaks a raw stack trace to clients.
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"success": False, "error": {"message": "Internal server error", "type": "InternalServerError"}},
        )
