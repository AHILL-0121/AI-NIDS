"""One error format for every failure, with real HTTP status codes (audit API-03):

{"error": {"code": "not_found", "message": "Alert A-123 not found", "details": null}}
"""

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger(__name__)

_CODES = {
    400: "bad_request",
    401: "unauthenticated",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "payload_too_large",
    415: "unsupported_media_type",
    422: "invalid_input",
    429: "rate_limited",
    503: "unavailable",
}


class ApiError(Exception):
    def __init__(
        self, status: int, message: str, code: str | None = None, details: Any = None
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code or _CODES.get(status, "error")
        self.message = message
        self.details = details


def _body(code: str, message: str, details: Any = None) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "details": details}}


def install(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def api_error(_: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(_body(exc.code, exc.message, exc.details), status_code=exc.status)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        message = exc.detail if isinstance(exc.detail, str) else "Request failed"
        return JSONResponse(
            _body(_CODES.get(exc.status_code, "error"), message),
            status_code=exc.status_code,
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        details = [
            {
                "field": ".".join(str(p) for p in e.get("loc", ()) if p != "body"),
                "message": e.get("msg"),
            }
            for e in exc.errors()
        ]
        return JSONResponse(
            _body("invalid_input", "Some values are invalid.", details), status_code=422
        )

    @app.exception_handler(Exception)
    async def unexpected(_: Request, exc: Exception) -> JSONResponse:
        log.exception("Unhandled error")
        return JSONResponse(
            _body("internal", "Something went wrong on the server."), status_code=500
        )
