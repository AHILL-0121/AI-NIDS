"""HTTP hardening and serving the frontend (audit SEC-10, SEC-08).

- Security headers on every response. API responses get a CSP that allows nothing; frontend pages
  get a strict CSP whose `script-src` lists the SHA-256 of each inline script in that page (the
  Next.js static export inlines its bootstrap data and our theme script). No 'unsafe-inline'.
- Request bodies over 1 MB are refused, except uploads (which have their own limit).
- The Next.js static export (`frontend/out`) is served from the same origin as the API.
"""

import base64
import hashlib
import re
from collections.abc import Awaitable, Callable
from functools import lru_cache
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, JSONResponse

MAX_BODY = 1024 * 1024
_INLINE_SCRIPT = re.compile(rb"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.S)

BASE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}
API_CSP = "default-src 'none'; frame-ancestors 'none'"


@lru_cache(maxsize=512)
def page_csp(path: str, mtime: float) -> str:
    """CSP for one HTML file, allowing exactly its inline scripts by hash."""
    del mtime  # part of the cache key only: a rebuilt page gets new hashes
    hashes = {
        "'sha256-" + base64.b64encode(hashlib.sha256(body).digest()).decode() + "'"
        for body in _INLINE_SCRIPT.findall(Path(path).read_bytes())
    }
    return (
        "default-src 'self'; "
        f"script-src 'self' {' '.join(sorted(hashes))}; "
        "style-src 'self' 'unsafe-inline'; "  # Next.js injects style tags; styles can't run code
        "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
        "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    )


def segment_file(candidate: Path) -> Path | None:
    """Next.js prefetches route segments as `__next.<a>.<b>.__PAGE__.txt` but the static export
    writes them nested (`__next.<a>/<b>/__PAGE__.txt`). Segment names never contain dots."""
    name = candidate.name
    if not (name.startswith("__next.") and name.endswith(".txt")):
        return None
    head, *rest = name.removeprefix("__next.").removesuffix(".txt").split(".")
    if not rest or not all(rest):
        return None
    return candidate.parent.joinpath(f"__next.{head}", *rest[:-1], f"{rest[-1]}.txt")


def install(app: FastAPI, frontend_dir: Path | None, secure: bool) -> None:
    @app.middleware("http")
    async def harden(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        length = request.headers.get("content-length")
        is_upload = request.url.path == "/api/uploads"
        if length and length.isdigit() and int(length) > MAX_BODY and not is_upload:
            response: Response = JSONResponse(
                {
                    "error": {
                        "code": "payload_too_large",
                        "message": "Request body too large.",
                        "details": None,
                    }
                },
                status_code=413,
            )
        else:
            response = await call_next(request)
        for name, value in BASE_HEADERS.items():
            response.headers.setdefault(name, value)
        response.headers.setdefault("Content-Security-Policy", API_CSP)
        if secure:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    if frontend_dir is None or not frontend_dir.is_dir():
        return
    root = frontend_dir.resolve()

    # HEAD too: the Next.js router probes pages with HEAD before client-side navigation.
    @app.api_route("/{path:path}", methods=["GET", "HEAD"], include_in_schema=False)
    def frontend(path: str) -> Response:
        if path.startswith("api/"):
            return JSONResponse(
                {"error": {"code": "not_found", "message": "Not found", "details": None}}, 404
            )
        candidate = (root / path).resolve()
        if root != candidate and root not in candidate.parents:  # no ../ escapes
            candidate = root / "__outside__"  # never exists: falls through to the 404 page
        if candidate.is_dir():
            candidate = candidate / "index.html"
        elif not candidate.exists() and candidate.with_suffix(".html").exists():
            candidate = candidate.with_suffix(".html")
        elif not candidate.exists() and (segment := segment_file(candidate)) is not None:
            candidate = segment.resolve()
            if root not in candidate.parents:
                candidate = root / "__outside__"
        status = 200
        if not candidate.is_file():
            candidate, status = root / "404.html", 404
            if not candidate.is_file():
                return Response("Not found", status_code=404)
        response = FileResponse(candidate, status_code=status)
        if candidate.suffix == ".html":
            response.headers["Content-Security-Policy"] = page_csp(
                str(candidate), candidate.stat().st_mtime
            )
            response.headers["Cache-Control"] = "no-cache"
        elif "/_next/static/" in f"/{path}":
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        return response
