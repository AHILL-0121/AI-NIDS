"""FastAPI application factory."""

from fastapi import FastAPI

from nids import __version__


def create_app() -> FastAPI:
    app = FastAPI(title="AI-NIDS", version=__version__)

    @app.get("/healthz", tags=["system"])
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    return app
