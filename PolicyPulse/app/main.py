"""PolicyPulse application factory.

Run:  uvicorn app.main:app --reload
"""
import logging
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import __version__
from app.api import pages, routes
from app.config import Settings, get_settings
from app.database import init_db, make_engine, make_session_factory

log = logging.getLogger("policypulse")
BASE_DIR = Path(__file__).resolve().parent
_DOC_PATHS = ("/docs", "/redoc", "/openapi.json")
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")

DESCRIPTION = (
    "**Educational zero-trust policy simulator.** Identity, role, MFA and device posture are "
    "*self-asserted inputs*, not verified facts. This is not a production security gateway."
)


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    settings = settings or get_settings()
    engine = make_engine(settings.database_url)
    session_factory = make_session_factory(engine)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        init_db(engine, session_factory)
        yield
        engine.dispose()

    app = FastAPI(title="PolicyPulse - Adaptive Zero-Trust Access Engine", version=__version__,
                  description=DESCRIPTION, lifespan=lifespan)
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = session_factory

    app.add_middleware(
        CORSMiddleware, allow_origins=settings.cors_origin_list, allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"], allow_headers=["Content-Type"],
    )

    @app.middleware("http")
    async def guard(request: Request, call_next):
        length = request.headers.get("content-length")
        if length is not None:
            try:
                too_big = int(length) > settings.max_request_bytes
            except ValueError:
                too_big = True
            if too_big:
                return JSONResponse({"detail": "Request body too large"}, status_code=413)
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.url.path not in _DOC_PATHS:  # Swagger UI loads assets from a CDN
            response.headers.setdefault("Content-Security-Policy", CSP)
        if request.url.path.startswith("/api/") or request.url.path == "/health":
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):
        errors = [{"loc": list(e.get("loc", [])), "msg": str(e.get("msg", "invalid")), "type": e.get("type", "")}
                  for e in exc.errors()]
        return JSONResponse({"detail": errors}, status_code=422)

    @app.exception_handler(StarletteHTTPException)
    async def http_handler(request: Request, exc: StarletteHTTPException):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        error_id = uuid.uuid4().hex[:12]
        log.exception("Unhandled error %s on %s", error_id, request.url.path)
        return JSONResponse({"detail": "Internal server error", "error_id": error_id}, status_code=500)

    app.include_router(routes.router)
    app.include_router(pages.router)
    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
    return app


_app: Optional[FastAPI] = None


def __getattr__(name: str):
    """Lazily build ``app`` so importing this module has no side effects (e.g. creating data/)."""
    global _app
    if name == "app":
        if _app is None:
            _app = create_app()
        return _app
    raise AttributeError(name)
