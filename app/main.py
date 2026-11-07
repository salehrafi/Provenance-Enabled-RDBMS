from __future__ import annotations

import json
import logging
import re
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import oracledb
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app import __version__, ratelimit
from app.config import get_settings
from app.db import close_pool, init_pool, system_session
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.errors import http_error_handler, oracle_error_handler, validation_error_handler
from app.routers import audit, auth, catalog, dev, governance, ingest, integration, orders, users
from app.workers import workers

STATIC_DIR = Path(__file__).parent / "static"
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data = {"ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"), "level": record.levelname,
                "logger": record.name, "msg": record.getMessage()}
        for key in ("request_id", "method", "path", "status", "ms"):
            if hasattr(record, key):
                data[key] = getattr(record, key)
        if record.exc_info:
            data["exc"] = self.formatException(record.exc_info)
        return json.dumps(data)


def _configure_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)
    logging.getLogger("uvicorn.access").disabled = True  # replaced by our request log
    logging.getLogger("httpx").setLevel(logging.WARNING)  # one line per webhook delivery is noise


@asynccontextmanager
async def lifespan(app: FastAPI):
    _configure_logging()
    init_pool()
    if get_settings().workers_enabled:
        workers.start()
    yield
    workers.stop()
    close_pool()


settings = get_settings()
app = FastAPI(
    title=f"{settings.app_name} API",
    version=__version__,
    description=(
        "Provenance-enabled e-commerce backend on Oracle. Every change is captured by database triggers "
        "into a tamper-evident SHA-256 hash chain, tenants are isolated by Oracle VPD, and the API answers "
        "*why*, *where* and *how* any value came to be.\n\n"
        "Authenticate with **Authorize** (email + password), or call `POST /api/v1/auth/login`.\n\n"
        "**Integrations:** upstream systems send CloudEvents to `POST /api/v1/events` with an API key "
        "(`Authorization: Bearer prv_...`). Errors follow RFC 9457 (`application/problem+json`); webhooks "
        "are signed per the Standard Webhooks spec."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID"],
    )

_access_log = logging.getLogger("app.access")


@app.middleware("http")
async def request_context(request: Request, call_next):
    incoming = request.headers.get("x-request-id", "")
    request_id = incoming if _REQUEST_ID.match(incoming) else uuid.uuid4().hex
    request.state.request_id = request_id
    start = time.perf_counter()
    response = await call_next(request)
    ms = round((time.perf_counter() - start) * 1000, 1)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if not request.url.path.startswith(("/docs", "/redoc")):
        # The SPA uses no inline scripts; Swagger/ReDoc load assets from a CDN so they are exempt.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; script-src 'self'; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
    if request.url.path.startswith("/api/"):
        _access_log.info("request", extra={"request_id": request_id, "method": request.method,
                                           "path": request.url.path, "status": response.status_code, "ms": ms})
    return response


app.add_exception_handler(oracledb.DatabaseError, oracle_error_handler)
app.add_exception_handler(StarletteHTTPException, http_error_handler)
app.add_exception_handler(RequestValidationError, validation_error_handler)

API = "/api/v1"
for module in (auth, users, catalog, orders, audit, governance, integration, ingest):
    app.include_router(module.router, prefix=API)
if settings.is_dev:
    app.include_router(dev.router, prefix=API)


@app.get("/health", tags=["ops"], summary="Liveness probe")
def health():
    return {"status": "ok", "version": __version__}


@app.get("/ready", tags=["ops"], summary="Readiness probe (checks Oracle)")
def ready():
    try:
        with system_session() as db:
            db.scalar("SELECT 1 FROM dual")
        return {"status": "ready", "database": "ok", "rate_limiter": ratelimit.backend(), "workers": workers.last_run}
    except oracledb.Error as exc:
        return JSONResponse(status_code=503, content={"status": "unavailable", "database": str(exc).splitlines()[0]})


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")
