from __future__ import annotations

import json
import logging
import mimetypes
import re
import time
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path

import psycopg
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from psycopg_pool import PoolTimeout
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import __version__, ratelimit
from app.config import get_settings
from app.db import close_pool, init_pool, pool_stats, system_session
from app.errors import (
    db_error_handler,
    http_error_handler,
    pool_timeout_handler,
    problem,
    unhandled_error_handler,
    validation_error_handler,
)
from app.routers import (
    activity,
    audit,
    auth,
    catalog,
    governance,
    ingest,
    integration,
    orders,
    platform,
    sandbox,
    users,
)
from app.services import activity as activity_log
from app.services import platform as platform_svc
from app.worker import worker

mimetypes.add_type("text/javascript", ".js")  # Windows registries sometimes say text/plain, which browsers refuse for modules
mimetypes.add_type("text/css", ".css")
STATIC_DIR = Path(__file__).parent / "static"
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
log = logging.getLogger("app")
access_log = logging.getLogger("app.access")


class JsonFormatter(logging.Formatter):
    FIELDS = ("request_id", "tenant_id", "actor", "method", "path", "status", "ms")

    def format(self, record: logging.LogRecord) -> str:
        data = {"ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"), "level": record.levelname,
                "logger": record.name, "msg": record.getMessage()}
        for key in self.FIELDS:
            if hasattr(record, key):
                data[key] = getattr(record, key)
        if record.exc_info:
            data["exc"] = self.formatException(record.exc_info)
        return json.dumps(data, default=str)


def configure_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(get_settings().log_level.upper())
    logging.getLogger("uvicorn.access").disabled = True  # replaced by the request log below
    logging.getLogger("httpx").setLevel(logging.WARNING)


class Metrics:
    """Tiny in-process Prometheus exposition (per process; scrape every instance)."""

    BUCKETS = (0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10)

    def __init__(self) -> None:
        self.count: dict[tuple[str, str, str], int] = defaultdict(int)
        self.buckets: dict[float, int] = defaultdict(int)
        self.total = 0.0
        self.n = 0

    def observe(self, method: str, route: str, status: int, seconds: float) -> None:
        self.count[(method, route, str(status))] += 1
        self.n += 1
        self.total += seconds
        for b in self.BUCKETS:
            if seconds <= b:
                self.buckets[b] += 1

    def render(self) -> str:
        out = ["# TYPE http_requests_total counter"]
        out += [f'http_requests_total{{method="{m}",route="{r}",status="{s}"}} {c}' for (m, r, s), c in sorted(self.count.items())]
        out.append("# TYPE http_request_duration_seconds histogram")
        out += [f'http_request_duration_seconds_bucket{{le="{b}"}} {self.buckets[b]}' for b in self.BUCKETS]
        out += [f'http_request_duration_seconds_bucket{{le="+Inf"}} {self.n}',
                f"http_request_duration_seconds_sum {self.total:.6f}", f"http_request_duration_seconds_count {self.n}"]
        for k, v in pool_stats().items():
            if isinstance(v, int):
                out.append(f"db_pool_{k} {v}")
        out.append(f"worker_last_dispatch_timestamp {worker.last_run.get('dispatch', 0):.0f}")
        out.append(f"worker_last_checkpoint_timestamp {worker.last_run.get('checkpoint', 0):.0f}")
        return "\n".join(out) + "\n"


metrics = Metrics()


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    s = get_settings()
    problems = s.problems()
    if problems and not s.is_dev:
        raise RuntimeError("Unsafe configuration: " + "; ".join(problems))
    for p in problems:
        log.warning("configuration: %s", p)
    init_pool()
    if s.workers_enabled:
        worker.start()
    yield
    worker.stop()
    close_pool()


settings = get_settings()
app = FastAPI(
    title=f"{settings.app_name} API",
    version=__version__,
    description=(
        "Provenance-enabled data platform: every change is captured into a tamper-evident SHA-256 hash chain "
        "with signed checkpoints, tenants are isolated by PostgreSQL row-level security, and the API answers "
        "*why*, *where* and *how* any value came to be, and what it looked like at any past time.\n\n"
        "**People** sign in with `POST /api/v1/auth/login` and send the access token as `Authorization: Bearer ...`.\n\n"
        "**Systems** use an API key (`Authorization: Bearer prv_...`) with narrow scopes and send CloudEvents "
        "to `POST /api/v1/events`.\n\n"
        "Errors follow RFC 9457 (`application/problem+json`) with a stable `code`. Webhooks follow Standard "
        "Webhooks. Send an `Idempotency-Key` header on POSTs that create things."),
    lifespan=lifespan,
    docs_url="/docs" if settings.docs_enabled else None,
    redoc_url="/redoc" if settings.docs_enabled else None,
    openapi_url="/openapi.json",
)

if settings.cors_origins:
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=True,
                       allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
                       allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "X-Request-ID"],
                       expose_headers=["X-Request-ID", "Retry-After", "Idempotent-Replayed"])

CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self'; "
       "connect-src 'self'; font-src 'self' https://fonts.gstatic.com; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; "
       "form-action 'self'")


@app.middleware("http")
async def request_context(request: Request, call_next):
    incoming = request.headers.get("x-request-id", "")
    request_id = incoming if _REQUEST_ID.match(incoming) else uuid.uuid4().hex
    request.state.request_id = request_id
    limit = get_settings().max_request_bytes
    length = request.headers.get("content-length")
    start = time.perf_counter()
    if length and length.isdigit() and int(length) > limit:
        response = problem(request, 413, f"Request body larger than {limit // 1024} KiB", code="PAYLOAD_TOO_LARGE")
    else:
        try:
            response = await call_next(request)
        except Exception:  # last resort; routers handle their own errors
            log.exception("unhandled error", extra={"request_id": request_id})
            response = problem(request, 500, "Internal error", code="INTERNAL")
    seconds = time.perf_counter() - start
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if get_settings().cookie_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    elif request.url.path.startswith("/static/") or request.url.path in ("/", "/platform"):
        # Revalidate on every load (ETag/Last-Modified make that a cheap 304) so an upgrade is never masked by
        # stale cached scripts: ES-module imports cannot carry a version query string.
        response.headers["Cache-Control"] = "no-cache"
    if not request.url.path.startswith(("/docs", "/redoc")):
        response.headers["Content-Security-Policy"] = CSP
    route = request.scope.get("route")
    path = getattr(route, "path", None) or ("unmatched" if request.url.path.startswith("/api/") else "static")
    if path not in ("unmatched", "static") and not path.startswith(("/api/", "/health", "/ready", "/metrics", "/docs", "/redoc", "/openapi", "/static")) and path != "/":
        path = API + path  # routers report their path relative to the include prefix
    if request.url.path.startswith("/api/"):
        await run_in_threadpool(activity_log.record, request, response.status_code, seconds * 1000)
        await run_in_threadpool(platform_svc.record_request, request, response.status_code, seconds * 1000)
        metrics.observe(request.method, path, response.status_code, seconds)
        access_log.info("request", extra={
            "request_id": request_id, "tenant_id": getattr(request.state, "tenant_id", None),
            "actor": getattr(request.state, "actor", None), "method": request.method,
            "path": request.url.path, "status": response.status_code, "ms": round(seconds * 1000, 1)})
    return response


app.add_exception_handler(psycopg.Error, db_error_handler)  # type: ignore[arg-type]
app.add_exception_handler(PoolTimeout, pool_timeout_handler)  # type: ignore[arg-type]
app.add_exception_handler(StarletteHTTPException, http_error_handler)  # type: ignore[arg-type]
app.add_exception_handler(RequestValidationError, validation_error_handler)  # type: ignore[arg-type]
app.add_exception_handler(Exception, unhandled_error_handler)

API = "/api/v1"
for module in (auth, users, catalog, orders, audit, governance, integration, ingest, sandbox, activity):
    app.include_router(module.router, prefix=API)
app.include_router(platform.router)  # /api/platform/v1, deliberately outside the organization API


@app.get("/health", tags=["ops"], summary="Liveness probe")
def health():
    return {"status": "ok", "version": __version__}


@app.get("/ready", tags=["ops"], summary="Readiness probe (checks PostgreSQL and the worker)")
def ready():
    try:
        with system_session() as db:
            db.scalar("SELECT 1")
            db.rollback()
    except Exception as exc:
        return JSONResponse(status_code=503, content={"status": "unavailable", "database": type(exc).__name__})
    return {"status": "ready", "database": "ok", "rate_limiter": ratelimit.backend(),
            "worker": {"embedded": get_settings().workers_enabled, "last_run": worker.last_run}}


@app.get("/metrics", include_in_schema=False)
def prometheus(request: Request):
    # Exposed on the same port for simplicity: restrict it at the reverse proxy (see OPERATIONS.md).
    return PlainTextResponse(metrics.render(), media_type="text/plain; version=0.0.4")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/platform", include_in_schema=False)
def platform_console():
    return FileResponse(STATIC_DIR / "platform.html")
