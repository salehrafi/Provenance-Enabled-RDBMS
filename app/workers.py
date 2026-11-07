"""Background worker thread: webhook dispatch every few seconds, rules every minute.

Each tenant is processed in its own tenant-scoped session, so VPD isolation also applies to
background work. With several API processes, run this in one process only (WORKERS_ENABLED).
"""

from __future__ import annotations

import logging
import threading
import time
import uuid

import httpx

from app.config import get_settings
from app.db import system_session, tenant_session
from app.services import rules, webhooks

log = logging.getLogger("app.workers")


class Workers:
    def __init__(self) -> None:
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_rules = 0.0
        self.last_run: dict[str, float] = {}

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="provenance-workers", daemon=True)
        self._thread.start()
        log.info("background workers started")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)

    def _tenants(self) -> list[int]:
        with system_session() as db:
            return [int(r["tenant_id"]) for r in db.all("SELECT tenant_id FROM tenants ORDER BY tenant_id")]

    def run_once(self, include_rules: bool = False) -> None:
        with httpx.Client() as client:
            for tid in self._tenants():
                try:
                    with tenant_session(tid, None, "system:worker", f"worker-{uuid.uuid4().hex[:12]}") as db:
                        webhooks.process_tenant(db, tid, client)
                        if include_rules:
                            rules.run_rules(db, tid)
                except Exception:
                    log.exception("worker failed for tenant %s", tid)
        self.last_run["dispatch"] = time.time()
        if include_rules:
            self.last_run["rules"] = time.time()

    def _loop(self) -> None:
        s = get_settings()
        while not self._stop.wait(s.dispatcher_interval_seconds):
            due_rules = time.monotonic() - self._last_rules >= s.rules_interval_seconds
            try:
                self.run_once(include_rules=due_rules)
            except Exception:
                log.exception("worker loop iteration failed")
            if due_rules:
                self._last_rules = time.monotonic()


workers = Workers()
