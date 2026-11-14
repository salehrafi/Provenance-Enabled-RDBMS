"""Background worker: webhook dispatch, rules, audit checkpoints, housekeeping.

Run it as its own process in production:  python -m app.worker
or embed it in the API process for local development (WORKERS_ENABLED=true).

Any number of workers may run at once. Dispatch uses row leases with SKIP LOCKED; checkpoints
and rule alerts are idempotent (unique keys), so two workers racing produce one result. Every
unit of work runs inside a tenant-scoped session, so row-level security applies to background
work exactly as it does to requests.
"""

from __future__ import annotations

import logging
import signal
import threading
import time
import uuid

import httpx

from app.config import get_settings
from app.db import close_pool, init_pool, system_session, tenant_session
from app.services import integrity, rules, webhooks

log = logging.getLogger("app.worker")


class Worker:
    def __init__(self) -> None:
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last: dict[str, float] = {}
        self.last_run: dict[str, float] = {}

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self.loop, name="provenance-worker", daemon=True)
        self._thread.start()
        log.info("worker started")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=15)
            self._thread = None

    @staticmethod
    def tenants(only_pending: bool) -> list[int]:
        with system_session() as db:
            ids = [r["worker_tenants"] for r in db.all("SELECT prov.worker_tenants(%s)", (only_pending,))]
            db.rollback()
        return ids

    def _due(self, name: str, every: float) -> bool:
        if time.monotonic() - self._last.get(name, -1e12) >= every:
            self._last[name] = time.monotonic()
            return True
        return False

    def run_once(self, rules_too: bool = False, checkpoints_too: bool = False, prune_too: bool = False,
                 verify_too: bool = False) -> None:
        s = get_settings()
        run_id = uuid.uuid4().hex[:12]
        with httpx.Client() as client:
            for tid in self.tenants(only_pending=not (rules_too or checkpoints_too)):
                try:
                    with tenant_session(tid, None, "system:worker", f"worker-{run_id}") as db:
                        webhooks.process_tenant(db, tid, client)
                        broken = False
                        if verify_too or checkpoints_too and "verify" not in self.last_run:
                            # Full verification first: a checkpoint must never vouch for a chain that fails it.
                            res = rules.run_rules(db, tid, only={"DQ004"})
                            broken = bool(res["rules"].get("DQ004", {}).get("findings") or res["rules"].get("DQ004", {}).get("error"))
                        if checkpoints_too and not broken:
                            result = integrity.create_checkpoint(db, tid)
                            if result and not result.get("ok"):
                                log.error("audit chain verification failed for tenant %s: %s", tid, result.get("reason"))
                                rules.raise_alert(db, rules.Finding(
                                    "DQ004", "CRITICAL", "audit_log", str(result.get("first_bad_seq")),
                                    f"Audit chain integrity failure at record {result.get('first_bad_seq')}: {result.get('reason')}",
                                    {"reason": result.get("reason")}, f"DQ004:{result.get('first_bad_seq')}:{result.get('reason')}"))
                                db.commit()
                        if rules_too:
                            rules.run_rules(db, tid, skip={"DQ004"})
                except Exception:
                    log.exception("worker failed for tenant %s", tid)
        self.last_run["dispatch"] = time.time()
        if verify_too:
            self.last_run["verify"] = time.time()
        if checkpoints_too:
            self.last_run["checkpoint"] = time.time()
        if rules_too:
            self.last_run["rules"] = time.time()
        self.platform_jobs(checkpoints_too)
        if prune_too:
            with system_session() as db:
                r = db.one("SELECT * FROM prov.prune_operational_data(%s)", (s.delivery_retention_days,))
                db.commit()
            log.info("pruned %s", r)

    def platform_jobs(self, checkpoint: bool) -> None:
        """Expire break-glass grants on time and sign platform checkpoints (only when the console is configured)."""
        from app.db import platform_enabled, platform_session
        from app.services import platform as platform_svc

        if not platform_enabled():
            return
        try:
            with platform_session() as db:
                platform_svc.expire_grants(db)
                if checkpoint:
                    result = platform_svc.create_checkpoint(db)
                    if result and not result.get("ok"):
                        log.error("platform audit chain verification failed: %s", result.get("reason"))
                        platform_svc.append(db, actor="system:worker", actor_id=None, action="platform.integrity_failed",
                                            outcome="FAILURE", details={"reason": result.get("reason")})
            self.last_run["platform"] = time.time()
        except Exception:
            log.exception("platform jobs failed")

    def loop(self) -> None:
        s = get_settings()
        while not self._stop.wait(s.dispatcher_interval_seconds):
            try:
                self.run_once(
                    rules_too=self._due("rules", s.rules_interval_seconds),
                    checkpoints_too=self._due("checkpoint", s.checkpoint_interval_seconds),
                    verify_too=self._due("verify", s.full_verify_interval_seconds),
                    prune_too=self._due("prune", s.prune_interval_seconds))
            except Exception:
                log.exception("worker iteration failed")


worker = Worker()


def main() -> None:
    from app.main import configure_logging

    configure_logging()
    s = get_settings()
    problems = s.problems()
    if problems and not s.is_dev:
        raise SystemExit("Unsafe configuration: " + "; ".join(problems))
    init_pool()
    signal.signal(signal.SIGTERM, lambda *_: worker._stop.set())
    signal.signal(signal.SIGINT, lambda *_: worker._stop.set())
    worker.loop()
    close_pool()


if __name__ == "__main__":
    main()
