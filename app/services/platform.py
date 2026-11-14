"""Platform administration: operators, the platform audit chain, signed checkpoints and their independent anchor,
break-glass expiry.

Every function here runs on the platform connection (role prov_platform), which cannot read tenant tables.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from email_validator import EmailNotValidError, validate_email

from app.config import get_settings
from app.db import Db, dumps, jsonb, utc
from app.errors import ApiError
from app.security import checkpoint_public_key, hash_password, sign_platform_checkpoint, verify_platform_checkpoint

log = logging.getLogger("app.platform")

ROLES = ("super_admin", "security_officer")
MIN_OPERATOR_PASSWORD = 12  # stricter than organization users: operators guard every organization


# ---- platform audit chain ----------------------------------------------------------------------
def append(db: Db, *, actor: str, actor_id: int | None, action: str, outcome: str = "SUCCESS",
           tenant_id: int | None = None, target: str | None = None, ip: str | None = None, user_agent: str | None = None,
           request_id: str | None = None, details: dict[str, Any] | None = None, commit: bool = True) -> int:
    audit_id = db.scalar("SELECT prov.platform_audit_append(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                         (actor, actor_id, action, outcome, tenant_id, target, ip, user_agent, request_id,
                          jsonb(details or {})))
    if commit:
        db.commit()
    return int(audit_id)


def verify_chain(db: Db, from_seq: int = 1) -> dict[str, Any]:
    checked, nxt = 0, from_seq
    while True:
        r = db.one("SELECT * FROM prov.platform_audit_verify(%s, %s)", (nxt, 50_000))
        assert r is not None
        checked += int(r["checked"])
        if not r["ok"] or r["complete"]:
            return {"ok": r["ok"], "checked": checked, "first_bad_seq": r["first_bad_seq"], "reason": r["reason"],
                    "head_seq": r["head_seq"], "last_seq": r["last_seq"], "last_hash": r["last_hash"]}
        nxt = int(r["last_seq"]) + 1


def _check_checkpoints(db: Db, head_seq: int, cps: list[dict[str, Any]], origin: str) -> tuple[int, dict | None]:
    if not cps:
        return 0, None
    hashes = {r["seq"]: r["row_hash"] for r in db.all(
        "SELECT seq, row_hash FROM platform_audit_log WHERE seq = ANY(%s)", ([int(c["seq"]) for c in cps],))}
    key_id = checkpoint_public_key()["key_id"]
    checked = 0
    for cp in sorted(cps, key=lambda c: int(c["seq"])):
        seq = int(cp["seq"])
        if cp.get("key_id") not in (None, key_id):
            continue
        created = cp["created_at"] if isinstance(cp["created_at"], datetime) else datetime.fromisoformat(str(cp["created_at"]).replace("Z", "+00:00"))
        if not verify_platform_checkpoint(seq, cp["row_hash"], utc(created), cp["signature"]):
            return checked, {"first_bad_seq": seq, "reason": f"{origin} checkpoint at record {seq} has an invalid signature"}
        if seq > head_seq:
            return checked, {"first_bad_seq": head_seq + 1,
                             "reason": f"{origin} checkpoint proves record {seq} existed, but the chain ends at {head_seq} (history was truncated)"}
        if hashes.get(seq) != cp["row_hash"]:
            return checked, {"first_bad_seq": seq,
                             "reason": f"{origin} checkpoint at record {seq} does not match the chain (history was rewritten)"}
        checked += 1
    return checked, None


def read_anchor() -> list[dict[str, Any]]:
    path = get_settings().platform_anchor_path
    if not path or not Path(path).exists():
        return []
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except ValueError:
                out.append({"seq": 0, "row_hash": "", "created_at": "1970-01-01T00:00:00+00:00", "signature": "corrupt"})
    return out


def verify_all(db: Db, external: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """The chain, every stored checkpoint, every checkpoint in the independent anchor, and any the caller kept."""
    result = verify_chain(db)
    info: dict[str, Any] = {"stored": 0, "anchor": 0, "external": 0, "anchor_configured": bool(get_settings().platform_anchor_path)}
    if result["ok"]:
        head = int(result["head_seq"])
        stored = db.all("SELECT seq, row_hash, created_at, key_id, signature FROM platform_checkpoints ORDER BY seq")
        for name, cps in (("stored", stored), ("anchor", read_anchor()), ("external", external or [])):
            n, failure = _check_checkpoints(db, head, cps, {"stored": "Stored", "anchor": "Anchored", "external": "External"}[name])
            info[name] = n
            if failure:
                result.update(ok=False, **failure)
                break
    db.rollback()
    return {**result, "checkpoints": info, "verified_at": datetime.now(UTC)}


def _anchor_write(record: dict[str, Any]) -> None:
    path = get_settings().platform_anchor_path
    if not path:
        return
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    # O_APPEND: the process never seeks or rewrites. Put this path on write-once storage for immutability.
    fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
    try:
        os.write(fd, (json.dumps(record, sort_keys=True) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def create_checkpoint(db: Db, actor: str = "system:worker", actor_id: int | None = None) -> dict[str, Any] | None:
    last = db.one("SELECT seq, row_hash FROM platform_checkpoints ORDER BY seq DESC LIMIT 1")
    last_seq = int(last["seq"]) if last else 0
    head = db.scalar("SELECT last_seq FROM platform_chain_head")
    if not head or int(head) <= last_seq:
        db.rollback()
        return None
    if last and db.scalar("SELECT row_hash FROM platform_audit_log WHERE seq = %s", (last_seq,)) != last["row_hash"]:
        db.rollback()
        return {"ok": False, "first_bad_seq": last_seq, "reason": "Stored checkpoint does not match the chain (history was rewritten)"}
    result = verify_chain(db, last_seq + 1)
    if not result["ok"]:
        db.rollback()
        return {"ok": False, **result}
    seq, row_hash = int(result["last_seq"]), str(result["last_hash"])
    created = datetime.now(UTC).replace(microsecond=0)
    key = checkpoint_public_key()
    sig = sign_platform_checkpoint(seq, row_hash, created)
    if not db.execute("INSERT INTO platform_checkpoints (seq, row_hash, created_at, key_id, signature) VALUES (%s, %s, %s, %s, %s) "
                      "ON CONFLICT (seq) DO NOTHING", (seq, row_hash, created, key["key_id"], sig)):
        db.rollback()
        return None
    db.commit()
    record = {"seq": seq, "row_hash": row_hash, "created_at": created.isoformat(), "key_id": key["key_id"], "signature": sig}
    try:
        _anchor_write(record)
    except OSError:
        log.exception("could not write platform checkpoint to the anchor")
        append(db, actor=actor, actor_id=actor_id, action="platform.anchor_failed", outcome="FAILURE", details=record)
    append(db, actor=actor, actor_id=actor_id, action="platform.checkpoint", details={"seq": seq, "row_hash": row_hash})
    return {"ok": True, **record}


# ---- operators ------------------------------------------------------------------------------------
def create_operator(db: Db, email: str, full_name: str, role: str, password: str, created_by: str) -> int:
    if role not in ROLES:
        raise ApiError(422, f"role must be one of {ROLES}", "VALIDATION_ERROR")
    if len(password) < MIN_OPERATOR_PASSWORD:
        raise ApiError(422, f"Operator passwords need at least {MIN_OPERATOR_PASSWORD} characters", "VALIDATION_ERROR")
    # Same rules as sign-in (pydantic EmailStr), so an operator is never created with an address that can't log in.
    try:
        email = validate_email(email, check_deliverability=False).normalized
    except EmailNotValidError as exc:
        raise ApiError(422, f"Invalid operator email: {exc}", "VALIDATION_ERROR") from None
    return int(db.insert("INSERT INTO platform_users (email, full_name, password_hash, role, created_by) VALUES (%s, %s, %s, %s, %s)",
                         (email.lower(), full_name, hash_password(password), role, created_by), "platform_user_id"))


# ---- break-glass expiry -----------------------------------------------------------------------------
def expire_grants(db: Db) -> list[dict[str, Any]]:
    rows = db.all("UPDATE break_glass_grants SET status = 'EXPIRED' "
                  "WHERE (status = 'ACTIVE' AND expires_at <= now()) OR (status = 'APPROVED' AND approval_expires_at < now()) "
                  "RETURNING grant_id, tenant_id")
    db.commit()
    for r in rows:
        append(db, actor="system:worker", actor_id=None, action="breakglass.expired", tenant_id=r["tenant_id"],
               target=f"grant:{r['grant_id']}")
    return rows


def export_rows(rows: list[dict[str, Any]]) -> str:
    return dumps(rows)


def record_request(request: Any, status: int, duration_ms: float) -> None:
    """Middleware hook: every platform console request lands in the platform chain, including failures and
    anonymous probes. Runs after the response is known; failures to write are logged loudly."""
    from app.db import platform_enabled, platform_session
    from app.ratelimit import client_ip

    if not request.url.path.startswith("/api/platform/") or not platform_enabled():
        return
    st = request.state
    route = getattr(request.scope.get("route"), "path", None) or request.url.path
    action = getattr(st, "platform_action", None) or f"{request.method} {route.removeprefix('/api/platform/v1')}"
    outcome = "SUCCESS" if status < 400 else "DENIED" if status in (401, 403, 429) else "FAILURE"
    details: dict[str, Any] = {k: str(v) for k, v in (request.scope.get("path_params") or {}).items()}
    details.update(getattr(st, "platform_details", None) or {})
    details.update(status=status, ms=int(duration_ms), method=request.method)
    try:
        with platform_session() as db:
            append(db, actor=getattr(st, "platform_actor", None) or "anonymous", actor_id=getattr(st, "platform_actor_id", None),
                   action=action, outcome=outcome, tenant_id=getattr(st, "platform_tenant", None), target=request.url.path,
                   ip=client_ip(request), user_agent=request.headers.get("user-agent"),
                   request_id=getattr(st, "request_id", None), details=json.loads(dumps(details)))
    except Exception:
        log.exception("could not write platform audit record", extra={"request_id": getattr(st, "request_id", None)})
