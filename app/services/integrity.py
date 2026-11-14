"""Audit-chain verification and signed checkpoints.

The hash chain alone proves internal consistency: any edit, deletion or re-ordering of records
breaks a link. It does not stop someone with full control of the database from rewriting the
whole chain and recomputing every hash. Checkpoints close that gap: periodically the worker
signs "tenant T, record N, hash H, time" with an Ed25519 key that the database never holds, and
publishes the result to the outbox (so customers keep copies via webhooks) and optionally to an
append-only file. A rewritten chain cannot match a checkpoint it did not sign.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.common import emit_event
from app.config import get_settings
from app.db import Db, dumps, utc
from app.security import checkpoint_public_key, sign_checkpoint, verify_checkpoint

log = logging.getLogger("app.integrity")

SLICE = 50_000
ALGORITHM = "SHA-256 hash chain, Ed25519 checkpoints"


def verify_chain(db: Db, from_seq: int = 1) -> dict[str, Any]:
    """Verify records from `from_seq` to the chain head, in slices."""
    checked = 0
    next_seq = from_seq
    while True:
        r = db.one("SELECT * FROM prov.audit_verify(%s, %s)", (next_seq, SLICE))
        assert r is not None
        checked += int(r["checked"])
        if not r["ok"] or r["complete"]:
            return {"ok": r["ok"], "checked": checked, "first_bad_seq": r["first_bad_seq"], "reason": r["reason"],
                    "head_seq": r["head_seq"], "last_seq": r["last_seq"], "last_hash": r["last_hash"]}
        next_seq = int(r["last_seq"]) + 1


def list_checkpoints(db: Db, limit: int = 100, before_seq: int | None = None) -> list[dict[str, Any]]:
    return db.all(
        "SELECT checkpoint_id, chain_seq, row_hash, created_at, key_id, signature FROM audit_checkpoints "
        "WHERE (%(b)s::bigint IS NULL OR chain_seq < %(b)s) ORDER BY chain_seq DESC LIMIT %(l)s",
        {"b": before_seq, "l": limit})


def _check_checkpoints(db: Db, tenant_id: int, head_seq: int, checkpoints: Iterable[dict[str, Any]],
                       origin: str) -> tuple[int, int, dict[str, Any] | None]:
    """Return (checked, unknown_key, first failure or None)."""
    key = checkpoint_public_key()
    cps = sorted(checkpoints, key=lambda c: c["chain_seq"])
    if not cps:
        return 0, 0, None
    hashes = {r["chain_seq"]: r["row_hash"] for r in db.all(
        "SELECT chain_seq, row_hash FROM audit_log WHERE chain_seq = ANY(%s)", ([c["chain_seq"] for c in cps],))}
    checked = unknown = 0
    for cp in cps:
        seq = int(cp["chain_seq"])
        if cp.get("key_id") not in (None, key["key_id"]):
            unknown += 1  # signed by a retired key; cannot be judged with the current one
            continue
        if not verify_checkpoint(tenant_id, seq, cp["row_hash"], utc(cp["created_at"]), cp["signature"]):
            return checked, unknown, {"first_bad_seq": seq, "reason": f"{origin} checkpoint at record {seq} has an invalid signature"}
        if seq > head_seq:
            return checked, unknown, {"first_bad_seq": head_seq + 1, "reason":
                                      f"{origin} checkpoint proves record {seq} existed, but the chain ends at {head_seq} (history was truncated)"}
        if hashes.get(seq) != cp["row_hash"]:
            return checked, unknown, {"first_bad_seq": seq, "reason":
                                      f"{origin} checkpoint at record {seq} does not match the chain (history was rewritten)"}
        checked += 1
    return checked, unknown, None


def verify_tenant(db: Db, tenant_id: int, external: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Full verification: every link of the chain, every stored checkpoint, and any checkpoints
    the caller kept outside the system."""
    result = verify_chain(db)
    stats = db.one("SELECT count(*) AS n, max(chain_seq) AS head_seq FROM audit_log")
    assert stats is not None
    result["records"] = stats["n"]
    cp_info: dict[str, Any] = {"checked": 0, "external_checked": 0, "unknown_key": 0, "latest": None}
    if result["ok"]:
        stored = db.all("SELECT chain_seq, row_hash, created_at, key_id, signature FROM audit_checkpoints ORDER BY chain_seq")
        head = int(result["head_seq"])
        checked, unknown, failure = _check_checkpoints(db, tenant_id, head, stored, "Stored")
        cp_info.update(checked=checked, unknown_key=unknown)
        if stored:
            last = stored[-1]
            cp_info["latest"] = {"chain_seq": last["chain_seq"], "created_at": last["created_at"]}
        if not failure and external:
            ext_checked, _, failure = _check_checkpoints(db, tenant_id, head, external, "External")
            cp_info["external_checked"] = ext_checked
        if failure:
            result.update(ok=False, **failure)
    result["checkpoints"] = cp_info
    result["verified_at"] = datetime.now(UTC)
    result["algorithm"] = ALGORITHM
    return result


def _anchor(record: dict[str, Any]) -> None:
    path = get_settings().checkpoint_anchor_path
    if not path:
        return
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str, sort_keys=True) + "\n")
    except OSError:
        # The checkpoint is still stored and published; failing to anchor must be loud, not fatal.
        log.exception("could not write checkpoint to anchor file %s", path)


def create_checkpoint(db: Db, tenant_id: int) -> dict[str, Any] | None:
    """Verify everything since the last checkpoint and, if intact, sign the new chain head.

    Returns the new checkpoint, None if there is nothing new, or {"ok": False, ...} when the
    chain fails verification (in which case nothing is signed)."""
    last = db.one("SELECT chain_seq, row_hash FROM audit_checkpoints ORDER BY chain_seq DESC LIMIT 1")
    last_seq = int(last["chain_seq"]) if last else 0
    if last:
        # The incremental check below trusts the record at last_seq, so first confirm it is still
        # the record the previous checkpoint vouched for.
        current = db.scalar("SELECT row_hash FROM audit_log WHERE chain_seq = %s", (last_seq,))
        if current != last["row_hash"]:
            db.rollback()
            return {"ok": False, "first_bad_seq": last_seq, "checked": 0,
                    "reason": f"Stored checkpoint at record {last_seq} does not match the chain (history was rewritten)"}
    head = db.one("SELECT last_seq FROM audit_chain_head")
    if not head or int(head["last_seq"]) <= last_seq:
        db.rollback()
        return None
    result = verify_chain(db, last_seq + 1)
    if not result["ok"]:
        db.rollback()
        return {"ok": False, **result}
    seq, row_hash = int(result["last_seq"]), result["last_hash"]
    created_at = datetime.now(UTC).replace(microsecond=0)
    key = checkpoint_public_key()
    checkpoint = {"tenant_id": tenant_id, "chain_seq": seq, "row_hash": row_hash, "created_at": created_at,
                  "key_id": key["key_id"], "signature": sign_checkpoint(tenant_id, seq, row_hash, created_at)}
    inserted = db.execute(
        "INSERT INTO audit_checkpoints (chain_seq, row_hash, created_at, key_id, signature) "
        "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (tenant_id, chain_seq) DO NOTHING",
        (seq, row_hash, created_at, key["key_id"], checkpoint["signature"]))
    if not inserted:  # another worker got there first
        db.rollback()
        return None
    emit_event(db, "audit.checkpoint", "audit_log", seq, {**checkpoint, "algorithm": key["algorithm"]})
    db.commit()
    _anchor(json.loads(dumps(checkpoint)))
    return {"ok": True, **checkpoint}
