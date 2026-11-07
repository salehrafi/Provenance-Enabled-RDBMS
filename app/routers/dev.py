"""Development-only helpers. Not mounted unless ENVIRONMENT is development/test."""

from __future__ import annotations

import json
from collections import deque
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request

from app.deps import CurrentUser, viewer

router = APIRouter(prefix="/dev", tags=["development"])

_received: deque[dict] = deque(maxlen=200)


@router.post("/webhook-sink", include_in_schema=True, summary="Local webhook receiver for testing deliveries")
async def webhook_sink(request: Request):
    raw = await request.body()
    try:
        body = json.loads(raw)
    except ValueError:
        body = raw.decode(errors="replace")
    _received.appendleft({
        "received_at": datetime.now(timezone.utc).isoformat(),
        "event": request.headers.get("x-provenance-event"),
        "delivery": request.headers.get("webhook-id"),
        "signature": request.headers.get("webhook-signature"),
        "body": body,
    })
    return {"ok": True}


@router.get("/webhook-sink", summary="What the local webhook receiver has received (your tenant only)")
def webhook_sink_log(limit: int = 50, user: CurrentUser = Depends(viewer)):
    mine = [r for r in _received if isinstance(r["body"], dict) and r["body"].get("tenant_id") == user.tenant_id]
    return mine[:limit]
