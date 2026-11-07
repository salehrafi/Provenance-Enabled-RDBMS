"""Sliding-window rate limiter.

With REDIS_URL set, counters live in Redis (one sorted set per key), so the limit holds across
any number of API processes and servers. Without it, or if Redis becomes unreachable, a
per-process in-memory window is used, so the API keeps working (limits are then per process).
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from collections import defaultdict, deque
from typing import Any

from fastapi import HTTPException, Request, status

from app.config import get_settings

log = logging.getLogger("app.ratelimit")

_hits: dict[str, deque[float]] = defaultdict(deque)
_lock = threading.Lock()
_redis_client: Any = None
_redis_failed_at = 0.0
_PREFIX = "prov:rl:"


def set_redis_client(client: Any) -> None:
    """Use this Redis client (tests pass a fakeredis instance; None reverts to REDIS_URL/memory)."""
    global _redis_client
    _redis_client = client


def _redis() -> Any:
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    url = get_settings().redis_url
    if not url or time.monotonic() - _redis_failed_at < 30:  # back off 30 s after a failure
        return None
    import redis

    _redis_client = redis.Redis.from_url(url, socket_timeout=0.5, socket_connect_timeout=0.5)
    return _redis_client


def _too_many(limit: int, retry: int) -> HTTPException:
    return HTTPException(
        status.HTTP_429_TOO_MANY_REQUESTS,
        "Too many requests, try again later",
        headers={"Retry-After": str(max(retry, 1)), "RateLimit-Limit": str(limit), "RateLimit-Remaining": "0"},
    )


def _hit_redis(r: Any, key: str, limit: int, window: float) -> int:
    now = time.time()
    rkey = _PREFIX + key
    member = f"{now:.6f}-{uuid.uuid4().hex[:8]}"
    pipe = r.pipeline(transaction=True)
    pipe.zremrangebyscore(rkey, 0, now - window)
    pipe.zadd(rkey, {member: now})
    pipe.zcard(rkey)
    pipe.zrange(rkey, 0, 0, withscores=True)
    pipe.expire(rkey, int(window) + 1)
    _, _, count, oldest, _ = pipe.execute()
    if count > limit:
        r.zrem(rkey, member)  # a rejected request does not use up the window
        oldest_ts = oldest[0][1] if oldest else now
        raise _too_many(limit, int(window - (now - oldest_ts)) + 1)
    return limit - count


def _hit_memory(key: str, limit: int, window: float) -> int:
    now = time.monotonic()
    with _lock:
        q = _hits[key]
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= limit:
            raise _too_many(limit, int(window - (now - q[0])) + 1)
        q.append(now)
        return limit - len(q)


def hit(key: str, limit: int, window: float = 60.0) -> int:
    """Count one request against `key`; raise 429 if over `limit` per `window`. Returns remaining."""
    global _redis_client, _redis_failed_at
    r = _redis()
    if r is not None:
        try:
            return _hit_redis(r, key, limit, window)
        except HTTPException:
            raise
        except Exception:  # redis.RedisError, connection refused, timeouts
            log.warning("redis rate limiter unavailable, using in-memory limits", exc_info=True)
            _redis_failed_at = time.monotonic()
            if get_settings().redis_url:
                _redis_client = None
    return _hit_memory(key, limit, window)


def rate_limit(request: Request, bucket: str, limit: int | None = None, window: float = 60.0) -> None:
    limit = limit or get_settings().login_rate_limit_per_minute
    client = request.client.host if request.client else "unknown"
    hit(f"{bucket}:{client}", limit, window)


def reset() -> None:
    with _lock:
        _hits.clear()
    if _redis_client is not None:
        for k in _redis_client.scan_iter(_PREFIX + "*"):
            _redis_client.delete(k)


def backend() -> str:
    return "redis" if _redis() is not None else "memory"
