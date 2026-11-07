from __future__ import annotations

import uuid

import fakeredis
import pytest
from fastapi import HTTPException

from app import ratelimit


def _source(org, method="CSV_IMPORT", trust="LOW"):
    code = f"csv-{uuid.uuid4().hex[:6]}"
    org.req("POST", "/sources", {"code": code, "name": "Nightly export", "capture_method": method, "trust_level": trust},
            expect=201)
    return code


def _upload(org, path, source, csv_text, token=None, **form):
    data = {"source": source, "entity": "product", **{k: str(v).lower() if isinstance(v, bool) else v for k, v in form.items()}}
    return org.client.post(f"/api/v1{path}", data=data, files={"file": ("snapshot.csv", csv_text.encode(), "text/csv")},
                           headers=org.headers(token))


DAY1 = "external_id,name,price\nSKU-1,Keyboard,80.00\nSKU-2,Mouse,25.00\nSKU-3,Cable,5.00\n"
DAY2 = "external_id,name,price\nSKU-1,Keyboard,75.00\nSKU-2,Mouse,25\nSKU-4,Monitor,320.00\n"  # 1 changed, 3 gone, 4 new


def test_import_records_only_changes(org):
    src = _source(org)
    preview = _upload(org, "/imports", src, DAY1, dry_run=True).json()
    assert preview["dry_run"] and preview["created"] == 3
    assert org.req("GET", "/sources", expect=200).json()[0]["event_count"] == 0  # dry run wrote nothing

    first = _upload(org, "/imports", src, DAY1).json()
    assert (first["created"], first["updated"], first["unchanged"]) == (3, 0, 0)
    again = _upload(org, "/imports", src, DAY1).json()
    assert (again["created"], again["updated"], again["unchanged"]) == (0, 0, 3)  # same file twice: nothing new

    day2 = _upload(org, "/imports", src, DAY2, complete=True).json()
    changes = {c["external_id"]: c for c in day2["changes"]}
    assert (day2["created"], day2["updated"], day2["deleted"], day2["unchanged"]) == (1, 1, 1, 1)  # "25" == "25.00"
    assert changes["SKU-1"]["changed_fields"] == ["price"]
    assert changes["SKU-1"]["before"]["price"] == "80.00" and changes["SKU-1"]["after"]["price"] == "75.00"
    assert changes["SKU-3"]["change"] == "deleted" and changes["SKU-4"]["change"] == "created"

    # each change is hash-chained evidence attributed to the uploader, with the source's trust level
    hist = org.req("GET", f"/provenance/external_event/{changes['SKU-1']['event_pk']}/history", expect=200).json()["history"]
    assert hist[0]["actor"] == org.admin_email
    assert org.req("POST", "/audit/verify", expect=200).json()["ok"]


def test_flip_flop_history_is_kept(org):
    src = _source(org)
    a, b = "external_id,price\nX,1\n", "external_id,price\nX,2\n"
    results = [_upload(org, "/imports", src, body).json() for body in (a, b, a, b)]
    assert [(r["created"], r["updated"]) for r in results] == [(1, 0), (0, 1), (0, 1), (0, 1)]
    assert all(not c["duplicate"] for r in results for c in r["changes"])


def test_csv_reconciliation(org):
    src = _source(org)
    _upload(org, "/imports", src, DAY1)
    r = _upload(org, "/reconciliations/upload", src, "external_id,price\nSKU-1,80\nSKU-2,30.00\nSKU-9,1\n", complete=True)
    assert r.status_code == 201, r.text
    rec = r.json()
    assert (rec["matched"], rec["mismatched"], rec["missing"], rec["unexpected"]) == (1, 1, 1, 1)
    # reconciliation records no events
    sid = next(s["source_id"] for s in org.req("GET", "/sources", expect=200).json() if s["code"] == src)
    assert len(org.req("GET", f"/sources/{sid}/events", expect=200).json()) == 3


@pytest.mark.parametrize("bad, fragment", [
    ("name,price\nA,1\n", "external_id"),
    ("external_id,price\n,1\n", "external_id is empty"),
    ("external_id,price\nA,1\nA,2\n", "duplicate external_id"),
    ("external_id,price\nA,1,extra\n", "more values"),
    ("external_id,price\n", "no data rows"),
])
def test_bad_csv_is_rejected_with_line_numbers(org, bad, fragment):
    r = _upload(org, "/imports", _source(org), bad)
    assert r.status_code == 422 and fragment in r.json()["detail"]


def test_import_permissions_and_paused_source(org):
    src = _source(org)
    viewer = org.add_user("viewer")
    assert _upload(org, "/imports", src, DAY1, token=viewer).status_code == 403
    assert _upload(org, "/imports", "nope", DAY1).status_code == 422
    sid = next(s["source_id"] for s in org.req("GET", "/sources", expect=200).json() if s["code"] == src)
    org.req("PATCH", f"/sources/{sid}", {"status": "PAUSED"}, expect=200)
    assert _upload(org, "/imports", src, DAY1).status_code == 409
    assert _upload(org, "/imports", src, DAY1, dry_run=True).status_code == 200  # previews still allowed


def test_redis_rate_limiter_is_shared_and_sliding():
    fake = fakeredis.FakeRedis()
    ratelimit.set_redis_client(fake)
    try:
        assert ratelimit.backend() == "redis"
        assert ratelimit.hit("apikey:r", 2) == 1
        assert ratelimit.hit("apikey:r", 2) == 0
        with pytest.raises(HTTPException) as exc:
            ratelimit.hit("apikey:r", 2)
        assert exc.value.status_code == 429 and int(exc.value.headers["Retry-After"]) >= 1
        assert fake.zcard("prov:rl:apikey:r") == 2  # the rejected request did not consume a slot
        # a second "process" sharing the same Redis sees the same counter
        ratelimit._hits.clear()
        with pytest.raises(HTTPException):
            ratelimit.hit("apikey:r", 2)
        assert ratelimit.hit("apikey:other", 2) == 1
    finally:
        ratelimit.reset()
        ratelimit.set_redis_client(None)


def test_rate_limiter_falls_back_to_memory_when_redis_is_down():
    class Down:
        def pipeline(self, **_):
            raise ConnectionError("redis down")

    ratelimit.set_redis_client(Down())
    try:
        assert ratelimit.hit("apikey:fallback", 5) == 4  # served by the in-memory window
    finally:
        ratelimit.set_redis_client(None)
        ratelimit.reset()
