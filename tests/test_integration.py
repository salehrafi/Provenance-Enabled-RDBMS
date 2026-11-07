from __future__ import annotations

import uuid

import pytest


def _source(org, code=None, trust="HIGH", method="CDC"):
    code = code or f"legacy-{uuid.uuid4().hex[:6]}"
    org.req("POST", "/sources", {"code": code, "name": "Legacy shop", "capture_method": method, "trust_level": trust},
            expect=201)
    return code


def _key(org, scopes=("events:write", "events:read")):
    return org.req("POST", "/api-keys", {"name": f"connector-{uuid.uuid4().hex[:4]}", "scopes": list(scopes)},
                   expect=201).json()["api_key"]


def _event(source, event_id=None, **over):
    ev = {"specversion": "1.0", "id": event_id or uuid.uuid4().hex, "source": source, "type": "order.updated",
          "subject": "order/10045", "time": "2026-11-07T10:12:03Z",
          "data": {"op": "u", "before": {"total": "1500.00"}, "after": {"total": "1200.00"}}}
    ev.update(over)
    return ev


def _post(client, key, body):
    return client.post("/api/v1/events", json=body, headers={"Authorization": f"Bearer {key}"})


def test_ingest_is_idempotent_and_hash_chained(client, org):
    source, key = _source(org), _key(org)
    ev = _event(source)
    first = _post(client, key, ev)
    assert first.status_code == 201, first.text
    body = first.json()
    assert body["duplicate"] is False and body["entity"] == "order" and body["external_id"] == "10045"
    assert body["trust_level"] == "HIGH" and body["capture_method"] == "CDC"  # from registration

    again = _post(client, key, ev)
    assert again.status_code == 200 and again.json()["duplicate"] is True
    assert again.json()["event_pk"] == body["event_pk"]

    # the event is in the tamper-evident audit log, attributed to the API key
    hist = org.req("GET", f"/provenance/external_event/{body['event_pk']}/history", expect=200).json()["history"]
    assert len(hist) == 1 and hist[0]["actor"].startswith("apikey:connector-")
    assert hist[0]["new_values"]["data"]["after"]["total"] == "1200.00"
    assert org.req("POST", "/audit/verify", expect=200).json()["ok"]

    listed = client.get("/api/v1/ingested-events", headers={"Authorization": f"Bearer {key}"}).json()
    assert [e["id"] for e in listed["items"]] == [ev["id"]]


def test_sender_cannot_claim_trust_level(client, org):
    source, key = _source(org, trust="LOW", method="CSV_IMPORT"), _key(org)
    r = _post(client, key, {**_event(source), "trust_level": "HIGH"})
    assert r.status_code == 422  # unknown field rejected
    r = _post(client, key, _event(source))
    assert r.json()["trust_level"] == "LOW"


def test_scopes_revocation_and_bad_keys(client, org):
    source = _source(org)
    read_only = _key(org, scopes=["events:read"])
    r = _post(client, read_only, _event(source))
    assert r.status_code == 403 and r.headers["content-type"].startswith("application/problem+json")

    key = _key(org)
    key_id = key.split("_")[1]
    org.req("DELETE", f"/api-keys/{key_id}", expect=204)
    assert _post(client, key, _event(source)).status_code == 401
    assert _post(client, key[:-3] + "xyz", _event(source)).status_code == 401
    assert _post(client, "not-a-key", _event(source)).status_code == 401
    # a user JWT is not an API key
    assert _post(client, org.token, _event(source)).status_code == 401
    keys = org.req("GET", "/api-keys", expect=200).json()
    assert all("secret" not in k and "api_key" not in k for k in keys)


def test_unknown_and_paused_sources(client, org):
    key = _key(org)
    r = _post(client, key, _event("no-such-source"))
    assert r.status_code == 422 and r.json()["code"] == "ORA-20010"
    source = _source(org)
    sid = next(s["source_id"] for s in org.req("GET", "/sources", expect=200).json() if s["code"] == source)
    org.req("PATCH", f"/sources/{sid}", {"status": "PAUSED"}, expect=200)
    r = _post(client, key, _event(source))
    assert r.status_code == 409 and r.json()["code"] == "ORA-20011"


def test_api_keys_and_sources_are_tenant_scoped(client, org, other_org):
    source, key = _source(org), _key(org)
    # other tenant's key cannot write to this tenant's source (source is invisible to it)
    other_key = _key(other_org)
    assert _post(client, other_key, _event(source)).json()["code"] == "ORA-20010"
    assert source not in [s["code"] for s in other_org.req("GET", "/sources", expect=200).json()]
    assert _post(client, key, _event(source)).status_code == 201
    other_list = client.get("/api/v1/ingested-events", headers={"Authorization": f"Bearer {other_key}"}).json()
    assert other_list["items"] == []


@pytest.mark.parametrize("bad", [
    {"specversion": "0.3"},
    {"type": "NotDotted"},
    {"subject": "no-slash"},
    {"time": "yesterday"},
])
def test_validation_errors_are_problem_details(client, org, bad):
    source, key = _source(org), _key(org)
    r = _post(client, key, _event(source, **bad))
    assert r.status_code == 422
    body = r.json()
    assert r.headers["content-type"].startswith("application/problem+json")
    assert {"type", "title", "status", "detail", "instance"} <= body.keys() and body["status"] == 422


def test_batch_reports_each_event(client, org):
    source, key = _source(org), _key(org)
    dup = _event(source)
    assert _post(client, key, dup).status_code == 201
    batch = [_event(source), dup, _event(source, type="BAD"), _event("unknown-src"), "not an object"]
    r = client.post("/api/v1/events:batch", json=batch, headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert [x["status"] for x in body["results"]] == ["created", "duplicate", "invalid", "rejected", "invalid"]
    assert body["results"][3]["code"] == "ORA-20010"
    assert (body["created"], body["duplicates"], body["failed"]) == (1, 1, 3)
    # the good event was committed even though others failed
    listed = client.get("/api/v1/ingested-events", headers={"Authorization": f"Bearer {key}"}).json()
    assert len(listed["items"]) == 2


def test_reconciliation_finds_every_kind_of_discrepancy(client, org):
    source, key = _source(org), _key(org)
    h = {"Authorization": f"Bearer {key}"}
    for ext, total, op in (("A", "100.00", "c"), ("B", "50.00", "c"), ("D", "10.00", "c"), ("E", "5.00", "c")):
        assert _post(client, key, _event(source, subject=f"order/{ext}",
                                          data={"op": op, "after": {"total": total, "status": "OPEN"}})).status_code == 201
    _post(client, key, _event(source, subject="order/E", type="order.deleted", data={"op": "d", "before": {"total": "5"}},
                              time="2026-11-08T00:00:00Z"))
    r = client.post("/api/v1/reconciliations", headers=h, json={
        "source": source, "entity": "order", "complete": True, "as_of": "2026-12-01T00:00:00Z",
        "records": [{"external_id": "A", "fields": {"total": 100, "status": "OPEN"}},   # matches (100 == "100.00")
                    {"external_id": "B", "fields": {"total": "55.00"}},                # mismatch
                    {"external_id": "C", "fields": {"total": "1.00"}}]})               # missing
    assert r.status_code == 201, r.text
    rec = r.json()
    assert (rec["matched"], rec["mismatched"], rec["missing"], rec["unexpected"]) == (1, 1, 1, 1)  # D unexpected; E deleted
    by_id = {i["external_id"]: i for i in rec["issues"]}
    assert by_id["B"]["details"]["differences"] == [{"field": "total", "upstream": "55.00", "recorded": "50.00"}]
    assert by_id["C"]["outcome"] == "MISSING" and by_id["D"]["outcome"] == "UNEXPECTED" and "E" not in by_id

    # visible to humans, and raised an alert
    stored = org.req("GET", f"/reconciliations/{rec['recon_id']}", expect=200).json()
    assert len(stored["issues"]) == 3
    alerts = org.req("GET", "/alerts", expect=200).json()
    assert any(a["rule_code"] == "RC001" and a["entity_id"] == str(rec["recon_id"]) for a in alerts)
    # as_of before the events: nothing recorded yet, so everything is missing
    early = client.post("/api/v1/reconciliations", headers=h, json={
        "source": source, "entity": "order", "as_of": "2000-01-01T00:00:00Z",
        "records": [{"external_id": "A", "fields": {}}]}).json()
    assert early["missing"] == 1


def test_source_events_listing_for_humans(client, org):
    source, key = _source(org), _key(org)
    _post(client, key, _event(source))
    sid = next(s["source_id"] for s in org.req("GET", "/sources", expect=200).json() if s["code"] == source)
    rows = org.req("GET", f"/sources/{sid}/events", expect=200).json()
    assert len(rows) == 1 and rows[0]["payload"]["data"]["op"] == "u"


def test_per_key_rate_limit():
    from fastapi import HTTPException

    from app import ratelimit

    ratelimit.reset()
    assert ratelimit.hit("apikey:test", 2) == 1
    assert ratelimit.hit("apikey:test", 2) == 0
    with pytest.raises(HTTPException) as exc:
        ratelimit.hit("apikey:test", 2)
    assert exc.value.status_code == 429 and exc.value.headers["RateLimit-Remaining"] == "0"
    assert ratelimit.hit("apikey:other", 2) == 1  # keys are limited independently
    ratelimit.reset()


def test_ingested_event_triggers_outbox_event(org, client):
    source, key = _source(org), _key(org)
    _post(client, key, _event(source))
    types = [e["event_type"] for e in org.req("GET", "/events", expect=200).json()]
    assert "external_event.created" in types
