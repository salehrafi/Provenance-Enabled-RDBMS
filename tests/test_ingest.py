"""External event ingestion, record reconstruction, reconciliation and CSV imports."""

from __future__ import annotations

import io
import uuid
from datetime import UTC, datetime, timedelta

NOW = datetime.now(UTC).replace(microsecond=0)


def iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def event(source, subject="order/10045", op="u", before=None, after=None, at=None, event_id=None, **over):
    ev = {"specversion": "1.0", "id": event_id or uuid.uuid4().hex, "source": source, "type": "order.updated",
          "subject": subject, "time": iso(at or NOW - timedelta(days=1)),
          "data": {"op": op, "before": before, "after": after if after is not None else {"total": "1200.00"}}}
    ev.update(over)
    return ev


def post(client, key, body, path="/api/v1/events"):
    return client.post(path, json=body, headers={"Authorization": f"Bearer {key}"})


def test_ingest_is_idempotent_attributed_and_chained(client, org):
    source, key = org.source(), org.api_key()
    ev = event(source)
    first = post(client, key, ev)
    assert first.status_code == 201, first.text
    body = first.json()
    assert body["duplicate"] is False and body["entity"] == "order" and body["external_id"] == "10045"
    assert body["trust_level"] == "HIGH" and body["capture_method"] == "CDC"  # from the registration

    again = post(client, key, ev)
    assert again.status_code == 200 and again.json()["duplicate"] is True and again.json()["identical"] is True
    assert again.json()["event_pk"] == body["event_pk"]
    changed = post(client, key, {**ev, "data": {"op": "u", "after": {"total": "9.00"}}})
    assert changed.status_code == 200 and changed.json()["identical"] is False  # id reused for different content

    hist = org.req("GET", f"/provenance/external_event/{body['event_pk']}/history", expect=200).json()["history"]
    assert len(hist) == 1 and hist[0]["actor"].startswith("apikey:connector-")
    assert org.req("POST", "/audit/verify", expect=200).json()["ok"]
    assert [e["event_type"] for e in org.req("GET", "/events", expect=200, event_type="external_event.*").json()["items"]] == ["external_event.created"]


def test_sender_cannot_claim_trust_and_unknown_or_paused_sources_are_refused(client, org):
    source, key = org.source(trust="LOW", method="POLLING"), org.api_key()
    r = post(client, key, event(source, trust_level="HIGH", capture_method="CDC"))  # extension attributes are data only
    assert r.status_code == 201 and r.json()["trust_level"] == "LOW" and r.json()["capture_method"] == "POLLING"
    assert post(client, key, event("no-such-source")).json()["code"] == "SOURCE_UNKNOWN"
    sid = org.req("GET", "/sources", expect=200).json()["items"][0]["source_id"]
    org.req("PATCH", f"/sources/{sid}", {"status": "PAUSED"}, expect=200)
    assert post(client, key, event(source)).json()["code"] == "SOURCE_PAUSED"
    org.req("PATCH", f"/sources/{sid}", {"status": "ACTIVE"}, expect=200)
    assert post(client, key, event(source)).status_code == 201


def test_other_tenants_source_is_not_usable(client, org, other_org):
    source = org.source("shared-name")
    key = other_org.api_key()
    assert post(client, key, event(source)).json()["code"] == "SOURCE_UNKNOWN"


def test_validation_and_size_limits(client, org):
    source, key = org.source(), org.api_key()
    assert post(client, key, {**event(source), "specversion": "0.3"}).status_code == 422
    assert post(client, key, {**event(source), "type": "Not A Type"}).status_code == 422
    assert post(client, key, event(source, subject="no-slash")).json()["code"] == "INVALID_SUBJECT"
    huge = event(source, after={"blob": "x" * 300_000})
    assert post(client, key, huge).status_code == 413
    # json null / array bodies are rejected cleanly
    assert client.post("/api/v1/events", content=b"[1,2]", headers={"Authorization": f"Bearer {key}",
                                                                    "content-type": "application/json"}).status_code == 422


def test_batch_reports_per_event_outcomes_and_isolates_failures(client, org):
    source, key = org.source(), org.api_key()
    dup = event(source, event_id="b-1")
    assert post(client, key, dup).status_code == 201
    batch = [event(source, event_id="b-2"), dup, {"specversion": "1.0", "id": "bad"}, event("ghost", event_id="b-3"),
             event(source, event_id="b-4")]
    r = post(client, key, batch, "/api/v1/events:batch").json()
    assert [x["status"] for x in r["results"]] == ["created", "duplicate", "invalid", "rejected", "created"]
    assert (r["created"], r["duplicates"], r["failed"]) == (2, 1, 2)
    assert post(client, key, [], "/api/v1/events:batch").status_code == 422
    assert post(client, key, [event(source)] * 501, "/api/v1/events:batch").status_code == 413
    assert org.req("POST", "/audit/verify", expect=200).json()["ok"]


def test_cursor_listing(client, org):
    source, key = org.source(), org.api_key()
    for i in range(5):
        post(client, key, event(source, event_id=f"l-{i}", subject=f"order/{i}"))
    h = {"Authorization": f"Bearer {key}"}
    p1 = client.get("/api/v1/ingested-events", params={"limit": 2}, headers=h).json()
    p2 = client.get("/api/v1/ingested-events", params={"limit": 2, "cursor": p1["next_cursor"]}, headers=h).json()
    assert len(p1["items"]) == len(p2["items"]) == 2
    assert {i["id"] for i in p1["items"]}.isdisjoint({i["id"] for i in p2["items"]})
    assert len(client.get("/api/v1/ingested-events", params={"subject": "order/3"}, headers=h).json()["items"]) == 1


# ---- reconstruction ------------------------------------------------------------------------------
def test_external_record_history_time_travel_and_bitemporal_queries(client, org):
    source, key = org.source(), org.api_key()
    sid = org.req("GET", "/sources", expect=200).json()["items"][0]["source_id"]
    d1, d2, d3 = (NOW - timedelta(days=3), NOW - timedelta(days=2), NOW - timedelta(days=1))
    post(client, key, event(source, op="c", after={"status": "NEW", "total": "1500.00"}, at=d1, event_id="e1"))
    post(client, key, event(source, op="u", after={"status": "NEW", "total": "1200.00"}, at=d2, event_id="e2"))
    post(client, key, event(source, op="d", after=None, at=d3, event_id="e3"))
    base = f"/sources/{sid}/records/order/10045"

    h = org.req("GET", base + "/history", expect=200).json()
    assert [v["op"] for v in h["versions"]] == ["c", "u", "d"] and h["exists"] is False
    assert h["versions"][1]["changes"] == [{"field": "total", "old": "1500.00", "new": "1200.00"}]
    assert all(v["row_hash"] and v["chain_seq"] for v in h["versions"])  # each version links to its audit evidence

    at = lambda t: org.req("GET", base + "/as-of", at=iso(t), expect=200).json()  # noqa: E731
    assert at(d1 - timedelta(hours=1))["existed"] is False
    assert at(d1 + timedelta(hours=1))["state"]["total"] == "1500.00"
    assert at(d2 + timedelta(hours=1))["state"]["total"] == "1200.00"
    assert at(d3 + timedelta(hours=1))["existed"] is False  # deleted

    # bitemporal: events were all received "now", so as we knew it a day ago, nothing existed yet
    yesterday = iso(datetime.now(UTC) - timedelta(days=1))
    assert org.req("GET", base + "/as-of", at=iso(d2 + timedelta(hours=1)), known_at=yesterday, expect=200).json()["existed"] is False

    diff = org.req("GET", base + "/compare", t1=iso(d1 + timedelta(hours=1)), t2=iso(d2 + timedelta(hours=1)), expect=200).json()
    assert diff["changes"] == [{"field": "total", "old": "1500.00", "new": "1200.00"}] and len(diff["events_between"]) == 1

    listing = org.req("GET", f"/sources/{sid}/records/order", at=iso(d2 + timedelta(hours=1)), expect=200).json()
    assert listing["items"][0]["external_id"] == "10045" and listing["items"][0]["state"]["total"] == "1200.00"
    assert org.req("GET", f"/sources/{sid}/entities", expect=200).json()["items"][0]["entity"] == "order"
    org.req("GET", base.replace("10045", "nope") + "/history", expect=404)


def test_out_of_order_arrival_is_resolved_by_occurrence_time(client, org):
    source, key = org.source(), org.api_key()
    sid = org.req("GET", "/sources", expect=200).json()["items"][0]["source_id"]
    late, early = NOW - timedelta(hours=1), NOW - timedelta(hours=5)
    post(client, key, event(source, after={"v": 2}, at=late, event_id="late"))
    post(client, key, event(source, after={"v": 1}, at=early, event_id="early"))  # arrives second, happened first
    cur = org.req("GET", f"/sources/{sid}/records/order/10045/as-of", at=iso(NOW), expect=200).json()
    assert cur["state"]["v"] == 2
    assert org.req("GET", f"/sources/{sid}/records/order/10045/as-of", at=iso(early + timedelta(minutes=1)), expect=200).json()["state"]["v"] == 1


# ---- reconciliation ------------------------------------------------------------------------------
def test_reconciliation_outcomes_alert_and_event(client, org):
    source, key = org.source(), org.api_key()
    for ext, total in (("1", "100.00"), ("2", "200.00"), ("3", "300.00")):
        post(client, key, event(source, subject=f"order/{ext}", after={"total": total}, event_id=f"r-{ext}"))
    post(client, key, event(source, subject="order/4", op="d", after=None, event_id="r-4"))
    snapshot = {"source": source, "entity": "order", "complete": True, "records": [
        {"external_id": "1", "fields": {"total": 100}},           # matches ("100.00" == 100)
        {"external_id": "2", "fields": {"total": "250.00"}},      # mismatch
        {"external_id": "9", "fields": {"total": "5.00"}},        # never seen -> missing
        {"external_id": "4", "fields": {"total": "1.00"}},        # we recorded a delete -> mismatch
    ]}                                                            # 3 is absent -> unexpected
    r = client.post("/api/v1/reconciliations", json=snapshot, headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 201, r.text
    out = r.json()
    assert (out["matched"], out["mismatched"], out["missing"], out["unexpected"]) == (1, 2, 1, 1)
    by = {(i["external_id"], i["outcome"]) for i in out["issues"]}
    assert by == {("2", "MISMATCH"), ("4", "MISMATCH"), ("9", "MISSING"), ("3", "UNEXPECTED")}
    assert any(a["rule_code"] == "RC001" for a in org.req("GET", "/alerts", expect=200).json()["items"])
    assert org.req("GET", f"/reconciliations/{out['recon_id']}", expect=200).json()["issues"]
    assert org.req("GET", "/reconciliations", expect=200).json()["items"][0]["recon_id"] == out["recon_id"]
    clean = client.post("/api/v1/reconciliations", headers={"Authorization": f"Bearer {key}"},
                        json={**snapshot, "records": [{"external_id": "1", "fields": {"total": "100.00"}}], "complete": False}).json()
    assert clean["mismatched"] == clean["missing"] == clean["unexpected"] == 0


# ---- CSV imports ---------------------------------------------------------------------------------
def upload(org, csv_text, source, **form):
    files = {"file": ("snap.csv", io.BytesIO(csv_text.encode()), "text/csv")}
    data = {"source": source, "entity": "customer", **{k: str(v).lower() for k, v in form.items()}}
    return org.client.post("/api/v1/imports", files=files, data=data, headers=org.headers())


def test_csv_import_records_only_changes_and_is_idempotent(org):
    source = org.source(method="CSV_IMPORT", trust="MEDIUM")
    first = upload(org, "external_id,name,tier\nc1,Ann,gold\nc2,Bob,silver\n", source).json()
    assert (first["created"], first["updated"], first["unchanged"]) == (2, 0, 0) and first["trust_level"] == "MEDIUM"
    again = upload(org, "external_id,name,tier\nc1,Ann,gold\nc2,Bob,silver\n", source).json()
    assert (again["created"], again["updated"], again["unchanged"]) == (0, 0, 2)
    changed = upload(org, "external_id,name,tier\nc1,Ann,platinum\n", source, complete=True).json()
    assert (changed["updated"], changed["deleted"]) == (1, 1) and changed["changes"][0]["changed_fields"] == ["tier"]
    preview = upload(org, "external_id,name,tier\nc1,Ann,bronze\n", source, dry_run=True).json()
    assert preview["dry_run"] and preview["updated"] == 1
    assert upload(org, "external_id,name,tier\nc1,Ann,platinum\n", source).json()["unchanged"] == 1  # preview wrote nothing
    # A -> B -> A -> B history is preserved rather than collapsed by idempotency
    for tier in ("b", "a", "b"):
        upload(org, f"external_id,name,tier\nc1,Ann,{tier}\n", source)
    sid = org.req("GET", "/sources", expect=200).json()["items"][0]["source_id"]
    assert len(org.req("GET", f"/sources/{sid}/records/customer/c1/history", expect=200).json()["versions"]) >= 5


def test_csv_import_rejects_bad_files(org):
    source = org.source()
    assert upload(org, "name\nAnn\n", source).status_code == 422
    assert upload(org, "external_id,name\n,Ann\n", source).json()["code"] == "INVALID_CSV"
    assert upload(org, "external_id,name\nc1,A\nc1,B\n", source).json()["code"] == "INVALID_CSV"
    assert upload(org, "external_id,name\nc1,A,extra\n", source).json()["code"] == "INVALID_CSV"
    assert upload(org, "external_id,name\n", source).json()["code"] == "INVALID_CSV"
    viewer = org.add_user("viewer")
    r = org.client.post("/api/v1/imports", files={"file": ("a.csv", b"external_id\n1\n")},
                        data={"source": source, "entity": "customer"}, headers=org.headers(viewer))
    assert r.status_code == 403


def test_csv_reconciliation_upload(org):
    source = org.source()
    upload(org, "external_id,name\nc1,Ann\n", source)
    r = org.client.post("/api/v1/reconciliations/upload", headers=org.headers(), data={"source": source, "entity": "customer"},
                        files={"file": ("a.csv", io.BytesIO(b"external_id,name\nc1,Annie\n"), "text/csv")})
    assert r.status_code == 201 and r.json()["mismatched"] == 1


def test_events_read_key_can_reconstruct_records_but_not_manage_sources(client, org):
    source, writer = org.source(), org.api_key(("events:write",))
    reader = org.api_key(("events:read",))
    post(client, writer, event(source, op="c", after={"v": 1}, event_id="k1"))
    sid = org.req("GET", "/sources", expect=200).json()["items"][0]["source_id"]
    h = {"Authorization": f"Bearer {reader}"}
    base = f"/api/v1/sources/{sid}/records/order/10045"
    assert client.get(base + "/history", headers=h).status_code == 200
    assert client.get(base + "/as-of", params={"at": iso(NOW)}, headers=h).json()["state"]["v"] == 1
    assert client.get(f"/api/v1/sources/{sid}/entities", headers=h).status_code == 200
    assert client.get("/api/v1/sources", headers=h).status_code == 403  # listing/administering sources needs a person
    assert client.get(base + "/history", headers={"Authorization": f"Bearer {writer}"}).status_code == 403
