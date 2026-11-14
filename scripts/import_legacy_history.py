"""Import change history exported from the previous (Oracle) version, or any system, as external events.

Input is JSON Lines, one change per line:

    {"id": "oracle-audit-1042", "entity": "product", "record_pk": "7", "operation": "UPDATE",
     "old_values": {"price": 100}, "new_values": {"price": 120}, "changed_at": "2026-03-01T10:15:00Z",
     "actor": "staff@acme.example.com"}

Each line becomes a CloudEvent on the source you name (register it first, e.g. code `legacy-oracle`,
capture method MANUAL, trust MEDIUM). Ids make the import idempotent and resumable: run it again
after an interruption and already-imported lines are reported as duplicates, not re-recorded.

    python scripts/import_legacy_history.py history.jsonl --url http://localhost:8000 \
        --source legacy-oracle --api-key prv_... [--dry-run]

Exit status is non-zero if any line is rejected or if the imported counts do not match the file.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sdk" / "python"))
from provenance_cloud import Client  # noqa: E402

OPS = {"INSERT": ("c", "created"), "UPDATE": ("u", "updated"), "DELETE": ("d", "deleted")}
BATCH = 200


def to_event(line: dict, source: str) -> dict:
    op, verb = OPS[line["operation"].upper()]
    entity = str(line["entity"]).lower()
    return {
        "specversion": "1.0", "id": str(line["id"]), "source": source, "type": f"{entity}.{verb}",
        "subject": f"{entity}/{line['record_pk']}", "time": line["changed_at"],
        "legacyactor": line.get("actor"),
        "data": {"op": op, "before": line.get("old_values"), "after": line.get("new_values")},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--url", required=True)
    ap.add_argument("--source", required=True)
    ap.add_argument("--api-key", required=True)
    ap.add_argument("--dry-run", action="store_true", help="validate the file only; send nothing")
    args = ap.parse_args()

    events, errors, seen = [], [], set()
    for n, raw in enumerate(Path(args.file).read_text(encoding="utf-8").splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            ev = to_event(json.loads(raw), args.source)
        except (ValueError, KeyError) as exc:
            errors.append(f"line {n}: {type(exc).__name__}: {exc}")
            continue
        if ev["id"] in seen:
            errors.append(f"line {n}: duplicate id {ev['id']}")
            continue
        seen.add(ev["id"])
        events.append(ev)
    print(f"read {len(events)} valid change(s), {len(errors)} invalid")
    for e in errors[:20]:
        print("  !", e)
    if args.dry_run or errors:
        return 1 if errors else 0

    created = duplicates = failed = 0
    with Client(args.url, args.api_key) as pc:
        for i in range(0, len(events), BATCH):
            r = pc.send_events(events[i:i + BATCH])
            created, duplicates, failed = created + r["created"], duplicates + r["duplicates"], failed + r["failed"]
            for res in r["results"]:
                if res["status"] in ("invalid", "rejected"):
                    print(f"  ! {res.get('id')}: {res.get('error')}")
            print(f"  {min(i + BATCH, len(events))}/{len(events)}")
    print(f"created {created}, already present {duplicates}, failed {failed}")
    if failed or created + duplicates != len(events):
        print("VALIDATION FAILED: counts do not match the file")
        return 1
    print("validation passed: every line in the file is recorded exactly once")
    return 0


if __name__ == "__main__":
    sys.exit(main())
