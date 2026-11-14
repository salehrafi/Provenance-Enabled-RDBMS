# ADR 0007: Transactional outbox with leased, at-least-once webhook delivery

Status: accepted · Date: 2026-11-13

## Context
Events must never be lost nor announced for a rolled-back change. Delivery must survive worker crashes and slow or hostile endpoints.

## Decision
Events are inserted into `outbox_events` in the same transaction as the change. Workers fan out with `FOR UPDATE SKIP LOCKED`, claim deliveries with a lease (`locked_until`), send outside any transaction, and record success, exponential backoff with jitter, or dead-letter plus an alert. Receivers dedupe on the stable `webhook-id`. Target addresses are vetted and pinned (SSRF) and redirects are not followed.

## Consequences
* At-least-once, not exactly-once; ordering across events is not guaranteed.
* Any number of workers may run; a crashed worker's lease expires and the delivery is retried.
* An endpoint that is down for more than about 8 hours loses automatic retry and needs a manual retry (dead-letter list, `WH001` alert).
* A new subscription only receives events created after it, never the backlog.
