# 0003. Persist alert state and queue deliveries in SQLite

- **Status:** Accepted
- **Date:** 2026-07-09

## Context

certel is its own alerter — there is no Alertmanager behind it to remember what
has already fired. Three correctness requirements follow:

- a restart must not re-alert a problem it already reported;
- a problem that was fixed *while the monitor was down* must still get its
  recovery notice;
- a crash between "record that we alerted" and "the webhook actually accepted
  it" must not silence a live problem — with dedup state claiming the alert went
  out, the target stays quiet for a full repeat interval (24h default).

Any design that updates dedup state and performs the network send as two
separate steps has that crash window on one side or the other. The guiding
principle: **a duplicate is an annoyance, a missed alert is the product
failing** — alerting must be at-least-once.

## Decision

Persist state in an embedded **SQLite** database and split *deciding* an alert
from *delivering* it.

- `alert_state` holds per-target dedup and repeat-timer state, restored on startup.
- The `Manager` only **decides and enqueues**, in a **single transaction** that
  upserts `alert_state`, appends to `alert_log`, and queues the rendered body in a
  durable outbox. Because state and the pending delivery share one commit, a crash
  cannot mark a target alerted without a matching queued notice.
- A separate `Dispatcher` drains the outbox in the background, in enqueue order,
  deleting a row only once the send succeeds.

## Consequences

- Undelivered rows survive restarts and replay in order — including a problem that
  expired *and then recovered* while the monitor was down.
- `alert_state` needs no "pending recovery" bookkeeping: the outbox carries the
  "a notice is owed" obligation for both problems and recoveries uniformly.
- `alert_log` is an immutable history of *what was decided*, not how it was
  delivered; delivery bookkeeping lives in the outbox + process logs.
- Delivery concurrency is its own knob, independent of probe concurrency.
- SQLite (not a flat file or an external DB) keeps the "single binary, single file"
  promise while giving transactions, queryable logs, and safe concurrent inspection.
- The state store is also why a container **must** keep its DB volume — without it a
  recreation loses dedup state and re-sends alerts for known problems.
- The full schema with per-column notes lives in [`docs/schema.dbml`](../schema.dbml).

## Alternatives considered

- **Mark state before sending, reset it if the send returns an error.** Rejected:
  it races a SIGTERM/`kill -9` during the send and covers only the failure path —
  problems become at-most-once, the exact inversion of what alerting needs. The
  transactional enqueue collapses "crashed before send" and "send failed" into one
  "not yet delivered" representation.
- **No persistence (in-memory state).** Rejected outright: every restart would
  re-alert known problems and drop recoveries owed for downtime.

## References

- `internal/alert/manager.go`, `internal/alert/dispatcher.go`, `internal/store/store.go`.
- Related: [0004](adr-0004-kind-agnostic-delivery-queue.md), and the durable-delivery
  wording in the [README](../../README.md) "State and logs" section.
