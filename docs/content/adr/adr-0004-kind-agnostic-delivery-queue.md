---
title: '0004. A kind-agnostic, notifier-scoped delivery queue'
weight: 4
---

- **Status:** Accepted
- **Date:** 2026-07-10

## Context

A queue row is a **rendered notification pending delivery**, not an "alert" — and a
recovery notice is not an alert at all. The problem/recovery distinction, and severity,
belong to the *decision* layer that produced the notification, not to the layer that
ships bytes. Letting either leak onto queue rows would couple delivery to alerting
semantics and constrain every later routing and fan-out design.

## Decision

The delivery queue is **kind-agnostic: it delivers opaque bytes**. A row is `(body,
notifier, order)` and nothing more — no severity, no kind, no problem/recovery flag. The
queue is scoped per notifier and drained FIFO within a `(notifier, key)`. The
problem/recovery breakdown and severity live in `alert_log`, the record of what was
decided; the queue only knows "this body, for this notifier, in this order."

Concretely the table is `notification_outbox`, keyed by an `enqueued_at` timestamp, with
no kind/severity/recovered column.

## Consequences

- **This invariant is load-bearing for later designs.** Because rows carry no severity or
  kind, [0006](adr-0006-fan-out-is-delivery-only.md) can fan out by inserting one row per
  notifier with no schema change, and both severity routing and delivery windows were
  *rejected* precisely because they would have forced a severity column back onto the rows
  ([0007](adr-0007-per-notifier-min-severity-floor.md)).
- Kind is recorded once, at the decision point, in `alert_log` — never on the queue or
  its delivery counter.
- `id` is the FIFO drain order **within a `(notifier, key)`**, not a global per-target
  order.

## References

- `internal/store/store.go`, `internal/alert/dispatcher.go`, `docs/schema.dbml`.
- Related: [0003](adr-0003-sqlite-durable-alert-state-and-outbox.md),
  [0006](adr-0006-fan-out-is-delivery-only.md).
