---
title: '0006. Multi-notifier fan-out is delivery-only; the repeat clock lives on the target'
weight: 6
---

- **Status:** Accepted
- **Date:** 2026-07-11

## Context

[0005](adr-0005-config-only-webhook-notifiers.md) attached each target to a single
notifier, because fan-out looked expensive: with the repeat cadence
(`repeat_interval`) living on the *notifier*, each attached notifier would need its
own `last_alert_at`, forcing `alert_state`'s primary key to become
`(target, notifier)` — per-channel decision state and a schema migration. That
miscategorization of the repeat cadence is what made both fan-out and the
per-notifier severity floor
([0007](adr-0007-per-notifier-min-severity-floor.md)) look costly.

## Decision

Fan-out is a **pure delivery concern** — it touches neither the decision layer nor the
schema. The `Manager` keeps **one decision stream per target**, on the real
(unclamped) severity: new problem, shape change, repeat, recovery, exactly as before.
The only change is at enqueue: instead of one delivery it writes **one per attached
notifier**, each with that notifier's rendered body, inside the *same* transaction
that upserts `alert_state` **once**.

The key that makes this free: **the repeat cadence is a property of the problem on the
target, not of the channel.** A persisting problem is what initiates a reminder; a
notifier is a pipe and initiates nothing. So the field moves off the notifier onto the
target and is renamed **`alert_repeat_interval`** (a bare `repeat_interval` on a target
is ambiguous against `probe.check_interval`; the `alert_` prefix says "how often to
re-alert"). `TargetParams` gains `notifiers: [name, ...]`.

## Consequences

- `alert_state` stays **per-target**: one row, one `last_alert_at`, holding the real
  unclamped severity — no `notifier` column, no PK change, no migration.
- `alert_log` and `notification_outbox` already carry a `notifier` column
  ([0004](adr-0004-kind-agnostic-delivery-queue.md), [0005](adr-0005-config-only-webhook-notifiers.md)),
  so fan-out just loops attached notifiers inside the existing enqueue transaction —
  one commit, no half-persist window.
- Every notifier a target fans out to **shares one reminder clock** (the target's
  `alert_repeat_interval`), which is the property that also collapses the severity
  floor into a stateless filter ([0007](adr-0007-per-notifier-min-severity-floor.md)).
- `alert_repeat_interval` reuses the already-merged per-severity map form
  ([0010](adr-0010-severity-aware-repeat-cadence.md)); the scalar form still means "same
  cadence for every severity."
- `send_recovery` stays a per-notifier delivery flag, decided at enqueue, no state.
- Editing a target's `notifier` set or thresholds keeps the same `Target.Key`
  ([0016](adr-0016-target-vocabulary-and-key-identity.md)), so a notifier switch does not
  re-alert immediately on the new channel — the intended behavior, worth stating.

## Alternatives considered

- **Repeat cadence on the notifier** (the original sketch). Rejected: it forces
  per-`(target, notifier)` timers and the whole abandoned "notifier column on
  `alert_state`" migration. Moving it to the target is what keeps fan-out schema-free.
- **A target → single notifier only** ([0005](adr-0005-config-only-webhook-notifiers.md)).
  Superseded: once fan-out is delivery-only it is the *cheapest* of the severity-policy
  changes, not the one with a migration.

## References

- `internal/config/config.go` (`TargetParams`, `AlertConfig`), `internal/alert/manager.go`,
  `internal/store` (`Enqueue`).
- Related: [0007](adr-0007-per-notifier-min-severity-floor.md),
  [0010](adr-0010-severity-aware-repeat-cadence.md).
