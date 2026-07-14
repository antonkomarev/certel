---
title: '0007. Per-notifier `min_severity` as a stateless delivery floor'
weight: 7
---

- **Status:** Accepted
- **Date:** 2026-07-11

## Context

The concrete need: an always-on **SSL chat** that receives every alert, plus a shared
**pager/alert chat** that receives only `emergency`, from the same target — without
severity *routing*. Because the floor clamps each channel's decision, it seems to
need per-`(target, notifier)` state and a schema migration — but that is true only
if the repeat clock lives on the notifier;
[0006](adr-0006-fan-out-is-delivery-only.md) put it on the target and removed the
reason.

## Decision

`min_severity` is a **stateless per-notifier delivery filter**, default `warning`
(carry everything). Because `alert_state` already stores the real per-target
`prevSeverity/prevStatus`, what a channel with floor `F` last saw is exactly
`clamp(prev, F)` and what it sees now is `clamp(cur, F)` — both pure functions of state
the per-target decision already holds. So per firing cycle, for each attached notifier
the `Manager` runs **the same transition switch it already runs per target**, on the
clamped `(prev, cur)` pair. No per-channel row is persisted; the clamp is recomputed
each cycle.

The floor lives on the **notifier definition**, not on the target's attachment: it
states the channel's *role* ("alert_chat is the emergency channel") once, DRY across
every target, and keeps `notifiers: [name, ...]` a plain list of strings.

## Consequences

- Each channel gets a **self-consistent stream** with no new state and no schema
  change — a channel fires a new problem / shape change / repeat / recovery exactly
  when its clamped view does:
  - `ok → emergency`: an `emergency`-floored channel fires a trigger (crossing the
    floor upward is a clamped new-problem, immediate, never gated by the repeat timer).
  - `emergency → critical` (still bad, but below the floor): that channel's clamp goes
    `emergency → ok`, so it gets a **recovery** — no dangling incident.
  - `expired → ok` (renewal): both channels recover, each gated by its own
    `send_recovery`.
- `alert_log` records the **real** severity + notifier per delivery; `alert_state`
  keeps the real unclamped per-target severity.
- Forward-compatible: if "same channel, different floor per target" is ever
  demonstrated, a `notifiers` entry may become `{name, min_severity}` overriding the
  default — the string-list form keeps working, so this choice paints us into no corner.

## Alternatives considered

- **Severity routing with *move* semantics** (Alertmanager-style: the binding keyed by
  severity, `{warning: chat, emergency: pager}`). Rejected: a severity transition would
  move a target between notifier queues at runtime, turning the documented
  `dispatcher.go` exception ("a notifier switch is an intentional config edit;
  cross-notifier ordering is not guaranteed") into a *routine* event, and each channel
  would see a torn story (chat watches a warning open, it escalates away to the pager,
  chat never learns it resolved). Fan-out + `min_severity` expresses every routing
  setup with static queues and per-channel consistency.
- **Delivery windows / working hours** ("warning/critical deliver only in working
  hours, emergency always"). Rejected entirely: certel cannot know per-recipient
  timezones, holidays, vacations or on-call rotations — the receiving side owns this
  properly (client mute, pager schedules). A certel-side window would look
  authoritative and be half-wrong most of the year. The genuine concern (a warning
  pinging phones at 02:00) is solved cheaper by the channel split (`min_severity`
  keeps warnings out of the paged channel), client-side mute, and a severity-conditional
  silent flag in the body. Deliver-time gating would also re-add severity to outbox
  rows (breaking [0004](adr-0004-kind-agnostic-delivery-queue.md)), mandate coalescing of
  reminders piled up while the window is closed, and give the Dispatcher a write path
  to `alert_state` it deliberately lacks.

## References

- `internal/config/config.go` (`AlertConfig.MinSeverity`, `repeatSeverities`),
  `internal/alert/manager.go`.
- Related: [0006](adr-0006-fan-out-is-delivery-only.md), [0008](adr-0008-severity-ladder-and-status-mapping.md).
