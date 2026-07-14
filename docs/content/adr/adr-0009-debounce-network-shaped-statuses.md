---
title: '0009. Debounce network-shaped statuses; fact statuses alert on the first cycle'
weight: 9
---

- **Status:** Accepted
- **Date:** 2026-07-11

## Context

certel is its own alerter — there is no Prometheus `for:` downstream to absorb
noise. If a transition into a bad state alerts on the first bad cycle, a 2-minute
network blip produces a junk `critical` + `recovery` pair, and a target already in
`warning` (`expiring_soon`) that blips emits `warning→critical` then
`critical→warning` — two alerts, no recovery, pure noise. The in-probe
`connect_retries` only makes a blip outlive ~30s; dedup only suppresses repeats.

## Decision

The `Manager` counts consecutive bad cycles per target and treats a transition into an
**unreliable, network-shaped** status as real only after `flap_streak` cycles agree
(per-target, `target_defaults` fallback, default `2`; `1` disables). Scope is precise:
**`unreachable` and `tls_unavailable` only.** The debounce runs per-target *before*
notifier fan-out, so more notifiers don't multiply flap noise.

The counter lives in memory but is **reconstructed from `probe_log` on restart** rather
than re-counting from zero — `probe_log` already durably records every cycle's status,
so "how many consecutive unreliable-bad cycles precede now" is a query over the last
few rows.

## Consequences

- **Fact statuses bypass the debounce entirely.** `expired`, `invalid`,
  `weak_signature`, `expiring_soon` are computed from a *successfully retrieved*
  certificate — they have no noise source and must keep alerting on first observation,
  whatever `flap_streak` is.
- **The debounce is symmetric**: leaving a confirmed unreachable state also needs
  `flap_streak` healthy cycles. Without symmetry a down-up-down saw still emits an
  alert/recovery pair per tooth once the first alert fired. The accepted tradeoff: a
  genuine outage alerts, and a genuine recovery clears, one cycle later.
- **Metrics are untouched on purpose.** `ssl_probe_success` drops to 0 and
  `certel_probe_severity` rises on the *first* failed cycle — the debounce is alert
  policy, not observability, so the metrics never lag the probe.
- While pending confirmation, persisted/in-memory alert state keeps the **old** state,
  so a crash mid-confirmation neither alerts early nor records the problem as known —
  preserving `alert_state`'s "confirmed state only" invariant.
- Reconstructing from `probe_log` (rather than a persisted counter) fixes the
  perpetual-deferral failure mode where a crash loop or rapid reloads would reset an
  in-memory-only counter forever, and it needs **no `alert_state` schema change**.
  Retention prunes only old `probe_log` rows; the last N (2–3) cycles are always
  present, so reconstruction stays correct.

## Alternatives considered

- **A persisted counter column on `alert_state`.** Rejected: a pending confirmation is
  *tentative* state, but the design requires the persisted record to keep the old
  status until confirmed — a column would mean `pending_status/severity/count` beside
  the confirmed fields, the very schema growth this work was ordered to avoid, plus a
  broken invariant.
- **In-memory only, re-count from zero on restart.** Rejected for the
  perpetual-deferral-under-frequent-restarts failure mode.

## References

- `internal/alert/manager.go` (`Process`, `Restore`), `internal/store/store.go`
  (`RecentProbeStatuses`), `probe_log(target_key, checked_at)` index.
- "Flap debounce" section in the [README](https://github.com/antonkomarev/certel).
