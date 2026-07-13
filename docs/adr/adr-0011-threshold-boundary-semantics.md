# 0011. Alert when strictly fewer than N whole days remain

- **Status:** Accepted
- **Date:** 2026-07-11

## Context

The expiry-threshold fire/no-fire equivalence quietly depends on *both* halves working
together — the strict `<` in the decision switch *and* the truncate-toward-zero in
`daysUntil`. An innocent `<=`, a `math.Round`, or a well-meaning "fix" of the truncation
asymmetry would shift the boundary by up to a full day, uncaught.

## Decision

Pin the contract: **`warning_days: N` fires when strictly fewer than N days remain**
(`critical_days` likewise). Whole days are counted truncated toward zero. For integer N
this makes `floor(remaining) < N` ⟺ `remaining < N × 24h` exactly, so the alert
decision agrees with a Prometheus line at `N * 86400` over
`certel_cert_expiry_timestamp_seconds - time()` (up to probe staleness).

## Consequences

- Establishes a must-not-regress invariant tying the code (`days < *t.WarningDays` plus
  truncate-toward-zero `daysUntil`) to the Prometheus threshold equivalence — the reason
  a dashboard rule and the alert never disagree by a day.
- At the boundary: `N days − 1s` → warning; exactly `N days` and `N days + 1s` → ok; the
  same pair around `critical_days`; the already-expired side (read as day 0) still fires.
- `Result.DaysLeft` is computed **once** per probe from the injected clock (`p.Now()`),
  never from a second wall-clock read — so logs, metrics and the threshold decision see
  the same number, the property the boundary tests rely on.

## References

- `internal/probe/probe.go` (`daysUntil`, threshold switch), `internal/probe/result.go`
  (`DaysLeft`).
- "Check statuses" section in the [README](../../README.md).
