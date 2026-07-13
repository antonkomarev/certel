# 0010. Severity-aware repeat cadence

- **Status:** Accepted
- **Date:** 2026-07-11

## Context

A single flat reminder interval has no right value. Tuned quiet (24h) it leaves a
critical cert at 7 days out too silent; tuned tight (1h) a three-week warning spams
~500 identical notices until the channel is muted. The named failure mode: *warning →
everyone ignores it → critical → attention diverted → 7 days later the cert is expired
and it is now too late.* The point of a repeat is to keep escalating pressure so an
unfixed problem does not fade into the noise — which argues the cadence should tighten
as severity rises.

## Decision

`alert_repeat_interval` accepts **either a scalar or a complete per-severity map**
(`{warning, critical, emergency}`), e.g. `{warning: 3d, critical: 1d, emergency: 30m}`.
The scalar stays as the "same cadence for all severities" shorthand and remains the
**built-in default (flat `24h`)** — the map is the documented opt-in upgrade, not the
default. The interval is re-derived per probe from the current severity and compared
against `last_alert_at`; there is **no persisted state change**. (Per
[0006](adr-0006-fan-out-is-delivery-only.md) the field lives on the *target*, so all of a
target's notifiers share the one clock.)

## Consequences

- **The map must be complete** — a missing severity is a config *error*, not a silent
  24h fallback. The config package has no warning-log channel, so silent per-entry
  defaulting would recreate exactly the "one notice a day was actually 24h because I
  forgot to set `critical`" surprise this feature exists to kill.
- **Each entry is validated `>= probe.check_interval`.** `Process` only runs on a probe
  result, so `critical: 1h` under `check_interval: 6h` would silently degrade — a lie
  about the very cadence the feature promises. The error names the entry, its interval,
  and the floor.
- Escalation on a severity *rise* is already immediate via the shape-change branch;
  this governs cadence only *within* a held severity.
- The per-severity map doubles as the fatigue guard (`warning: 3d` stops the
  500-notice spam) and composes with, but does not subsume, the `min_severity` floor —
  "warning every 3d, critical every 1d on the same channel" cannot be expressed with
  floors alone.

## Alternatives considered

- **A time-to-expiry ladder** ("daily under 7d, hourly under 24h"). Rejected: it crosses
  the config boundary (expiry thresholds are per-*target*, repeat policy per-*notifier*/
  target), and `DaysLeft == 0` is overloaded ("expires today" vs "no expiry observed",
  e.g. unreachable), so a naive ladder puts every unreachable target on the most
  aggressive rung. The "already failing" end is better served by the emergency tier.
- **A send-count cap / fatigue cutoff.** Rejected: it contradicts the premise — the
  reminder should get louder, not fall silent exactly when nobody is looking — and would
  require persisting a send counter, breaking the "no new state" property. Muting is the
  operator's call (receiver-side).

## References

- `internal/alert/manager.go` (`Process` repeat branch), `internal/config/config.go`
  (`RepeatInterval.validate`), `config.example.yaml`.
- Related: [0006](adr-0006-fan-out-is-delivery-only.md), [0008](adr-0008-severity-ladder-and-status-mapping.md).
