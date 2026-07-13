# 0008. Three-tier severity ladder and the status→severity mapping

- **Status:** Accepted
- **Date:** 2026-07-10

## Context

"Expires in 3 days" and "the cert already expired right now" are not the same
emergency, yet a two-tier ladder (`warning`/`critical`) maps both to `critical` —
no level separates "deadline approaching" from "deadline already passed and
something is actively broken." We needed a top tier — and, just as importantly, a
principled rule for which of the seven check statuses reach it.

## Decision

The ladder is **`ok < warning < critical < emergency`**, locked and encoded by *order*
on the `certel_probe_severity` gauge (`0/1/2/3`). `emergency` means **"already failing
*and* the signal is trustworthy"** — the deadline has not approached, it has passed and
something is actively broken. The canonical status→severity map:

```
warning_days                  → warning
critical_days                 → critical
unreachable / tls_unavailable → critical
weak_signature                → critical
expired / invalid             → emergency
```

The asymmetry — three severities but only two day-thresholds — is **by design, not a
gap**: `emergency` is not a countdown, it is the already-failed fact state where a day
threshold would be meaningless.

## Consequences

- **`unreachable` is critical, never emergency** — it is the least reliable of the
  seven signals; a network blip or a monitoring-side problem looks identical to a dead
  service. Making the noisiest, least-trustworthy status the one that wakes people is
  the classic false-page recipe. Same trust argument keeps `tls_unavailable` (often a
  probe/protocol misconfig) and `weak_signature` ("live but legacy" — works, trust
  unconfirmed) at critical.
- This mapping is the semantic basis for the always-on-vs-pager split: `emergency` is
  the natural floor for a shared pager ([0007](adr-0007-per-notifier-min-severity-floor.md)),
  and the "trustworthy" half of its definition is why the noisy statuses are debounced
  rather than paged ([0009](adr-0009-debounce-network-shaped-statuses.md)).
- The ladder is a **strictly ordered escalation, append-only at the top** — an invariant
  that also justified exporting severity as an ordered numeric gauge rather than a
  state-set ([0015](adr-0015-metrics-surface-and-ssl-exporter-compat.md)).
- The enum spellings (`warning`/`critical`/`emergency`) are on the irreversible list —
  they live in user templates and PromQL — and were locked before 1.0.

## References

- `internal/probe/result.go`, `internal/probe/probe.go`, `internal/metrics/metrics.go`.
- Status table in the [README](../../README.md) "Check statuses" section.
