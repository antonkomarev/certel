# 0014. Size the scheduler cycle and liveness to the worst legal cycle

- **Status:** Accepted
- **Date:** 2026-07-10

## Context

A *healthy* probe cycle can legally take
`ceil(targets/concurrency) × attempts × (timeout + 1s)`, so a naive `/healthz`
liveness bound (`2×interval + jitter + slack`) is a lie for any non-trivial fleet.
Two design choices amplify the worst case further: acquiring the concurrency
semaphore slot *before* the per-target jitter sleep makes jitter stretch the cycle
in waves of `concurrency` instead of spreading load; and delivering alerts inside
the probe worker goroutine charges a down webhook's `retries × (timeout + backoff)`
(~33s per alerting target) against the cycle. The combination is a feedback loop:
webhook outage + ~50 alerting targets → cycle overruns the bound → `/healthz`
flips 503 → the Docker healthcheck restarts the container → the restart re-probes
and re-hits the dead webhook → repeat. **The monitor gets killed precisely when
things are on fire.**

## Decision

Three changes:

1. Apply per-target **jitter before acquiring the semaphore slot**, so jitter spreads
   load instead of serializing behind slots.
2. **Decouple delivery from probing** — hand probe results to a small bounded queue
   drained by a dedicated sender goroutine (per-target ordering preserved by the
   manager's state machine), so a blocked webhook never delays cycle completion.
3. **Derive the liveness threshold from the worst legal cycle:**
   `interval + ceil(targets/concurrency) × attempts × (timeout + 1s) + slack`.

## Consequences

- A slow/blocked notifier no longer sits on the liveness path — delivery latency is off
  the cycle-completion clock, breaking the restart feedback loop.
- Adding slow targets or raising timeouts legitimately lengthens a cycle, and the derived
  threshold grows with it, so `/healthz` doesn't false-flap to unhealthy.
- The `livenessThreshold` derivation is reused as a first-class value: the metrics
  surface exports it as `certel_probe_cycle_staleness_threshold_seconds` (so a staleness
  alert never hardcodes a bound that rots when config changes) and `/healthz` uses it for
  its startup grace — see [0015](adr-0015-metrics-surface-and-ssl-exporter-compat.md).

## Alternatives considered

- **Keep a crude threshold but only report unhealthy when no cycle has *started***
  (tracking cycle-start too). The derived bound was chosen as the more honest measure.

## References

- `cmd/certel/main.go` (liveness formula), `internal/scheduler/scheduler.go`
  (semaphore/jitter ordering, result handler).
