---
title: '0015. Prometheus metrics surface and ssl_exporter name compatibility'
weight: 15
---

- **Status:** Accepted
- **Date:** 2026-07-10

## Context

certel wants operators' existing `ssl_exporter` dashboards and alerts to port over, but
its architecture differs fundamentally. `ssl_exporter` uses the multi-target pattern:
one scrape per endpoint, identity carried by a relabeled `instance` label. certel serves
**every target from a single scrape target** and attaches its own
`host`/`address`/`protocol`/`servername` labels. Claiming "compatible with ssl_exporter
dashboards" would set an expectation the first user with a real `$instance`-templated
Grafana dashboard disproves in five minutes. The whole metrics surface also needed
designing as a coherent whole rather than accreting one gauge at a time.

## Decision

The full surface, its naming/label policy, per-metric semantics, absence rules and the
explicit rejections live in **[`docs/metrics.md`](../metrics.md)**; this ADR records the
load-bearing decisions:

- **Compatibility is on metric *names and meanings*, not the label model.** The `ssl_*`
  prefix is a **closed set of exactly three** (`ssl_probe_success`, `ssl_cert_not_after`,
  `ssl_verified_cert_not_after`) — frozen, never renamed or grown; any new cert metric
  goes under `certel_*`. The README says "ssl_exporter-compatible metric *names*" with an
  `instance → address`/`host` mapping note.
- **`certel_target_info` is the presence anchor.** Every measurement series exists only
  after a target's first probe, so a never-probed target is invisible to alerting and
  `absent()` can't express "for every configured target." `certel_target_info` (constant
  `1`, set from config alone at startup) is the one unconditional series, enabling
  `certel_target_info unless on(...) ssl_probe_success`. Its property labels (e.g.
  `insecure`) join onto per-target series rather than widening the identity family.
- **Publication is atomic per scrape via a single snapshot collector.** The last
  `probe.Result` per target sits in a map under a lock; every per-target series is derived
  inside one `Collect`. Separate vecs would let `Gather` lock each family independently
  and a scrape could catch an impossible pair (fresh `ssl_probe_success == 1` beside a
  stale/deleted `ssl_cert_not_after`).
- **Zero is never exported to mean "unknown."** A zero timestamp reads "expired in 1970";
  "no data" is expressed as *series absence* plus `ssl_probe_success == 0`. The snapshot
  model makes absence fall out for free.

## Consequences

- **The identity label family (`host`, `address`, `protocol`, `servername`) is frozen**
  alongside the `ssl_*` names: adding an identity label would break history, shift
  `sum without()`, and stop full-list joins matching. `servername` is the raw config
  value so the label set is injective with the store's `target_key` — and its presence
  prevents two targets that differ only in servername from deleting each other's series
  during stale-CN cleanup.
- **Cardinality invariant:** every label is either *config-bounded* (O(targets)/
  O(notifiers)) or *churn-bounded* (a stale series vanishes at the moment of change) —
  never free-form. A CN-changing renewal replaces (not accretes) the `ssl_cert_not_after`
  series, which also defuses a malicious server minting a fresh CN per probe (the
  cardinality-attack surface named in SECURITY.md).
- **A metric earns its place only if an operator would alert on it or trend it;** the same
  bar applies to labels. Everything else stays in logs / SQLite.
- The scheduler exports `certel_probe_cycle_staleness_threshold_seconds` (the
  `livenessThreshold` derivation from [0014](adr-0014-scheduler-cycle-and-liveness-sizing.md))
  beside the completed-timestamp gauge, so a staleness alert never hardcodes a bound that
  rots when config changes.

## Alternatives considered

(Full list in [`docs/metrics.md`](../metrics.md) §"Considered and rejected".)

- **`certel_probes_total` counter.** Rejected: probing is constant-rate by construction
  (`targets / check_interval`, knowable from config); success-over-time is
  `avg_over_time(ssl_probe_success[…])`; retry churn lives in `probe_log.attempts`.
- **`issuer_cn`/`serial_no` labels on `ssl_cert_not_after`.** Rejected — not on
  cardinality grounds (the snapshot collector bounds them) but because no alert or panel
  selects by issuer/serial; per-occurrence detail belongs in the log. `cn` stays only
  because imported dashboards template on it.
- **Severity as a state-set; a probe-status state-set; a probe-duration histogram; a
  days-left gauge; a `kind` label on the sends counter.** All rejected, each for a
  reason recorded in `docs/metrics.md` (ordered gauge is one-third the series; one
  observation per interval makes a histogram pointless; a zero days-left gauge is
  ambiguous; `kind` re-smuggles kind-awareness into a queue designed without it —
  [0004](adr-0004-kind-agnostic-delivery-queue.md)).
- **A real `/probe?target=` multi-target endpoint** (which would make the compat claim
  literally true). Rejected: a separate architectural change, not worth it just for
  wording.

## References

- [`docs/metrics.md`](../metrics.md) — the settled, living design.
- `internal/metrics/metrics.go`. Related: [0002](adr-0002-build-a-self-contained-monitor.md),
  [0014](adr-0014-scheduler-cycle-and-liveness-sizing.md).
