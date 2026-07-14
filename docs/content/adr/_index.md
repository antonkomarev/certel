---
title: 'Architecture Decision Records'
linkTitle: 'ADRs'
weight: 30
---

One short, backward-looking document per non-obvious design decision — its
*context*, the *decision*, and the *consequences* — so a future contributor can
see **why** a thing is the way it is and not accidentally undo a deliberate
choice. Why this format and not a monolithic design doc:
[0001](adr-0001-record-architecture-decisions-in-adrs.md).

## The system in one pass

certel is a self-contained certificate monitor
([0002](adr-0002-build-a-self-contained-monitor.md)): one binary, one YAML
file, its own scheduler, state and alerting — no Prometheus/Alertmanager
required. The ADRs each pin one link of the chain:

- **Probe.** On a fixed cycle the scheduler
  ([0014](adr-0014-scheduler-cycle-and-liveness-sizing.md)) probes each
  *target* — identity `protocol//address/servername`
  ([0016](adr-0016-target-vocabulary-and-key-identity.md)) — over implicit TLS
  or STARTTLS. The probe accepts legacy handshakes and verifies trust itself
  ([0013](adr-0013-accept-legacy-tls-verify-trust-manually.md)), verifying the
  chain *before* diagnosing expiry
  ([0012](adr-0012-verify-chain-before-diagnosing-expiry.md)).
- **Decide.** Statuses map onto the `ok < warning < critical < emergency`
  ladder ([0008](adr-0008-severity-ladder-and-status-mapping.md)); the day
  thresholds have exact boundary semantics
  ([0011](adr-0011-threshold-boundary-semantics.md)); network-shaped statuses
  must persist `flap_streak` cycles before they count
  ([0009](adr-0009-debounce-network-shaped-statuses.md)). The alert `Manager`
  keeps one decision stream per target with a severity-aware repeat cadence
  ([0010](adr-0010-severity-aware-repeat-cadence.md)) and commits confirmed
  state to SQLite atomically with the deliveries it owes
  ([0003](adr-0003-sqlite-durable-alert-state-and-outbox.md)).
- **Deliver.** A decision enqueues one rendered notification per attached
  notifier — fan-out is delivery-only, the repeat clock lives on the target
  ([0006](adr-0006-fan-out-is-delivery-only.md)) — into a kind-agnostic outbox
  ([0004](adr-0004-kind-agnostic-delivery-queue.md)) drained by isolated
  per-notifier dispatchers. Notifiers are plain config webhooks
  ([0005](adr-0005-config-only-webhook-notifiers.md)) with structured bodies
  ([0018](adr-0018-structured-webhook-bodies.md)) and a stateless
  `min_severity` floor ([0007](adr-0007-per-notifier-min-severity-floor.md)).
- **Observe & contract.** Optional Prometheus metrics with
  ssl_exporter-compatible names
  ([0015](adr-0015-metrics-surface-and-ssl-exporter-compat.md)); the whole
  config surface was reviewed and locked before 1.0
  ([0017](adr-0017-lock-the-config-surface-before-1-0.md)).

## Conventions

- **Location & filename:** `docs/adr/adr-NNNN-kebab-case-title.md`, four-digit
  zero-padded number, assigned monotonically in order added (never renumbered).
- **Template:** copy [`adr-0000-template.md`](adr-0000-template.md).
- **Status:** one of `Proposed` · `Accepted` · `Superseded by NNNN` · `Deprecated`.
  ADRs are **append-only**: a decision that changes gets a *new* ADR that supersedes
  the old one; the old one is marked `Superseded by NNNN` and left in place, not
  edited away.
- **Cross-reference, don't duplicate.** `docs/alternatives.md` (the build-vs-buy
  survey) and `docs/metrics.md` (the full metrics surface) are longer living design
  docs; ADRs link to them rather than copying their content.

## Lifecycle: how a `todo/` becomes an ADR

The `todo/` tree holds *forward-looking* work items; ADRs are *backward-looking*
rationale. When a `todo/` design lock is resolved and its feature ships, its
outcome graduates into an ADR and the todo is deleted. The ADR must absorb
everything decision-relevant from the todo — ADRs do not cite deleted todo
files; the shipping commit's history holds their full text if archaeology is
ever needed. Open todos (e.g. `config-reload.md`, `notifier-failure-backoff.md`,
`packaging.md`) are **not** ADRs yet; they become one only once decided and
shipped.

Not every change earns an ADR. Bug fixes and mechanical hardening — timeouts,
path escaping, CI pinning, input validation — live in git history, not here. An
ADR is for a decision that shaped the design and could plausibly be *reversed by
someone who didn't know why*.

## Index

| ADR | Decision |
|---|---|
| [0001](adr-0001-record-architecture-decisions-in-adrs.md) | Record architecture decisions in ADRs |
| [0002](adr-0002-build-a-self-contained-monitor.md) | Build a self-contained monitor, not an exporter add-on |
| [0003](adr-0003-sqlite-durable-alert-state-and-outbox.md) | Persist alert state and queue deliveries in SQLite |
| [0004](adr-0004-kind-agnostic-delivery-queue.md) | A kind-agnostic, notifier-scoped delivery queue |
| [0005](adr-0005-config-only-webhook-notifiers.md) | Config-only named webhook notifiers |
| [0006](adr-0006-fan-out-is-delivery-only.md) | Multi-notifier fan-out is delivery-only; the repeat clock lives on the target |
| [0007](adr-0007-per-notifier-min-severity-floor.md) | Per-notifier `min_severity` as a stateless delivery floor |
| [0008](adr-0008-severity-ladder-and-status-mapping.md) | Three-tier severity ladder and the status→severity mapping |
| [0009](adr-0009-debounce-network-shaped-statuses.md) | Debounce network-shaped statuses; fact statuses alert on the first cycle |
| [0010](adr-0010-severity-aware-repeat-cadence.md) | Severity-aware repeat cadence |
| [0011](adr-0011-threshold-boundary-semantics.md) | Alert when strictly fewer than N whole days remain |
| [0012](adr-0012-verify-chain-before-diagnosing-expiry.md) | Verify the chain before diagnosing expiry |
| [0013](adr-0013-accept-legacy-tls-verify-trust-manually.md) | Accept TLS ≥ 1.0, verify trust manually; the `weak_signature` status |
| [0014](adr-0014-scheduler-cycle-and-liveness-sizing.md) | Size the scheduler cycle and liveness to the worst legal cycle |
| [0015](adr-0015-metrics-surface-and-ssl-exporter-compat.md) | Prometheus metrics surface and ssl_exporter name compatibility |
| [0016](adr-0016-target-vocabulary-and-key-identity.md) | "target" as the domain vocabulary and `Target.Key` identity |
| [0017](adr-0017-lock-the-config-surface-before-1-0.md) | Lock the config surface before 1.0 |
| [0018](adr-0018-structured-webhook-bodies.md) | Structured webhook bodies with `${namespace.path}` interpolation |
