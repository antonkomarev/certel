# 0002. Build a self-contained monitor, not an exporter add-on

- **Status:** Accepted
- **Date:** 2026-07-09

## Context

Before writing any code we surveyed the existing open-source SSL/TLS certificate
tooling (the full comparison is in [`docs/alternatives.md`](../alternatives.md)). The
niche we wanted — *a single binary + one YAML file → templated alerts to an arbitrary
webhook, with no mandatory Prometheus/Alertmanager stack, and STARTTLS support* — was
not covered by any of them. The closest matches (`ssl_exporter`, Blackbox exporter)
are **stateless probes that run "on scrape"**: the schedule lives in Prometheus and
the alerting (dedup, webhooks, templates) lives in Alertmanager. Others (Gatus,
Uptime Kuma) can't do STARTTLS, which is a v1 requirement for us
(`smtp`/`imap`/`pop3`/`ftp`/`postgres`). The CLI one-shot checkers have no scheduler,
state, or alerts at all.

## Decision

We build our own tool. certel is a **self-contained binary** carrying the three
things an exporter deliberately externalizes: its own scheduler, its own
"already-alerted / recovered" state, and its own webhook templating. The actual TLS
probe — the part an exporter would give us — is the *smaller* piece (~300–500 lines);
adopting an exporter would hand us the easy part and leave us to build the scheduler,
state and alerting anyway, on top of a mandatory Prometheus stack.

We **borrow** one thing from `ssl_exporter` rather than depend on it: its metric
*names* (`ssl_probe_success`, `ssl_cert_not_after`, `ssl_verified_cert_not_after`),
kept for backward compatibility so third-party Grafana dashboards port over. No
code was copied — its sources served only as a behavioral reference for corner
cases (verified-chain selection, STARTTLS dialogs); the license terms that would
govern actually porting code are noted in `alternatives.md`.

## Consequences

- certel owns its whole control loop; a deployment needs no Prometheus, no
  Alertmanager, no external scheduler. Metrics are *optional* output, not the spine.
- We take on the maintenance of the scheduler, state store and templating ourselves —
  accepted, since that is where the product's value is.
- Metric-name (not label-model) compatibility with `ssl_exporter` is a standing
  constraint, expanded in [0015](adr-0015-metrics-surface-and-ssl-exporter-compat.md).
- CT-log monitoring (à la certspotter) is explicitly a *different problem* and a
  candidate for a separate post-v1 module, with the MPL-2.0 licensing caveats noted
  in `alternatives.md`.

## Alternatives considered

- **Adopt/extend `ssl_exporter` + Alertmanager.** Rejected: gives us only the small
  probe piece, forces a Prometheus stack on every user, and bases a security product
  on a single-maintainer dependency that releases ~yearly.
- **Gatus / Uptime Kuma.** Rejected: no STARTTLS; Uptime Kuma is a heavyweight
  all-in-one UI for our niche.

## References

- [`docs/alternatives.md`](../alternatives.md) — full tool survey, license analysis,
  what we borrow.
- Related: [0015](adr-0015-metrics-surface-and-ssl-exporter-compat.md).
