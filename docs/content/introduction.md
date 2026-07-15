---
title: 'What is certel?'
linkTitle: 'Introduction'
weight: 1
---

**Cert**ificate **E**xpiry & **L**ogs — a self-hosted SSL/TLS certificate
monitor: a single binary and a single YAML file. certel probes your endpoints
on a schedule and delivers templated webhook alerts when a certificate is
expiring, expired, invalid, or TLS becomes unavailable.

## The concept

Most open-source certificate monitoring is built as *exporters*: stateless
probes that run "on scrape", where the schedule lives in Prometheus and the
alerting (deduplication, webhooks, templates) lives in Alertmanager. certel
inverts that: it is a **self-contained monitor** that owns the whole control
loop —

- **its own scheduler** — probes run on certel's cadence; no external scraper
  is required;
- **its own alert state** — "already alerted / recovered" is persisted in
  SQLite, so a known problem is not re-alerted after a restart and a problem
  fixed while the monitor was down still gets its recovery notice;
- **its own webhook templating** — alerts go straight to any HTTP endpoint,
  with the body written as structured YAML and rendered per notifier.

STARTTLS (`smtp`, `imap`, `pop3`, `ftp`, `postgres`) is supported alongside
implicit TLS, so mail and database endpoints are first-class targets, not an
afterthought.

Prometheus metrics are *optional* output, not the spine: `/metrics` uses
[ssl_exporter](https://github.com/ribbybibby/ssl_exporter)-compatible
certificate metric *names and meanings*, so third-party Grafana dashboards
and alerting rules port over with one small edit — the label model differs
(certel's `host` instead of ssl_exporter's `instance`). See
[Metrics](metrics.md).

## Why we built it

A survey of the open-source landscape before development started (July 2026)
showed that the niche — *a single binary + YAML → templated alerts to an
arbitrary webhook, with no mandatory Prometheus stack, and STARTTLS support* —
was not covered by existing tools:

1. **Architectural mismatch with exporters.** ssl_exporter and Blackbox are
   stateless probes: the only thing they would give us is the TLS probe itself
   (~300–500 lines) — the smaller part of the project — while forcing a
   Prometheus/Alertmanager stack on every deployment.
2. **Gatus / Uptime Kuma cannot do STARTTLS** — while smtp/imap/pop3/postgres
   are v1 requirements for us.
3. **Single-maintainer dependency.** ssl_exporter is alive, but releases come
   out roughly once a year and mostly bump dependencies. Basing the core of a
   security product on such a dependency is a bad trade given its size.

The full survey — comparison table, what we borrowed, and the license
constraints — is in [Alternatives](alternatives.md). If certel's trade-offs
don't fit your setup, that page is the map of what else exists.
