---
title: 'certel'
toc: false
# Give every descendant page the docs layout so the left navigation sidebar
# persists on single pages too (metrics, alternatives, and each ADR). Without
# this they fall back to Hextra's centered no-sidebar single layout. The
# cascade does not apply to this home page itself, so the landing cards stay.
cascade:
  type: docs
---

**Cert**ificate **E**xpiry & **L**ogs.

Self-hosted SSL/TLS certificate monitor: a single binary and a single YAML file.
certel probes your endpoints on a schedule and delivers templated webhook alerts
when a certificate is expiring, expired, invalid, or TLS becomes unavailable.
Optionally it exposes Prometheus metrics whose certificate metric *names* match
[ssl_exporter](https://github.com/ribbybibby/ssl_exporter).

{{< cards >}}
  {{< card link="introduction" title="Introduction" subtitle="The concept, what certel owns itself, and why we built it." icon="information-circle" >}}
  {{< card link="quick-start" title="Quick Start" subtitle="From zero to a working certificate check in one command." icon="play" >}}
  {{< card link="metrics" title="Metrics" subtitle="Everything exported on /metrics, and the rules new metrics follow." icon="chart-bar" >}}
  {{< card link="alternatives" title="Alternatives" subtitle="The survey of existing SSL monitoring tools, licenses included." icon="clipboard-list" >}}
  {{< card link="adr" title="ADRs" subtitle="Architecture Decision Records — the why behind the design." icon="book-open" >}}
  {{< card link="https://github.com/antonkomarev/certel" title="Source" subtitle="Repository, issues, and releases on GitHub." icon="github" >}}
{{< /cards >}}
