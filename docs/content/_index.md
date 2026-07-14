---
title: 'certel'
toc: false
---

**Cert**ificate **E**xpiry & **L**ogs.

Self-hosted SSL/TLS certificate monitor: a single binary and a single YAML file.
certel probes your endpoints on a schedule and delivers templated webhook alerts
when a certificate is expiring, expired, invalid, or TLS becomes unavailable.
Optionally it exposes Prometheus metrics whose certificate metric *names* match
[ssl_exporter](https://github.com/ribbybibby/ssl_exporter).

{{< cards >}}
  {{< card link="metrics" title="Metrics" subtitle="Everything exported on /metrics, and the rules new metrics follow." icon="chart-bar" >}}
  {{< card link="alternatives" title="Alternatives" subtitle="The survey of existing tools that motivated building certel." icon="clipboard-list" >}}
  {{< card link="adr" title="ADRs" subtitle="Architecture Decision Records — the why behind the design." icon="book-open" >}}
  {{< card link="https://github.com/antonkomarev/certel" title="Source" subtitle="Repository, issues, and releases on GitHub." icon="github" >}}
{{< /cards >}}
