---
title: 'Survey of existing SSL certificate monitoring tools'
linkTitle: 'Alternatives'
weight: 40
---

An analysis of open-source alternatives carried out before development started
(July 2026). Conclusion: the niche of "a single binary + YAML → templated
alerts to an arbitrary webhook, with no mandatory Prometheus stack" is not
covered by existing tools. The reasoning that led from this survey to building
certel is in the [Introduction](introduction.md); this page keeps the raw
material — the comparison table, what we borrowed, and the license
constraints.

## Comparison table

| Tool | Language | License | STARTTLS | Webhook alerts | Prometheus | Notes |
|---|---|---|---|---|---|---|
| [ssl_exporter](https://github.com/ribbybibby/ssl_exporter) | Go | Apache-2.0 | yes (smtp, imap, pop3, ftp, postgres) | only via Alertmanager | yes (its whole point) | Closest match in terms of checks |
| [Blackbox exporter](https://github.com/prometheus/blackbox_exporter) | Go | Apache-2.0 | no | only via Alertmanager | yes | Official Prometheus prober, `probe_ssl_earliest_cert_expiry` |
| [Gatus](https://github.com/TwiN/gatus) | Go | Apache-2.0 | no | yes, many providers | yes | YAML conditions like `[CERTIFICATE_EXPIRATION] > 720h`, has a dashboard |
| [Uptime Kuma](https://github.com/louislam/uptime-kuma) | Node.js (JS/TS + Vue) | MIT | no | yes | partially | An all-in-one with UI and SQLite; heavyweight for our niche |
| [check_ssl_cert](https://github.com/matteocorti/check_ssl_cert) | Bash | GPL-3.0 | yes | via Nagios/Icinga/Zabbix | no | Classic plugin, requires a monitoring system |
| [certok](https://github.com/genuinetools/certok) | Go | MIT | no | no | no | CLI for a one-shot validity/expiry check over a host list; no scheduler, state or alerts |
| [certo](https://github.com/Arvil/certo) | Rust | MIT | no | no | no | CLI expiry checker over remote hosts, text/JSON output for cron/CI; no scheduler or alerts |
| [certify](https://github.com/shivamsaraswat/certify) | Python | MIT | no | no | no | One-shot security audit of a remote host's cert (TLS version, cipher, misconfig), not monitoring |
| [certalert (ickerwx)](https://github.com/ickerwx/certalert) | Python | Unlicense | yes | no (Splunk/email) | no | Scans remote hosts, ships to Splunk HEC / email, stores in SQLite |
| [certalert (containeroo)](https://github.com/containeroo/certalert) | Go | Apache-2.0 | no | no | yes | Expiry of local cert files (PEM/PKCS12/JKS) → metrics / Pushgateway; no network probing, deprecated |
| [certalert (gi8lino)](https://github.com/gi8lino/certalert) | Java | Apache-2.0 | no | no | yes | Spring Boot: monitors local cert files/keystores + dashboard → metrics; does not probe remote hosts |
| Zabbix / Nagios / Icinga | C / C / C++ | GPL | via plugins | yes | via exporters | Full monitoring systems, not utilities |
| [certspotter](https://github.com/SSLMate/certspotter) | Go | **MPL-2.0** | n/a | script hooks, email | no | Different niche: watches CT logs for certificate *issuance* |

## What we may borrow

- **Metric-name compatibility with ssl_exporter** (`ssl_probe_success`,
  `ssl_cert_not_after`, `ssl_verified_cert_not_after`): third-party Grafana
  dashboards and alerting rules port over with a label swap (certel's `host`
  instead of the multi-target `instance`) — a cheap way to lower the
  migration barrier.
- **ssl_exporter sources as a reference** for corner cases (verified-chain
  numbering, STARTTLS dialogs, custom CAs).

## License constraints

- **ssl_exporter (Apache-2.0)**: compatible with an MIT project. Any copied
  pieces remain under Apache-2.0 — keep file headers and NOTICE.
- **certspotter (MPL-2.0, file-level copyleft)**: if we ever get to a CT
  module — either import it as an unmodified dependency (noting it in
  THIRD_PARTY_LICENSES with a link to the sources), or write our own
  implementation from RFC 6962. Porting pieces of their code into our MIT
  files is **not allowed** (the file becomes Covered Software and must be
  MPL), and their code cannot be relicensed. Copying their files wholesale
  into the repo is legal but makes the repository's licensing mixed — we
  avoid that.

## certspotter — adjacent, but a different problem

certspotter does not connect to servers at all: it reads public Certificate
Transparency logs and reports the fact that a certificate was issued for your
domains (unauthorized issuance, shadow infrastructure, misissuance). It does
not see internal CAs and does not verify the chain/hostname/expiry on the
actual host. Our monitor and certspotter complement each other; CT monitoring
is a candidate for a separate module after v1.
