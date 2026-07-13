# certel

**Cert**ificate **E**xpiry & **L**ogs.

Self-hosted SSL/TLS certificate monitor: a single binary and a single YAML
file. Probes your endpoints on a schedule and delivers templated webhook
alerts when a certificate is expiring, expired, invalid, or TLS becomes
unavailable. Optionally exposes Prometheus metrics whose certificate metric
*names* match [ssl_exporter](https://github.com/ribbybibby/ssl_exporter).

## Features

- **Certificate checks**: expiry (leaf *and* intermediates), chain of trust,
  hostname/SAN match, configurable warning/critical thresholds per target.
- **STARTTLS**: `smtp`, `imap`, `pop3`, `ftp`, `postgres` — plus implicit TLS
  for everything else. A server that stops offering STARTTLS is reported
  (`tls_unavailable`), which also catches STARTTLS-stripping.
- **Private infrastructure**: custom CA bundle per target (`ca_file`),
  `insecure` mode that still checks expiry, `servername` decoupled from the
  connect address (probe via IP/bastion, verify the public name via SNI). Each
  notifier takes the same `ca_file`/`insecure` options for a receiver behind an
  internal CA.
- **Multiple notifiers with fan-out**: define several named `notifiers`, each
  with its own url, template, headers, delivery/retry policy and severity floor;
  attach each target to one or more via `target_defaults.notifiers` or a
  per-target `notifiers`. A target fans out to all its notifiers off one
  decision. Delivery is isolated per notifier — a down or slow endpoint can't
  delay another's alerts.
- **Per-notifier `min_severity`**: a stateless delivery floor. A channel carries
  only alerts at or above its floor (default `warning` = everything); a problem
  dropping below the floor reads as a recovery for that channel. So an always-on
  SSL chat can take every alert while a shared pager takes only `emergency`, from
  the same target — no severity routing, each channel a self-consistent stream.
- **Sane alerting**: alert on the *transition* into a bad state, periodic
  reminders (`alert_repeat_interval` on the target, per-severity so the cadence
  tightens as severity rises), recovery notices, delivery retries with
  exponential backoff, connection retries before declaring a target unreachable.
- **Structured webhook bodies**: write the message as a YAML `body:`, not
  hand-built JSON — certel renders each value and marshals it, escaping for free.
  One `${namespace.path}` syntax covers both `${alert.Path}` data and `${env.VAR}`
  secrets (in the url, headers and body), so secrets stay out of the config file.
- **Persistent state (SQLite)**: alert dedup state survives restarts — a
  known problem is not re-alerted after a restart, and a problem fixed while
  the monitor was down still gets its recovery notice. Alerts are queued in a
  durable outbox and delivered at least once, so a crash between deciding to
  alert and sending re-sends on restart rather than staying silent. Probe
  results and alert events are kept as queryable append-only logs with
  configurable retention.
- **Observability**: `/metrics` (Prometheus, ssl_exporter-compatible names),
  `/healthz` (scheduler progress and database reachability), structured logs.

## Quick start

```sh
make build                           # binaries land in bin/
cp config.example.yaml config.yaml   # edit targets and alert endpoint
export ALERT_TOKEN=...               # if referenced in headers
bin/certel validate-config config.yaml
bin/certel monitor -config config.yaml
```

For a one-off check of a single endpoint — no config file, no database, no
alerts — use `certel check`; the verdict is printed as JSON:

```sh
bin/certel check example.com
bin/certel check -protocol smtp -warning-days 14 mail.example.com:587
```

The exit code follows the severity (0 ok, 1 warning, 2 critical), so the
command drops straight into scripts and CI. `-servername`, `-ca-file`,
`-insecure`, `-timeout` and `-retries` mirror the per-target config options;
run `certel check -h` for the full list.

Or with Docker:

```sh
docker build --build-arg VERSION=$(git describe --tags --always --dirty) -t certel .
docker run -v $PWD/config.yaml:/etc/certel/config.yaml \
  -v certel-data:/opt/certel/db \
  -e ALERT_TOKEN -p 8880:8880 certel
```

The `VERSION` build-arg stamps the version reported by `certel version`, the
startup log and `/healthz`; omit it and the image reports `dev`.

The `/opt/certel/db` volume holds the SQLite database (alert state and
logs); without it a container recreation loses dedup state and re-sends
alerts for known problems.

## Configuration

See [config.example.yaml](config.example.yaml) for the annotated reference.
Minimal config:

```yaml
notifiers:
  default:
    url: https://example.com/alert
    body:
      host: ${alert.Host}
      status: ${alert.Status}
      message: ${alert.Message}
target_defaults:
  notifiers: [default]            # every target fans out here unless it overrides
targets:
  - address: example.com          # port defaults per protocol (tls -> 443)
  - address: mail.example.com:587
    protocol: smtp
```

Each target must resolve to at least one notifier — set
`target_defaults.notifiers` (as above) or a per-target `notifiers:`; there is no
implicit default even with one notifier defined. A single notifier is still a
one-element list (`notifiers: [default]`). A target with several notifiers fans
out to all of them. See
[config.example.yaml](config.example.yaml) for a setup where a critical database
pages on `emergency` (via a `min_severity: emergency` pager) while everything
posts to chat.

The repeat cadence is `alert_repeat_interval` on the target (or
`target_defaults`), not on the notifier — a persisting problem is what drives a
reminder, and every notifier a target fans out to shares that one clock. It takes
a single duration (same cadence for all severities) or a complete per-severity
map (`{warning, critical, emergency}`) so the reminder tightens as severity
rises; each entry must be at least `probe.check_interval`. The built-in default
is a flat `24h`; the per-severity map is the opt-in upgrade, not the default.

### Body

A notifier's `body:` is a YAML structure whose string values carry
`${alert.Path}` references; certel renders each and marshals the whole thing to
JSON, so quotes and newlines are escaped automatically — never hand-build JSON. A
value that is *exactly* one `${alert.X}` reference keeps its native JSON type
(`days_left: ${alert.DaysLeft}` → a number); a reference inside a larger string
yields a string. `${env.VAR}` interpolates a secret (resolved once at startup) in
the url, headers or body; write a literal `${` as `$${`.

An optional `recovery_body:` is a sparse override deep-merged onto `body` when the
alert is a recovery — name only the keys that differ; the rest is inherited.

Timestamp fields take an optional `| format` suffix: a preset (`date`, `datetime`,
`time`, `human`, `rfc3339`) or a strftime pattern (`%Y-%m-%d`).

**Fields:** `Host`, `Address`, `Port`, `Protocol`, `Status`, `Severity`,
`Message`, `Recovered`, `DaysLeft`, `CheckedAt`, and under `Cert.`: `Subject`,
`SubjectCN`, `Issuer`, `IssuerCN`, `IssuerOrg`, `NotBefore`, `NotAfter`,
`EarliestNotAfter`, `SigAlg`, `Serial`, `SANs`. `Cert.*` renders empty when the
handshake never completed.

`DaysLeft` and the `Cert.*` fields are only meaningful when a certificate was
actually inspected; for `unreachable` and `tls_unavailable` alerts there is no
expiry to report and `DaysLeft` renders `0`. Route on severity with separate
notifiers (`min_severity`) rather than branching inside a body — there is no
inline control flow.

### Check statuses

| Status | Severity | Meaning |
|---|---|---|
| `ok` | ok | Verified, expiry beyond `warning_days` |
| `expiring_soon` | warning / critical | Expires within `warning_days` / `critical_days` |
| `expired` | emergency | A certificate in the presented chain has expired |
| `invalid` | emergency | Untrusted chain or hostname mismatch |
| `weak_signature` | critical | Chain unverifiable — a certificate is signed with a deprecated algorithm (e.g. SHA-1); expiry is still reported |
| `tls_unavailable` | critical | Server did not offer STARTTLS |
| `unreachable` | critical | Connection/protocol failure after retries — the certificate could not be inspected |

A threshold fires when strictly fewer than N days remain: `warning_days: 30`
alerts once fewer than 30 days are left, `critical_days: 7` once fewer than 7.
Whole days are counted truncated toward zero, so the decision matches a
Prometheus line at `N * 86400` over
`certel_cert_expiry_timestamp_seconds - time()` (up to probe staleness).

The probe accepts TLS 1.0 and above so legacy endpoints (old appliances,
embedded management interfaces, legacy mail servers) can still be monitored
for expiry; trust is verified manually regardless of the negotiated version.

### Flap debounce

A network blip and a genuinely dead service look identical to the prober, so a
transition **into or out of** a network-shaped status (`unreachable`,
`tls_unavailable`) is only alerted on after `flap_streak` consecutive cycles
agree — default `2`, set per target or in `target_defaults`. A single bad cycle
that clears on the next one produces no alert and no recovery notice; a real
outage alerts one cycle later than before. `flap_streak: 1` restores
alert-on-first-cycle. The debounce is symmetric: leaving a confirmed
unreachable state also needs `flap_streak` healthy cycles, so a
down-up-down flap does not emit an alert/recovery pair per tooth.

Fact statuses read from a successfully retrieved certificate (`expired`,
`invalid`, `weak_signature`, `expiring_soon`) have no such noise source and
always alert on the first observation, whatever `flap_streak` is set to.

The counter lives in memory but is rebuilt from `probe_log` on startup, so a
restart mid-confirmation resumes the count instead of restarting from zero. It
is alert policy only: `ssl_probe_success` and `certel_probe_severity` still
move on the first failed cycle, so the metrics never lag the probe.

## State and logs

A SQLite database (`database.path`; by default `db/certel.sqlite`
next to the binary, the directory is created automatically) stores:

- `alert_state` — per-target alert dedup and repeat-timer state, restored on
  startup. This is why a restart neither re-alerts a known problem nor swallows
  the recovery notice for one fixed while the monitor was down. State for targets
  removed from the config is pruned at startup.
- `notification_outbox` — pending-delivery queue, tagged with the target `notifier`.
  Each notification is enqueued in the same transaction that updates
  `alert_state`, so a crash between deciding to alert and sending cannot lose
  it: on restart each notifier's dispatcher re-sends whatever is still queued
  for it. Deliveries drain in order per target and a row is removed only once
  sent, so alerts are delivered at least once. Not pruned by age — but rows for
  a notifier no longer in the config (renamed or removed) are dropped at startup
  with a logged count, since their body was frozen with the old notifier's
  template; a dropped recovery is genuinely lost, while a still-present problem
  re-alerts within `alert_repeat_interval`.
- `probe_log` — append-only log of every check: status, severity, days left,
  expiry, duration, attempts.
- `alert_log` — append-only history of alert events, one row per delivery (a
  fanned-out alert writes one row per firing notifier), recorded when the alert
  is decided; it records what happened and which notifier it reached — the
  status/severity that channel saw — not how it was delivered.

Probe and alert log entries older than `database.probe_log_retention` and
`database.alert_log_retention` (each default 90 days) are pruned hourly. The full schema with per-column notes is documented in
[docs/schema.dbml](docs/schema.dbml). The file is safe to inspect while the
monitor runs:

```sh
sqlite3 db/certel.sqlite \
  "SELECT datetime(checked_at, 'unixepoch'), address, status, days_left
   FROM probe_log ORDER BY checked_at DESC LIMIT 20"
```

## Metrics

`certel monitor` optionally exposes Prometheus metrics on `/metrics`, with the
certificate metric *names* matching
[ssl_exporter](https://github.com/ribbybibby/ssl_exporter) so alert
expressions and panels port over.

The `ssl_*` *names* match ssl_exporter, but the label model does not:
ssl_exporter is scraped once per probed endpoint and carries identity in the
`instance` label attached by relabeling, while certel serves every target from
a single scrape and attaches `host`/`address`/`protocol`/`servername` labels
itself. Dashboards and alert rules built for ssl_exporter need their queries
rewritten:

```promql
ssl_cert_not_after{instance="$target"}   # ssl_exporter
ssl_cert_not_after{address="$target"}    # certel
```

The full surface — every metric, the naming and label policy, per-metric
semantics, absence rules, and what was deliberately left out — is in
[docs/metrics.md](docs/metrics.md).

## Shell completion

Tab-completes certel's command names. Run the one line for your shell (assumes
`certel` is on your `PATH`), then restart the shell:

```sh
# zsh
echo 'source <(certel completion zsh)' >> ~/.zshrc

# bash
echo 'source <(certel completion bash)' >> ~/.bashrc

# fish
certel completion fish > ~/.config/fish/completions/certel.fish
```

It completes command names only — no flags, no target names. During local
development, replace `certel` with `bin/certel`.

When packaging lands the script will be shipped into the OS completion
directory (`/usr/share/{bash-completion/completions,zsh/site-functions,fish/vendor_completions.d}`),
so an installed package completes with no setup.

## Development

```sh
make build   # build bin/certel and bin/notification-sink (version from git describe)
make test
make vet
make clean
```

To watch alerts flow end to end, run the bundled webhook receiver and point
`alert.url` at it (the config.example.yaml placeholder already does):

```sh
go run ./cmd/notification-sink                # listen on :9999, print alerts, respond 200
go run ./cmd/notification-sink -status 500    # simulate a broken endpoint to test retries
go run ./cmd/notification-sink -verbose       # also print request headers (auth etc.)
```

See [docs/alternatives.md](docs/alternatives.md) for the survey of existing
tools and the reasoning behind building this one, and
[docs/adr/](docs/adr/) for the Architecture Decision Records — the *why* behind
the non-obvious design choices (delivery-only fan-out, the stateless
`min_severity` floor, the SQLite outbox model, the severity ladder, and the rest).

## License

MIT — see [LICENSE](LICENSE).
