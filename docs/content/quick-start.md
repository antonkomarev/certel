---
title: 'Quick Start'
linkTitle: 'Quick Start'
weight: 5
---

From nothing to a working certificate check in one command — no clone, no
build. All you need is [Go](https://go.dev/dl/) 1.24 or newer.

## Step 1 — Run your first check

Point certel at any public endpoint. `go run` fetches and runs it straight
from the repository — no config file, no database, no setup:

```sh
go run github.com/antonkomarev/certel/cmd/certel@latest check example.com
```

You get the verdict as JSON:

```json
{
  "address": "example.com:443",
  "protocol": "tls",
  "status": "ok",
  "severity": "ok",
  "message": "certificate valid, expires in 45 day(s)",
  "days_left": 45,
  "not_after": "2026-08-29T21:41:26Z",
  "verify_ok": true,
  "cert": {
    "cn": "example.com",
    "issuer": "CN=Cloudflare TLS Issuing ECC CA 3,O=SSL Corporation,C=US",
    "sans": ["example.com", "*.example.com"]
  }
}
```

That's it — certel works. The exit code follows the severity (`0` ok,
`1` warning, `2` critical), so the command drops straight into scripts and CI.

## Step 2 — Install it as a command

Typing the full module path every time is a mouthful. Install once and you get
a plain `certel` binary on your `PATH`:

```sh
go install github.com/antonkomarev/certel/cmd/certel@latest
```

The rest of this guide uses `certel …`. (The binary lands in `$(go env GOBIN)`,
or `$(go env GOPATH)/bin` if `GOBIN` is unset — make sure that directory is on
your `PATH`.)

## Step 3 — Check whatever you need

The same command handles STARTTLS and tighter thresholds:

```sh
# a mail server over STARTTLS, warn if it expires within 14 days
certel check -protocol smtp -warning-days 14 mail.example.com:587
```

Run `certel check -h` for every flag (`-servername`, `-ca-file`, `-insecure`,
`-timeout`, `-retries`).

---

That covers ad-hoc checks. To monitor endpoints **continuously** — on a
schedule, with webhook alerts and no re-alerting after restarts — set up the
monitor.

## Step 4 — Write a config

A minimal `config.yaml` is one webhook plus a list of targets:

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

Each target must resolve to at least one notifier — there is no implicit
default even with a single notifier defined. The full annotated reference is
[config.example.yaml](https://github.com/antonkomarev/certel/blob/main/config.example.yaml).

## Step 5 — Validate and run

Check the config is well-formed, then start the monitor:

```sh
certel validate-config config.yaml
certel monitor -config config.yaml
```

certel now probes every target on its schedule and delivers a webhook alert
when a certificate is expiring, expired, invalid, or TLS becomes unavailable —
and a recovery notice when it clears.

## Watch alerts flow

Don't have a real webhook endpoint yet? Run the bundled receiver and point
`notifiers.default.url` at it (the `config.example.yaml` placeholder already
does). It prints every alert and responds `200`:

```sh
go run github.com/antonkomarev/certel/cmd/notification-sink@latest   # listens on :9999
```

## Next steps

- [Introduction](introduction.md) — the concept and what certel owns itself.
- [Metrics](metrics.md) — the optional Prometheus surface on `/metrics`.
- [ADRs](adr/) — the *why* behind the design.
