# 0005. Config-only named webhook notifiers

- **Status:** Accepted
- **Date:** 2026-07-09

## Context

Alerting needs several named destinations, each with full config — url, body,
headers, timeouts, retries, TLS — plus a per-target selector, so (e.g.) databases
page one endpoint while everything else posts to a chat webhook. Nothing was in
production yet, so no compatibility was owed to the original single `alert:`
destination: a clean break was available.

## Decision

Notifiers are **plain config, not code**: `Notifiers map[string]AlertConfig` —
the map key is the notifier name, so uniqueness and by-name reference come free
and fit `KnownFields(true)` strict parsing. A notifier is just a webhook: url +
method + headers + a rendered body + delivery policy. There is deliberately
**no per-provider code** (no "Telegram driver", no "PagerDuty driver") —
Telegram, PagerDuty, ntfy, Mattermost etc. are all reached as ordinary webhooks
whose shape is expressed entirely in config (see
[0018](adr-0018-structured-webhook-bodies.md) for the body model).

Delivery is **isolated per notifier**: one `WebhookSender` + one `Dispatcher` (its own
concurrency semaphore and wake channel) over a notifier-scoped store view. The
`Manager` stays single — it owns the alert/recovery *decision* — and reads delivery
policy and the body from the target's resolved notifier.

Notifiers carry the same TLS options as targets — `ca_file` (custom trust anchor) and
`insecure` — because the typical self-hosted deployment posts alerts to an internal
receiver behind an internal CA; without these, delivery fails with an x509 error the
user cannot fix in config.

## Consequences

- `concurrency` is per-notifier: a down or slow notifier can't starve another's
  delivery budget — the same isolation the dispatcher gives between targets, one
  level up.
- **Selector resolution is always explicit.** A target that resolves to no notifier
  fails validation *even when only one notifier is defined* — "clarity over one saved
  line," no implicit single pick, no magic `default` name.
- `notification_outbox` and `alert_log` carry a `notifier` column (history must answer
  "which notifier was this decided for" when debugging a pager that never fired).
- Adding a new alerting target (Slack, Teams, a home-grown relay) is a config edit,
  never a code change or a new build.
- **Orphaned outbox rows** — a notifier renamed/removed while rows are still queued —
  are dropped at startup with a logged count (`DropOrphanedOutbox`). Their body was
  frozen with the old notifier's template, so re-tagging them to a new notifier would
  POST a mis-shaped body forever; a still-present problem re-alerts within the repeat
  interval, while a dropped *recovery* is genuinely lost (the log says so).

## Alternatives considered

- **A target → *list* of notifiers, from day one.** Deferred here (a target took a
  single notifier string): outside severity routing the demand for multi-destination
  is thin, and most of it (human+machine consumers, shared infra, migration
  dual-send) is served by fanning out behind one webhook. Later *granted* once it
  could be made schema-free — see [0006](adr-0006-fan-out-is-delivery-only.md).
- **Per-provider notifier drivers.** Rejected: a webhook + a config-authored body
  covers every JSON receiver without shipping and maintaining integration code.
- **A `default`/implicit notifier when only one is defined.** Rejected for explicitness.

## References

- `internal/config/config.go`, `internal/alert/manager.go`, `internal/store/store.go`.
