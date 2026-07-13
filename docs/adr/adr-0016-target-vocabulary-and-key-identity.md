# 0016. "target" as the domain vocabulary and `Target.Key` identity

- **Status:** Accepted
- **Date:** 2026-07-10

## Context

The stored identifier for a monitored thing is `protocol//address/servername` — not a
host: one host/address can expose several distinct monitored things on different ports,
protocols or server names. So `host` names less than the identity encodes, and the `key`
column shared across `alert_state`, `probe_log`, `alert_log` and `notification_outbox` is
too generic to tell a reader *which* key it is. The domain vocabulary and the identity
contract are one question: what is a monitored thing called, and what makes two of them
the same?

## Decision

The canonical domain noun is **"target"** — chosen over `host` (too narrow:
`protocol//address/servername` is more than a host) and `endpoint` (the interim
front-runner). The config type is `Target` and the identity is `Target.Key()`, which
returns `protocol + "//" + address + "/" + servername`.

That format is a **stable contract**: it is the dedup key, the `alert_state` primary key,
and the join key across every table, so it must not change across versions.

## Consequences

- `Target.Key()`'s components define target *identity*: editing a target's `notifiers` or
  `warning_days`/`critical_days` keeps the same key (so it inherits dedup state and
  `last_alert_at` — a notifier switch does **not** re-alert;
  [0006](adr-0006-fan-out-is-delivery-only.md)), while editing `address`/`protocol`/
  `servername` changes the key, making it a remove + add (state pruned, metric series
  deleted, fresh start).
- The identity components line up with the frozen Prometheus identity label family
  ([0015](adr-0015-metrics-surface-and-ssl-exporter-compat.md)), so the exported labels and
  the DB key can't drift apart.
- One consistent word ("target") from config to code to docs to the `certel check` CLI.

## Alternatives considered

- **`host`.** Rejected: names less than the key encodes; misleads about one-host,
  many-targets.
- **`endpoint`.** The deferred front-runner (it matches "protocol + address + SNI"), but
  "target" won as the term that also reads naturally in the CLI and user-facing prose.

## References

- `internal/config/config.go` (`Target.Key`, `config.go:387`), `docs/schema.dbml`.
