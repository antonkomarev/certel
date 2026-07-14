---
title: '0018. Structured webhook bodies with `${namespace.path}` interpolation'
weight: 18
---

- **Status:** Accepted
- **Date:** 2026-07-13

## Context

A raw `template:` string run through Go's `text/template` forces notifier authors
to **hand-build JSON**: `{{json}}` + `printf` + backtick raw strings + positional
`%s` args — hard to read, easy to get wrong (a stray brace breaks the payload). It
also blurred two interpolation layers: bare `${VAR}` env expansion worked in some
fields but not others — `${PAGERDUTY_KEY}` inside a template body silently did
nothing.

## Decision

Remove JSON authoring entirely and collapse the two layers into one syntax.

1. **Bodies are structured, not hand-written JSON.** A notifier declares `body:` as a
   YAML structure; certel renders each string value and `json.Marshal`s the whole thing,
   so quotes and newlines are escaped for free. Authors write the *message*, never a brace.
2. **One `${namespace.path}` grammar, two namespaces:** `${env.VAR}` (secrets, resolved
   once at config load, valid in `url`, `headers` and `body`) and `${alert.Path}`
   (per-alert data, resolved at render, `body` only). No `text/template`, no `{{...}}`.
   A value that is *exactly* one `${alert.X}` keeps the datum's native JSON type
   (`days_left: ${alert.DaysLeft}` → a number); a reference inside a larger string yields
   a string. Substitution is **single-pass and non-recursive**, so an interpolated cert
   CN of `${env.SECRET}` is inert — it can neither leak a secret nor self-reference.
   A literal `${` is written `$${`.
3. **No inline control flow.** Severity routing is already handled by multiple notifiers
   with `min_severity` floors ([0007](adr-0007-per-notifier-min-severity-floor.md)), and the
   prober sets `Message`/`Status`/`Severity` correctly for both firing and recovery, so
   the common case renders both from one `body`. The one genuine divergence — recovery
   wording — is an optional **`recovery_body:`**, a *sparse* deep-merge override onto
   `body` (name only the keys that differ), matching how `target_defaults` overrides work
   elsewhere. Not a `{{if .Recovered}}`.

Timestamp fields take an optional `| format` suffix — a named preset (`date`, `datetime`,
`time`, `human`, `rfc3339`) or a strftime pattern (`%Y-%m-%d`) — so the unreadable Go
reference layout (`2006-01-02`) is never exposed.

## Consequences

- Every JSON webhook (Telegram, PagerDuty's nested schema, a generic receiver) is
  expressed in config with no braces — the config-only notifier model
  ([0005](adr-0005-config-only-webhook-notifiers.md)) now has an author-friendly body.
- Uniform `${env.*}` scope over `url`/`headers`/`body` closes the latent bug where an
  env reference in a body did nothing; secrets stay out of the config file.
- **Static validation at load** replaces the old sample-render guess: every `${...}` is
  parsed, an unknown `${alert.Path}` (not in the field allowlist) or an unset `${env.VAR}`
  fails at startup, not at alert time. A representative sample render still runs to catch
  encoding/format bugs.
- This is a **pre-1.0 breaking change** with no alias path (aliases start at 1.0):
  `template:` → `body:`, bare `${VAR}` → `${env.VAR}`, `{{.Field}}` → `${alert.Field}`,
  and the top-level `NotAfter` is gone (`DaysLeft` is the effective decision number; the
  rare chain-earliest date is `${alert.Cert.EarliestNotAfter}`). The alert data model
  nests all certificate facts under `.Cert`, which renders empty when the handshake never
  completed.

## Alternatives considered

- **Keep `text/template` with `{{json}}` helpers.** Rejected: it *is* the hand-built-JSON
  problem this ADR removes.
- **A `{{if .Recovered}}` conditional inside one body.** Rejected in favor of the sparse
  `recovery_body:` override — no inline control flow anywhere, and the diverging wording
  lives in exactly one place with no duplication to drift.
- **A low-level `raw_body:` string** for non-JSON (form-encoded, plaintext) receivers.
  Deferred: not a current need; `body` covers every JSON webhook. Reintroduce only if a
  real non-JSON receiver appears.

## References

- `internal/alert/template.go`, `internal/config/config.go` (`AlertConfig.Body`,
  `expandEnv`), `internal/probe/result.go` (`CertInfo`), `config.example.yaml`.
- "Body" section in the [README](https://github.com/antonkomarev/certel).
