# 0017. Lock the config surface before 1.0

- **Status:** Accepted
- **Date:** 2026-07-12

## Context

The first release turns every key name, nesting choice, default value and duration
unit in the config into a backward-compatibility contract. Not all of it is equally
locked, so the review ranked the surface by **reversibility**:

- **Irreversible — no alias can save these:** default *values* (changing one
  silently changes behavior for every config that omits the key), enum spellings
  (`severity`, `status`, `protocol` — baked into user bodies and PromQL), metric
  names/labels ([0015](adr-0015-metrics-surface-and-ssl-exporter-compat.md)), and
  alert-body field names ([0018](adr-0018-structured-webhook-bodies.md)).
- **Alias-able:** YAML key names — a rename can carry a deprecation alias for a
  migration window after 1.0.

Every key was walked once, and the changes landed **atomically in one commit**, so
the first published `config.example.yaml` is the contract we keep.

## Decision

**Renames and removals** (old spellings rejected by `KnownFields` strict parsing):

- Target `retries` → **`connect_retries`** — it retries only the connection
  (`unreachable`), *within* a cycle; the name scopes it to what it governs and
  separates it from the cross-cycle debounce. Notifier-side `retries` (delivery
  retries) deliberately keeps the plain name — locally unambiguous, like `timeout`.
- Target `confirmations` → **`flap_streak`** — "flap" says *what* it debounces
  (transient network statuses, not fact statuses;
  [0009](adr-0009-debounce-network-shaped-statuses.md)), "streak" says *how*
  (a run of N consecutive cycles).
- The singular **`notifier:` sugar is removed** — a mutually-exclusive dual form
  (pointer field, two both-set error paths, doc caveats) to save typing `[ ]` in
  one case. Only `notifiers: [name]` remains.
- Notifier **`content_type` is removed, folded into `headers`** — it was two ways
  to set one header with a silent precedence. The `Content-Type: application/json`
  default moves into the sender *before* the headers loop, so a header still
  overrides it and JSON notifiers don't hand-write it.

**Defaults** (the irreversible bucket, checked value by value):

- **`send_recovery` defaults to `true`** — a notifier that omits it must still
  close the loop ("recovered"), not go silent. This forces the type `bool` →
  `*bool` (a bare bool's zero value `false` is indistinguishable from unset);
  auto-resolving receivers (e.g. PagerDuty) opt out with an explicit `false`.
- **`alert_repeat_interval` default stays a flat `24h` scalar** — simple and
  predictable; the per-severity map
  ([0010](adr-0010-severity-aware-repeat-cadence.md)) is the documented upgrade,
  not the default.
- `database.alert_log_retention` default corrected to `365d` (code said `90d`
  while the example promised `365d` — a plain bug, fixed ahead of the pass).
  The remaining defaults (`check_interval 5m`, `concurrency 10`,
  `timeout 10s`, `warning_days 30`, `critical_days 7`, `probe_log_retention 90d`)
  were reviewed and kept.

**Deliberate keeps**, recorded so they don't get "fixed" later:

- **`servername`, not `server_name`.** It is a cross-surface word: also a frozen
  metric label ([0015](adr-0015-metrics-surface-and-ssl-exporter-compat.md)) and a
  CLI flag, and a legitimate TLS/SNI token (`openssl s_client -servername`).
  Renaming only the key desyncs three surfaces, and the metric label is on the
  irreversible list — the snake_case exception is the lesser evil.
- **`protocol: tls`, not `https`.** The enum's axis is "how the TLS session
  starts": the STARTTLS entries are named by the app dialog the prober actually
  speaks (`smtp`/`imap`/`pop3`/`ftp`/`postgres`), and `tls` names the case with no
  app dialog — pure handshake from byte 0, covering *every* implicit-TLS target
  (443, 465, 993, 995, 636, raw TLS…). `https` is a subset name for a superset
  behavior and invites "why no `smtps`/`imaps`?".
- `concurrency`/`timeout`/`insecure` reused across probe and notifier scopes (same
  concept, different scope; qualifying them stutters), and `check_interval`
  matching the user-facing `certel check` verb.
- **The "days" vocabulary convention:** "days" always means whole days until
  expiry; threshold keys are `<severity>_days`, the live value is `days_left` —
  never a second root (`remaining`, `expires_in`).

## Consequences

- After 1.0, any key change needs a deprecation/alias path; default values and enum
  spellings effectively cannot change at all. The churn budget was spent where no
  alias could ever help.
- `KnownFields` strict parsing makes removed/renamed keys fail loudly at load
  instead of being silently ignored.
- The `connect_retries` / `flap_streak` pair keeps the probe/alert boundary visible
  in config: intra-cycle "try harder" vs cross-cycle "wait and confirm" — they
  don't even gate the same statuses.

## Alternatives considered

- **Group `connect_retries` + `flap_streak` into an `unreachable_policy` object.**
  Rejected: they sit on opposite sides of the probe/alert boundary, don't gate the
  same statuses, and nesting would break the clean per-field `target_defaults`
  fallthrough (merge-vs-replace ambiguity).
- **A `notifier_defaults` section** mirroring `target_defaults`. Rejected:
  notifiers number 1–3 in practice, not dozens; the duplication is minimal and an
  extra top-level section costs more clarity than it saves.
- **Symmetric `connect_retries` on the notifier.** Rejected: delivery retries are
  not connects; the plain `retries` is locally unambiguous.

## References

- `internal/config/config.go`, `config.example.yaml`, README.
- Related: [0009](adr-0009-debounce-network-shaped-statuses.md),
  [0010](adr-0010-severity-aware-repeat-cadence.md),
  [0015](adr-0015-metrics-surface-and-ssl-exporter-compat.md),
  [0016](adr-0016-target-vocabulary-and-key-identity.md).
