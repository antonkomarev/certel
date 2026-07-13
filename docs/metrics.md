# Metrics

Everything `certel monitor` exports on `/metrics`, designed as one surface:
what each metric is for, the rules new metrics must follow, and what was
deliberately left out. The endpoint also exports the standard Go runtime
(`go_*`) and process (`process_*`) collectors.

## The surface at a glance

Per-target metrics carry the identity labels `host`, `address`, `protocol`,
`servername`; each section below has the full semantics.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `ssl_cert_not_after` | gauge | per-target + `cn` | Leaf certificate expiry, unix time |
| `ssl_verified_cert_not_after` | gauge | per-target | Earliest expiry in the best verified chain, unix time |
| `certel_cert_expiry_timestamp_seconds` | gauge | per-target | Effective expiry the alert decision uses, unix time |
| `ssl_probe_success` | gauge | per-target | 1 = certificate retrieved and acceptable, 0 = any failure |
| `certel_probe_severity` | gauge | per-target | Decided alerting level: 0 ok, 1 warning, 2 critical, 3 emergency |
| `certel_probe_duration_seconds` | gauge | per-target | Wall time of the last probe, retries included |
| `certel_probe_cycle_completed_timestamp_seconds` | gauge | — | When the last probe cycle finished, unix time |
| `certel_probe_cycle_duration_seconds` | gauge | — | Wall time of the last probe cycle |
| `certel_probe_cycle_staleness_threshold_seconds` | gauge | — | Config-derived bound for cycle staleness (the `/healthz` liveness threshold) |
| `certel_notification_sends_total` | counter | `notifier`, `result` | Delivery attempts, `result` = `success`/`failure` |
| `certel_notification_outbox_pending` | gauge | `notifier` | Deliveries currently queued |
| `certel_notification_outbox_oldest_age_seconds` | gauge | `notifier` | Age of the oldest queued delivery, 0 when empty |
| `certel_store_write_errors_total` | counter | — | Failed writes to the SQLite store (alert state, outbox, logs) |
| `certel_target_info` | gauge | per-target + properties | Constant 1 per configured target; presence anchor and property labels (`insecure`) |
| `certel_build_info` | gauge | `version` | Constant 1; the running certel version as a label |

## What earns a metric

A signal becomes a metric only if an operator would alert on it or watch its
trend on a dashboard. Everything else stays in the structured log or the
SQLite tables, where per-occurrence detail belongs:

| Signal | Home |
|---|---|
| Current certificate state per target; probe, delivery, queue, store-write health; scheduler liveness | metric |
| Which alert fired, where, when; problem/recovery breakdown | `alert_log` |
| Per-check history: status, error message, attempts, duration | `probe_log`, process log |
| One-shot startup events (state prunes, orphaned-outbox drops) | process log |

## Naming policy

Two prefixes, one rule each:

- **`ssl_*` — the ssl_exporter compatibility set. Closed.** Exactly three
  metrics (`ssl_probe_success`, `ssl_cert_not_after`,
  `ssl_verified_cert_not_after`), names and meanings matched to
  [ribbybibby/ssl_exporter](https://github.com/ribbybibby/ssl_exporter). They
  are never renamed and the set never grows: a new certificate metric goes
  under `certel_*` even when it thematically belongs beside them.
- **`certel_*` — everything else**, following Prometheus conventions: base
  units (seconds), `_total` suffix on counters, `_timestamp_seconds` for unix
  timestamps.

No exceptions currently. A "days left" metric matching the config unit was
considered and rejected — see `certel_cert_expiry_timestamp_seconds` for why
the quantity is a timestamp instead.

Vocabulary, fixed so names stay coherent: a **probe** is one
measurement-and-evaluation of one target — its result carries status,
severity and duration (`ssl_probe_success`, `certel_probe_severity`,
`certel_probe_duration_seconds`); a **cycle** is one scheduler pass probing
every target (`certel_probe_cycle_*`); an **alert** is a decided event —
problem, repeat, or recovery — recorded in `alert_log`; a **notification** is
one delivery of an alert through one channel (an outbox row; one alert may
fan out to several notifications); a **send** is one delivery attempt of a
notification (`certel_notification_sends_total`). The word **check** is
deliberately absent from metric names: in the product it means the one-off
CLI mode (`certel check example.com`).

## ssl_exporter compatibility: names, not label model

The `ssl_*` metric *names and meanings* match ssl_exporter, so alert
expressions and panel formulas port over. The *label model* does not:
ssl_exporter follows the multi-target pattern — one scrape per probed
endpoint, identity carried by the `instance`/target labels that relabeling
attaches — while certel serves every target from a single scrape and attaches
its own identity labels. A dashboard templated on `$instance` comes up empty
against certel until its queries are rewritten:

```promql
ssl_cert_not_after{instance="$target"}   # ssl_exporter
ssl_cert_not_after{address="$target"}    # certel
```

certel also exports only `cn` on `ssl_cert_not_after`, not ssl_exporter's
`issuer_cn`/`serial_no` — rejected not on cardinality but because no query
wants them (see the rejected list).

## Label taxonomy

Two label families, one per subsystem.

**Per-target family — `host`, `address`, `protocol`, `servername`.** Every
metric measured per monitored target carries the same identifying set:

- `address` — the configured connect address (`host:port`). The primary
  selector; matches `probe_log.address`.
- `host` — the hostname part of `address`. Convenience for grouping several
  ports of one machine, and the nearest analogue of ssl_exporter's instance
  identity.
- `protocol` — the probe protocol (`tls`, `smtp`, `postgres`, …).
- `servername` — the raw `servername` from
  the target's config, empty when not set (empty means "the hostname part of
  `address`", mirroring the SNI default). Needed for identity: two targets may
  share `address`+`protocol` and differ only in `servername` (probe via one
  IP/bastion, verify different public names); without the label their series
  collide and overwrite each other every cycle — including the per-target `cn`
  cleanup on `ssl_cert_not_after`, where each would delete the other's series.
  An empty label value is idiomatic Prometheus: it is identical to the label
  being absent.

  The raw config value rather than the *effective* servername, on purpose:
  with the raw value the label set is injective with the store's `target_key` —
  the key is mechanically `protocol + "//" + address + "/" + servername`, and
  since the key format is frozen (database contract) the derivation is safe
  forever. That makes correlating any series with its `probe_log`/`alert_log`
  rows deterministic. The effective name would collapse "unset" and
  "explicitly set to the hostname" into one series and cannot reconstruct the
  key.

The identity family is **frozen** alongside the `ssl_*` names. Adding an
identity label would be only superficially compatible: selectors and
`by`-aggregations survive, but every series changes identity (history breaks),
`sum without(...)` results shift, and full-list
`on(host, address, protocol, ...)` joins stop matching. Every static fact
about a target is therefore a property label on `certel_target_info`, never a
new identity label.

There is deliberately no `target_key` **label**. The key is a composite of
dimensions that are already individual labels, and a composite label is the
antipattern labels exist to avoid: filtering by one of its parts means
regexing into substrings, and every series exports the same data twice. When
the key is needed, derive it from `protocol`/`address`/`servername` as above.

`cn` (leaf CN on `ssl_cert_not_after`) is the one non-identity label. It is
churn-bounded: the snapshot collector emits only the current leaf's series
(see the scrape-consistency contract below), so exactly one live `cn` series
per target exists no matter how often the certificate rotates — a
rotated-away CN simply stops being emitted.

**Delivery family — `notifier`.** Delivery health is a property of the
endpoint, so the config-bounded notifier name is the only label. Per-target
delivery detail lives in the process log and the outbox rows, not in labels.

**Property labels — on `certel_target_info` only.** Static config-derived
facts about a target (`insecure`) ride the info metric as labels and join
onto any per-target series at query time; they never widen the identity
family on measurement metrics.

**Cardinality rules** — every current and future label must satisfy one of:

1. *Config-bounded*: the value set comes from the configuration (`address`,
   `protocol`, `servername`, `notifier`, `insecure`). Series count is
   O(targets) or O(notifiers).
2. *Churn-bounded*: the value can change over time (`cn`), but a stale series
   vanishes at the moment of change — the snapshot collector emits only
   current values — keeping one live series per identity.

Never free-form values: error messages, serials, certificate subjects. Those
belong in logs.

**Absence semantics.** A series disappears the moment the fact it states is no
longer observed — `certel_cert_expiry_timestamp_seconds` when no expiry was
seen, `ssl_verified_cert_not_after` when verification fails, the old `cn`
series on rotation. Zero is never exported to mean "unknown": a zero expiry
timestamp would read as "expired in 1970", not "no data". "No data" is
expressed as series absence combined with `ssl_probe_success == 0`.

That rule presupposes `ssl_probe_success` itself exists, which is only true
after the target's first probe: between startup and the end of the first
cycle a target has *no* series at all, and neither `== 0` alerts nor expiry
rules can see it. Per-target absence therefore needs an anchor that does not
depend on probing — `certel_target_info`, the one series set at
startup from config alone:

```promql
# configured targets with no probe data at all
certel_target_info unless on(address, protocol, servername) ssl_probe_success
```

`absent()` cannot express this question — it has no notion of "for every
configured target" — so without the info metric a never-probed target would be
invisible to alerting. (Alerting on that expression needs a `for:` clause —
see the startup transient in the `certel_target_info` section.)

**Scrape-consistency contract.** The pairing rules above are claims about
what a single scrape can see, so publication must be atomic per scrape.
Updating a separate vec per metric is not: `Gather` locks each metric family
independently, and a scrape interleaving with a delete-then-set publish can
catch a pair the rules declare impossible — a fresh `ssl_probe_success == 1`
beside a still-deleted `ssl_cert_not_after`. The per-target family is
therefore implemented as one snapshot collector: the last `probe.Result` per
target sits in a map under a lock, and every per-target series is derived
from that snapshot inside a single `Collect`, so each scrape sees one
consistent probe per target. Absence then needs no delete calls — a series
is absent because the snapshot derives nothing to emit — and the `cn` churn
rule holds by construction.

## Reference: certificate metrics

The certificate's current state, per target. Labels on all of these: the
per-target identity family above.

### `ssl_cert_not_after` — gauge, extra label `cn`

`NotAfter` of the **leaf** certificate as unix time. Absent when the *last*
probe captured no leaf certificate (`unreachable`, `tls_unavailable`) — a
leaf that fails verification is still exported, so pair with
`ssl_probe_success` for validity. One live series per target (see churn
rule).

*Verdict: keep, frozen.* Leaf expiry is what most imported dashboards graph.

### `ssl_verified_cert_not_after` — gauge

Earliest `NotAfter` within the best **verified** chain, as unix time — an
intermediate can expire before the leaf. Absent when verification failed, so a
stale "last good" value is never exported as if current.

*Verdict: keep, frozen.* The honest expiry: what the alert decision uses when
verification succeeds.

### `certel_cert_expiry_timestamp_seconds` — gauge

The *effective* expiry as unix time: the earliest certificate in the verified
chain, falling back to the earliest in the presented chain when verification
fails (an `insecure` target always takes this path). Absent when no expiry was
observed at all. "Days left" is a query, not a metric:
`certel_cert_expiry_timestamp_seconds - time()`, rendered as days by Grafana's
unit system.

*Verdict: keep, as a timestamp.* Decisions, in order:

- **A metric must exist — the value is not derivable from the `ssl_*` pair.**
  When verification fails the verified series is absent and
  `ssl_cert_not_after` carries only the leaf; the effective expiry may come
  from an earlier intermediate in the presented chain.
- **A timestamp, not a "days/seconds left" gauge.** A remaining-time value is
  frozen at probe time and goes stale for up to a whole `check_interval`; a
  timestamp stays exact at query time via `- time()`. It is also the
  ecosystem-standard shape (blackbox_exporter's
  `probe_ssl_earliest_cert_expiry`), so custom thresholds read familiar:
  `certel_cert_expiry_timestamp_seconds - time() < 14 * 86400`.
- **Threshold agreement.** The alert decision truncates remaining time to
  whole days and fires on `days < warning_days`, which for an integer
  threshold is exactly `remaining < warning_days × 24h` — a graph line at
  `warning_days * 86400` matches the decision precisely (up to probe
  staleness). Pinning that boundary with tests is
  `todo/threshold-boundary-semantics.md`.
- **Days stay where humans read them**: the config thresholds
  (`warning_days`), the webhook payload (`DaysLeft`), and
  `probe_log.days_left`. The database already stores both views —
  `probe_log.not_after` (unix seconds; this metric's value) sits next to
  `probe_log.days_left` — so no schema change rides along.

## Reference: probe metrics

The probe itself, per target: did it succeed, what level it decided, how long
it took. Labels on all of these: the per-target identity family above.

### `ssl_probe_success` — gauge

`1` when the certificate was retrieved and is acceptable *under the target's
policy* — statuses `ok` and `expiring_soon` (expiry pressure is a separate
signal, not a probe failure); `0` for `expired`, `invalid`, `weak_signature`,
`tls_unavailable`, `unreachable`.

"Acceptable" is certel's policy, not a chain-verification claim: an
`insecure` target skips chain-of-trust and hostname verification entirely and
still reports `1` while healthy, and `weak_signature` fails targets whose
handshake ssl_exporter would accept. To assert "1 *and* the chain actually
verified", require `ssl_verified_cert_not_after` to exist for the target — or
join against `certel_target_info{insecure="true"}` to enumerate
targets where verification is skipped by config.

*Verdict: keep, frozen.* The primary alert (`== 0`) and the compat anchor:
the name and shape match ssl_exporter; the acceptance policy is certel's.

### `certel_probe_severity` — gauge

The alerting level the last probe decided: `0` ok, `1` warning, `2` critical,
`3` emergency (an already-failing, trustworthy signal — expired or invalid).

"Probe", not "alert", deliberately: severity is part of the probe result
(literally a `probe.Result` field), exported every cycle whether or not any
alert is in flight — `0` describes a healthy target with no alert at all, and
the value holds steady between deduplicated repeats. The gap is real: a
transition into (or out of) an unreliable status is debounced by
`flap_streak` cycles before it alerts, so the *alerting* state intentionally
lags the probe by design, while this metric keeps reporting what the probe
decided, immediately — a network blip shows here as `severity=2` on the first
failed cycle even though no alert fires until it is confirmed.

And "probe", not "check": in the product "check" means the one-off CLI mode,
and `probe` keeps the per-cycle family under one autocomplete stem —
`certel_probe_severity`, `certel_probe_duration_seconds`, `certel_probe_cycle_*`.

*Verdict: keep, as an ordered enum.* A state-set (`{severity="warning"} 0|1`
per level) is the textbook encoding, but severity is *ordered*, and the
numeric gauge is what makes `> 0`, `== 2`, and fleet-wide `max()` read
naturally, at a third of the series.

The invariant that keeps the numeric encoding correct as the product evolves:
**severity is a strictly ordered escalation ladder, and the scale is
append-only at the top.** The `emergency` tier took the next integer (`3`);
existing values are never renumbered. Anything *unordered* — unknown, muted,
flapping — or anything that does not drive alert policy is its own metric or
an absence rule, never a severity value ("no data" is already expressed as
series absence + `ssl_probe_success == 0`, not as a level). If this invariant
ever has to break — a tier wedged into the middle, a non-ordered member — that
is the moment to migrate to a state-set as a conscious breaking change, not
something to hedge against now.

### `certel_probe_duration_seconds` — gauge

Wall time of the last probe, **including** connection retries and the pauses
between attempts — the whole cost of checking the target, not one handshake.

*Verdict: keep as a last-value gauge, not a histogram.* A histogram earns its
bucket-multiplied series (~14 per target instead of 1) when observations are
frequent relative to the scrape interval; here each target produces one
observation per `check_interval` (minutes), so the scraped gauge *is* the full
sample stream — `quantile_over_time()`/`max_over_time()` reconstruct any
distribution later. The live operator question — "which target is slow or
timing out right now" — is the gauge itself, directly comparable to the
target's `timeout`.

The honest trade-off and the revisit condition: a histogram is cumulative and
survives scrape gaps, while gauge samples missed by a down scraper are gone —
relevant only when scraping is *rarer* than `check_interval`, a broken setup
in its own right. The decision rests on "probes are rare, scrapes are
frequent"; if a future mode probes at second-scale intervals, the ratio flips
and this verdict should be reversed.

## Reference: notification metrics

Delivery health, per notifier.

### `certel_notification_sends_total` — counter, labels `notifier`, `result`

One increment per webhook delivery attempt; `result` is `success` or
`failure`. Counts everything the outbox tries to deliver — problems, repeats,
recoveries. A failed send is not a lost notification: the row stays at the
head of its target's FIFO and is retried every 30s, so a down endpoint
increments `result="failure"` at a steady rate until it recovers — which is
the useful signal (`rate(...{result="failure"}) > 0` sustained = endpoint
down; pair with the backlog gauges below for "and work is piling up").
At-least-once delivery means a duplicate re-send (crash between send and
dequeue) counts twice: the counter measures delivery work done, not distinct
incidents.

Both `result` series are zero-initialized for every configured notifier at
startup, so `rate()` expressions see a series before the first failure rather
than "no data".

Design decisions:

- **One counter with a `result` label, not a pair of metric names.** Total
  attempts is `sum without(result)`, the failure ratio is a plain division, and
  a future third outcome (say, `dropped`) is a new label value rather than a
  third metric name. On a queue that never stops retrying, the counting unit is
  the attempt — not "failures after all retries", which has no meaning here.
- **"Notification", not "alert".** The counting unit is one delivery through
  one channel; one alert may fan out to several notifications on different
  notifiers. Same vocabulary as `notification_outbox`, and the same
  alert/notification split Alertmanager uses
  (`alertmanager_notifications_total`).
- **"Sends" — attempts, not notifications.** One queued notification behind a
  down endpoint produces N failure sends and then one success; counting
  attempts is exactly what makes the failure rate an endpoint-health signal.
- Its question is "is delivery working", not "what was delivered": the
  problem/recovery breakdown is deliberately **not a metric** — it is decided
  at enqueue time and recorded per occurrence in `alert_log`
  (`SELECT status, COUNT(*) FROM alert_log GROUP BY status`); a delivery-time
  kind label would re-smuggle kind-awareness into a queue designed not to
  have it.

## Reference: scheduler metrics

Cycle liveness for the whole probe loop, unlabelled.

### `certel_probe_cycle_*`

Three unlabelled gauges. Two are set at the end of each cycle:
`certel_probe_cycle_completed_timestamp_seconds` (when the last cycle
finished, unix time) and `certel_probe_cycle_duration_seconds` (how long it
took). The third, `certel_probe_cycle_staleness_threshold_seconds`, is a
config-derived constant set once at startup: how stale the completed
timestamp may legally get, computed by the same derivation `/healthz` uses
(`livenessThreshold`: check interval + jitter + probing —
`ceil(targets/concurrency)` waves, each bounded by the slowest legal target,
attempts × timeout plus inter-attempt pauses — plus slack).

`/healthz` already folds cycle staleness in with that threshold — it stays
the orchestrator's signal. The metrics let Prometheus alert rules watch the
same thing without blackbox-probing `/healthz`, and exporting the threshold
beside the timestamp keeps the rule correct as the config evolves — the
`process_open_fds` / `process_max_fds` pattern: export the limit next to the
measurement rather than hardcoding a bound that silently rots when
`check_interval` or the target list changes:

```promql
time() - certel_probe_cycle_completed_timestamp_seconds
  > certel_probe_cycle_staleness_threshold_seconds
```

The duration gauge additionally shows a cycle *trending* toward
`check_interval` long before it overruns. The two per-cycle gauges are
absent until the first cycle completes; a wedged first cycle is caught by
`absent()` or by `/healthz`'s startup grace. The `absent()` rule has the
same startup transient as `certel_target_info`: the registry is in-process,
so every restart empties the gauges until the first cycle legally completes
— the rule needs `for:` longer than the worst legal first cycle (the same
bound `/healthz` uses as startup grace; `for:` takes a fixed duration, so
it cannot read the threshold gauge), or every deploy pages. The threshold
gauge exists from startup and is re-derived on config reload when that
lands (`todo/config-reload.md`).

## Reference: notification queue health

Two gauges expose the delivery queue to Prometheus, labelled `notifier`:

- `certel_notification_outbox_pending` — rows currently queued.
- `certel_notification_outbox_oldest_age_seconds` — age of the oldest queued
  row; `0` when the queue is empty.

The names spell out `notification_outbox` — matching the table they measure —
rather than a bare `outbox`, so the whole delivery subsystem shares one stem:
typing `certel_notification_` in PromQL autocomplete surfaces the sends
counter and both queue gauges together.

Together they distinguish "endpoint briefly hiccuped" (failures tick, backlog
drains) from "endpoint dead / dispatcher stuck" (`oldest_age` climbs
monotonically) — alert on `certel_notification_outbox_oldest_age_seconds >
900`, paired with an `absent()` rule (see failure isolation below) so a
failing collector cannot silently resolve it.

Design notes:

- A custom `prometheus.Collector` queries SQLite at scrape
  time (`SELECT notifier, COUNT(*), MIN(enqueued_at) FROM notification_outbox
  GROUP BY notifier`), emitting `0` for every *configured* notifier with no
  rows. The config list is authoritative in both directions: rows whose
  notifier is not configured (orphans that survived a failed startup drop —
  `DropOrphanedOutbox` only warns on error) are ignored, not minted into
  series nothing selects. One cheap query per scrape, always consistent with
  the table, no event plumbing through Manager/Dispatcher; the
  single-connection store serializes it safely alongside writers.
- Age, not the `_timestamp_seconds` convention, on purpose: a timestamp gauge
  has no honest value for an empty queue — `0` makes `time() - x` fire
  forever, and absence makes "empty" indistinguishable from "scrape broken".
  Age `0` when empty keeps `> bound` alert expressions correct with no
  `or`-vector gymnastics. The value is computed fresh at scrape, so it never
  goes stale.
- Failure isolation: a broken queue must never break the certificate metrics.
  On query error the collector emits nothing and logs — never
  `NewInvalidMetric`, which with default `promhttp.HandlerOpts` fails the
  whole scrape with it. Combined with the empty-queue `0` rule this stays
  unambiguous: `0` = empty, absence on an otherwise-successful scrape =
  collector failed. The query runs under a short context timeout (~1s),
  which *bounds* the damage rather than isolating it: `Gather` waits for
  every collector before responding, so a stalled query still adds up to
  the timeout to the whole scrape's latency — bounded, not hung. And the
  timeout can fire without any wedged database: the store's single
  connection is shared with writers, so an unlucky overlap with a mid-cycle
  write burst can drop the gauges for one scrape on a perfectly healthy
  system. Rare (the contention window is milliseconds), but it means
  emit-nothing is an occasional mode, not only an accident mode.
- The alerting corollary of emit-nothing: a series absent from a successful
  scrape is marked stale immediately, which *resolves* a firing `> bound`
  alert — and the wedged database that empties these gauges is the same
  failure that grows the backlog, so the threshold alert disappears exactly
  when the queue is at its worst. Pair it with
  `absent(certel_notification_outbox_oldest_age_seconds)` so "cannot measure
  the queue" fires as its own signal — with a short `for:` (a couple of
  scrape intervals), since a single-scrape gap can be benign lock contention
  (see the timeout note above).

## Reference: store write health

### `certel_store_write_errors_total`

An unlabelled counter: one increment per failed write to the SQLite store —
alert-state saves, notification enqueues, probe-log records, outbox
delete/fail, prunes. A plain registered counter is exported from startup, so
the series exists at `0` before the first failure and `increase()` needs no
seeding.

The counting lives in the store layer, not at the call sites: every write
method routes its error return through one hook, so the counter is one
increment per failed *logical* write (a multi-statement transaction counts
once) and every write path — including future ones — is covered by
construction. Reads never touch it, which is what keeps "the store cannot
write" distinct from "a query failed". Enumerating call sites instead would
be a standing invitation to miss one: the outbox delete/fail writes, on the
dispatcher's path, were exactly such a gap.

The write path is the one failure mode the rest of this surface cannot see —
worse, the surface looks *healthy* while it fails. A store that stops
accepting writes (`SQLITE_FULL`, a read-only remount, permissions) silently
loses notifications: a failed enqueue is logged and gone — never queued, so
never retried. Nothing downstream notices: `/healthz` stays green (`db.Ping`
is a read), the outbox gauges honestly read empty — inserts are failing, so
the queue *is* empty — and the sends counter stays flat, which is exactly
what healthy targets look like. Host-level disk alerts catch a full disk but
not permissions or a corrupted database file, and certel does not get to
assume the host is monitored.

*Verdict: a tripwire, not a dashboard metric.* The
`alertmanager_notifications_failed_total` /
`prometheus_tsdb_wal_corruptions_total` class: zero for its whole life,
never graphed, one alert —

```promql
increase(certel_store_write_errors_total[15m]) > 0
```

Deliberately no `op` label: which write failed and why is per-occurrence
detail, already in the error log the failing caller emits; one series is
the whole budget. Partial self-healing bounds the blast radius but does not
remove the need: once writes recover, still-standing problems re-alert
within `alert_repeat_interval`, but recoveries lost in the window are gone for
good — the tripwire has to fire promptly, not wait for someone to read
logs.

## Reference: target properties

### `certel_target_info`

An info-style gauge, constant `1` per configured target, carrying the
per-target identity family plus config-derived property labels — initially
just `insecure` (`"true"`/`"false"`). It is set from config alone, before
any probe runs, which gives it two jobs:

**Presence anchor.** Every other per-target series exists only after a
successful cycle reaches the target, so the absence-semantics rule (see
label taxonomy) is blind to a target that has never been probed. This is
the one series whose existence is unconditional, making it the anchor that
turns "configured but no probe data" from invisible into queryable —
something `absent()` cannot do per target:

```promql
# configured targets with no probe data at all
certel_target_info unless on(address, protocol, servername) ssl_probe_success
```

The anchor's startup transient: the registry is in-process, so a restart
clears every probe series while the info series reappears instantly from
config — the expression above is true for *every* target from startup until
the first cycle reaches it. An alert on it needs `for:` longer than the worst
legal first cycle (the same bound `/healthz` derives for its startup grace —
the derivation is spelled out in the scheduler section; `for:` takes a fixed
duration, so unlike the staleness rule it cannot read the exported threshold
gauge); without it, every deploy fires once per target. Closing the window by seeding
probe series at startup instead was considered and rejected — see below.

**Property joins.** The idiomatic home for static facts about a target
(the `node_uname_info` / `*_build_info` pattern): properties join onto any
per-target series at query time instead of widening every metric's label set.

```promql
# healthy targets whose chain was never actually verified
ssl_probe_success == 1 and on(address, protocol, servername)
  certel_target_info{insecure="true"}
```

One series per configured target, set once at startup (and re-synced on
config reload when that lands: removed targets' series deleted, added
targets' created — `todo/config-reload.md`). Future target
properties (a `ca_file` override, the assigned notifier) become new labels
here, not new metrics. All property labels must be config-bounded, so the
series count stays O(targets).

## Reference: build identity

### `certel_build_info`

The standard info gauge, constant `1`, with a single `version` label carrying
the value already injected via `-ldflags "-X main.version=..."` (the same one
`certel version` and `/healthz` report). What it buys: which version runs
where across a fleet, deploy moments visible on any dashboard (`min by
(version) (certel_build_info)` changes exactly at rollout), and the standard
Grafana version panel. Set once at startup; churn-bounded by definition — the
label can only change with the process. No `goversion` label: the registered
Go collector already exports `go_info{version}`.

## Reserved: config reload

When hot reload lands (`todo/config-reload.md`):
`certel_config_reload_total{result="success"|"error"}`. Named here so it lands
under the right prefix and conventions; not designed further until the feature
exists. The series lifecycle on reload — removed targets' per-target series
(including `certel_target_info`) deleted, added targets' info series created,
the sends counter deliberately left in place — is specced in
`todo/config-reload.md` § Stale Prometheus series.

## Considered and rejected

- **`kind` label (problem/recovery) on the sends counter** — see
  `certel_notification_sends_total`: settled as *not a metric*; `alert_log`
  is the breakdown.
- **Probe duration histogram** — see `certel_probe_duration_seconds`: one
  observation per `check_interval` per target makes the scraped gauge the full
  sample stream; buckets would multiply series for nothing.
- **`certel_probes_total` counter** — probing is a constant-rate process by
  construction: the scheduler probes every configured target every cycle, so
  the counter's rate is `targets / check_interval` — knowable from config,
  carrying no signal. What such counters guard elsewhere (silently dropped
  work items) cannot happen here — only the whole cycle can stall, which the
  cycle timestamp gauge and `/healthz` already catch — and success-over-time
  is `avg_over_time(ssl_probe_success[…])`, since scrapes outpace probes.
  The one novel signal a probe-counter family could add — retry churn, a
  target that limps to success on attempt 3 every cycle — lives in
  `probe_log.attempts` and shows up in the duration gauge; revisit only if
  "flaky before dead" becomes an alerting need.
- **`issuer_cn`/`serial_no` labels on `ssl_cert_not_after`** (ssl_exporter
  exports both) — cardinality is not the binding objection: under the
  snapshot collector they would ride the same one-live-series-per-target as
  `cn`. The binding one is that labels earn their place the way metrics do,
  and no alert or panel selects by issuer or serial — *which* issuer, *which*
  serial is per-occurrence detail, the log's home (the same ground on which
  the label rules ban free-form values categorically). `cn` stays because
  imported ssl_exporter dashboards template on it.
- **Delivery duration histogram** — deferred, not designed. Failure rate plus
  backlog age cover endpoint health; revisit only with a concrete question
  they cannot answer.
- **Per-status breakdown** (`certel_probe_status` state-set) — seven series
  per target to re-encode what `ssl_probe_success` + `certel_probe_severity`
  already alert on. The *why* — which status, which error — lives in
  `probe_log`, the process log, and the alert payload itself.
- **Startup prune / orphaned-outbox-drop counters** — one-shot events that
  reset with the process; logged (the orphan drop loudly, at error level).
  Nothing to trend, nothing to alert on beyond the log line.
- **`target_key` (or per-target labels) on delivery counters** — delivery
  failure is a property of the endpoint; a per-target split multiplies series
  while the per-target detail is already in the process log and outbox rows.
- **Outbox attempts counter** — `certel_notification_sends_total` already
  counts attempts, and per-row `attempts_count` is queryable in the table.
- **Seeding per-target series at startup** (from config, `probe_log`, or
  `alert_state`) — to close the restart window where `certel_target_info`
  exists but no probe series do. From config there is nothing honest to
  publish: a synthetic `ssl_probe_success` lies in either direction — `0`
  fires the primary alert on every deploy, `1` vouches for targets nobody has
  probed. The last `probe_log` row per target restores status/severity/expiry
  but not `cn` or the verified-chain expiry — partial series that break this
  document's pairing semantics — and republishes state of unbounded age
  (certel may have been down for days) as current, exactly what the absence
  rules exist to prevent. `alert_state` is the wrong layer entirely: it is
  alert-dedup state, written only on transitions, so an always-healthy target
  has no row at all — it cannot distinguish "never probed" from "probed and
  healthy" — and it intentionally lags the probe by the flap-debounce
  `flap_streak` window. All variants buy back one `for:` clause on an
  auxiliary alert.
