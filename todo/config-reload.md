# No config reload — adding a host requires a restart

**Where:** `cmd/certel/main.go` (config is loaded once and captured by the
`/healthz` closure, the prune goroutine, and the `Notify` fan-out),
`internal/scheduler/scheduler.go` (holds `*config.Config` for its lifetime and
builds its ticker once), `internal/alert/manager.go` (holds the notifier
runtime map, read lock-free in `Process`).

**Problem.** Any config change — adding a host, tweaking a threshold —
requires restarting the process. Thanks to the persisted alert state a restart
is *safe* (no duplicate alerts, no lost recoveries), so this is a
quality-of-life gap rather than a correctness one. It will likely be the
first feature request after going public.

**Trigger.** Reload on SIGHUP (the conventional trigger for this kind of
daemon; a file watcher can come later). SIGINT/SIGTERM already drive shutdown
via `signal.NotifyContext`; add a separate `signal.Notify` channel for SIGHUP
with its own goroutine.

## The invariant that makes this safe: validate everything, then swap

A reload must be **all-or-nothing**. Build and validate the *entire* new world
off to the side; only once every fallible step has succeeded do you swap.
If any step fails, log it and keep running unchanged — a bad reload must never
half-apply and never kill the process. Concretely, before touching any live
state:

1. `config.Load` the file (parse + `applyDefaults` + `Validate`).
2. `buildRuntimes` — re-parses every template and **test-renders** it
   (`alert.ParseTemplate` already does the test render, so a broken template is
   caught here, not at the first alert).
3. Build every sender (`alert.NewWebhookSender`) — this is fallible too: a
   `ca_file` that is missing or unreadable fails *here*, so senders must be
   built during validation, not lazily after the swap.

Only if 1–3 all succeed do the mutations below run. This is the part the
naive "load then mutate step by step" ordering gets wrong: `NewWebhookSender`
failing after the config pointer was already swapped leaves a torn runtime.

## Restart-only fields — actively guarded, not just documented

`server.listen` and `database.path` are restart-only (rebinding the listener
and reopening the store mid-flight isn't worth the complexity). But it is not
enough to *document* that — `config.Load` will happily load a file that changes
them, and then the cfg getter reports the new value while the live listener and
DB handle still use the old one (silent divergence; e.g. `/healthz` and the
prune loop would read a `database.path` nothing is actually writing to).

So the reload must **compare old vs new** for these fields and, if they differ,
log a `WARN` that the change is ignored until restart and keep the old value in
the swapped-in config (don't let the new string leak into the getter). Rejecting
the whole reload is the stricter alternative; warn-and-ignore is friendlier for
the common case of editing an unrelated field in the same file.

## What is hot-swappable, and how each is picked up

Everything reads the live config through one `atomic.Pointer[config.Config]`
(getter `func() *config.Config`); the swap is the single `Store` at the end.
Two derived structures swap alongside it and need their own atomic handoff:
the Manager's **runtime map** (parsed templates) and the **dispatcher set**.

- **Targets (add/remove/edit), thresholds, `probe.concurrency`, `probe.jitter`**
  — the scheduler's `cycle` must **load the pointer once into a local at the top
  of the cycle** and use that snapshot throughout, so a mid-cycle swap cannot
  tear the concurrency/jitter/targets reads against each other. Picked up on the
  next cycle. "Between cycles" is thus approximate and fine: a cycle already in
  flight finishes on its old snapshot.

- **`probe.check_interval`** — **the one that needs explicit help.**
  `scheduler.Run` builds its `time.NewTicker` once (scheduler.go:46) and never
  rebuilds it, so a changed interval is silently ignored. On reload the
  scheduler must reset the ticker when the interval changes (e.g. `Run` selects
  on a `reload` channel / re-reads the interval each iteration and calls
  `ticker.Reset`). Without this, "tweak the interval" appears to reload but does
  nothing until restart — a confusing half-feature.

- **Liveness threshold** — `livenessThreshold(cfg)` is computed once and
  captured by the `/healthz` closure as `liveness` (main.go:251). Adding slow
  targets or raising timeouts legitimately lengthens a cycle; against a stale,
  smaller threshold `/healthz` would false-flap to unhealthy. Recompute it on
  reload and have the closure read it via the same atomic indirection (or store
  it in an `atomic.Pointer`/`atomic.Int64`).

- **Retention (`database.*_retention`)** — the hourly prune goroutine must read
  these through the getter, not a captured `cfg`, so a changed retention takes
  effect on the next prune tick.

- **Notifiers (add/remove/edit) and delivery policy** — see the two sections
  below; this is the fiddly part.

## Swapping the Manager's notifier runtimes (data race)

`Manager.Process` reads `m.notifiers[notifier]` **without holding `m.mu`**
(manager.go:147), and `Process` runs concurrently across targets within a
cycle. Replacing that map on reload is therefore a data race. Give the Manager
an atomic swap for its runtime map (e.g. `atomic.Pointer[map[string]NotifierRuntime]`
or a setter that takes `m.mu`) and have `Process` load it once per call.

## Dispatcher lifecycle (double-drain hazard)

Today every dispatcher runs under the single global `ctx` and is joined via
`dispDone` only at shutdown. Reload can't reuse that: to replace a notifier's
dispatcher you must **cancel the old one and fully join its goroutine before
starting the replacement**. Two dispatchers over the same notifier-scoped
outbox view would drain it concurrently — double-sends and a broken per-target
FIFO. So each dispatcher needs its own child context + a joinable handle, and
reload does, per notifier:

- **added** → build sender + dispatcher, start its goroutine.
- **removed** → cancel + join its goroutine; then drop it. Its queued rows are
  now orphaned (nobody drains them) — see below.
- **changed** (url/headers/template/timeout/retries/concurrency/ca_file/…) →
  cancel + join, then rebuild and restart. Simplest correct policy is
  "rebuild every dispatcher whose `AlertConfig` changed"; unchanged ones keep
  running so a healthy notifier's in-flight retries aren't disturbed.

An in-flight send on a dispatcher being torn down is safe: cancelling leaves the
row queued (at-least-once), and the replacement re-drains it. That is exactly
why the join-before-start ordering matters — the two must not overlap.

Also: `Manager.Notify` is a closure over the `dispatchers` map (main.go:233).
After a rebuild it must resolve to the *new* set (swap the map under a lock, or
have the closure read an atomic pointer), or wakeups fan out to dead
dispatchers.

## Pruning removed hosts and orphaned queues

- **Alert state (in-memory).** Startup pruning runs on the loaded `states` map
  *before* `Restore`; a live reload can't reuse that path because the state is
  already inside the Manager. Add a `Manager.Prune(valid map[string]bool)` that
  deletes removed target keys from `m.states` under `m.mu`. Then call
  `db.PruneAlertStates(valid)` (log-on-error, like startup) so a re-add later
  starts clean.

- **Orphaned outbox (missing from the naive sketch).** A removed *or renamed*
  notifier's dispatcher is now stopped, so its still-queued rows have no drainer
  and would sit forever. Run `db.DropOrphanedOutbox(validNotifiers)` on reload,
  exactly as startup does (main.go:201) — its bodies were frozen against the old
  template, so dropping is the safe choice (a still-present problem re-alerts
  within `repeat_interval`; a dropped recovery is genuinely lost, same tradeoff
  as startup).

## Alert-state identity under edits (intended, worth stating)

`Target.Key()` is `protocol//address/servername` — it excludes `notifier` and
all thresholds. Two consequences to keep in mind (both are the desired
behavior, but surprising if unstated):

- **Editing a target's `notifier` or `warning_days`/`critical_days`** keeps the
  same key, so the target inherits its existing dedup state and `lastAlertAt`.
  A notifier switch therefore does **not** re-alert immediately on the new
  notifier. (Old queued rows drain on the old notifier's dispatcher; the
  dispatcher doc already notes the two aren't FIFO-ordered against each other.)
- **Editing `address`/`protocol`/`servername`** changes the key, so it's a
  remove + add: old state pruned, old metric series deleted, new target starts
  clean.

## Stale Prometheus series

For a removed (or key-changed) target, delete its series so a dashboard doesn't
show a frozen last value forever. That's six per-target `GaugeVec`s
(`ssl_probe_success`, `ssl_cert_not_after`, `ssl_verified_cert_not_after`,
`certel_cert_expiry_timestamp_seconds`, `certel_probe_severity`,
`certel_probe_duration_seconds` — designed names per docs/metrics.md; the code
still carries the pre-redesign ones) plus the planned `certel_target_info`, a
seventh per-target family — `DeletePartialMatch` on the
`{host,address,protocol,servername}` identity subset covers all of them,
including `ssl_cert_not_after`'s extra `cn` label and `target_info`'s property
labels. `certel_target_info` needs the write side too: an *added* target must
get its info series at reload — "set once at startup" becomes "at startup and
on every reload". The per-notifier
`certel_notification_sends_total` counter for a removed notifier is best
**left in place** — deleting a monotonic counter is a lie to downstream
rate() queries; document that its series persist until restart. The planned
`certel_notification_outbox_*` gauges need no reload cleanup at all: the
scrape-time collector emits series only for currently configured notifiers.

## Serialization

The SIGHUP handler must serialize reloads (coalesce a burst; never run two
concurrently) and must not race shutdown — once `ctx` is cancelled, ignore
further SIGHUPs.

## Order of operations (once validation in steps 1–3 has passed)

1. Guard restart-only fields (warn + keep old values).
2. Atomically swap: config pointer, Manager runtime map, recomputed liveness.
3. Reconcile dispatchers (join removed/changed, start added/rebuilt); repoint
   `Notify`.
4. `Manager.Prune` + `db.PruneAlertStates` for removed targets.
5. `db.DropOrphanedOutbox` for removed/renamed notifiers.
6. Delete stale per-target metric series.
7. Reset the scheduler ticker if `check_interval` changed.
8. Log a one-line summary (targets before/after, notifiers added/removed,
   ignored restart-only fields).

**Docs.** Until implemented, add a README note that config changes need a
restart, that restarts are safe by design, and (once implemented) that
`server.listen` and `database.path` remain restart-only.
