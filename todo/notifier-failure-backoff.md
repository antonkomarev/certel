# Per-notifier failure backoff — stop retrying a dead endpoint every 30s forever

**Where:** `internal/alert/dispatcher.go` — the hardcoded `retryInterval = 30 * time.Second` (top of file) and `drainTarget`'s `FailOutbox(row.ID, err) → return` path; `internal/store/store.go` — `FailOutbox` (bumps `attempts_count`, records `last_error`, never deletes) and `NextPending` (orders by `id`, no filter on attempts or last-failure time); `internal/config/config.go` (`AlertConfig`) if the tick/backoff become configurable.

**Problem.** Delivery to a down notifier is already well-bounded and is *not* a DDoS risk — three independent throttles cover the burst case:

- per-notifier `concurrency` cap (default 10) limits parallel `Send`s;
- one failing target = exactly one `Send` per drain pass (`drainTarget` returns on first error, does not loop-hammer);
- persistent problems re-enqueue only every `repeat_interval` (default 24h), so the queue does not grow each probe cycle.

Peak load on a downed endpoint is ~`concurrency × (retries+1)` requests over a few seconds, then a trickle of one pass per 30s tick.

What is missing is **graceful degradation for a *long* outage**. There is no circuit breaker, no per-row backoff, no max-attempts, and no dead-letter:

- A target pointed at a permanently-dead notifier keeps its outbox row queued and retried every 30s **indefinitely**, with `attempts_count` growing unbounded. Harmless load-wise, but the queue never self-clears until the endpoint recovers or the notifier is removed from config (which triggers `DropOrphanedOutbox`).
- The 30s tick is flat regardless of how long the endpoint has been down. An endpoint that has failed 500 times in a row is polled just as eagerly as one that failed once — no adaptive back-pressure.

So: today's behaviour is safe, but a dead notifier produces a permanent low-grade background of doomed requests and an ever-growing `attempts_count`, rather than backing off and eventually parking the work.

**Concept to settle (not yet decided):**

1. **Per-row exponential backoff.** Use `attempts_count` (already persisted) to compute a next-eligible time: `NextPending` filters out rows whose `last_attempt_at + backoff(attempts)` is still in the future, so a repeatedly-failing row stretches from 30s → minutes → an hour cap. Needs a `last_attempt_at` column (or reuse an existing timestamp) — confirm the schema.
2. **Circuit breaker per notifier.** After N consecutive failures on a notifier, open the breaker: skip the endpoint entirely and probe it with a single canary on a slow cadence until a 2xx closes it again. Cheaper than per-row math and models "the whole endpoint is down" more honestly than "this row is unlucky."
3. **Max-attempts / dead-letter (optional).** Decide whether a row should ever be parked (moved to a dead-letter state / metric) after M attempts, or whether reminders should retry forever until the endpoint or config changes. Ties into the same "abandoned host" fatigue question raised in `severity-policy/severity-aware-repeat-cadence.md` (cap/fatigue guard).
4. **Make the tick configurable, or leave it derived.** If (1) lands, the flat `retryInterval` becomes the *floor* of the backoff curve; expose min/max as notifier config or keep sane hardcoded bounds.
5. **Observability.** Expose per-notifier consecutive-failure count / breaker state as a metric so a silently-dead notifier is visible without reading the outbox table.

**Fix sketch (if we go with (2), the cheaper option):**

1. Track consecutive-failure count and an "open-until" time per notifier in the `Dispatcher` (in-memory is fine; it re-derives from the queue on restart).
2. In `dispatchOnce`/`drainTarget`, if the breaker is open and not yet due for a canary, skip the pass early (no `Send`).
3. On a successful `Send`, reset the count and close the breaker; on failure, increment and, past the threshold, open with an exponentially-growing open window (cap ~1h).
4. Emit the breaker state as a gauge and log open/close transitions.

**No rush — hardening, not a bug.** Nothing misfires or floods today; this is about a permanently-dead notifier degrading to "park and canary" instead of "retry forever every 30s."
