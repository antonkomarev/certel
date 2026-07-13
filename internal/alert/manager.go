// Package alert decides when a probe result warrants a webhook notification
// and hands it to the outbox for delivery.
package alert

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/antonkomarev/certel/internal/config"
	"github.com/antonkomarev/certel/internal/probe"
)

// StateRecord is the persisted per-target alert state: what makes deduplication
// and the repeat-interval timer survive a restart. It is deliberately just the
// dedup inputs — the "a notification is owed" obligation lives in the outbox,
// not here.
type StateRecord struct {
	Status      probe.Status
	Severity    probe.Severity
	LastAlertAt time.Time
}

// AlertEvent is one alert occurrence on a target at the moment it is decided
// (enqueued), independent of whether — or how many times — delivery is later
// attempted. It carries the per-target facts shared by every fanned-out
// delivery; the per-channel status/severity live on each Delivery.
type AlertEvent struct {
	TargetKey string
	Address   string
	At        time.Time
}

// Delivery is one fanned-out notice for a single notifier: the rendered body and
// the status/severity that notifier saw (its clamped view — equal to the real
// pair for a problem it carries, ok for a recovery below its floor). One decision
// produces one Delivery per attached notifier that fires.
type Delivery struct {
	Notifier string
	Status   probe.Status
	Severity probe.Severity
	Body     []byte
}

// OutboxRow is one queued delivery drained by the Dispatcher. The row is
// kind-agnostic: whether it is a problem or recovery notice lives only in the
// frozen body — the queue just delivers bytes. Query alert_log for the
// problem/recovery breakdown.
type OutboxRow struct {
	ID        int64
	TargetKey string
	Body      []byte
}

// ProbeObservation is one past probe outcome, as recorded in the probe log. It
// is all the flap debounce needs to rebuild its consecutive-bad-cycle counter
// across a restart, without any new persisted state of its own.
type ProbeObservation struct {
	Status   probe.Status
	Severity probe.Severity
}

// Store persists alert state and queues deliveries. Implemented by
// store.Store; nil disables persistence (tests without a queue).
type Store interface {
	// SaveAlertState upserts dedup/timer state without queuing a delivery —
	// used when a transition changes state but warrants no notification (e.g.
	// a recovery while recovery notices are disabled).
	SaveAlertState(targetKey string, st StateRecord) error
	// Enqueue atomically upserts dedup state once and, for each fanned-out
	// delivery, records the alert event and queues its rendered body against that
	// notifier — all in one transaction so a crash can never persist "already
	// alerted" without the matching pending deliveries.
	Enqueue(st StateRecord, ev AlertEvent, deliveries []Delivery) error
	// RecentProbeStatuses returns up to limit of a target's most recent probe
	// outcomes, newest first. The flap debounce reads it once at Restore to
	// rebuild its in-memory confirmation counter from the durable probe log,
	// so a restart mid-confirmation does not re-count from zero.
	RecentProbeStatuses(targetKey string, limit int) ([]ProbeObservation, error)
}

// unreliableStatus reports whether a status is network-shaped — a blip and a
// dead service look identical to the prober — and therefore subject to the
// confirmation debounce. Fact statuses (expired, invalid, weak_signature,
// expiring_soon, ok) come from a successfully retrieved certificate and are
// never debounced.
func unreliableStatus(s probe.Status) bool {
	return s == probe.StatusUnreachable || s == probe.StatusTLSUnavailable
}

// severityRank orders the severity ladder for the delivery-floor clamp: ok
// below every alerting level, then warning < critical < emergency. An unknown
// value ranks as ok (0), so a mis-set floor carries nothing rather than
// everything.
func severityRank(s probe.Severity) int {
	switch s {
	case probe.SeverityWarning:
		return 1
	case probe.SeverityCritical:
		return 2
	case probe.SeverityEmergency:
		return 3
	default:
		return 0
	}
}

// clampView returns the (severity, status) a channel with the given floor sees:
// the real pair when the real severity meets the floor, otherwise ok/ok — a
// severity below the floor, and its status, read as healthy. The clamp is a pure
// function of the per-target state, so no per-channel row is ever persisted.
func clampView(sev probe.Severity, status probe.Status, floor probe.Severity) (probe.Severity, probe.Status) {
	if severityRank(sev) >= severityRank(floor) {
		return sev, status
	}
	return probe.SeverityOK, probe.StatusOK
}

// notifierFloor reads a notifier's configured min_severity as a severity floor,
// defaulting an unset value to warning (carry every alert) so a runtime built
// outside the config loader still behaves.
func notifierFloor(minSeverity string) probe.Severity {
	if minSeverity == "" {
		return probe.SeverityWarning
	}
	return probe.Severity(minSeverity)
}

// NotifierRuntime pairs a notifier's config with its compiled body. Built once
// at startup and handed to the Manager keyed by notifier name.
type NotifierRuntime struct {
	Config config.AlertConfig
	Body   *Body
}

// Manager tracks per-target alert state so a persistent problem alerts on the
// transition into the bad state (plus periodic repeats), not on every check,
// and a fixed problem produces a recovery notice. Delivery is the Dispatcher's
// job: Manager only decides and enqueues.
type Manager struct {
	notifiers map[string]NotifierRuntime
	store     Store
	log       *slog.Logger
	now       func() time.Time

	mu     sync.Mutex
	states map[string]*targetState

	// Notify, when non-nil, is called with the notifier name after a delivery is
	// enqueued so that notifier's dispatcher can drain promptly instead of
	// waiting for its retry tick.
	Notify func(notifier string)
}

type targetState struct {
	severity    probe.Severity
	status      probe.Status
	lastAlertAt time.Time

	// Flap-debounce bookkeeping, in-memory only (rebuilt from the probe log on
	// Restore). While a transition into or out of an unreliable status is being
	// confirmed, the fields above hold the *old*, confirmed state and these hold
	// the tentative observation and how many consecutive cycles have shown it.
	pendingSeverity probe.Severity
	pendingStatus   probe.Status
	pendingCount    int
}

// NewManager builds the decision engine over a per-notifier runtime map. One
// per-target decision runs on the real severity; each attached notifier's
// send_recovery flag, min_severity floor and body template are read from its
// runtime, so notifiers deliver independently off that single decision.
func NewManager(notifiers map[string]NotifierRuntime, st Store, log *slog.Logger) *Manager {
	return &Manager{
		notifiers: notifiers, store: st, log: log,
		now:    time.Now,
		states: map[string]*targetState{},
	}
}

// Restore seeds the in-memory state from persisted records. Call once before
// the first Process: a target that was already alerting keeps its repeat timer
// instead of re-alerting. Notices owed but not yet delivered live in the
// outbox, so they are re-sent by the dispatcher, not reconstructed here.
//
// The flap-debounce confirmation counter is rebuilt from the probe log rather
// than persisted: for each target it replays the trailing run of identical
// unreliable observations, so a restart mid-confirmation resumes the count
// instead of re-counting from zero. targets supplies the per-target
// flap_streak threshold (and the full target list, since a target flapping
// but not yet alerting has no alert_state row to restore from).
func (m *Manager) Restore(states map[string]StateRecord, targets []config.Target) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for targetKey, r := range states {
		m.states[targetKey] = &targetState{
			severity: r.Severity, status: r.Status, lastAlertAt: r.LastAlertAt,
		}
	}
	if m.store == nil {
		return
	}
	for _, t := range targets {
		n := 1
		if t.FlapStreak != nil {
			n = *t.FlapStreak
		}
		if n <= 1 {
			continue // debounce disabled: no counter to rebuild
		}
		key := t.Key()
		st := m.states[key]
		if st == nil {
			// No alert_state row: the target's confirmed state is healthy, but it
			// may still have an unconfirmed unreliable streak in the probe log.
			st = &targetState{severity: probe.SeverityOK, status: probe.StatusOK}
		}
		obs, err := m.store.RecentProbeStatuses(key, n)
		if err != nil {
			m.log.Error("flap-debounce restore: probe log read failed", "target_key", key, "err", err)
			continue
		}
		if pendStatus, pendSeverity, count, ok := reconstructPending(st.severity, st.status, obs, n); ok {
			st.pendingStatus, st.pendingSeverity, st.pendingCount = pendStatus, pendSeverity, count
			m.states[key] = st
		}
	}
}

// reconstructPending rebuilds the debounce counter from the newest-first probe
// history. It returns a pending candidate only when the most recent observation
// is an unconfirmed transition touching an unreliable status (relative to the
// confirmed severity/status); the count is the trailing run of identical such
// observations, capped at n-1 so Restore never leaves an already-confirmed
// state — the next matching live cycle is what tips it over and alerts.
func reconstructPending(confSeverity probe.Severity, confStatus probe.Status, obs []ProbeObservation, n int) (probe.Status, probe.Severity, int, bool) {
	if len(obs) == 0 {
		return "", "", 0, false
	}
	newest := obs[0]
	changing := newest.Status != confStatus || newest.Severity != confSeverity
	touchesUnreliable := unreliableStatus(newest.Status) || unreliableStatus(confStatus)
	if !changing || !touchesUnreliable {
		return "", "", 0, false
	}
	count := 0
	for _, o := range obs {
		if o.Status != newest.Status || o.Severity != newest.Severity {
			break
		}
		count++
	}
	if count > n-1 {
		count = n - 1
	}
	return newest.Status, newest.Severity, count, true
}

func stateKey(t config.Target) string { return t.Key() }

// persistState writes one target's dedup state through to the store, logging
// rather than failing: a broken database must not stop alert decisioning.
func (m *Manager) persistState(targetKey string, st targetState) {
	if m.store == nil {
		return
	}
	rec := StateRecord{Status: st.status, Severity: st.severity, LastAlertAt: st.lastAlertAt}
	if err := m.store.SaveAlertState(targetKey, rec); err != nil {
		m.log.Error("alert state persist failed", "target_key", targetKey, "err", err)
	}
}

// Process examines one probe result and enqueues an alert or recovery notice
// if warranted. It is called sequentially per target but may run concurrently
// across targets.
func (m *Manager) Process(_ context.Context, r probe.Result) {
	targetKey := stateKey(r.Target)
	now := m.now()

	// The target fans out to one or more notifiers, resolved by config. Each
	// notifier's floor/recovery policy and template are applied below; the
	// per-target decision (repeat cadence included) is notifier-independent. A
	// target with no notifiers means a misconfiguration slipped past validation,
	// so log and skip rather than panic.
	notifiers := r.Target.Notifiers
	if len(notifiers) == 0 {
		m.log.Error("alert skipped: target has no notifiers", "target", r.Target.Address)
		return
	}

	m.mu.Lock()
	st, known := m.states[targetKey]
	if !known {
		st = &targetState{severity: probe.SeverityOK, status: probe.StatusOK}
		m.states[targetKey] = st
	}
	prevSeverity, prevStatus := st.severity, st.status

	// Flap debounce: a transition into — or out of — an unreliable status
	// (unreachable, tls_unavailable) is only trusted after `flap_streak`
	// consecutive cycles agree, because a network blip and a dead service look
	// identical to the prober. Until then the confirmed state (prevSeverity/
	// prevStatus) is left untouched, so a crash mid-confirmation neither alerts
	// early nor records the tentative problem as known. Fact statuses are never
	// unreliable, so a real expiry/invalidity still alerts on first observation.
	n := 1
	if r.Target.FlapStreak != nil {
		n = *r.Target.FlapStreak
	}
	changing := r.Status != prevStatus || r.Severity != prevSeverity
	if n > 1 && changing && (unreliableStatus(r.Status) || unreliableStatus(prevStatus)) {
		if st.pendingCount > 0 && st.pendingStatus == r.Status && st.pendingSeverity == r.Severity {
			st.pendingCount++
		} else {
			st.pendingStatus, st.pendingSeverity, st.pendingCount = r.Status, r.Severity, 1
		}
		if st.pendingCount < n {
			// Not yet confirmed: hold the old state, enqueue nothing, persist
			// nothing. The probe log already recorded this cycle for metrics and
			// for the restart rebuild.
			m.mu.Unlock()
			return
		}
		// Confirmed: adopt the observation and decide as usual below.
		st.pendingCount = 0
	} else {
		// A trusted reading — a reliable status, or no change at all — abandons
		// any half-built debounce candidate.
		st.pendingCount = 0
	}

	// One per-target decision on the real, unclamped severity drives the shared
	// state: the repeat timer (on the real severity, per §3) and whether this
	// cycle is a fresh/changed problem or a due reminder. lastAlertAt is the
	// target's single reminder clock — reset whenever the target's problem alerts,
	// independent of which channels carry it.
	bad := r.Severity != probe.SeverityOK
	wasBad := prevSeverity != probe.SeverityOK
	shapeChange := bad && (!wasBad || r.Status != prevStatus || r.Severity != prevSeverity)
	repeatDue := bad && now.Sub(st.lastAlertAt) >= r.Target.AlertRepeatInterval.For(string(r.Severity))
	targetProblemFired := shapeChange || repeatDue

	st.severity, st.status = r.Severity, r.Status
	if targetProblemFired {
		// The repeat timer starts at enqueue: a durable queue guarantees the
		// alert will be delivered at least once, so we need not wait for the
		// send to confirm before counting the interval.
		st.lastAlertAt = now
	}
	stateChanged := st.severity != prevSeverity || st.status != prevStatus || targetProblemFired
	snapshot := *st
	m.mu.Unlock()

	rec := StateRecord{Status: snapshot.status, Severity: snapshot.severity, LastAlertAt: snapshot.lastAlertAt}

	// Fan out: for each attached notifier, run the same transition switch on its
	// clamped (prev, cur) view. A channel fires a new/changed problem or a
	// recovery exactly when its clamped view does; a repeat is the shared
	// per-target timer (repeatDue). The body is rendered on the clamped view, so a
	// channel never sees a severity below its floor — a drop beneath the floor is
	// delivered as a recovery.
	ev := AlertEvent{TargetKey: targetKey, Address: r.Target.Address, At: now}
	var deliveries []Delivery
	var fired []string
	for _, name := range notifiers {
		rt, ok := m.notifiers[name]
		if !ok {
			// Validation guarantees resolution; a miss means a misconfiguration
			// slipped through. Skip this channel rather than fail the others.
			m.log.Error("alert skipped: target references unknown notifier",
				"target", r.Target.Address, "notifier", name)
			continue
		}
		floor := notifierFloor(rt.Config.MinSeverity)
		cPrevSev, cPrevStatus := clampView(prevSeverity, prevStatus, floor)
		cCurSev, cCurStatus := clampView(r.Severity, r.Status, floor)
		cbad := cCurSev != probe.SeverityOK
		cwasBad := cPrevSev != probe.SeverityOK

		var send, recovered bool
		switch {
		case cbad && (!cwasBad || cCurStatus != cPrevStatus || cCurSev != cPrevSev):
			// New problem for this channel, or one that changed shape — including
			// crossing the floor upward, which is a severity change and so fires
			// immediately, never gated by the repeat timer.
			send = true
		case cbad && repeatDue:
			// Same problem still above this channel's floor: the shared reminder.
			send = true
		case !cbad && cwasBad && rt.Config.SendRecoveryEnabled():
			// The problem this channel tracked cleared (fully, or dropped below its
			// floor): a per-channel recovery, if the channel opted in.
			send, recovered = true, true
		}
		if !send {
			continue
		}

		cr := r
		cr.Severity, cr.Status = cCurSev, cCurStatus
		body, err := rt.Body.Render(NewPayload(cr, recovered))
		if err != nil {
			// Body was sample-rendered at startup; a failure here means data-
			// dependent breakage worth surfacing loudly. Skip this channel; the
			// per-target state is still persisted below so dedup does not loop.
			m.log.Error("alert body render failed",
				"target", r.Target.Address, "notifier", name, "err", err)
			continue
		}
		deliveries = append(deliveries, Delivery{
			Notifier: name, Status: cCurStatus, Severity: cCurSev, Body: body,
		})
		fired = append(fired, name)
		m.log.Info("alert enqueued", "target", r.Target.Address, "notifier", name,
			"status", cCurStatus, "severity", cCurSev, "recovered", recovered)
	}

	if len(deliveries) == 0 {
		// No channel fired (all floored above the current severity, or a render
		// failed): still persist the per-target state so dedup and the timer move.
		if stateChanged {
			m.persistState(targetKey, snapshot)
		}
		return
	}

	if m.store != nil {
		if err := m.store.Enqueue(rec, ev, deliveries); err != nil {
			// State update and the queued deliveries share one commit, so a failure
			// leaves all undone: the next cycle re-evaluates and re-enqueues.
			// Nothing is silently marked "already alerted".
			m.log.Error("alert enqueue failed", "target", r.Target.Address, "err", err)
			return
		}
	}
	if m.Notify != nil {
		for _, name := range fired {
			m.Notify(name)
		}
	}
}
