package alert

import (
	"context"
	"sort"
	"sync"
)

// fakeStore is an in-memory stand-in for store.Store implementing both the
// enqueue side (Store) and the queue side (OutboxStore). Rows drain in id
// order per key, mirroring the real per-target FIFO.
type fakeStore struct {
	mu       sync.Mutex
	states   map[string]StateRecord
	events   []AlertEvent
	enqueued []string // every enqueued body, append-only (survives delivery)
	outbox   []*queuedRow
	nextID   int64
	// probeHistory is the per-target probe log, newest first, seeded by tests
	// that exercise the flap-debounce restart rebuild.
	probeHistory map[string][]ProbeObservation
}

type queuedRow struct {
	row      OutboxRow
	notifier string
	attempts int
	lastErr  string
}

func newFakeStore() *fakeStore {
	return &fakeStore{states: map[string]StateRecord{}}
}

func (f *fakeStore) SaveAlertState(key string, st StateRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.states[key] = st
	return nil
}

// RecentProbeStatuses returns the seeded probe history for a target, newest
// first, capped at limit — the fake stand-in for store.Store's probe_log read.
func (f *fakeStore) RecentProbeStatuses(key string, limit int) ([]ProbeObservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	hist := f.probeHistory[key]
	if len(hist) > limit {
		hist = hist[:limit]
	}
	return append([]ProbeObservation(nil), hist...), nil
}

// seedProbeHistory records a target's probe outcomes newest-first, so a
// reconstructed Manager can rebuild its debounce counter from them.
func (f *fakeStore) seedProbeHistory(key string, obs ...ProbeObservation) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.probeHistory == nil {
		f.probeHistory = map[string][]ProbeObservation{}
	}
	f.probeHistory[key] = append([]ProbeObservation(nil), obs...)
}

func (f *fakeStore) Enqueue(st StateRecord, ev AlertEvent, deliveries []Delivery) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.states[ev.TargetKey] = st
	for _, d := range deliveries {
		f.events = append(f.events, ev)
		b := append([]byte(nil), d.Body...)
		f.enqueued = append(f.enqueued, string(b))
		f.nextID++
		f.outbox = append(f.outbox, &queuedRow{
			row:      OutboxRow{ID: f.nextID, TargetKey: ev.TargetKey, Body: b},
			notifier: d.Notifier,
		})
	}
	return nil
}

// seed appends a delivery directly, for dispatcher tests that don't need the
// Manager's decision logic.
func (f *fakeStore) seed(key, body string) {
	f.seedN(key, "", body)
}

// seedN is seed with an explicit notifier, for the notifier-scoped view.
func (f *fakeStore) seedN(key, notifier, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	f.outbox = append(f.outbox, &queuedRow{
		row:      OutboxRow{ID: f.nextID, TargetKey: key, Body: []byte(body)},
		notifier: notifier,
	})
}

// forNotifier returns an OutboxStore view scoped to one notifier, mirroring
// store.Store.ForNotifier so a Dispatcher drains only its own notifier's rows.
func (f *fakeStore) forNotifier(notifier string) OutboxStore {
	return &fakeOutbox{store: f, notifier: notifier}
}

type fakeOutbox struct {
	store    *fakeStore
	notifier string
}

func (o *fakeOutbox) PendingKeys() ([]string, error) {
	o.store.mu.Lock()
	defer o.store.mu.Unlock()
	seen := map[string]bool{}
	var keys []string
	for _, q := range o.store.outbox {
		if q.notifier != o.notifier || seen[q.row.TargetKey] {
			continue
		}
		seen[q.row.TargetKey] = true
		keys = append(keys, q.row.TargetKey)
	}
	sort.Strings(keys)
	return keys, nil
}

func (o *fakeOutbox) NextPending(key string) (*OutboxRow, error) {
	o.store.mu.Lock()
	defer o.store.mu.Unlock()
	for _, q := range o.store.outbox { // append order == id order
		if q.notifier == o.notifier && q.row.TargetKey == key {
			r := q.row
			return &r, nil
		}
	}
	return nil, nil
}

func (o *fakeOutbox) DeleteOutbox(id int64) error { return o.store.DeleteOutbox(id) }

func (o *fakeOutbox) FailOutbox(id int64, errMsg string) error {
	return o.store.FailOutbox(id, errMsg)
}

func (f *fakeStore) PendingKeys() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	seen := map[string]bool{}
	var keys []string
	for _, q := range f.outbox {
		if !seen[q.row.TargetKey] {
			seen[q.row.TargetKey] = true
			keys = append(keys, q.row.TargetKey)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

func (f *fakeStore) NextPending(key string) (*OutboxRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, q := range f.outbox { // append order == id order
		if q.row.TargetKey == key {
			r := q.row
			return &r, nil
		}
	}
	return nil, nil
}

func (f *fakeStore) DeleteOutbox(id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, q := range f.outbox {
		if q.row.ID == id {
			f.outbox = append(f.outbox[:i], f.outbox[i+1:]...)
			return nil
		}
	}
	return nil
}

func (f *fakeStore) FailOutbox(id int64, errMsg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, q := range f.outbox {
		if q.row.ID == id {
			q.attempts++
			q.lastErr = errMsg
			return nil
		}
	}
	return nil
}

func (f *fakeStore) pending() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.outbox)
}

// bodies returns every body handed to Enqueue, in order, regardless of whether
// it was later delivered — the record of what the Manager decided to send.
func (f *fakeStore) bodies() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.enqueued...)
}

// bodiesForNotifier returns the bodies queued for one notifier, in enqueue
// order — the per-channel view a fan-out test asserts on. Rows are never drained
// in a Manager-only test, so the outbox holds the full history.
func (f *fakeStore) bodiesForNotifier(notifier string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, q := range f.outbox {
		if q.notifier == notifier {
			out = append(out, string(q.row.Body))
		}
	}
	return out
}

// fakeSender records delivered bodies and can be told to fail a number of
// upcoming sends, or every send matching a specific body.
type fakeSender struct {
	mu       sync.Mutex
	bodies   []string
	err      error
	failNext int
	failBody map[string]int
}

func (f *fakeSender) Send(_ context.Context, body []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := string(body)
	if f.failBody != nil && f.failBody[s] > 0 {
		f.failBody[s]--
		return context.DeadlineExceeded
	}
	if f.failNext > 0 {
		f.failNext--
		return context.DeadlineExceeded
	}
	if f.err != nil {
		return f.err
	}
	f.bodies = append(f.bodies, s)
	return nil
}

func (f *fakeSender) delivered() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.bodies...)
}
