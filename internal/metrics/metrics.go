// Package metrics exposes everything certel monitor publishes on /metrics. The
// certificate metric names (ssl_*) are drop-in compatible with
// ribbybibby/ssl_exporter so existing dashboards and alert rules keep working;
// everything else lives under the certel_* prefix. The full design — naming
// policy, label taxonomy, absence semantics — is in docs/metrics.md.
package metrics

import (
	"context"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/antonkomarev/certel/internal/config"
	"github.com/antonkomarev/certel/internal/probe"
	"github.com/antonkomarev/certel/internal/store"
)

// targetLabels are the frozen identity labels on every per-target metric. The
// "host" label is the hostname part of the address (ssl_exporter compatibility);
// "servername" is the raw config value so the set is injective with the store's
// target_key. Deliberately NOT the target key itself — see docs/metrics.md.
var targetLabels = []string{"host", "address", "protocol", "servername"}

// targetInfoLabels are the identity family plus the config-derived property
// labels that ride certel_target_info instead of widening the measurement
// metrics.
var targetInfoLabels = []string{"host", "address", "protocol", "servername", "insecure"}

// Per-target descriptors, all derived from one snapshot in a single Collect so
// publication is atomic per scrape (see the scrape-consistency contract).
var (
	probeSuccessDesc = prometheus.NewDesc("ssl_probe_success",
		"1 if the certificate was retrieved and is acceptable under the target's policy, 0 otherwise (ssl_exporter compatible).",
		targetLabels, nil)
	certNotAfterDesc = prometheus.NewDesc("ssl_cert_not_after",
		"NotAfter of the leaf certificate as unix time (ssl_exporter compatible).",
		[]string{"host", "address", "protocol", "servername", "cn"}, nil)
	verifiedNotAfterDesc = prometheus.NewDesc("ssl_verified_cert_not_after",
		"Earliest NotAfter within the best verified chain as unix time (ssl_exporter compatible).",
		targetLabels, nil)
	expiryDesc = prometheus.NewDesc("certel_cert_expiry_timestamp_seconds",
		"Effective certificate expiry the alert decision uses, as unix time.",
		targetLabels, nil)
	severityDesc = prometheus.NewDesc("certel_probe_severity",
		"Alerting level the last probe decided: 0 ok, 1 warning, 2 critical, 3 emergency.",
		targetLabels, nil)
	durationDesc = prometheus.NewDesc("certel_probe_duration_seconds",
		"Duration of the last probe including retries.",
		targetLabels, nil)
)

// OutboxStatser supplies the delivery-queue depth the outbox collector reads at
// scrape time. Implemented by *store.Store.
type OutboxStatser interface {
	OutboxStats(ctx context.Context) ([]store.OutboxStat, error)
}

// Metrics owns every certel-published collector and the entry points the rest
// of the monitor calls to feed them.
type Metrics struct {
	snap        *snapshotCollector
	targetInfo  *prometheus.GaugeVec
	buildInfo   *prometheus.GaugeVec
	sends       *prometheus.CounterVec
	storeErrors prometheus.Counter
	cycle       *cycleCollector
}

// New registers every collector on reg and seeds the config-derived series that
// exist before any probe runs: certel_target_info (one per target),
// certel_build_info, and the zero-initialised send counters. version is the
// running build; cycleStaleness is the same liveness bound /healthz derives, and
// outbox is queried at scrape time for the queue gauges.
func New(reg prometheus.Registerer, cfg *config.Config, version string, cycleStaleness time.Duration, outbox OutboxStatser, log *slog.Logger) *Metrics {
	m := &Metrics{
		snap: newSnapshotCollector(),
		targetInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "certel_target_info",
			Help: "Constant 1 per configured target; presence anchor carrying identity and property labels.",
		}, targetInfoLabels),
		buildInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "certel_build_info",
			Help: "Constant 1; the running certel version as a label.",
		}, []string{"version"}),
		sends: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "certel_notification_sends_total",
			Help: "Webhook delivery attempts, by notifier and result (success or failure).",
		}, []string{"notifier", "result"}),
		storeErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "certel_store_write_errors_total",
			Help: "Failed writes to the SQLite store (alert state, outbox, logs).",
		}),
		cycle: &cycleCollector{staleness: cycleStaleness.Seconds()},
	}
	ob := &outboxCollector{
		querier:   outbox,
		notifiers: sortedNotifiers(cfg.Notifiers),
		log:       log,
		pendingDesc: prometheus.NewDesc("certel_notification_outbox_pending",
			"Deliveries currently queued for a notifier.",
			[]string{"notifier"}, nil),
		oldestDesc: prometheus.NewDesc("certel_notification_outbox_oldest_age_seconds",
			"Age of the oldest queued delivery for a notifier, in seconds; 0 when the queue is empty.",
			[]string{"notifier"}, nil),
	}
	reg.MustRegister(m.snap, m.targetInfo, m.buildInfo, m.sends, m.storeErrors, m.cycle, ob)

	// Series that come from config alone, published once at startup.
	m.buildInfo.WithLabelValues(version).Set(1)
	for _, t := range cfg.Targets {
		m.targetInfo.With(prometheus.Labels{
			"host":       hostOf(t.Address),
			"address":    t.Address,
			"protocol":   string(t.Protocol),
			"servername": t.Servername,
			"insecure":   strconv.FormatBool(t.Insecure),
		}).Set(1)
	}
	// Zero-init both result series per notifier so rate() sees a series before
	// the first failure rather than "no data".
	for name := range cfg.Notifiers {
		m.sends.WithLabelValues(name, "success").Add(0)
		m.sends.WithLabelValues(name, "failure").Add(0)
	}
	return m
}

// Observe records the outcome of one probe, replacing that target's snapshot.
// Every per-target series is re-derived from the snapshot at scrape time.
func (m *Metrics) Observe(r probe.Result) { m.snap.observe(r) }

// ObserveAlert records one webhook delivery attempt for a notifier, wired to
// Dispatcher.OnSent. A non-nil err counts as result="failure", otherwise
// "success".
func (m *Metrics) ObserveAlert(notifier string, err error) {
	result := "success"
	if err != nil {
		result = "failure"
	}
	m.sends.WithLabelValues(notifier, result).Inc()
}

// ObserveCycle records that a probe cycle finished at completedAt taking d,
// wired to Scheduler.OnCycle.
func (m *Metrics) ObserveCycle(completedAt time.Time, d time.Duration) {
	m.cycle.observe(completedAt, d)
}

// ObserveStoreWriteError increments the store-write tripwire, wired to every
// failed SQLite write (alert state, enqueue, probe log, prune).
func (m *Metrics) ObserveStoreWriteError() { m.storeErrors.Inc() }

// snapshotCollector holds the last probe.Result per target and derives every
// per-target series from it inside a single Collect, so each scrape sees one
// consistent probe per target and absence needs no delete calls.
type snapshotCollector struct {
	mu   sync.Mutex
	last map[string]probe.Result
}

func newSnapshotCollector() *snapshotCollector {
	return &snapshotCollector{last: map[string]probe.Result{}}
}

func (c *snapshotCollector) observe(r probe.Result) {
	c.mu.Lock()
	c.last[r.Target.Key()] = r
	c.mu.Unlock()
}

func (c *snapshotCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- probeSuccessDesc
	ch <- certNotAfterDesc
	ch <- verifiedNotAfterDesc
	ch <- expiryDesc
	ch <- severityDesc
	ch <- durationDesc
}

func (c *snapshotCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	results := make([]probe.Result, 0, len(c.last))
	for _, r := range c.last {
		results = append(results, r)
	}
	c.mu.Unlock()

	for _, r := range results {
		lv := []string{hostOf(r.Target.Address), r.Target.Address, string(r.Target.Protocol), r.Target.Servername}

		// Success mirrors ssl_exporter: the certificate was retrieved and is
		// acceptable under the target's policy. Expiring-soon still counts as
		// success — expiry pressure is a separate signal (severity, expiry
		// timestamp), not a probe failure.
		success := 0.0
		if r.Status == probe.StatusOK || r.Status == probe.StatusExpiringSoon {
			success = 1
		}
		ch <- prometheus.MustNewConstMetric(probeSuccessDesc, prometheus.GaugeValue, success, lv...)
		ch <- prometheus.MustNewConstMetric(severityDesc, prometheus.GaugeValue, severityValue(r.Severity), lv...)
		ch <- prometheus.MustNewConstMetric(durationDesc, prometheus.GaugeValue, r.Duration.Seconds(), lv...)

		// Absent when no expiry was observed — a zero timestamp would read as
		// "expired in 1970", not "no data".
		if exp := r.EffectiveNotAfter(); !exp.IsZero() {
			ch <- prometheus.MustNewConstMetric(expiryDesc, prometheus.GaugeValue, float64(exp.Unix()), lv...)
		}
		// Absent when verification failed, so a stale "last good" value is never
		// exported as if current.
		if !r.VerifiedNotAfter.IsZero() {
			ch <- prometheus.MustNewConstMetric(verifiedNotAfterDesc, prometheus.GaugeValue, float64(r.VerifiedNotAfter.Unix()), lv...)
		}
		// Only the current leaf's cn is emitted, so a rotated-away CN simply
		// stops being published — exactly one live cn series per target.
		if r.Cert != nil {
			ch <- prometheus.MustNewConstMetric(certNotAfterDesc, prometheus.GaugeValue,
				float64(r.Cert.NotAfter.Unix()), hostOf(r.Target.Address), r.Target.Address,
				string(r.Target.Protocol), r.Target.Servername, r.Cert.CN)
		}
	}
}

// Cycle descriptors: two per-cycle gauges plus the config-derived staleness
// bound.
var (
	cycleCompletedDesc = prometheus.NewDesc("certel_probe_cycle_completed_timestamp_seconds",
		"When the last probe cycle finished, as unix time.", nil, nil)
	cycleDurationDesc = prometheus.NewDesc("certel_probe_cycle_duration_seconds",
		"Wall time of the last probe cycle.", nil, nil)
	cycleStalenessDesc = prometheus.NewDesc("certel_probe_cycle_staleness_threshold_seconds",
		"How stale the completed-cycle timestamp may legally get (the /healthz liveness threshold).", nil, nil)
)

// cycleCollector exports the scheduler cycle gauges. The staleness threshold is
// a startup constant and always present; the completed/duration pair is absent
// until the first cycle finishes, so a wedged first cycle is caught by absent().
type cycleCollector struct {
	staleness float64

	mu          sync.Mutex
	completedAt time.Time
	duration    time.Duration
	have        bool
}

func (c *cycleCollector) observe(at time.Time, d time.Duration) {
	c.mu.Lock()
	c.completedAt, c.duration, c.have = at, d, true
	c.mu.Unlock()
}

func (c *cycleCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- cycleCompletedDesc
	ch <- cycleDurationDesc
	ch <- cycleStalenessDesc
}

func (c *cycleCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(cycleStalenessDesc, prometheus.GaugeValue, c.staleness)
	c.mu.Lock()
	have, at, d := c.have, c.completedAt, c.duration
	c.mu.Unlock()
	if have {
		ch <- prometheus.MustNewConstMetric(cycleCompletedDesc, prometheus.GaugeValue, float64(at.Unix()))
		ch <- prometheus.MustNewConstMetric(cycleDurationDesc, prometheus.GaugeValue, d.Seconds())
	}
}

// outboxCollector queries the delivery queue at scrape time and emits one
// pending/oldest-age pair per configured notifier. It emits 0 for a notifier
// with no rows and, on query error, emits nothing (never NewInvalidMetric,
// which would fail the whole scrape) — so absence on an otherwise-successful
// scrape means the collector failed, while 0 means an empty queue.
type outboxCollector struct {
	querier     OutboxStatser
	notifiers   []string
	log         *slog.Logger
	pendingDesc *prometheus.Desc
	oldestDesc  *prometheus.Desc
}

func (c *outboxCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.pendingDesc
	ch <- c.oldestDesc
}

func (c *outboxCollector) Collect(ch chan<- prometheus.Metric) {
	// A short timeout bounds the damage: Gather waits for every collector, so a
	// stalled query adds at most this to scrape latency rather than hanging it.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stats, err := c.querier.OutboxStats(ctx)
	if err != nil {
		c.log.Error("outbox metrics query failed", "err", err)
		return
	}
	byNotifier := make(map[string]store.OutboxStat, len(stats))
	for _, st := range stats {
		byNotifier[st.Notifier] = st
	}
	// The config list is authoritative: orphan rows for a notifier no longer
	// configured are ignored, not minted into series nothing selects.
	now := time.Now()
	for _, n := range c.notifiers {
		st := byNotifier[n]
		ch <- prometheus.MustNewConstMetric(c.pendingDesc, prometheus.GaugeValue, float64(st.Pending), n)
		age := 0.0
		if !st.OldestEnqueuedAt.IsZero() {
			if s := now.Sub(st.OldestEnqueuedAt).Seconds(); s > 0 {
				age = s
			}
		}
		ch <- prometheus.MustNewConstMetric(c.oldestDesc, prometheus.GaugeValue, age, n)
	}
}

// hostOf returns the hostname part of a host:port address, falling back to the
// whole string when it carries no port.
func hostOf(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}

func sortedNotifiers(notifiers map[string]config.AlertConfig) []string {
	names := make([]string, 0, len(notifiers))
	for name := range notifiers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func severityValue(s probe.Severity) float64 {
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
