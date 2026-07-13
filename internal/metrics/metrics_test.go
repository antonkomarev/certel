package metrics

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/antonkomarev/certel/internal/config"
	"github.com/antonkomarev/certel/internal/probe"
	"github.com/antonkomarev/certel/internal/store"
)

// fakeOutbox is a stand-in for the store's OutboxStats query in collector tests.
type fakeOutbox struct {
	stats []store.OutboxStat
	err   error
}

func (f *fakeOutbox) OutboxStats(context.Context) ([]store.OutboxStat, error) {
	return f.stats, f.err
}

// testTarget mirrors the fields New reads from config to seed the info series.
func testTarget(address string, mutate ...func(*config.Target)) config.Target {
	t := config.Target{Address: address, Protocol: config.ProtoTLS}
	for _, m := range mutate {
		m(&t)
	}
	return t
}

// newMetrics builds a Metrics over a fresh registry with the given config, a
// no-op outbox, and a discard logger. Extra knobs get their own helper.
func newMetrics(targets ...config.Target) (*Metrics, *prometheus.Registry) {
	return newMetricsWith(&fakeOutbox{}, targets...)
}

func newMetricsWith(outbox OutboxStatser, targets ...config.Target) (*Metrics, *prometheus.Registry) {
	reg := prometheus.NewRegistry()
	cfg := &config.Config{
		Targets:   targets,
		Notifiers: map[string]config.AlertConfig{"default": {}},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(reg, cfg, "1.2.3", 15*time.Minute, outbox, log), reg
}

// okResult is a healthy probe result for the standard example target; mutators
// tailor it per test.
func okResult(mutate ...func(*probe.Result)) probe.Result {
	r := probe.Result{
		Target:   config.Target{Address: "example.com:443", Protocol: config.ProtoTLS},
		Status:   probe.StatusOK,
		Severity: probe.SeverityOK,
	}
	for _, m := range mutate {
		m(&r)
	}
	return r
}

func gather(t *testing.T, reg *prometheus.Registry) map[string]*dto.MetricFamily {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	byName := make(map[string]*dto.MetricFamily, len(mfs))
	for _, mf := range mfs {
		byName[mf.GetName()] = mf
	}
	return byName
}

// seriesValue returns the value of the metric family whose labels match want,
// and whether such a series was published this scrape.
func seriesValue(mf *dto.MetricFamily, want prometheus.Labels) (float64, bool) {
	if mf == nil {
		return 0, false
	}
	for _, met := range mf.GetMetric() {
		labels := map[string]string{}
		for _, l := range met.GetLabel() {
			labels[l.GetName()] = l.GetValue()
		}
		match := true
		for k, v := range want {
			if labels[k] != v {
				match = false
				break
			}
		}
		if match {
			return metricValue(met), true
		}
	}
	return 0, false
}

func metricValue(m *dto.Metric) float64 {
	switch {
	case m.Gauge != nil:
		return m.Gauge.GetValue()
	case m.Counter != nil:
		return m.Counter.GetValue()
	default:
		return 0
	}
}

func labelNames(mf *dto.MetricFamily) []string {
	var names []string
	for _, l := range mf.GetMetric()[0].GetLabel() {
		names = append(names, l.GetName())
	}
	sort.Strings(names)
	return names
}

func labelValue(mf *dto.MetricFamily, name string) string {
	for _, l := range mf.GetMetric()[0].GetLabel() {
		if l.GetName() == name {
			return l.GetValue()
		}
	}
	return ""
}

// targetLabelsFor is the identity label set a probe of addr publishes.
func targetLabelsFor(addr string) prometheus.Labels {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return prometheus.Labels{"host": host, "address": addr, "protocol": "tls", "servername": ""}
}

func TestObserveSuccessAndSeverityPerStatus(t *testing.T) {
	for _, tc := range []struct {
		name         string
		status       probe.Status
		severity     probe.Severity
		wantSuccess  float64
		wantSeverity float64
	}{
		{"ok", probe.StatusOK, probe.SeverityOK, 1, 0},
		{"expiring soon warning", probe.StatusExpiringSoon, probe.SeverityWarning, 1, 1},
		{"expiring soon critical", probe.StatusExpiringSoon, probe.SeverityCritical, 1, 2},
		{"expired", probe.StatusExpired, probe.SeverityEmergency, 0, 3},
		{"invalid", probe.StatusInvalid, probe.SeverityEmergency, 0, 3},
		{"tls unavailable", probe.StatusTLSUnavailable, probe.SeverityCritical, 0, 2},
		{"unreachable", probe.StatusUnreachable, probe.SeverityCritical, 0, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// GIVEN: свежие метрики и результат пробинга с заданным статусом и severity
			m, reg := newMetrics()
			m.Observe(okResult(func(r *probe.Result) {
				r.Status = tc.status
				r.Severity = tc.severity
			}))

			// WHEN: собраны опубликованные семейства
			families := gather(t, reg)
			labels := targetLabelsFor("example.com:443")

			// THEN: ssl_probe_success равен 1 лишь для валидного (в т.ч. истекающего) сертификата, severity кодируется 0/1/2
			if got, ok := seriesValue(families["ssl_probe_success"], labels); !ok || got != tc.wantSuccess {
				t.Errorf("ssl_probe_success = %v (present %v), want %v", got, ok, tc.wantSuccess)
			}
			if got, ok := seriesValue(families["certel_probe_severity"], labels); !ok || got != tc.wantSeverity {
				t.Errorf("certel_probe_severity = %v (present %v), want %v", got, ok, tc.wantSeverity)
			}
		})
	}
}

func TestCompatMetricNamesAndLabels(t *testing.T) {
	// GIVEN: полностью успешный результат с сертификатом и проверенной цепочкой
	m, reg := newMetrics()
	notAfter := time.Unix(1893456000, 0)
	m.Observe(okResult(func(r *probe.Result) {
		r.Cert = &probe.CertInfo{CN: "example.com", NotAfter: notAfter, EarliestNotAfter: notAfter}
		r.VerifiedNotAfter = notAfter
	}))

	// WHEN: собраны опубликованные метрические семейства
	families := gather(t, reg)

	// THEN: имена и наборы меток совместимы с ssl_exporter, идентичность несёт servername — их изменение обязано ломать тест
	for _, want := range []struct {
		name   string
		labels []string
	}{
		{"ssl_probe_success", []string{"address", "host", "protocol", "servername"}},
		{"ssl_cert_not_after", []string{"address", "cn", "host", "protocol", "servername"}},
		{"ssl_verified_cert_not_after", []string{"address", "host", "protocol", "servername"}},
	} {
		mf, ok := families[want.name]
		if !ok {
			t.Errorf("metric %q is missing — ssl_exporter drop-in compatibility broken", want.name)
			continue
		}
		if got := labelNames(mf); !reflect.DeepEqual(got, want.labels) {
			t.Errorf("%s labels = %v, want %v", want.name, got, want.labels)
		}
	}
}

func TestObserveServernameLabel(t *testing.T) {
	// GIVEN: две цели с одинаковыми address+protocol, различающиеся лишь servername
	m, reg := newMetrics()
	m.Observe(okResult(func(r *probe.Result) { r.Target.Servername = "a.internal" }))
	m.Observe(okResult(func(r *probe.Result) { r.Target.Servername = "b.internal" }))

	// WHEN: собрана метрика ssl_probe_success
	mf := gather(t, reg)["ssl_probe_success"]

	// THEN: обе серии сосуществуют, различаясь по метке servername — коллизии идентичности нет
	if got := len(mf.GetMetric()); got != 2 {
		t.Fatalf("ssl_probe_success series = %d, want 2 (servername must disambiguate identity)", got)
	}
	for _, sn := range []string{"a.internal", "b.internal"} {
		labels := prometheus.Labels{"host": "example.com", "address": "example.com:443", "protocol": "tls", "servername": sn}
		if _, ok := seriesValue(mf, labels); !ok {
			t.Errorf("no ssl_probe_success series for servername %q", sn)
		}
	}
}

func TestObserveExpiryTimestamp(t *testing.T) {
	// GIVEN: результат с сертификатом и проверенной цепочкой, срок проверенной цепочки истекает раньше листа
	m, reg := newMetrics()
	leafExpiry := time.Unix(1893456000, 0)
	verifiedExpiry := time.Unix(1800000000, 0)
	m.Observe(okResult(func(r *probe.Result) {
		r.Cert = &probe.CertInfo{CN: "example.com", NotAfter: leafExpiry, EarliestNotAfter: leafExpiry}
		r.VerifiedNotAfter = verifiedExpiry
	}))

	// WHEN: собраны семейства
	families := gather(t, reg)
	labels := targetLabelsFor("example.com:443")

	// THEN: лист экспортирует unix-время (с меткой cn), проверенная цепочка — своё, а эффективный срок равен проверенному
	leaf := prometheus.Labels{"host": "example.com", "address": "example.com:443", "protocol": "tls", "servername": "", "cn": "example.com"}
	if got, ok := seriesValue(families["ssl_cert_not_after"], leaf); !ok || got != float64(leafExpiry.Unix()) {
		t.Errorf("ssl_cert_not_after = %v (present %v), want %v", got, ok, leafExpiry.Unix())
	}
	if got, ok := seriesValue(families["ssl_verified_cert_not_after"], labels); !ok || got != float64(verifiedExpiry.Unix()) {
		t.Errorf("ssl_verified_cert_not_after = %v (present %v), want %v", got, ok, verifiedExpiry.Unix())
	}
	if got, ok := seriesValue(families["certel_cert_expiry_timestamp_seconds"], labels); !ok || got != float64(verifiedExpiry.Unix()) {
		t.Errorf("certel_cert_expiry_timestamp_seconds = %v (present %v), want %v", got, ok, verifiedExpiry.Unix())
	}
}

func TestObserveWithoutCertOmitsCertMetrics(t *testing.T) {
	// GIVEN: недостижимая цель — сертификат не получен, цепочка не проверена
	m, reg := newMetrics()
	m.Observe(okResult(func(r *probe.Result) {
		r.Status = probe.StatusUnreachable
		r.Severity = probe.SeverityCritical
		r.Cert = nil
		r.VerifiedNotAfter = time.Time{}
	}))

	// WHEN: собраны опубликованные семейства
	families := gather(t, reg)

	// THEN: сертификатные и expiry-метрики не публикуются, а ssl_probe_success равен нулю
	if _, ok := families["ssl_cert_not_after"]; ok {
		t.Error("ssl_cert_not_after must not be published when no certificate was retrieved")
	}
	if _, ok := families["ssl_verified_cert_not_after"]; ok {
		t.Error("ssl_verified_cert_not_after must not be published when verification failed")
	}
	if _, ok := families["certel_cert_expiry_timestamp_seconds"]; ok {
		t.Error("certel_cert_expiry_timestamp_seconds must be absent when no expiry was observed")
	}
	if got, ok := seriesValue(families["ssl_probe_success"], targetLabelsFor("example.com:443")); !ok || got != 0 {
		t.Errorf("ssl_probe_success = %v (present %v), want 0 for an unreachable target", got, ok)
	}
}

func TestObserveRotatedCNKeepsSingleSeries(t *testing.T) {
	// GIVEN: одна цель, сертификат которой при ротации сменил CN с "a" на "b"
	m, reg := newMetrics()
	first := time.Unix(1800000000, 0)
	second := time.Unix(1893456000, 0)
	m.Observe(okResult(func(r *probe.Result) {
		r.Cert = &probe.CertInfo{CN: "a.example.com", NotAfter: first, EarliestNotAfter: first}
	}))

	// WHEN: следующий пробинг той же цели наблюдает уже новый CN
	m.Observe(okResult(func(r *probe.Result) {
		r.Cert = &probe.CertInfo{CN: "b.example.com", NotAfter: second, EarliestNotAfter: second}
	}))

	// THEN: устаревшая серия cn="a" не публикуется — снимок отдаёт ровно одну живую серию с актуальным значением
	mf := gather(t, reg)["ssl_cert_not_after"]
	if got := len(mf.GetMetric()); got != 1 {
		t.Fatalf("ssl_cert_not_after series = %d, want 1 (stale cn must not be emitted after rotation)", got)
	}
	if got := labelValue(mf, "cn"); got != "b.example.com" {
		t.Errorf("surviving series cn = %q, want %q", got, "b.example.com")
	}
	leaf := prometheus.Labels{"host": "example.com", "address": "example.com:443", "protocol": "tls", "servername": "", "cn": "b.example.com"}
	if got, ok := seriesValue(mf, leaf); !ok || got != float64(second.Unix()) {
		t.Errorf("ssl_cert_not_after = %v (present %v), want %v", got, ok, second.Unix())
	}
}

func TestObserveClearsVerifiedWhenVerificationLost(t *testing.T) {
	// GIVEN: цель, чья цепочка ранее успешно проверялась
	m, reg := newMetrics()
	verified := time.Unix(1893456000, 0)
	m.Observe(okResult(func(r *probe.Result) {
		r.Cert = &probe.CertInfo{CN: "example.com", NotAfter: verified, EarliestNotAfter: verified}
		r.VerifiedNotAfter = verified
	}))

	// WHEN: проверка перестала проходить (VerifiedNotAfter обнулился)
	m.Observe(okResult(func(r *probe.Result) {
		r.Status = probe.StatusInvalid
		r.Severity = probe.SeverityCritical
		r.Cert = &probe.CertInfo{CN: "example.com", NotAfter: verified, EarliestNotAfter: verified}
		r.VerifiedNotAfter = time.Time{}
	}))

	// THEN: серия проверенного срока не публикуется, а не заморожена на последнем «здоровом» значении
	if _, ok := gather(t, reg)["ssl_verified_cert_not_after"]; ok {
		t.Error("ssl_verified_cert_not_after must be absent once the chain no longer verifies")
	}
}

func TestObserveDropsExpiryWhenNoExpiry(t *testing.T) {
	// GIVEN: цель, для которой ранее наблюдался живой срок (expiry опубликован)
	m, reg := newMetrics()
	expiry := time.Unix(1893456000, 0)
	m.Observe(okResult(func(r *probe.Result) {
		r.Cert = &probe.CertInfo{CN: "example.com", NotAfter: expiry, EarliestNotAfter: expiry}
		r.VerifiedNotAfter = expiry
	}))
	if _, ok := gather(t, reg)["certel_cert_expiry_timestamp_seconds"]; !ok {
		t.Fatal("precondition: certel_cert_expiry_timestamp_seconds should be published for a certificate-bearing result")
	}

	// WHEN: следующий пробинг недостижим — срока истечения нет
	m.Observe(okResult(func(r *probe.Result) {
		r.Status = probe.StatusUnreachable
		r.Severity = probe.SeverityCritical
		r.Cert = nil
		r.VerifiedNotAfter = time.Time{}
	}))

	// THEN: серия expiry исчезает — отсутствие честнее, чем неоднозначный 0 («истёк в 1970» vs «нет данных»)
	if _, ok := gather(t, reg)["certel_cert_expiry_timestamp_seconds"]; ok {
		t.Error("certel_cert_expiry_timestamp_seconds must be absent when no expiry was observed, not exported as 0")
	}
}

func TestObserveHostLabelSplit(t *testing.T) {
	for _, tc := range []struct {
		name     string
		address  string
		wantHost string
	}{
		{"ipv6 splits host from port", "[2001:db8::1]:443", "2001:db8::1"},
		{"ipv4 splits host from port", "192.0.2.1:443", "192.0.2.1"},
		{"address without port falls back whole", "example.com", "example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// GIVEN: результат пробинга для адреса с портом (или без него)
			m, reg := newMetrics()
			m.Observe(okResult(func(r *probe.Result) { r.Target.Address = tc.address }))

			// WHEN: собрана метрика ssl_probe_success
			mf := gather(t, reg)["ssl_probe_success"]

			// THEN: метка host содержит адрес без порта, а метка address — исходный адрес целиком
			if got := labelValue(mf, "host"); got != tc.wantHost {
				t.Errorf("host label = %q, want %q", got, tc.wantHost)
			}
			if got := labelValue(mf, "address"); got != tc.address {
				t.Errorf("address label = %q, want %q", got, tc.address)
			}
		})
	}
}

func TestNotificationSendsCounter(t *testing.T) {
	// GIVEN: метрики, где нотификатор default zero-инициализирован
	m, reg := newMetrics()

	// WHEN: две доставки на default прошли, одна на default провалилась
	m.ObserveAlert("default", nil)
	m.ObserveAlert("default", nil)
	m.ObserveAlert("default", errors.New("webhook unreachable"))

	// THEN: один счётчик с метками notifier+result считает попытки доставки
	mf := gather(t, reg)["certel_notification_sends_total"]
	success := prometheus.Labels{"notifier": "default", "result": "success"}
	failure := prometheus.Labels{"notifier": "default", "result": "failure"}
	if got, ok := seriesValue(mf, success); !ok || got != 2 {
		t.Errorf("sends success = %v (present %v), want 2", got, ok)
	}
	if got, ok := seriesValue(mf, failure); !ok || got != 1 {
		t.Errorf("sends failure = %v (present %v), want 1", got, ok)
	}
}

func TestNotificationSendsZeroInit(t *testing.T) {
	// GIVEN: метрики с настроенным нотификатором, но без единой доставки
	_, reg := newMetrics()

	// WHEN/THEN: обе result-серии присутствуют на нуле, чтобы rate() видел серию до первого сбоя
	mf := gather(t, reg)["certel_notification_sends_total"]
	for _, result := range []string{"success", "failure"} {
		labels := prometheus.Labels{"notifier": "default", "result": result}
		if got, ok := seriesValue(mf, labels); !ok || got != 0 {
			t.Errorf("sends %s = %v (present %v), want a zero-initialised series", result, got, ok)
		}
	}
}

func TestTargetInfoPresenceAnchor(t *testing.T) {
	// GIVEN: две настроенные цели с разными servername и insecure — пробингов ещё не было
	m, reg := newMetrics(
		testTarget("a.example.com:443", func(t *config.Target) { t.Servername = "sni.a" }),
		testTarget("b.example.com:443", func(t *config.Target) { t.Insecure = true }),
	)
	_ = m

	// WHEN: собрана метрика certel_target_info
	mf := gather(t, reg)["certel_target_info"]

	// THEN: каждая цель имеет константную серию 1 с идентичностью и свойством insecure — до всякого пробинга
	if got := len(mf.GetMetric()); got != 2 {
		t.Fatalf("certel_target_info series = %d, want 2 (one per configured target)", got)
	}
	a := prometheus.Labels{"host": "a.example.com", "address": "a.example.com:443", "protocol": "tls", "servername": "sni.a", "insecure": "false"}
	if got, ok := seriesValue(mf, a); !ok || got != 1 {
		t.Errorf("certel_target_info{a} = %v (present %v), want 1", got, ok)
	}
	b := prometheus.Labels{"host": "b.example.com", "address": "b.example.com:443", "protocol": "tls", "servername": "", "insecure": "true"}
	if got, ok := seriesValue(mf, b); !ok || got != 1 {
		t.Errorf("certel_target_info{b} = %v (present %v), want 1", got, ok)
	}
}

func TestBuildInfo(t *testing.T) {
	// GIVEN/WHEN: метрики созданы с версией сборки
	_, reg := newMetrics()

	// THEN: certel_build_info экспортирует константную 1 с меткой version
	mf := gather(t, reg)["certel_build_info"]
	if got, ok := seriesValue(mf, prometheus.Labels{"version": "1.2.3"}); !ok || got != 1 {
		t.Errorf("certel_build_info{version=1.2.3} = %v (present %v), want 1", got, ok)
	}
}

func TestStoreWriteErrorsTripwire(t *testing.T) {
	// GIVEN: свежие метрики — счётчик экспортируется на нуле от регистрации
	m, reg := newMetrics()
	if got, ok := seriesValue(gather(t, reg)["certel_store_write_errors_total"], nil); !ok || got != 0 {
		t.Fatalf("certel_store_write_errors_total = %v (present %v), want 0 at registration", got, ok)
	}

	// WHEN: две записи в стор провалились
	m.ObserveStoreWriteError()
	m.ObserveStoreWriteError()

	// THEN: счётчик считает каждый провал
	if got, ok := seriesValue(gather(t, reg)["certel_store_write_errors_total"], nil); !ok || got != 2 {
		t.Errorf("certel_store_write_errors_total = %v (present %v), want 2", got, ok)
	}
}

func TestCycleGaugesAbsentUntilFirstCycle(t *testing.T) {
	// GIVEN: метрики до первого завершённого цикла
	m, reg := newMetrics()

	// WHEN: собраны семейства
	families := gather(t, reg)

	// THEN: порог staleness присутствует от старта, а два per-cycle гейджа отсутствуют
	if got, ok := seriesValue(families["certel_probe_cycle_staleness_threshold_seconds"], nil); !ok || got != (15*time.Minute).Seconds() {
		t.Errorf("staleness threshold = %v (present %v), want %v", got, ok, (15 * time.Minute).Seconds())
	}
	if _, ok := families["certel_probe_cycle_completed_timestamp_seconds"]; ok {
		t.Error("certel_probe_cycle_completed_timestamp_seconds must be absent before the first cycle")
	}
	if _, ok := families["certel_probe_cycle_duration_seconds"]; ok {
		t.Error("certel_probe_cycle_duration_seconds must be absent before the first cycle")
	}

	// WHEN: цикл завершился
	completed := time.Unix(1800000000, 0)
	m.ObserveCycle(completed, 3*time.Second)

	// THEN: обе per-cycle серии публикуются
	families = gather(t, reg)
	if got, ok := seriesValue(families["certel_probe_cycle_completed_timestamp_seconds"], nil); !ok || got != float64(completed.Unix()) {
		t.Errorf("cycle completed = %v (present %v), want %v", got, ok, completed.Unix())
	}
	if got, ok := seriesValue(families["certel_probe_cycle_duration_seconds"], nil); !ok || got != 3 {
		t.Errorf("cycle duration = %v (present %v), want 3", got, ok)
	}
}

func TestOutboxCollectorEmptyAndPopulated(t *testing.T) {
	// GIVEN: очередь с двумя рядами для default, старейший — минуту назад
	oldest := time.Now().Add(-90 * time.Second)
	outbox := &fakeOutbox{stats: []store.OutboxStat{
		{Notifier: "default", Pending: 2, OldestEnqueuedAt: oldest},
	}}
	_, reg := newMetricsWith(outbox, testTarget("example.com:443"))

	// WHEN: собраны семейства
	families := gather(t, reg)

	// THEN: pending отражает счётчик, oldest_age — возраст старейшего ряда
	if got, ok := seriesValue(families["certel_notification_outbox_pending"], prometheus.Labels{"notifier": "default"}); !ok || got != 2 {
		t.Errorf("outbox pending = %v (present %v), want 2", got, ok)
	}
	if got, ok := seriesValue(families["certel_notification_outbox_oldest_age_seconds"], prometheus.Labels{"notifier": "default"}); !ok || got < 80 {
		t.Errorf("outbox oldest age = %v (present %v), want ~90", got, ok)
	}
}

func TestOutboxCollectorZeroForEmptyNotifier(t *testing.T) {
	// GIVEN: настроенный нотификатор default без единого ряда в очереди
	_, reg := newMetricsWith(&fakeOutbox{}, testTarget("example.com:443"))

	// WHEN/THEN: обе серии присутствуют на нуле — 0 значит «пусто», отсутствие значило бы «сбой сбора»
	families := gather(t, reg)
	if got, ok := seriesValue(families["certel_notification_outbox_pending"], prometheus.Labels{"notifier": "default"}); !ok || got != 0 {
		t.Errorf("outbox pending = %v (present %v), want 0 for an empty queue", got, ok)
	}
	if got, ok := seriesValue(families["certel_notification_outbox_oldest_age_seconds"], prometheus.Labels{"notifier": "default"}); !ok || got != 0 {
		t.Errorf("outbox oldest age = %v (present %v), want 0 for an empty queue", got, ok)
	}
}

func TestOutboxCollectorEmitsNothingOnError(t *testing.T) {
	// GIVEN: сбор очереди возвращает ошибку (лок, таймаут)
	_, reg := newMetricsWith(&fakeOutbox{err: errors.New("db locked")}, testTarget("example.com:443"))

	// WHEN: собраны семейства — скрейп в целом успешен
	families := gather(t, reg)

	// THEN: очередные серии отсутствуют (не NewInvalidMetric, который свалил бы весь скрейп);
	// отсутствие при успешном скрейпе = сбой сбора, а не пустая очередь
	if _, ok := families["certel_notification_outbox_pending"]; ok {
		t.Error("certel_notification_outbox_pending must be absent when the query fails")
	}
	if _, ok := families["certel_notification_outbox_oldest_age_seconds"]; ok {
		t.Error("certel_notification_outbox_oldest_age_seconds must be absent when the query fails")
	}
}
