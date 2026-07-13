package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/antonkomarev/certel/internal/config"
	"github.com/antonkomarev/certel/internal/probe"
)

// fakeChecker records every Check call and, when block is non-nil, holds each
// probe in flight until the channel is closed (or the context is cancelled) so
// tests can observe concurrency deterministically.
type fakeChecker struct {
	mu          sync.Mutex
	started     []config.Target
	startTimes  []time.Time
	inFlight    int
	maxInFlight int

	block  chan struct{}      // held probes wait here; nil means return at once
	starts chan config.Target // if non-nil, receives each target as its probe begins
}

func (f *fakeChecker) Check(ctx context.Context, h config.Target) probe.Result {
	f.mu.Lock()
	f.started = append(f.started, h)
	f.startTimes = append(f.startTimes, time.Now())
	f.inFlight++
	if f.inFlight > f.maxInFlight {
		f.maxInFlight = f.inFlight
	}
	f.mu.Unlock()

	if f.starts != nil {
		f.starts <- h
	}
	if f.block != nil {
		select {
		case <-ctx.Done():
		case <-f.block:
		}
	}

	f.mu.Lock()
	f.inFlight--
	f.mu.Unlock()
	return probe.Result{Target: h, Status: probe.StatusOK, Severity: probe.SeverityOK}
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func testConfig(concurrency int, jitter time.Duration, hosts ...config.Target) *config.Config {
	return &config.Config{
		Probe: config.ProbeConfig{
			CheckInterval: config.Duration(time.Hour),
			Concurrency:   concurrency,
			Jitter:        config.Duration(jitter),
		},
		Targets: hosts,
	}
}

func target(addr string) config.Target {
	return config.Target{Address: addr, Protocol: config.ProtoTLS}
}

func manyTargets(n int) []config.Target {
	hs := make([]config.Target, n)
	for i := range hs {
		hs[i] = target(fmt.Sprintf("host-%d:443", i))
	}
	return hs
}

func addrCounts(hs []config.Target) map[string]int {
	m := map[string]int{}
	for _, h := range hs {
		m[h.Address]++
	}
	return m
}

func TestCycleRespectsConcurrencyCap(t *testing.T) {
	// GIVEN: восемь целей и пул, допускающий только два одновременных пробинга
	fc := &fakeChecker{block: make(chan struct{}), starts: make(chan config.Target, 8)}
	s := New(testConfig(2, 0, manyTargets(8)...), fc, func(context.Context, probe.Result) {}, discardLogger())

	// WHEN: цикл запущен и первые два пробинга захватили оба слота
	done := make(chan struct{})
	go func() { s.cycle(context.Background()); close(done) }()
	<-fc.starts
	<-fc.starts
	select {
	case h := <-fc.starts:
		t.Fatalf("third probe %s started while both pool slots are still busy", h.Address)
	case <-time.After(50 * time.Millisecond):
	}
	close(fc.block)
	<-done

	// THEN: одновременно в работе было не больше двух пробингов, но проверены все восемь целей
	if fc.maxInFlight != 2 {
		t.Errorf("max concurrent probes = %d, want 2", fc.maxInFlight)
	}
	if got := len(fc.started); got != 8 {
		t.Errorf("probes started = %d, want 8", got)
	}
}

func TestCycleProbesEachHostOnceAndHandlesResult(t *testing.T) {
	// GIVEN: три различные цели и обработчик, собирающий доставленные результаты
	hs := []config.Target{target("a:443"), target("b:443"), target("c:443")}
	fc := &fakeChecker{}
	var mu sync.Mutex
	var handled []config.Target
	s := New(testConfig(10, 0, hs...), fc, func(_ context.Context, r probe.Result) {
		mu.Lock()
		handled = append(handled, r.Target)
		mu.Unlock()
	}, discardLogger())

	// WHEN: выполнен один цикл
	s.cycle(context.Background())

	// THEN: каждая цель проверена ровно один раз и её результат передан обработчику
	want := map[string]int{"a:443": 1, "b:443": 1, "c:443": 1}
	if got := addrCounts(fc.started); !reflect.DeepEqual(got, want) {
		t.Errorf("probes per target = %v, want %v", got, want)
	}
	if got := addrCounts(handled); !reflect.DeepEqual(got, want) {
		t.Errorf("handled results per target = %v, want %v", got, want)
	}
}

func TestCycleStopsOnContextCancellation(t *testing.T) {
	// GIVEN: тридцать целей, пул на два слота, пробинги висят до отмены контекста
	fc := &fakeChecker{block: make(chan struct{}), starts: make(chan config.Target, 30)}
	var handled atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	s := New(testConfig(2, 0, manyTargets(30)...), fc, func(context.Context, probe.Result) {
		handled.Add(1)
	}, discardLogger())

	// WHEN: два пробинга успели стартовать, после чего контекст отменяется
	done := make(chan struct{})
	go func() { s.cycle(ctx); close(done) }()
	<-fc.starts
	<-fc.starts
	cancel()

	// THEN: цикл завершается без зависания, а незапущенные цели не пробятся и не попадают в обработчик
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cycle did not return after cancellation — goroutines leaked in wg.Wait")
	}
	started := len(fc.started)
	if started >= 30 {
		t.Errorf("started %d probes, want fewer than all 30 after cancellation", started)
	}
	if int64(started) != handled.Load() {
		t.Errorf("handler ran %d times for %d started probes; unstarted targets must not be handled",
			handled.Load(), started)
	}
}

func TestCycleJitterStaysWithinBounds(t *testing.T) {
	// GIVEN: шесть целей, джиттер 80мс и пул, достаточный для одновременного старта всех
	const jitter = 80 * time.Millisecond
	const slack = 250 * time.Millisecond // запас на планирование горутин
	fc := &fakeChecker{}
	s := New(testConfig(10, jitter, manyTargets(6)...), fc, func(context.Context, probe.Result) {}, discardLogger())

	// WHEN: выполнен один цикл, начало которого зафиксировано
	start := time.Now()
	s.cycle(context.Background())

	// THEN: ни один пробинг не стартовал позже, чем через джиттер после начала цикла, но джиттер реально применён
	fc.mu.Lock()
	defer fc.mu.Unlock()
	var maxDelay time.Duration
	for i, ts := range fc.startTimes {
		d := ts.Sub(start)
		if d > jitter+slack {
			t.Errorf("probe %d started %v after cycle start, exceeds jitter bound %v", i, d, jitter)
		}
		if d > maxDelay {
			maxDelay = d
		}
	}
	if maxDelay < 10*time.Millisecond {
		t.Errorf("largest start delay was %v; jitter does not appear to be applied", maxDelay)
	}
}

func TestCycleJitterRunsOutsideConcurrencySlot(t *testing.T) {
	// GIVEN: пул на один слот, джиттер j и n мгновенных проб. Если бы джиттер
	// спал внутри слота, цикл сериализовал бы задержки и занял бы ~n×j; вне
	// слота все n проб пережидают джиттер параллельно, и цикл укладывается в ~j.
	const jitter = 40 * time.Millisecond
	const n = 10
	fc := &fakeChecker{}
	s := New(testConfig(1, jitter, manyTargets(n)...), fc, func(context.Context, probe.Result) {}, discardLogger())

	// WHEN: выполнен один цикл
	start := time.Now()
	s.cycle(context.Background())
	elapsed := time.Since(start)

	// THEN: все цели проверены, но цикл завершился много быстрее, чем n×j —
	// значит джиттер вынесен за пределы слота конкурентности
	if got := len(fc.started); got != n {
		t.Fatalf("probes started = %d, want %d", got, n)
	}
	if serial := time.Duration(n) * jitter; elapsed >= serial/2 {
		t.Errorf("cycle took %v; jitter appears to run inside the slot (serial bound %v)", elapsed, serial)
	}
}

func TestLastCycleZeroBeforeFirstCycle(t *testing.T) {
	// GIVEN: планировщик, ещё не выполнивший ни одного цикла
	s := New(testConfig(1, 0, target("a:443")), &fakeChecker{}, func(context.Context, probe.Result) {}, discardLogger())

	// WHEN/THEN: время последнего цикла — нулевое (признак старта для liveness-проверки)
	if !s.LastCycle().IsZero() {
		t.Errorf("LastCycle = %v, want zero before any cycle completes", s.LastCycle())
	}
}

func TestRunExecutesImmediatelyThenStopsOnCancel(t *testing.T) {
	// GIVEN: часовой интервал, чтобы второй цикл не наступил сам по себе
	fc := &fakeChecker{starts: make(chan config.Target, 4)}
	ctx, cancel := context.WithCancel(context.Background())
	s := New(testConfig(4, 0, target("a:443")), fc, func(context.Context, probe.Result) {}, discardLogger())

	// WHEN: Run стартует и должен выполнить немедленный первый цикл ещё до первого тика
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	select {
	case <-fc.starts:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not execute an immediate first cycle")
	}

	// THEN: после отмены контекста Run завершается, а LastCycle отражает завершённый цикл
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
	if s.LastCycle().IsZero() {
		t.Error("LastCycle should be set after the immediate cycle completes")
	}
}
