// Package scheduler runs probe cycles on an interval through a bounded
// worker pool.
package scheduler

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/antonkomarev/certel/internal/config"
	"github.com/antonkomarev/certel/internal/probe"
)

// ResultHandler consumes each probe result (alerting, metrics, logging).
type ResultHandler func(ctx context.Context, r probe.Result)

// Checker probes a single target. *probe.Prober is the production implementation;
// tests substitute a fake to drive scheduling without real network I/O.
type Checker interface {
	Check(ctx context.Context, t config.Target) probe.Result
}

type Scheduler struct {
	cfg    *config.Config
	prober Checker
	handle ResultHandler
	log    *slog.Logger

	// lastCycle is the unix time of the most recently completed cycle, 0 until
	// the first finishes. Read by the liveness probe.
	lastCycle atomic.Int64

	// OnCycle, when non-nil, is called at the end of each completed cycle with
	// its completion time and wall duration, so the cycle gauges can be exported.
	OnCycle func(completedAt time.Time, d time.Duration)
}

func New(cfg *config.Config, p Checker, handle ResultHandler, log *slog.Logger) *Scheduler {
	return &Scheduler{cfg: cfg, prober: p, handle: handle, log: log}
}

// Run blocks until ctx is cancelled, executing one cycle immediately and
// then one per check_interval. A cycle that overruns the interval is not
// stacked: the ticker simply fires again after it finishes.
func (s *Scheduler) Run(ctx context.Context) {
	s.cycle(ctx)
	ticker := time.NewTicker(s.cfg.Probe.CheckInterval.Std())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cycle(ctx)
		}
	}
}

func (s *Scheduler) cycle(ctx context.Context) {
	start := time.Now()
	sem := make(chan struct{}, s.cfg.Probe.Concurrency)
	var wg sync.WaitGroup
	for _, t := range s.cfg.Targets {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(t config.Target) {
			defer wg.Done()
			// Spread the start of each probe so a large target list does not
			// hammer the network in one burst. Jitter runs *before* the
			// concurrency slot is taken, so it spreads out starts instead of
			// stretching the cycle in waves of `concurrency`.
			if j := s.cfg.Probe.Jitter.Std(); j > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(rand.N(j)):
				}
			}
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()
			r := s.prober.Check(ctx, t)
			s.log.Info("check finished",
				"target", t.Address, "protocol", t.Protocol,
				"status", r.Status, "severity", r.Severity,
				"days_left", r.DaysLeft, "attempts", r.Attempts,
				"duration", r.Duration.Round(time.Millisecond).String(),
				"detail", r.Message)
			s.handle(ctx, r)
		}(t)
	}
	wg.Wait()
	completedAt := time.Now()
	s.lastCycle.Store(completedAt.Unix())
	if s.OnCycle != nil {
		s.OnCycle(completedAt, completedAt.Sub(start))
	}
	s.log.Debug("cycle complete", "targets", len(s.cfg.Targets),
		"took", completedAt.Sub(start).Round(time.Millisecond).String())
}

// LastCycle reports when the most recent probe cycle finished. The zero time
// means no cycle has completed yet (startup).
func (s *Scheduler) LastCycle() time.Time {
	ts := s.lastCycle.Load()
	if ts == 0 {
		return time.Time{}
	}
	return time.Unix(ts, 0)
}
