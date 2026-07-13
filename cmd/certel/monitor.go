package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/antonkomarev/certel/internal/alert"
	"github.com/antonkomarev/certel/internal/config"
	"github.com/antonkomarev/certel/internal/metrics"
	"github.com/antonkomarev/certel/internal/probe"
	"github.com/antonkomarev/certel/internal/scheduler"
	"github.com/antonkomarev/certel/internal/store"
)

// hasAuthHeader reports whether the alert headers carry an Authorization
// credential, matched case-insensitively since HTTP header names are.
func hasAuthHeader(headers map[string]string) bool {
	for k := range headers {
		if strings.EqualFold(k, "Authorization") {
			return true
		}
	}
	return false
}

// buildRuntimes compiles each notifier's body up front, so a broken body or
// reference fails at startup (and under validate-config), not at the first
// alert. The resulting runtimes drive both the Manager's decisions and
// delivery.
func buildRuntimes(cfg *config.Config) (map[string]alert.NotifierRuntime, error) {
	runtimes := make(map[string]alert.NotifierRuntime, len(cfg.Notifiers))
	for name, nc := range cfg.Notifiers {
		body, err := alert.ParseBody(nc.Body, nc.RecoveryBody)
		if err != nil {
			return nil, fmt.Errorf("notifier %q: %w", name, err)
		}
		runtimes[name] = alert.NotifierRuntime{Config: nc, Body: body}
	}
	return runtimes, nil
}

// buildDispatchers wires one sender + dispatcher per notifier over a
// notifier-scoped store view, so each notifier's delivery is isolated: its own
// concurrency budget, its own wake, its own drain pass. Kept in one place so
// the config-reload path can rebuild and tear these down together.
func buildDispatchers(runtimes map[string]alert.NotifierRuntime, db *store.Store, mets *metrics.Metrics, log *slog.Logger) (map[string]*alert.Dispatcher, error) {
	dispatchers := make(map[string]*alert.Dispatcher, len(runtimes))
	for name, rt := range runtimes {
		sender, err := alert.NewWebhookSender(rt.Config)
		if err != nil {
			return nil, fmt.Errorf("notifier %q: %w", name, err)
		}
		d := alert.NewDispatcher(sender, db.ForNotifier(name), rt.Config.Concurrency, log)
		notifier := name
		d.OnSent = func(err error) { mets.ObserveAlert(notifier, err) }
		dispatchers[name] = d
	}
	return dispatchers, nil
}

// sortedNames returns a map's keys in ascending order, for deterministic
// startup logging over the notifier map.
func sortedNames[V any](m map[string]V) []string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// livenessThreshold returns how stale the last completed cycle may get before
// /healthz reports unhealthy. It is derived from the worst *legal* cycle rather
// than a fixed guess, so a healthy-but-slow cycle (many targets, long timeouts,
// retries) does not flap the probe. Alert delivery is not included: it runs off
// the probe path in the outbox dispatcher and never stretches a cycle.
//
// Worst cycle ≈ interval between cycles + jitter tail + probing, where probing
// is ceil(targets/concurrency) sequential waves, each bounded by the slowest
// single target: attempts × timeout + the 1s pause between attempts.
func livenessThreshold(cfg *config.Config) time.Duration {
	var maxAttempts int
	var maxTimeout time.Duration
	for _, t := range cfg.Targets {
		if a := *t.ConnectRetries + 1; a > maxAttempts {
			maxAttempts = a
		}
		if to := t.Timeout.Std(); to > maxTimeout {
			maxTimeout = to
		}
	}
	// Slowest a single target may legally take: one timeout per attempt plus a
	// 1s pause between attempts.
	perTarget := time.Duration(maxAttempts)*maxTimeout +
		time.Duration(maxAttempts-1)*time.Second

	waves := 0
	if c := cfg.Probe.Concurrency; c > 0 {
		waves = (len(cfg.Targets) + c - 1) / c
	}
	probing := time.Duration(waves) * perTarget

	const slack = 30 * time.Second
	return cfg.Probe.CheckInterval.Std() + cfg.Probe.Jitter.Std() + probing + slack
}

// runMonitor is the long-running mode: probe the configured targets on a
// schedule, persist state, and deliver webhook alerts.
func runMonitor(args []string) {
	fs := flag.NewFlagSet("monitor", flag.ExitOnError)
	configPath := fs.String("config", "config.yaml", "path to the YAML configuration file")
	logJSON := fs.Bool("log-json", false, "emit logs as JSON")
	fs.Parse(args)

	var handler slog.Handler = slog.NewTextHandler(os.Stderr, nil)
	if *logJSON {
		handler = slog.NewJSONHandler(os.Stderr, nil)
	}
	log := slog.New(handler)

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("configuration error", "err", err)
		os.Exit(1)
	}
	runtimes, err := buildRuntimes(cfg)
	if err != nil {
		log.Error("configuration error", "err", err)
		os.Exit(1)
	}

	db, err := store.Open(cfg.Database.Path)
	if err != nil {
		log.Error("database error", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	states, err := db.LoadAlertStates()
	if err != nil {
		log.Error("database error", "err", err)
		os.Exit(1)
	}
	// Forget targets that were removed from the config so a later re-add
	// starts from a clean state.
	valid := map[string]bool{}
	for _, t := range cfg.Targets {
		valid[t.Key()] = true
	}
	for k := range states {
		if !valid[k] {
			delete(states, k)
		}
	}
	if err := db.PruneAlertStates(valid); err != nil {
		log.Warn("pruning stale alert state failed", "err", err)
	}

	// Drop queued deliveries for notifiers no longer in the config (renamed or
	// removed). Their bodies were frozen with the old notifier's template, so
	// re-tagging could POST a mis-shaped payload forever; dropping is safe — a
	// still-present problem re-alerts within alert_repeat_interval, though a
	// dropped recovery is genuinely lost.
	validNotifiers := map[string]bool{}
	for name := range cfg.Notifiers {
		validNotifiers[name] = true
	}
	if orphans, err := db.DropOrphanedOutbox(validNotifiers); err != nil {
		log.Warn("dropping orphaned outbox rows failed", "err", err)
	} else {
		for _, o := range orphans {
			log.Error("dropped queued alerts for a notifier no longer in the config",
				"notifier", o.Notifier, "rows", o.Rows)
		}
	}

	// A cycle is considered overdue once the last completed one is older than
	// the worst legal cycle, so a slow-but-healthy cycle doesn't flap the probe.
	// Derived once and shared by /healthz and the exported staleness threshold
	// gauge so the alert never hardcodes a bound that rots as the config changes.
	liveness := livenessThreshold(cfg)

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	mets := metrics.New(reg, cfg, version, liveness, db, log)
	// The store counts its own failed writes, so every write path — alert
	// state, outbox, probe log, prunes — feeds the tripwire without per-caller
	// wiring.
	db.OnWriteError = mets.ObserveStoreWriteError

	for _, name := range sortedNames(cfg.Notifiers) {
		nc := cfg.Notifiers[name]
		if nc.Insecure {
			log.Warn("notifier insecure is set: TLS verification of the webhook endpoint is disabled",
				"notifier", name)
		}
		if strings.HasPrefix(nc.URL, "http://") && hasAuthHeader(nc.Headers) {
			log.Warn("notifier url uses plain http with an Authorization header: credentials are sent in cleartext",
				"notifier", name)
		}
	}

	dispatchers, err := buildDispatchers(runtimes, db, mets, log)
	if err != nil {
		log.Error("alert configuration error", "err", err)
		os.Exit(1)
	}
	mgr := alert.NewManager(runtimes, db, log)
	// Fan enqueue wakeups out to the right notifier's dispatcher.
	mgr.Notify = func(notifier string) {
		if d, ok := dispatchers[notifier]; ok {
			d.Wake()
		}
	}
	mgr.Restore(states, cfg.Targets)
	log.Info("alert state restored", "path", cfg.Database.Path, "targets", len(states))

	sched := scheduler.New(cfg, probe.New(), func(ctx context.Context, r probe.Result) {
		mets.Observe(r)
		if err := db.RecordProbe(r); err != nil {
			log.Warn("probe log write failed", "target", r.Target.Address, "err", err)
		}
		mgr.Process(ctx, r)
	}, log)
	sched.OnCycle = mets.ObserveCycle

	startedAt := time.Now()

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		last := sched.LastCycle()
		var cycleFresh bool
		if last.IsZero() {
			// No cycle has completed yet: healthy only within a startup grace,
			// so a first cycle that hangs forever is still caught.
			cycleFresh = time.Since(startedAt) < liveness
		} else {
			cycleFresh = time.Since(last) < liveness
		}
		// Alerting is DB-backed, so a monitor that probes fine but lost its
		// database is not healthy either.
		dbErr := db.Ping()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if cycleFresh && dbErr == nil {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		fmt.Fprintf(w, "version %s\ntargets %d\n", version, len(cfg.Targets))
		if last.IsZero() {
			fmt.Fprintln(w, "last_cycle none")
		} else {
			fmt.Fprintf(w, "last_cycle %s (%s ago)\n",
				last.UTC().Format(time.RFC3339), time.Since(last).Round(time.Second))
		}
		if dbErr != nil {
			fmt.Fprintf(w, "database error: %v\n", dbErr)
		} else {
			fmt.Fprintln(w, "database ok")
		}
	})
	srv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		prune := func() {
			now := time.Now()
			probeCutoff := now.Add(-cfg.Database.ProbeLogRetention.Std())
			alertCutoff := now.Add(-cfg.Database.AlertLogRetention.Std())
			if n, err := db.PruneLogs(probeCutoff, alertCutoff); err != nil {
				log.Warn("log pruning failed", "err", err)
			} else if n > 0 {
				log.Info("logs pruned", "rows", n,
					"probe_retention", cfg.Database.ProbeLogRetention.Std().String(),
					"alert_retention", cfg.Database.AlertLogRetention.Std().String())
			}
		}
		prune()
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				prune()
			}
		}
	}()

	go func() {
		log.Info("http server listening", "addr", cfg.Server.Listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("http server failed", "err", err)
			stop()
		}
	}()

	// One dispatcher per notifier drains its own scoped outbox: fresh alerts go
	// out on Notify, and anything left undelivered from a prior run is re-sent on
	// startup. A down or slow notifier can't delay another's delivery.
	dispDone := make(chan struct{})
	go func() {
		defer close(dispDone)
		var wg sync.WaitGroup
		for _, d := range dispatchers {
			wg.Add(1)
			go func(d *alert.Dispatcher) {
				defer wg.Done()
				d.Run(ctx)
			}(d)
		}
		wg.Wait()
	}()

	log.Info("certel starting", "version", version,
		"targets", len(cfg.Targets), "interval", cfg.Probe.CheckInterval.Std().String())
	sched.Run(ctx)

	// Let the dispatcher observe the cancellation and return before the
	// deferred db.Close, so a send in flight cannot race the closing database.
	<-dispDone

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	log.Info("shut down cleanly")
}
