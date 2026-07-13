package alert

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// retryInterval is how often the dispatcher re-attempts deliveries that are
// still queued after a failure. Prompt delivery of fresh alerts does not wait
// for it — Manager.Notify wakes the dispatcher on enqueue; this tick only
// paces retries of a target whose endpoint is down.
const retryInterval = 30 * time.Second

// OutboxStore is the queue side of the store the Dispatcher drains.
type OutboxStore interface {
	// PendingKeys returns the distinct target keys that have queued deliveries.
	PendingKeys() ([]string, error)
	// NextPending returns the oldest queued delivery for targetKey, or nil when
	// the target's queue is empty.
	NextPending(targetKey string) (*OutboxRow, error)
	// DeleteOutbox removes a delivered row.
	DeleteOutbox(id int64) error
	// FailOutbox bumps the attempt counter and records the last error, leaving
	// the row queued for a later retry.
	FailOutbox(id int64, errMsg string) error
}

// Dispatcher delivers queued notifications at least once, preserving per-target
// order: a target's alerts go out in the order they were enqueued, and a target
// whose endpoint is failing blocks only its own queue, never another's.
//
// One Dispatcher runs per notifier over a notifier-scoped store view, so its
// concurrency budget and wake are isolated from other notifiers. Per-target FIFO
// therefore holds only within a notifier: if a target is switched to a different
// notifier while it still has queued rows, the old rows drain on the old
// notifier's dispatcher while new ones enqueue to the new one, and the two are
// not ordered against each other. This is accepted — a notifier switch is an
// intentional config edit.
type Dispatcher struct {
	sender Sender
	store  OutboxStore
	log    *slog.Logger
	conc   int
	retry  time.Duration
	wake   chan struct{}

	// OnSent, when non-nil, observes delivery outcomes (used for metrics).
	OnSent func(err error)
}

func NewDispatcher(sender Sender, store OutboxStore, conc int, log *slog.Logger) *Dispatcher {
	if conc < 1 {
		conc = 1
	}
	return &Dispatcher{
		sender: sender, store: store, log: log, conc: conc,
		retry: retryInterval,
		// Buffered so a Wake during a drain pass is not lost and does not block
		// the caller.
		wake: make(chan struct{}, 1),
	}
}

// Wake asks the dispatcher to drain the outbox promptly. Non-blocking and safe
// to call from any goroutine.
func (d *Dispatcher) Wake() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// Run drains the outbox until ctx is cancelled. Each wake or retry tick makes
// one full pass over every target with queued deliveries. Passes never overlap,
// so a given target is drained by at most one goroutine at a time.
func (d *Dispatcher) Run(ctx context.Context) {
	t := time.NewTicker(d.retry)
	defer t.Stop()
	for {
		d.dispatchOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-d.wake:
		case <-t.C:
		}
	}
}

// dispatchOnce delivers each target's queue, targets in parallel up to conc.
func (d *Dispatcher) dispatchOnce(ctx context.Context) {
	keys, err := d.store.PendingKeys()
	if err != nil {
		d.log.Error("outbox scan failed", "err", err)
		return
	}
	sem := make(chan struct{}, d.conc)
	var wg sync.WaitGroup
	for _, targetKey := range keys {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(targetKey string) {
			defer wg.Done()
			defer func() { <-sem }()
			d.drainTarget(ctx, targetKey)
		}(targetKey)
	}
	wg.Wait()
}

// drainTarget sends a single target's queued notices in id order until the queue
// empties or a send fails. On failure it stops before advancing: the failed
// row stays at the head so ordering holds and a later pass retries it.
func (d *Dispatcher) drainTarget(ctx context.Context, targetKey string) {
	for {
		if ctx.Err() != nil {
			return
		}
		row, err := d.store.NextPending(targetKey)
		if err != nil {
			d.log.Error("outbox read failed", "target_key", targetKey, "err", err)
			return
		}
		if row == nil {
			return
		}
		err = d.sender.Send(ctx, row.Body)
		if d.OnSent != nil {
			d.OnSent(err)
		}
		if err != nil {
			if ferr := d.store.FailOutbox(row.ID, err.Error()); ferr != nil {
				d.log.Error("outbox fail-mark failed", "id", row.ID, "err", ferr)
			}
			d.log.Error("alert delivery failed", "target_key", targetKey, "err", err)
			return
		}
		if derr := d.store.DeleteOutbox(row.ID); derr != nil {
			// The send succeeded but we could not clear the row; a later pass
			// re-sends it. At-least-once means a duplicate here, not a loss.
			d.log.Error("outbox delete failed", "id", row.ID, "err", derr)
			return
		}
		d.log.Info("alert sent", "target_key", targetKey)
	}
}
