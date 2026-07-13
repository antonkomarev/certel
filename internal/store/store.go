// Package store persists alert state, the delivery outbox, and probe and alert
// logs in a local SQLite database (modernc.org/sqlite, pure Go — no cgo), so
// restarts neither re-send alerts for known problems nor lose notices queued
// but not yet delivered, and past checks stay queryable.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/antonkomarev/certel/internal/alert"
	"github.com/antonkomarev/certel/internal/probe"
)

// Timestamps are stored as unix seconds; 0 means "never"/"unknown".
const schema = `
CREATE TABLE IF NOT EXISTS alert_state (
	target_key    TEXT PRIMARY KEY,
	status        TEXT NOT NULL,
	severity      TEXT NOT NULL,
	last_alert_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS probe_log (
	id          INTEGER PRIMARY KEY,
	target_key  TEXT NOT NULL,
	address     TEXT NOT NULL,
	protocol    TEXT NOT NULL,
	checked_at  INTEGER NOT NULL,
	status      TEXT NOT NULL,
	severity    TEXT NOT NULL,
	message     TEXT NOT NULL DEFAULT '',
	days_left   INTEGER NOT NULL,
	not_after   INTEGER NOT NULL,
	duration_ms INTEGER NOT NULL,
	attempts    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS probe_log_key_time ON probe_log(target_key, checked_at);
CREATE INDEX IF NOT EXISTS probe_log_time ON probe_log(checked_at);
-- alert_log is the immutable history of alert events: one row per occurrence,
-- written when the alert is decided. It records what happened, never how it was
-- delivered — delivery lives in notification_outbox and the process logs.
CREATE TABLE IF NOT EXISTS alert_log (
	id         INTEGER PRIMARY KEY,
	target_key TEXT NOT NULL,
	notifier   TEXT NOT NULL,
	address    TEXT NOT NULL,
	logged_at  INTEGER NOT NULL,
	status     TEXT NOT NULL,
	severity   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS alert_log_time ON alert_log(logged_at);
-- notification_outbox is the pure delivery queue: a row exists only while a notice is
-- still owed. Rows drain in id order per target_key (per-target FIFO) and are deleted
-- on successful send, so the table holds only pending work.
CREATE TABLE IF NOT EXISTS notification_outbox (
	id             INTEGER PRIMARY KEY,
	target_key     TEXT NOT NULL,
	notifier       TEXT NOT NULL,
	body           BLOB NOT NULL,
	enqueued_at    INTEGER NOT NULL,
	attempts_count INTEGER NOT NULL DEFAULT 0,
	last_error     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS notification_outbox_notifier_key_id ON notification_outbox(notifier, target_key, id);
`

type Store struct {
	db *sql.DB

	// OnWriteError, when non-nil, is called once per failed write to the store
	// (the store-write tripwire counter). Counting lives here, in the one layer
	// that distinguishes writes from reads, so every write path is covered by
	// construction and no caller has to remember to wire a hook. See
	// docs/metrics.md § store write health.
	OnWriteError func()
}

// writeErr reports a failed write through OnWriteError and returns err
// unchanged, so a write method can wrap its error return in one call. A nil err
// is a no-op; reads never route through it.
func (s *Store) writeErr(err error) error {
	if err != nil && s.OnWriteError != nil {
		s.OnWriteError()
	}
	return err
}

// Open creates or opens the database at path, creating the parent directory
// if needed, and applies the schema.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("creating database directory for %s: %w", path, err)
	}
	// busy_timeout guards against transient locks from external readers
	// (e.g. sqlite3 CLI inspecting the logs while the monitor runs).
	// The DSN is opened as a SQLite URI, so a literal '?' or '#' in the path
	// would terminate the filename and be parsed as query/fragment — silently
	// opening a different file and dropping the pragmas. Percent-escape those
	// (and '%' itself, first, to keep the decoding lossless).
	db, err := sql.Open("sqlite",
		"file:"+escapeDSNPath(path)+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("opening database %s: %w", path, err)
	}
	// Probes report concurrently; a single connection serializes writes in
	// database/sql instead of surfacing SQLITE_BUSY to callers.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("initializing database %s: %w", path, err)
	}
	return &Store{db: db}, nil
}

// escapeDSNPath percent-escapes the characters that are special in a SQLite
// URI filename so the path round-trips through the URI parser unchanged. '%'
// is escaped first so the escapes we add are not themselves re-decoded.
var dsnPathEscaper = strings.NewReplacer("%", "%25", "?", "%3f", "#", "%23")

func escapeDSNPath(path string) string { return dsnPathEscaper.Replace(path) }

func (s *Store) Close() error { return s.db.Close() }

// Ping verifies the database still answers a query, with a read against a
// real table so an actual page is fetched — nothing is written. Alerting is
// DB-backed (state, log and outbox all commit inside Enqueue), so a monitor
// that probes fine but lost its database is not healthy; /healthz folds this
// in. A lock held by an external reader is waited out by busy_timeout.
func (s *Store) Ping() error {
	var n int
	return s.db.QueryRow(`SELECT COUNT(*) FROM alert_state`).Scan(&n)
}

// LoadAlertStates returns every persisted per-target alert state.
func (s *Store) LoadAlertStates() (map[string]alert.StateRecord, error) {
	rows, err := s.db.Query(`SELECT target_key, status, severity, last_alert_at FROM alert_state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	states := map[string]alert.StateRecord{}
	for rows.Next() {
		var targetKey, status, severity string
		var lastAlert int64
		if err := rows.Scan(&targetKey, &status, &severity, &lastAlert); err != nil {
			return nil, err
		}
		rec := alert.StateRecord{
			Status: probe.Status(status), Severity: probe.Severity(severity),
		}
		if lastAlert != 0 {
			rec.LastAlertAt = time.Unix(lastAlert, 0)
		}
		states[targetKey] = rec
	}
	return states, rows.Err()
}

// RecentProbeStatuses returns up to limit of a target's most recent probe
// outcomes, newest first, for the flap-debounce restart rebuild. It reads the
// same durable probe_log every cycle already writes, so the confirmation
// counter needs no state of its own. The id tiebreak keeps ordering stable when
// two cycles share a checked_at second.
func (s *Store) RecentProbeStatuses(targetKey string, limit int) ([]alert.ProbeObservation, error) {
	rows, err := s.db.Query(
		`SELECT status, severity FROM probe_log WHERE target_key = ? ORDER BY checked_at DESC, id DESC LIMIT ?`,
		targetKey, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var obs []alert.ProbeObservation
	for rows.Next() {
		var status, severity string
		if err := rows.Scan(&status, &severity); err != nil {
			return nil, err
		}
		obs = append(obs, alert.ProbeObservation{
			Status: probe.Status(status), Severity: probe.Severity(severity),
		})
	}
	return obs, rows.Err()
}

// SaveAlertState upserts one target's dedup/timer state.
func (s *Store) SaveAlertState(targetKey string, st alert.StateRecord) error {
	return s.writeErr(saveAlertState(s.db, targetKey, st))
}

// execer is the shared subset of *sql.DB and *sql.Tx, so state upserts run the
// same way standalone or inside the Enqueue transaction.
type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func saveAlertState(x execer, targetKey string, st alert.StateRecord) error {
	var lastAlert int64
	if !st.LastAlertAt.IsZero() {
		lastAlert = st.LastAlertAt.Unix()
	}
	_, err := x.Exec(`
		INSERT INTO alert_state (target_key, status, severity, last_alert_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(target_key) DO UPDATE SET
			status = excluded.status,
			severity = excluded.severity,
			last_alert_at = excluded.last_alert_at`,
		targetKey, string(st.Status), string(st.Severity), lastAlert)
	return err
}

// PruneAlertStates drops state rows for targets no longer in the configuration,
// so a target that is removed and later re-added starts clean.
func (s *Store) PruneAlertStates(valid map[string]bool) error {
	rows, err := s.db.Query(`SELECT target_key FROM alert_state`)
	if err != nil {
		return err
	}
	var stale []string
	for rows.Next() {
		var targetKey string
		if err := rows.Scan(&targetKey); err != nil {
			rows.Close()
			return err
		}
		if !valid[targetKey] {
			stale = append(stale, targetKey)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, targetKey := range stale {
		if _, err := s.db.Exec(`DELETE FROM alert_state WHERE target_key = ?`, targetKey); err != nil {
			return s.writeErr(err)
		}
	}
	return nil
}

// RecordProbe appends one check outcome to the probe log.
func (s *Store) RecordProbe(r probe.Result) error {
	var notAfter int64
	if exp := r.EffectiveNotAfter(); !exp.IsZero() {
		notAfter = exp.Unix()
	}
	_, err := s.db.Exec(`
		INSERT INTO probe_log
			(target_key, address, protocol, checked_at, status, severity, message,
			 days_left, not_after, duration_ms, attempts)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Target.Key(), r.Target.Address, string(r.Target.Protocol),
		r.CheckedAt.Unix(), string(r.Status), string(r.Severity), r.Message,
		r.DaysLeft, notAfter, r.Duration.Milliseconds(), r.Attempts)
	return s.writeErr(err)
}

// Enqueue upserts the dedup state once and, for each fanned-out delivery,
// records the alert event and queues its rendered body — all in one transaction.
// Either everything commits or nothing does, so a crash can never leave state
// marked "already alerted" without the pending deliveries to back it, and
// fan-out has no "crash between two enqueues" window. Each delivery carries the
// notifier that fired and the status/severity that notifier saw (its clamped
// view); the shared per-target facts (key, address, time) come from ev.
func (s *Store) Enqueue(st alert.StateRecord, ev alert.AlertEvent, deliveries []alert.Delivery) (err error) {
	// The whole enqueue is one logical write; any failure along it — begin, any
	// insert, the state upsert, or commit — trips the counter once.
	defer func() { _ = s.writeErr(err) }()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := saveAlertState(tx, ev.TargetKey, st); err != nil {
		return err
	}
	for _, d := range deliveries {
		if _, err := tx.Exec(`
			INSERT INTO alert_log (target_key, notifier, address, logged_at, status, severity)
			VALUES (?, ?, ?, ?, ?, ?)`,
			ev.TargetKey, d.Notifier, ev.Address, ev.At.Unix(), string(d.Status), string(d.Severity)); err != nil {
			return err
		}
		if _, err := tx.Exec(`
			INSERT INTO notification_outbox (target_key, notifier, body, enqueued_at)
			VALUES (?, ?, ?, ?)`,
			ev.TargetKey, d.Notifier, d.Body, ev.At.Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ForNotifier returns an OutboxStore view scoped to a single notifier: its
// PendingKeys/NextPending see only that notifier's rows, so each notifier's
// dispatcher drains its own queue and the Dispatcher stays notifier-unaware.
func (s *Store) ForNotifier(notifier string) *NotifierOutbox {
	return &NotifierOutbox{store: s, notifier: notifier}
}

// NotifierOutbox is a notifier-scoped view of the outbox implementing
// alert.OutboxStore. DeleteOutbox/FailOutbox act on a row id and need no
// scoping — the id already came from a scoped read.
type NotifierOutbox struct {
	store    *Store
	notifier string
}

// PendingKeys returns the distinct target keys with queued deliveries for this
// notifier.
func (n *NotifierOutbox) PendingKeys() ([]string, error) {
	rows, err := n.store.db.Query(
		`SELECT DISTINCT target_key FROM notification_outbox WHERE notifier = ? ORDER BY target_key`, n.notifier)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var targetKey string
		if err := rows.Scan(&targetKey); err != nil {
			return nil, err
		}
		keys = append(keys, targetKey)
	}
	return keys, rows.Err()
}

// NextPending returns the oldest queued delivery for targetKey on this notifier,
// or nil when the target's queue is empty.
func (n *NotifierOutbox) NextPending(targetKey string) (*alert.OutboxRow, error) {
	var row alert.OutboxRow
	err := n.store.db.QueryRow(
		`SELECT id, target_key, body FROM notification_outbox WHERE notifier = ? AND target_key = ? ORDER BY id LIMIT 1`,
		n.notifier, targetKey).
		Scan(&row.ID, &row.TargetKey, &row.Body)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// DeleteOutbox removes a delivered row.
func (n *NotifierOutbox) DeleteOutbox(id int64) error { return n.store.DeleteOutbox(id) }

// FailOutbox bumps the attempt counter and records the last error.
func (n *NotifierOutbox) FailOutbox(id int64, errMsg string) error {
	return n.store.FailOutbox(id, errMsg)
}

// OrphanedOutbox reports rows dropped by DropOrphanedOutbox for one notifier
// that no longer exists in the configuration.
type OrphanedOutbox struct {
	Notifier string
	Rows     int
}

// DropOrphanedOutbox deletes queued deliveries whose notifier is not in valid
// (renamed or removed from the config while rows were still queued) and returns
// what was dropped, per notifier, sorted by name. The bodies were frozen with
// the old notifier's body, so re-tagging them to a target's current notifier
// could POST a mis-shaped payload that 400s forever and blocks the queue;
// dropping is the safe choice. A dropped recovery notice is genuinely lost; a
// still-present problem re-alerts within alert_repeat_interval.
func (s *Store) DropOrphanedOutbox(valid map[string]bool) ([]OrphanedOutbox, error) {
	rows, err := s.db.Query(
		`SELECT notifier, COUNT(*)
		 FROM notification_outbox GROUP BY notifier ORDER BY notifier`)
	if err != nil {
		return nil, err
	}
	var orphans []OrphanedOutbox
	for rows.Next() {
		var o OrphanedOutbox
		if err := rows.Scan(&o.Notifier, &o.Rows); err != nil {
			rows.Close()
			return nil, err
		}
		if !valid[o.Notifier] {
			orphans = append(orphans, o)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, o := range orphans {
		if _, err := s.db.Exec(`DELETE FROM notification_outbox WHERE notifier = ?`, o.Notifier); err != nil {
			return orphans, s.writeErr(err)
		}
	}
	return orphans, nil
}

// DeleteOutbox removes a delivered row.
func (s *Store) DeleteOutbox(id int64) error {
	_, err := s.db.Exec(`DELETE FROM notification_outbox WHERE id = ?`, id)
	return s.writeErr(err)
}

// FailOutbox bumps the attempt counter and records the last error, leaving the
// row queued for a later retry.
func (s *Store) FailOutbox(id int64, errMsg string) error {
	_, err := s.db.Exec(
		`UPDATE notification_outbox SET attempts_count = attempts_count + 1, last_error = ? WHERE id = ?`,
		errMsg, id)
	return s.writeErr(err)
}

// OutboxStat is one notifier's queue depth at a point in time: how many
// deliveries are pending and when the oldest was enqueued (zero when empty).
type OutboxStat struct {
	Notifier         string
	Pending          int
	OldestEnqueuedAt time.Time
}

// OutboxStats returns the pending count and oldest enqueue time per notifier
// that currently has queued rows, in one grouped query. Notifiers with an empty
// queue produce no row — the caller supplies the authoritative notifier list
// and reads 0 for the rest. Read-only, run under the caller's context so a
// scrape-time query can be bounded by a timeout.
func (s *Store) OutboxStats(ctx context.Context) ([]OutboxStat, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT notifier, COUNT(*), COALESCE(MIN(enqueued_at), 0)
		 FROM notification_outbox GROUP BY notifier`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var stats []OutboxStat
	for rows.Next() {
		var st OutboxStat
		var oldest int64
		if err := rows.Scan(&st.Notifier, &st.Pending, &oldest); err != nil {
			return nil, err
		}
		if oldest != 0 {
			st.OldestEnqueuedAt = time.Unix(oldest, 0)
		}
		stats = append(stats, st)
	}
	return stats, rows.Err()
}

// PruneLogs deletes probe log entries older than probeOlderThan and alert log
// entries older than alertOlderThan, returning how many rows were removed in
// total. The two cutoffs are independent so probe and alert history can be kept
// for different durations. The outbox is never pruned: a row there is an
// undelivered obligation, and dropping it by age would silently lose an alert —
// exactly what the queue exists to prevent.
func (s *Store) PruneLogs(probeOlderThan, alertOlderThan time.Time) (int64, error) {
	var total int64
	res, err := s.db.Exec(`DELETE FROM probe_log WHERE checked_at < ?`, probeOlderThan.Unix())
	if err != nil {
		return total, s.writeErr(err)
	}
	if n, err := res.RowsAffected(); err == nil {
		total += n
	}
	res, err = s.db.Exec(`DELETE FROM alert_log WHERE logged_at < ?`, alertOlderThan.Unix())
	if err != nil {
		return total, s.writeErr(err)
	}
	if n, err := res.RowsAffected(); err == nil {
		total += n
	}
	return total, nil
}
