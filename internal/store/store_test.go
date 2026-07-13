package store

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/antonkomarev/certel/internal/alert"
	"github.com/antonkomarev/certel/internal/config"
	"github.com/antonkomarev/certel/internal/probe"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	// The db/ subdirectory does not exist yet: Open must create it, since
	// the default database path points into a not-yet-existing directory
	// next to the binary.
	s, err := Open(filepath.Join(t.TempDir(), "db", "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestAlertStateRoundtrip(t *testing.T) {
	// GIVEN: пустое хранилище и запись о состоянии с заполненным временем последней тревоги
	s := testStore(t)
	sent := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

	rec := alert.StateRecord{
		Status: probe.StatusExpiringSoon, Severity: probe.SeverityWarning,
		LastAlertAt: sent,
	}

	// WHEN: одна запись сохранена, затем перезаписана по тому же ключу (upsert), плюс добавлен второй, никогда не тревожившая цель
	if err := s.SaveAlertState("tls//a:443/", rec); err != nil {
		t.Fatal(err)
	}
	rec.Severity = probe.SeverityCritical
	if err := s.SaveAlertState("tls//a:443/", rec); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveAlertState("tls//b:443/", alert.StateRecord{Status: probe.StatusOK, Severity: probe.SeverityOK}); err != nil {
		t.Fatal(err)
	}

	// THEN: повторное сохранение обновило запись на месте, а не задвоило её; все поля пережили сериализацию, а никогда не тревожившая цель загружается с нулевым временем
	states, err := s.LoadAlertStates()
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 2 {
		t.Fatalf("want 2 states, got %d", len(states))
	}
	a := states["tls//a:443/"]
	if a.Severity != probe.SeverityCritical || a.Status != probe.StatusExpiringSoon {
		t.Fatalf("unexpected state after upsert: %+v", a)
	}
	if !a.LastAlertAt.Equal(sent) {
		t.Fatalf("LastAlertAt: want %v, got %v", sent, a.LastAlertAt)
	}
	if b := states["tls//b:443/"]; !b.LastAlertAt.IsZero() {
		t.Fatalf("never-alerted target must load with zero LastAlertAt, got %v", b.LastAlertAt)
	}
}

func TestPruneAlertStates(t *testing.T) {
	// GIVEN: два сохранённых состояния, из которых в конфигурации остаётся только одна цель
	s := testStore(t)
	for _, key := range []string{"tls//keep:443/", "tls//drop:443/"} {
		if err := s.SaveAlertState(key, alert.StateRecord{Status: probe.StatusOK, Severity: probe.SeverityOK}); err != nil {
			t.Fatal(err)
		}
	}

	// WHEN: чистка оставляет состояния только для по-прежнему настроенных целей
	if err := s.PruneAlertStates(map[string]bool{"tls//keep:443/": true}); err != nil {
		t.Fatal(err)
	}

	// THEN: осталось лишь состояние настроенной цели, а осиротевшее удалено
	states, err := s.LoadAlertStates()
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states["tls//keep:443/"].Status == "" {
		t.Fatalf("want only the configured target to survive, got %v", states)
	}
}

func TestProbeLogAndRetention(t *testing.T) {
	// GIVEN: журнал с одной старой и одной свежей записью пробинга, а также старая запись о тревоге
	s := testStore(t)
	target := config.Target{Address: "example.com:443", Protocol: config.ProtoTLS}
	old := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

	for _, at := range []time.Time{old, recent} {
		err := s.RecordProbe(probe.Result{
			Target: target, Status: probe.StatusOK, Severity: probe.SeverityOK,
			CheckedAt: at, Duration: 120 * time.Millisecond, Attempts: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	err := s.Enqueue(
		alert.StateRecord{Status: probe.StatusExpired, Severity: probe.SeverityCritical, LastAlertAt: old},
		alert.AlertEvent{TargetKey: target.Key(), Address: target.Address, At: old},
		[]alert.Delivery{{Notifier: "default", Status: probe.StatusExpired, Severity: probe.SeverityCritical, Body: []byte("body")}})
	if err != nil {
		t.Fatal(err)
	}

	// WHEN: удаляются все записи старше границы удержания (для обоих журналов — одна дата)
	cutoff := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	n, err := s.PruneLogs(cutoff, cutoff)
	if err != nil {
		t.Fatal(err)
	}

	// THEN: удержание затронуло оба типа журналов (старый пробинг и старую тревогу), а свежая запись пробинга уцелела
	if n != 2 {
		t.Fatalf("want 2 pruned rows (1 probe + 1 alert), got %d", n)
	}

	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM probe_log`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("want 1 probe row to survive retention, got %d", count)
	}
}

func TestRecentProbeStatuses(t *testing.T) {
	// GIVEN: журнал пробинга одной цели — три цикла в хронологическом порядке
	s := testStore(t)
	target := config.Target{Address: "example.com:443", Protocol: config.ProtoTLS}
	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	seq := []struct {
		at     time.Time
		status probe.Status
		sev    probe.Severity
	}{
		{base, probe.StatusOK, probe.SeverityOK},
		{base.Add(5 * time.Minute), probe.StatusUnreachable, probe.SeverityCritical},
		{base.Add(10 * time.Minute), probe.StatusUnreachable, probe.SeverityCritical},
	}
	for _, c := range seq {
		if err := s.RecordProbe(probe.Result{
			Target: target, Status: c.status, Severity: c.sev,
			CheckedAt: c.at, Duration: time.Millisecond, Attempts: 1,
		}); err != nil {
			t.Fatal(err)
		}
	}

	// WHEN: запрашиваются два последних исхода
	obs, err := s.RecentProbeStatuses(target.Key(), 2)
	if err != nil {
		t.Fatal(err)
	}

	// THEN: они возвращаются в порядке «сначала самый свежий» и ограничены лимитом
	want := []alert.ProbeObservation{
		{Status: probe.StatusUnreachable, Severity: probe.SeverityCritical},
		{Status: probe.StatusUnreachable, Severity: probe.SeverityCritical},
	}
	if !reflect.DeepEqual(obs, want) {
		t.Fatalf("recent statuses: got %+v, want %+v", obs, want)
	}

	// THEN: у цели без журнала — пустой результат, а не ошибка
	empty, err := s.RecentProbeStatuses("tls//nope:443/", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 0 {
		t.Fatalf("unknown target must yield no rows, got %+v", empty)
	}
}

func TestOutboxQueueRoundtrip(t *testing.T) {
	// GIVEN: три поставленные в очередь доставки — две для одной цели, одна для другой
	s := testStore(t)
	at := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	enqueue := func(key, notifier, body string) {
		t.Helper()
		st := alert.StateRecord{Status: probe.StatusExpired, Severity: probe.SeverityCritical, LastAlertAt: at}
		ev := alert.AlertEvent{TargetKey: key, Address: key, At: at}
		d := alert.Delivery{Notifier: notifier, Status: probe.StatusExpired, Severity: probe.SeverityCritical, Body: []byte(body)}
		if err := s.Enqueue(st, ev, []alert.Delivery{d}); err != nil {
			t.Fatal(err)
		}
	}
	enqueue("tls//a:443/", "default", "a-1")
	enqueue("tls//a:443/", "default", "a-2")
	enqueue("tls//b:443/", "default", "b-1")

	// THEN: обе таблицы получили по записи на событие
	var events int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM alert_log`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 3 {
		t.Fatalf("alert_log must hold one row per event, got %d", events)
	}

	outbox := s.ForNotifier("default")
	// WHEN: перечисляем цели с очередью
	keys, err := outbox.PendingKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("want 2 targets with pending deliveries, got %v", keys)
	}

	// THEN: для цели a первой отдаётся самая ранняя запись (per-target FIFO)
	row, err := outbox.NextPending("tls//a:443/")
	if err != nil {
		t.Fatal(err)
	}
	if row == nil || string(row.Body) != "a-1" {
		t.Fatalf("NextPending must return the oldest row, got %+v", row)
	}

	// WHEN: доставленную запись удаляют
	if err := outbox.DeleteOutbox(row.ID); err != nil {
		t.Fatal(err)
	}
	// THEN: следующей отдаётся вторая запись цели
	row, err = outbox.NextPending("tls//a:443/")
	if err != nil {
		t.Fatal(err)
	}
	if row == nil || string(row.Body) != "a-2" {
		t.Fatalf("after delete, next row expected, got %+v", row)
	}

	// WHEN: доставка второй записи падает
	if err := outbox.FailOutbox(row.ID, "boom"); err != nil {
		t.Fatal(err)
	}
	// THEN: строка остаётся в очереди со счётчиком попыток и текстом ошибки
	var attempts int
	var lastErr string
	if err := s.db.QueryRow(
		`SELECT attempts_count, last_error FROM notification_outbox WHERE id = ?`, row.ID).
		Scan(&attempts, &lastErr); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || lastErr != "boom" {
		t.Fatalf("failed row must record attempt and error, got attempts=%d err=%q", attempts, lastErr)
	}
}

func TestWriteErrorHookCountsWritesNotReads(t *testing.T) {
	// GIVEN: хранилище со счётчиком неудачных записей, у которого закрыто
	// соединение — так любая последующая операция с БД падает
	s := testStore(t)
	var writeErrors int
	s.OnWriteError = func() { writeErrors++ }
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}

	// WHEN: вызваны методы записи (в т.ч. DeleteOutbox/FailOutbox, которые
	// раньше ручными хуками не покрывались) — каждый падает уже на самой записи
	rec := alert.StateRecord{Status: probe.StatusExpired, Severity: probe.SeverityCritical}
	ev := alert.AlertEvent{TargetKey: "tls//a:443/", Address: "a:443"}
	deliveries := []alert.Delivery{{Notifier: "default", Status: probe.StatusExpired, Severity: probe.SeverityCritical, Body: []byte("body")}}
	writes := []func() error{
		func() error { return s.SaveAlertState("tls//a:443/", rec) },
		func() error {
			return s.RecordProbe(probe.Result{Target: config.Target{Address: "a:443", Protocol: "tls"}})
		},
		func() error { return s.Enqueue(rec, ev, deliveries) },
		func() error { return s.DeleteOutbox(1) },
		func() error { return s.FailOutbox(1, "boom") },
		func() error { _, err := s.PruneLogs(time.Now(), time.Now()); return err },
	}
	for _, w := range writes {
		if err := w(); err == nil {
			t.Fatal("expected a write against a closed db to fail")
		}
	}
	// Operations that fail before reaching a write must not touch the tripwire:
	// a pure read, and PruneAlertStates whose leading SELECT fails first.
	reads := []func() error{
		func() error { _, err := s.LoadAlertStates(); return err },
		func() error { return s.PruneAlertStates(map[string]bool{}) },
	}
	for _, r := range reads {
		if err := r(); err == nil {
			t.Fatal("expected a read against a closed db to fail")
		}
	}

	// THEN: каждая логическая запись взвела счётчик ровно раз, чтения — ни разу
	if writeErrors != len(writes) {
		t.Errorf("write error count = %d, want %d (one per failed logical write, none for the reads)", writeErrors, len(writes))
	}
}

func TestOutboxStats(t *testing.T) {
	// GIVEN: очередь с двумя рядами для default (разного возраста) и одним для pager
	s := testStore(t)
	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	enqueue := func(key, notifier string, at time.Time) {
		t.Helper()
		st := alert.StateRecord{Status: probe.StatusExpired, Severity: probe.SeverityCritical, LastAlertAt: at}
		ev := alert.AlertEvent{TargetKey: key, Address: key, At: at}
		d := alert.Delivery{Notifier: notifier, Status: probe.StatusExpired, Severity: probe.SeverityCritical, Body: []byte("body")}
		if err := s.Enqueue(st, ev, []alert.Delivery{d}); err != nil {
			t.Fatal(err)
		}
	}
	enqueue("tls//a:443/", "default", base.Add(time.Minute))
	enqueue("tls//b:443/", "default", base) // oldest for default
	enqueue("tls//c:443/", "pager", base.Add(2*time.Minute))

	// WHEN: собрана статистика очереди
	stats, err := s.OutboxStats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byNotifier := map[string]OutboxStat{}
	for _, st := range stats {
		byNotifier[st.Notifier] = st
	}

	// THEN: pending считает ряды нотификатора, а oldest — самый ранний enqueued_at
	if got := byNotifier["default"]; got.Pending != 2 || !got.OldestEnqueuedAt.Equal(base) {
		t.Errorf("default stat = %+v, want pending 2 oldest %v", got, base)
	}
	if got := byNotifier["pager"]; got.Pending != 1 || !got.OldestEnqueuedAt.Equal(base.Add(2*time.Minute)) {
		t.Errorf("pager stat = %+v, want pending 1 oldest %v", got, base.Add(2*time.Minute))
	}

	// AND: пустая очередь не порождает рядов — вызывающий сам знает список нотификаторов
	empty := testStore(t)
	stats, err = empty.OutboxStats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 0 {
		t.Errorf("empty outbox must yield no stat rows, got %v", stats)
	}
}

func TestDropOrphanedOutbox(t *testing.T) {
	// GIVEN: очередь с записями трёх нотификаторов, из которых в конфиге остаётся
	// лишь один
	s := testStore(t)
	at := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	enqueue := func(key, notifier, body string) {
		t.Helper()
		st := alert.StateRecord{Status: probe.StatusExpired, Severity: probe.SeverityCritical, LastAlertAt: at}
		ev := alert.AlertEvent{TargetKey: key, Address: key, At: at}
		d := alert.Delivery{Notifier: notifier, Status: probe.StatusExpired, Severity: probe.SeverityCritical, Body: []byte(body)}
		if err := s.Enqueue(st, ev, []alert.Delivery{d}); err != nil {
			t.Fatal(err)
		}
	}
	enqueue("tls//a:443/", "default", "a-1")
	enqueue("tls//b:443/", "gone", "b-1")     // orphan
	enqueue("tls//c:443/", "gone", "c-1")     // orphan, genuinely lost
	enqueue("tls//d:443/", "vanished", "d-1") // orphan

	// WHEN: дропаем записи нотификаторов, которых больше нет в конфиге
	orphans, err := s.DropOrphanedOutbox(map[string]bool{"default": true})
	if err != nil {
		t.Fatal(err)
	}

	// THEN: отчёт перечисляет осиротевшие нотификаторы по имени, с числом строк
	if len(orphans) != 2 {
		t.Fatalf("want 2 orphaned notifiers reported, got %+v", orphans)
	}
	if orphans[0].Notifier != "gone" || orphans[0].Rows != 2 {
		t.Fatalf("gone: want 2 rows, got %+v", orphans[0])
	}
	if orphans[1].Notifier != "vanished" || orphans[1].Rows != 1 {
		t.Fatalf("vanished: want 1 row, got %+v", orphans[1])
	}

	// AND: только записи по-прежнему настроенного нотификатора остаются в очереди
	keys, err := s.ForNotifier("default").PendingKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != "tls//a:443/" {
		t.Fatalf("only the surviving notifier's rows must remain, got %v", keys)
	}
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM notification_outbox`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Fatalf("orphaned rows must be deleted, %d left in outbox", total)
	}
}

func TestStatePersistsAcrossRestart(t *testing.T) {
	// GIVEN: реальные Manager и Store поверх одного файла БД; boot имитирует
	// перезапуск процесса, поднимая менеджер заново из сохранённого состояния.
	// Считаем поставленные в очередь события по append-only журналу alert_log.
	path := filepath.Join(t.TempDir(), "state.db")
	body, err := alert.ParseBody(map[string]any{"status": "${alert.Status}"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sendRecovery := true
	cfg := config.AlertConfig{SendRecovery: &sendRecovery}
	notifier := "default"
	target := config.Target{
		Address: "example.com:443", Protocol: config.ProtoTLS,
		TargetParams: config.TargetParams{
			Notifiers:           []string{notifier},
			AlertRepeatInterval: config.NewRepeatInterval(config.Duration(24 * time.Hour)),
		},
	}
	runtimes := map[string]alert.NotifierRuntime{notifier: {Config: cfg, Body: body}}
	ctx := context.Background()

	boot := func() (*Store, *alert.Manager) {
		s, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		states, err := s.LoadAlertStates()
		if err != nil {
			t.Fatal(err)
		}
		m := alert.NewManager(runtimes, s, slog.New(slog.DiscardHandler))
		m.Restore(states, []config.Target{target})
		return s, m
	}
	enqueued := func(s *Store) int {
		var n int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM alert_log`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// WHEN: в первой жизни процесса возникает критическая проблема
	s1, m1 := boot()
	m1.Process(ctx, probe.Result{Target: target, Status: probe.StatusExpired, Severity: probe.SeverityCritical})
	// THEN: событие тревоги поставлено в очередь ровно один раз
	if got := enqueued(s1); got != 1 {
		t.Fatalf("first life: want 1 enqueued alert, got %d", got)
	}

	// WHEN: процесс перезапущен, а проблема всё ещё держится в пределах repeat_interval
	s2, m2 := boot()
	m2.Process(ctx, probe.Result{Target: target, Status: probe.StatusExpired, Severity: probe.SeverityCritical})
	// THEN: восстановленное состояние подавляет повторную постановку в очередь
	if got := enqueued(s2); got != 1 {
		t.Fatalf("after restart: persisting problem within repeat_interval must stay silent, got %d event(s)", got)
	}

	// WHEN: процесс снова перезапущен, а сертификат тем временем починили, пока монитор был недоступен
	s3, m3 := boot()
	m3.Process(ctx, probe.Result{Target: target, Status: probe.StatusOK, Severity: probe.SeverityOK})
	// THEN: несмотря на перезапуск, уведомление о восстановлении ставится в очередь
	if got := enqueued(s3); got != 2 {
		t.Fatalf("after restart: want a recovery event for problem fixed while down, got %d total", got)
	}
}

func TestFlapDebounceCounterRebuildsFromProbeLogAcrossRestart(t *testing.T) {
	// GIVEN: реальные Manager и Store поверх одного файла БД; цель с порогом
	// подтверждения 2. boot имитирует перезапуск, поднимая менеджер заново и
	// переигрывая дебаунс-счётчик из probe_log (как это делает monitor.go).
	path := filepath.Join(t.TempDir(), "state.db")
	body, err := alert.ParseBody(map[string]any{"status": "${alert.Status}"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sendRecovery := true
	cfg := config.AlertConfig{SendRecovery: &sendRecovery}
	notifier := "default"
	flapStreak := 2
	target := config.Target{
		Address: "example.com:443", Protocol: config.ProtoTLS,
		TargetParams: config.TargetParams{
			Notifiers:           []string{notifier},
			FlapStreak:          &flapStreak,
			AlertRepeatInterval: config.NewRepeatInterval(config.Duration(24 * time.Hour)),
		},
	}
	runtimes := map[string]alert.NotifierRuntime{notifier: {Config: cfg, Body: body}}
	ctx := context.Background()

	boot := func() (*Store, *alert.Manager) {
		s, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		states, err := s.LoadAlertStates()
		if err != nil {
			t.Fatal(err)
		}
		m := alert.NewManager(runtimes, s, slog.New(slog.DiscardHandler))
		m.Restore(states, []config.Target{target})
		return s, m
	}
	enqueued := func(s *Store) int {
		var n int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM alert_log`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	unreachable := probe.Result{
		Target: target, Status: probe.StatusUnreachable, Severity: probe.SeverityCritical,
		CheckedAt: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), Duration: time.Millisecond, Attempts: 1,
	}

	// WHEN: в первой жизни процесса один цикл unreachable — записан в probe_log
	// (как в monitor.go), но не подтверждён, так что тревоги ещё нет
	s1, m1 := boot()
	if err := s1.RecordProbe(unreachable); err != nil {
		t.Fatal(err)
	}
	m1.Process(ctx, unreachable)
	if got := enqueued(s1); got != 0 {
		t.Fatalf("first life: unconfirmed unreachable must not enqueue, got %d", got)
	}

	// WHEN: процесс перезапущен (счётчик подтверждения теряется из памяти), затем
	// приходит ещё один цикл unreachable
	s2, m2 := boot()
	if err := s2.RecordProbe(unreachable); err != nil {
		t.Fatal(err)
	}
	m2.Process(ctx, unreachable)
	// THEN: тревога уходит немедленно — счётчик восстановлен из probe_log и
	// продолжился с 1, а не начался с нуля (иначе потребовался бы ещё цикл)
	if got := enqueued(s2); got != 1 {
		t.Fatalf("after restart: rebuilt counter must confirm on the next cycle, got %d", got)
	}
}

func TestOpenPathWithURISpecialChars(t *testing.T) {
	// GIVEN: путь к базе с литеральными '?' и '#', которые в SQLite URI
	// обрывают имя файла и уходят в query/fragment
	dir := t.TempDir()
	path := filepath.Join(dir, "cert?el#db", "state.db")

	// WHEN: открываем хранилище и что-нибудь пишем
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open(%q): %v", path, err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.SaveAlertState("target", alert.StateRecord{
		Status: probe.StatusOK, Severity: probe.SeverityOK,
	}); err != nil {
		t.Fatal(err)
	}

	// THEN: база создаётся ровно по заданному пути, а не по обрезанному
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("database not at configured path %q: %v", path, err)
	}
	// AND: обрезанный на первом спецсимволе путь не создан
	if _, err := os.Stat(filepath.Join(dir, "cert")); err == nil {
		t.Fatalf("truncated path %q was opened instead", filepath.Join(dir, "cert"))
	}
}
