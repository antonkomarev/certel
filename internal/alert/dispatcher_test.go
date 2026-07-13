package alert

import (
	"context"
	"log/slog"
	"reflect"
	"testing"
	"time"

	"github.com/antonkomarev/certel/internal/probe"
)

func testDispatcher(store OutboxStore, sender Sender) *Dispatcher {
	return NewDispatcher(sender, store, 4, slog.New(slog.DiscardHandler))
}

func TestDispatcherDeliversInEnqueueOrder(t *testing.T) {
	// GIVEN: две поставленные в очередь для одной цели записи — сначала проблема,
	// затем восстановление
	store := newFakeStore()
	store.seed("target-a", "expired")
	store.seed("target-a", "recovered")
	sender := &fakeSender{}
	d := testDispatcher(store, sender)

	// WHEN: диспетчер делает проход
	d.dispatchOnce(context.Background())

	// THEN: доставлены обе в порядке постановки, очередь пуста
	if got := sender.delivered(); !reflect.DeepEqual(got, []string{"expired", "recovered"}) {
		t.Fatalf("per-target FIFO expected, got %v", got)
	}
	if store.pending() != 0 {
		t.Fatalf("delivered rows must be removed, %d left", store.pending())
	}
}

func TestDispatcherRetriesFailedRowKeepingOrder(t *testing.T) {
	// GIVEN: одна запись, а эндпоинт падает на двух ближайших попытках
	store := newFakeStore()
	store.seed("target-a", "expired")
	sender := &fakeSender{failNext: 2}
	d := testDispatcher(store, sender)
	ctx := context.Background()

	// WHEN: первый проход — доставка падает
	d.dispatchOnce(ctx)
	if len(sender.delivered()) != 0 || store.pending() != 1 {
		t.Fatalf("failed send must keep the row queued, delivered=%v pending=%d",
			sender.delivered(), store.pending())
	}
	// WHEN: второй проход — снова падает
	d.dispatchOnce(ctx)
	if len(sender.delivered()) != 0 || store.pending() != 1 {
		t.Fatalf("second failure must still keep the row, delivered=%v pending=%d",
			sender.delivered(), store.pending())
	}
	// WHEN: третий проход — эндпоинт вернулся
	d.dispatchOnce(ctx)
	// THEN: запись наконец доставлена и удалена
	if got := sender.delivered(); !reflect.DeepEqual(got, []string{"expired"}) {
		t.Fatalf("row must deliver once endpoint returns, got %v", got)
	}
	if store.pending() != 0 {
		t.Fatalf("delivered row must be removed, %d left", store.pending())
	}
}

func TestHeadOfLineBlocksOnlyItsOwnHost(t *testing.T) {
	// GIVEN: у цели A эндпоинт постоянно падает, у цели B — работает
	store := newFakeStore()
	store.seed("target-a", "a-alert")
	store.seed("target-b", "b-alert")
	sender := &fakeSender{failBody: map[string]int{"a-alert": 1000}}
	d := testDispatcher(store, sender)

	// WHEN: диспетчер делает проход
	d.dispatchOnce(context.Background())

	// THEN: B доставлен, A застрял в своей очереди и не блокирует B
	if got := sender.delivered(); !reflect.DeepEqual(got, []string{"b-alert"}) {
		t.Fatalf("healthy target must deliver despite a stuck peer, got %v", got)
	}
	if store.pending() != 1 {
		t.Fatalf("stuck target's row must stay queued, pending=%d", store.pending())
	}
}

func TestCrashWindowReplaysUndeliveredAlert(t *testing.T) {
	// GIVEN: менеджер поставил критический алерт в очередь, но процесс упал до
	// отправки — диспетчер так и не отработал
	m, store, _ := testManager(t)
	ctx := context.Background()
	m.Process(ctx, result(probe.StatusExpired, probe.SeverityCritical))
	if store.pending() != 1 {
		t.Fatalf("problem must be enqueued before crash, pending=%d", store.pending())
	}

	// WHEN: свежий процесс поднимается — новый менеджер восстанавливает состояние,
	// новый диспетчер разгребает ту же очередь
	m2 := NewManager(m.notifiers, store, slog.New(slog.DiscardHandler))
	m2.Restore(store.states, nil)
	sender := &fakeSender{}
	testDispatcher(store, sender).dispatchOnce(ctx)

	// THEN: недоставленный алерт уходит ровно один раз, а не молчит repeat_interval
	if got := sender.delivered(); len(got) != 1 || got[0] != `{"msg":"expired/critical/recovered=false"}` {
		t.Fatalf("queued alert must survive the crash and deliver once, got %v", got)
	}
	if store.pending() != 0 {
		t.Fatalf("outbox must drain, %d left", store.pending())
	}
}

func TestFaithfulReplayAcrossFlipDuringDowntime(t *testing.T) {
	// GIVEN: критический алерт поставлен в очередь, но процесс упал до отправки
	m, store, now := testManager(t)
	ctx := context.Background()
	m.Process(ctx, result(probe.StatusExpired, probe.SeverityCritical))

	// WHEN: пока процесс лежал, сертификат починили; свежий процесс видит уже OK
	m2 := NewManager(m.notifiers, store, slog.New(slog.DiscardHandler))
	m2.Restore(store.states, nil)
	*now = now.Add(6 * time.Hour)
	m2.now = func() time.Time { return *now }
	m2.Process(ctx, result(probe.StatusOK, probe.SeverityOK))

	// THEN: в очереди обе записи, и диспетчер проигрывает честную ленту событий —
	// сначала «истёк», потом «восстановлено»
	sender := &fakeSender{}
	testDispatcher(store, sender).dispatchOnce(ctx)
	want := []string{`{"msg":"expired/critical/recovered=false"}`, `{"msg":"ok/ok/recovered=true"}`}
	if got := sender.delivered(); !reflect.DeepEqual(got, want) {
		t.Fatalf("faithful replay in event order expected, got %v", got)
	}
}

func TestDispatcherScopedToItsOwnNotifier(t *testing.T) {
	// GIVEN: очередь с записями двух нотификаторов под одним и тем же ключом цели
	store := newFakeStore()
	store.seedN("target-a", "chat", "chat-alert")
	store.seedN("target-a", "pager", "pager-alert")
	sender := &fakeSender{}

	// WHEN: диспетчер, привязанный к «chat», делает проход
	d := NewDispatcher(sender, store.forNotifier("chat"), 4, slog.New(slog.DiscardHandler))
	d.dispatchOnce(context.Background())

	// THEN: он доставил только свою запись; чужая осталась в очереди
	if got := sender.delivered(); !reflect.DeepEqual(got, []string{"chat-alert"}) {
		t.Fatalf("dispatcher must see only its own notifier's rows, got %v", got)
	}
	if store.pending() != 1 {
		t.Fatalf("other notifier's row must stay queued, pending=%d", store.pending())
	}
}

func TestDownNotifierDoesNotDelayHealthyOne(t *testing.T) {
	// GIVEN: у нотификатора «pager» эндпоинт всегда падает, у «chat» — работает;
	// каждый обслуживается своим диспетчером над своим срезом очереди
	store := newFakeStore()
	store.seedN("target-a", "pager", "pager-alert")
	store.seedN("target-b", "chat", "chat-alert")
	log := slog.New(slog.DiscardHandler)

	pagerSender := &fakeSender{failBody: map[string]int{"pager-alert": 1000}}
	chatSender := &fakeSender{}
	pager := NewDispatcher(pagerSender, store.forNotifier("pager"), 4, log)
	chat := NewDispatcher(chatSender, store.forNotifier("chat"), 4, log)

	// WHEN: оба диспетчера делают проход
	ctx := context.Background()
	pager.dispatchOnce(ctx)
	chat.dispatchOnce(ctx)

	// THEN: здоровый нотификатор доставил свою запись, несмотря на застрявший соседний
	if got := chatSender.delivered(); !reflect.DeepEqual(got, []string{"chat-alert"}) {
		t.Fatalf("healthy notifier must deliver despite a down peer, got %v", got)
	}
	if len(pagerSender.delivered()) != 0 || store.pending() != 1 {
		t.Fatalf("down notifier's row must stay queued, delivered=%v pending=%d",
			pagerSender.delivered(), store.pending())
	}
}

func TestDeliveredRecoveryNotResent(t *testing.T) {
	// GIVEN: восстановление доставлено и удалено из очереди
	store := newFakeStore()
	store.seed("target-a", "recovered")
	sender := &fakeSender{}
	d := testDispatcher(store, sender)
	d.dispatchOnce(context.Background())

	// WHEN: последующие проходы диспетчера
	d.dispatchOnce(context.Background())
	// THEN: повторной отправки нет — очередь пуста
	if got := sender.delivered(); len(got) != 1 {
		t.Fatalf("recovery must not re-send after delivery, got %v", got)
	}
}
