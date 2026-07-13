package alert

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/antonkomarev/certel/internal/config"
	"github.com/antonkomarev/certel/internal/probe"
)

// testNotifier is the single notifier every test target resolves to.
const testNotifier = "default"

// testRepeat is the 24h scalar repeat cadence every test target carries; the
// cadence now lives on the target, not the notifier.
func testRepeat() config.RepeatInterval {
	return config.NewRepeatInterval(config.Duration(24 * time.Hour))
}

// testBody compiles a single-field body whose "msg" string carries the given
// references; a rendered alert is therefore the JSON object {"msg":"..."}.
func testBody(t *testing.T, msg string) *Body {
	t.Helper()
	b, err := ParseBody(map[string]any{"msg": msg}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testManager(t *testing.T) (*Manager, *fakeStore, *time.Time) {
	t.Helper()
	body := testBody(t, `${alert.Status}/${alert.Severity}/recovered=${alert.Recovered}`)
	cfg := config.AlertConfig{
		SendRecovery: boolPtr(true),
	}
	store := newFakeStore()
	runtimes := map[string]NotifierRuntime{testNotifier: {Config: cfg, Body: body}}
	m := NewManager(runtimes, store, slog.New(slog.DiscardHandler))
	now := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	return m, store, &now
}

func result(status probe.Status, sev probe.Severity) probe.Result {
	return probe.Result{
		Target: config.Target{
			Address:  "example.com:443",
			Protocol: config.ProtoTLS,
			TargetParams: config.TargetParams{
				Notifiers:           []string{testNotifier},
				AlertRepeatInterval: testRepeat(),
			},
		},
		Status:   status,
		Severity: sev,
	}
}

func intPtr(n int) *int { return &n }

func boolPtr(b bool) *bool { return &b }

// resultN is result with an explicit flap_streak threshold, for the flap
// debounce tests.
func resultN(status probe.Status, sev probe.Severity, flapStreak int) probe.Result {
	r := result(status, sev)
	r.Target.FlapStreak = intPtr(flapStreak)
	return r
}

func TestEnqueueOnTransitionNotOnEveryCheck(t *testing.T) {
	// GIVEN: менеджер с интервалом повтора в сутки и включёнными уведомлениями о восстановлении
	m, store, now := testManager(t)
	ctx := context.Background()

	// WHEN: цель здорова
	m.Process(ctx, result(probe.StatusOK, probe.SeverityOK))
	// THEN: тревога не ставится в очередь
	if got := len(store.bodies()); got != 0 {
		t.Fatalf("healthy target must not enqueue, got %v", store.bodies())
	}

	// WHEN: цель впервые переходит в состояние предупреждения
	m.Process(ctx, result(probe.StatusExpiringSoon, probe.SeverityWarning))
	// THEN: об изменении состояния уведомляют ровно один раз
	if got := len(store.bodies()); got != 1 {
		t.Fatalf("transition into warning must enqueue once, got %d", got)
	}

	// WHEN: та же проблема сохраняется внутри интервала повтора
	*now = now.Add(5 * time.Minute)
	m.Process(ctx, result(probe.StatusExpiringSoon, probe.SeverityWarning))
	// THEN: повторного спама быть не должно
	if got := len(store.bodies()); got != 1 {
		t.Fatalf("persisting problem within repeat_interval must stay silent, got %d", got)
	}

	// WHEN: серьёзность эскалируется с предупреждения до критической
	m.Process(ctx, result(probe.StatusExpiringSoon, probe.SeverityCritical))
	// THEN: об эскалации уведомляют немедленно
	if got := len(store.bodies()); got != 2 {
		t.Fatalf("severity escalation must enqueue, got %d", got)
	}

	// WHEN: проблема держится дольше интервала повтора
	*now = now.Add(25 * time.Hour)
	m.Process(ctx, result(probe.StatusExpiringSoon, probe.SeverityCritical))
	// THEN: приходит напоминание о всё ещё открытом инциденте
	if got := len(store.bodies()); got != 3 {
		t.Fatalf("reminder after repeat_interval expected, got %d", got)
	}

	// WHEN: цель восстанавливается
	m.Process(ctx, result(probe.StatusOK, probe.SeverityOK))
	// THEN: в очередь ставится уведомление о восстановлении
	bodies := store.bodies()
	if len(bodies) != 4 || bodies[3] != `{"msg":"ok/ok/recovered=true"}` {
		t.Fatalf("recovery notice expected, got %v", bodies)
	}
	// WHEN: цель остаётся здоровой после восстановления
	m.Process(ctx, result(probe.StatusOK, probe.SeverityOK))
	// THEN: новых уведомлений нет
	if got := len(store.bodies()); got != 4 {
		t.Fatalf("healthy after recovery must stay silent, got %d", got)
	}
}

func TestFlapDebounceSuppressesTransientUnreachable(t *testing.T) {
	// GIVEN: здоровая цель с порогом подтверждения 2
	m, store, _ := testManager(t)
	ctx := context.Background()
	m.Process(ctx, resultN(probe.StatusOK, probe.SeverityOK, 2))

	// WHEN: одиночный сетевой сбой, а следующий цикл снова здоров
	m.Process(ctx, resultN(probe.StatusUnreachable, probe.SeverityCritical, 2))
	// THEN: пока сбой не подтверждён — ни одной тревоги
	if got := len(store.bodies()); got != 0 {
		t.Fatalf("unconfirmed unreachable must not enqueue, got %v", store.bodies())
	}
	m.Process(ctx, resultN(probe.StatusOK, probe.SeverityOK, 2))
	// THEN: моргание погашено целиком — ни тревоги, ни восстановления
	if got := len(store.bodies()); got != 0 {
		t.Fatalf("transient blip must produce no alert/recovery pair, got %v", store.bodies())
	}
}

func TestFlapDebounceAlertsAfterFlapStreak(t *testing.T) {
	// GIVEN: здоровая цель с порогом подтверждения 2
	m, store, now := testManager(t)
	ctx := context.Background()
	m.Process(ctx, resultN(probe.StatusOK, probe.SeverityOK, 2))

	// WHEN: сбой держится первый цикл
	m.Process(ctx, resultN(probe.StatusUnreachable, probe.SeverityCritical, 2))
	if got := len(store.bodies()); got != 0 {
		t.Fatalf("first bad cycle must stay silent, got %d", got)
	}
	// WHEN: сбой подтверждён вторым подряд циклом
	m.Process(ctx, resultN(probe.StatusUnreachable, probe.SeverityCritical, 2))
	// THEN: тревога уходит ровно один раз
	if got := len(store.bodies()); got != 1 {
		t.Fatalf("confirmed unreachable must enqueue once, got %d", got)
	}
	// WHEN: сбой держится и дальше, внутри интервала повтора
	*now = now.Add(5 * time.Minute)
	m.Process(ctx, resultN(probe.StatusUnreachable, probe.SeverityCritical, 2))
	// THEN: повторного спама нет
	if got := len(store.bodies()); got != 1 {
		t.Fatalf("persisting unreachable within repeat_interval must stay silent, got %d", got)
	}
}

func TestFlapDebounceNeverDelaysFactStatus(t *testing.T) {
	// GIVEN: здоровая цель с порогом подтверждения 2
	m, store, _ := testManager(t)
	ctx := context.Background()

	// WHEN: первый же цикл показывает истёкший сертификат — это факт, не сетевой шум
	m.Process(ctx, resultN(probe.StatusExpired, probe.SeverityEmergency, 2))
	// THEN: тревога уходит немедленно, дебаунс её не задерживает
	if got := len(store.bodies()); got != 1 {
		t.Fatalf("fact status must alert on first observation despite debounce, got %d", got)
	}
}

func TestFlapDebounceProtectsAlreadyWarningTarget(t *testing.T) {
	// GIVEN: цель уже в предупреждении (истекает скоро), порог подтверждения 2
	m, store, _ := testManager(t)
	ctx := context.Background()
	m.Process(ctx, resultN(probe.StatusExpiringSoon, probe.SeverityWarning, 2))
	if got := len(store.bodies()); got != 1 {
		t.Fatalf("transition into warning must enqueue once, got %d", got)
	}

	// WHEN: одиночный сетевой сбой и возврат в предупреждение
	m.Process(ctx, resultN(probe.StatusUnreachable, probe.SeverityCritical, 2))
	m.Process(ctx, resultN(probe.StatusExpiringSoon, probe.SeverityWarning, 2))
	// THEN: пары ложных смен формы (warning→critical→warning) нет — только исходная тревога
	if got := len(store.bodies()); got != 1 {
		t.Fatalf("blip on a warning target must not add churn, got %d", got)
	}
}

func TestFlapDebounceRecoveryIsSymmetric(t *testing.T) {
	// GIVEN: подтверждённый и разосланный инцидент unreachable (порог 2)
	m, store, now := testManager(t)
	ctx := context.Background()
	m.Process(ctx, resultN(probe.StatusUnreachable, probe.SeverityCritical, 2))
	m.Process(ctx, resultN(probe.StatusUnreachable, probe.SeverityCritical, 2))
	if got := len(store.bodies()); got != 1 {
		t.Fatalf("setup: confirmed unreachable must enqueue once, got %d", got)
	}

	// WHEN: цель моргает вверх на один цикл и снова падает
	m.Process(ctx, resultN(probe.StatusOK, probe.SeverityOK, 2))
	m.Process(ctx, resultN(probe.StatusUnreachable, probe.SeverityCritical, 2))
	// THEN: восстановление не рассылалось — пила down-up-down не даёт мусорной пары
	if got := len(store.bodies()); got != 1 {
		t.Fatalf("unconfirmed recovery must not enqueue, got %d", got)
	}

	// WHEN: восстановление подтверждено двумя подряд здоровыми циклами
	*now = now.Add(5 * time.Minute)
	m.Process(ctx, resultN(probe.StatusOK, probe.SeverityOK, 2))
	m.Process(ctx, resultN(probe.StatusOK, probe.SeverityOK, 2))
	// THEN: уведомление о восстановлении уходит ровно один раз
	bodies := store.bodies()
	if len(bodies) != 2 || bodies[1] != `{"msg":"ok/ok/recovered=true"}` {
		t.Fatalf("confirmed recovery expected, got %v", bodies)
	}
}

func TestFlapDebounceRebuildsCounterOnRestart(t *testing.T) {
	// GIVEN: цель, у которой перед рестартом уже был один неподтверждённый цикл
	// unreachable — он записан в probe_log, но тревоги ещё не было (порог 2)
	m, store, _ := testManager(t)
	ctx := context.Background()
	target := resultN(probe.StatusUnreachable, probe.SeverityCritical, 2).Target
	store.seedProbeHistory(target.Key(), ProbeObservation{
		Status: probe.StatusUnreachable, Severity: probe.SeverityCritical,
	})

	// WHEN: свежий менеджер восстанавливается и переигрывает счётчик из probe_log
	m2 := NewManager(m.notifiers, store, slog.New(slog.DiscardHandler))
	m2.now = m.now
	m2.Restore(store.states, []config.Target{target})

	// WHEN: приходит один новый цикл unreachable
	m2.Process(ctx, resultN(probe.StatusUnreachable, probe.SeverityCritical, 2))
	// THEN: тревога уходит сразу — счётчик продолжился с 1, а не начался с нуля
	if got := len(store.bodies()); got != 1 {
		t.Fatalf("rebuilt counter must confirm on the next cycle, got %d", got)
	}
}

func TestRepeatTimerStartsAtEnqueue(t *testing.T) {
	// GIVEN: свежая критическая проблема
	m, store, now := testManager(t)
	ctx := context.Background()
	m.Process(ctx, result(probe.StatusExpired, probe.SeverityCritical))
	if got := len(store.bodies()); got != 1 {
		t.Fatalf("new problem must enqueue, got %d", got)
	}

	// WHEN: проблема держится внутри интервала повтора
	*now = now.Add(23 * time.Hour)
	m.Process(ctx, result(probe.StatusExpired, probe.SeverityCritical))
	// THEN: повтора нет — таймер отсчитывается от момента постановки в очередь
	if got := len(store.bodies()); got != 1 {
		t.Fatalf("within repeat_interval must not re-enqueue, got %d", got)
	}

	// WHEN: интервал повтора истёк
	*now = now.Add(2 * time.Hour)
	m.Process(ctx, result(probe.StatusExpired, probe.SeverityCritical))
	// THEN: приходит напоминание
	if got := len(store.bodies()); got != 2 {
		t.Fatalf("reminder after repeat_interval expected, got %d", got)
	}
}

func TestRepeatCadenceTightensWithSeverity(t *testing.T) {
	// GIVEN: у цели разная частота повтора по серьёзности — предупреждение раз в
	// 3 дня, критическое раз в час (каденция живёт на цели, не на нотификаторе)
	m, store, now := testManager(t)
	cadence := config.NewRepeatIntervalMap(map[string]config.Duration{
		"warning":   config.Duration(3 * 24 * time.Hour),
		"critical":  config.Duration(time.Hour),
		"emergency": config.Duration(time.Hour),
	})
	res := func(status probe.Status, sev probe.Severity) probe.Result {
		r := result(status, sev)
		r.Target.AlertRepeatInterval = cadence
		return r
	}
	ctx := context.Background()

	// WHEN: цель в предупреждении, проходит час (внутри 3-дневной каденции)
	m.Process(ctx, res(probe.StatusExpiringSoon, probe.SeverityWarning))
	*now = now.Add(time.Hour)
	m.Process(ctx, res(probe.StatusExpiringSoon, probe.SeverityWarning))
	// THEN: напоминания нет — предупреждение напоминает раз в 3 дня
	if got := len(store.bodies()); got != 1 {
		t.Fatalf("warning within 3d cadence must stay silent, got %d", got)
	}

	// WHEN: серьёзность растёт до критической (немедленное уведомление об эскалации)
	m.Process(ctx, res(probe.StatusExpiringSoon, probe.SeverityCritical))
	if got := len(store.bodies()); got != 2 {
		t.Fatalf("escalation to critical must enqueue, got %d", got)
	}

	// WHEN: проблема держится критической ещё час (истекла часовая каденция)
	*now = now.Add(time.Hour)
	m.Process(ctx, res(probe.StatusExpiringSoon, probe.SeverityCritical))
	// THEN: приходит напоминание — критическое напоминает раз в час, не раз в 3 дня
	if got := len(store.bodies()); got != 3 {
		t.Fatalf("critical reminder after 1h cadence expected, got %d", got)
	}
}

func TestNoRecoveryWhenDisabled(t *testing.T) {
	// GIVEN: менеджер с отключёнными уведомлениями о восстановлении
	m, store, _ := testManager(t)
	rt := m.notifiers[testNotifier]
	rt.Config.SendRecovery = boolPtr(false)
	m.notifiers[testNotifier] = rt
	ctx := context.Background()

	// WHEN: инцидент возникает, а затем цель восстанавливается
	m.Process(ctx, result(probe.StatusExpired, probe.SeverityCritical))
	m.Process(ctx, result(probe.StatusOK, probe.SeverityOK))
	// THEN: в очередь попадает только уведомление о проблеме, без восстановления
	if got := len(store.bodies()); got != 1 {
		t.Fatalf("recovery disabled: want 1 alert only, got %d", got)
	}
	// THEN: но состояние восстановления всё равно сохранено, чтобы дедуп не зациклился
	if st := store.states["tls//example.com:443/"]; st.Severity != probe.SeverityOK {
		t.Fatalf("recovered state must persist even with recovery disabled, got %q", st.Severity)
	}
}

func TestNotifyFiredOnEnqueue(t *testing.T) {
	// GIVEN: менеджер с подключённым уведомлением диспетчера
	m, _, _ := testManager(t)
	ctx := context.Background()
	var woke int
	m.Notify = func(string) { woke++ }

	// WHEN: здоровая проверка — постановки в очередь нет
	m.Process(ctx, result(probe.StatusOK, probe.SeverityOK))
	if woke != 0 {
		t.Fatalf("no enqueue must not wake dispatcher, got %d", woke)
	}
	// WHEN: возникает проблема
	m.Process(ctx, result(probe.StatusExpired, probe.SeverityCritical))
	// THEN: диспетчер разбужен
	if woke != 1 {
		t.Fatalf("enqueue must wake dispatcher once, got %d", woke)
	}
}

func TestPerNotifierBodyAndPolicy(t *testing.T) {
	// GIVEN: два нотификатора с разными телами и политиками — «chat» шлёт
	// восстановления, «pager» нет; каждый со своим текстом тела
	chatBody := testBody(t, `chat:${alert.Status}`)
	pagerBody := testBody(t, `pager:${alert.Status}`)
	store := newFakeStore()
	runtimes := map[string]NotifierRuntime{
		"chat":  {Config: config.AlertConfig{SendRecovery: boolPtr(true)}, Body: chatBody},
		"pager": {Config: config.AlertConfig{SendRecovery: boolPtr(false)}, Body: pagerBody},
	}
	m := NewManager(runtimes, store, slog.New(slog.DiscardHandler))
	ctx := context.Background()

	targetFor := func(addr, notifier string, status probe.Status, sev probe.Severity) probe.Result {
		return probe.Result{
			Target: config.Target{
				Address:  addr,
				Protocol: config.ProtoTLS,
				TargetParams: config.TargetParams{
					Notifiers:           []string{notifier},
					AlertRepeatInterval: testRepeat(),
				},
			},
			Status: status, Severity: sev,
		}
	}

	// WHEN: обе цели ломаются, затем обе восстанавливаются
	m.Process(ctx, targetFor("a:443", "chat", probe.StatusExpired, probe.SeverityCritical))
	m.Process(ctx, targetFor("b:443", "pager", probe.StatusExpired, probe.SeverityCritical))
	m.Process(ctx, targetFor("a:443", "chat", probe.StatusOK, probe.SeverityOK))
	m.Process(ctx, targetFor("b:443", "pager", probe.StatusOK, probe.SeverityOK))

	// THEN: тело каждой цели отрендерено шаблоном его нотификатора, и лишь
	// «chat» (SendRecovery=true) добавил уведомление о восстановлении
	want := []string{`{"msg":"chat:expired"}`, `{"msg":"pager:expired"}`, `{"msg":"chat:ok"}`}
	if got := store.bodies(); !reflect.DeepEqual(got, want) {
		t.Fatalf("per-notifier body/policy mismatch: got %v, want %v", got, want)
	}
}

// fanOutManager builds a Manager over two notifiers: ssl carries every alert
// (floor warning), alert only already-failing ones (floor emergency). Both send
// recoveries. The body echoes the clamped view each channel saw.
func fanOutManager(t *testing.T) (*Manager, *fakeStore, func(probe.Status, probe.Severity) probe.Result) {
	t.Helper()
	body := testBody(t, `${alert.Status}/${alert.Severity}/recovered=${alert.Recovered}`)
	store := newFakeStore()
	runtimes := map[string]NotifierRuntime{
		"ssl":   {Config: config.AlertConfig{SendRecovery: boolPtr(true), MinSeverity: "warning"}, Body: body},
		"alert": {Config: config.AlertConfig{SendRecovery: boolPtr(true), MinSeverity: "emergency"}, Body: body},
	}
	m := NewManager(runtimes, store, slog.New(slog.DiscardHandler))
	now := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	res := func(status probe.Status, sev probe.Severity) probe.Result {
		return probe.Result{
			Target: config.Target{
				Address:  "example.com:443",
				Protocol: config.ProtoTLS,
				TargetParams: config.TargetParams{
					Notifiers:           []string{"ssl", "alert"},
					AlertRepeatInterval: testRepeat(),
				},
			},
			Status: status, Severity: sev,
		}
	}
	return m, store, res
}

func TestFanOutPerNotifierMinSeverity(t *testing.T) {
	// GIVEN: цель, разосланная в ssl (порог warning) и alert (порог emergency)
	m, store, res := fanOutManager(t)
	ctx := context.Background()

	// WHEN: ok → critical — ssl видит критику, alert (порог emergency) молчит
	m.Process(ctx, res(probe.StatusExpiringSoon, probe.SeverityCritical))
	if got := store.bodiesForNotifier("ssl"); len(got) != 1 || got[0] != `{"msg":"expiring_soon/critical/recovered=false"}` {
		t.Fatalf("ssl must receive the critical alert, got %v", got)
	}
	if got := store.bodiesForNotifier("alert"); len(got) != 0 {
		t.Fatalf("alert (floor emergency) must not see a critical, got %v", got)
	}

	// WHEN: critical → emergency — ssl эскалирует, alert впервые срабатывает,
	// пересекая свой порог вверх (немедленно, а не по таймеру)
	m.Process(ctx, res(probe.StatusExpired, probe.SeverityEmergency))
	if got := store.bodiesForNotifier("ssl"); len(got) != 2 || got[1] != `{"msg":"expired/emergency/recovered=false"}` {
		t.Fatalf("ssl must receive the emergency escalation, got %v", got)
	}
	if got := store.bodiesForNotifier("alert"); len(got) != 1 || got[0] != `{"msg":"expired/emergency/recovered=false"}` {
		t.Fatalf("alert must fire when severity crosses its floor, got %v", got)
	}

	// WHEN: emergency → critical (упало ниже порога, но всё ещё плохо) — для alert
	// это восстановление (его вид склампился в ok), ssl видит критику
	m.Process(ctx, res(probe.StatusUnreachable, probe.SeverityCritical))
	if got := store.bodiesForNotifier("alert"); len(got) != 2 || got[1] != `{"msg":"ok/ok/recovered=true"}` {
		t.Fatalf("alert must recover when the problem drops below its floor, got %v", got)
	}
	if got := store.bodiesForNotifier("ssl"); len(got) != 3 || got[2] != `{"msg":"unreachable/critical/recovered=false"}` {
		t.Fatalf("ssl must see the critical update, got %v", got)
	}

	// WHEN: critical → ok (продление) — ssl восстанавливается, alert уже
	// восстановлен и молчит
	m.Process(ctx, res(probe.StatusOK, probe.SeverityOK))
	if got := store.bodiesForNotifier("ssl"); len(got) != 4 || got[3] != `{"msg":"ok/ok/recovered=true"}` {
		t.Fatalf("ssl must recover on renewal, got %v", got)
	}
	if got := store.bodiesForNotifier("alert"); len(got) != 2 {
		t.Fatalf("alert already recovered, must stay silent, got %v", got)
	}
}

func TestFanOutRepeatRespectsFloor(t *testing.T) {
	// GIVEN: та же пара нотификаторов, но проблема держится критической
	m, store, res := fanOutManager(t)
	now := m.now()
	m.now = func() time.Time { return now }
	ctx := context.Background()

	// WHEN: критическая проблема возникает и держится дольше суточной каденции
	m.Process(ctx, res(probe.StatusUnreachable, probe.SeverityCritical))
	now = now.Add(25 * time.Hour)
	m.Process(ctx, res(probe.StatusUnreachable, probe.SeverityCritical))
	// THEN: ssl получает исходную тревогу и напоминание; alert не видит критику вовсе
	if got := store.bodiesForNotifier("ssl"); len(got) != 2 {
		t.Fatalf("ssl must get the alert plus one reminder, got %v", got)
	}
	if got := store.bodiesForNotifier("alert"); len(got) != 0 {
		t.Fatalf("critical below alert's floor must never reach it, got %v", got)
	}

	// WHEN: проблема эскалирует до emergency и держится дольше каденции
	m.Process(ctx, res(probe.StatusExpired, probe.SeverityEmergency))
	now = now.Add(25 * time.Hour)
	m.Process(ctx, res(probe.StatusExpired, probe.SeverityEmergency))
	// THEN: теперь оба напоминают синхронно по общему таймеру цели
	if got := store.bodiesForNotifier("ssl"); len(got) != 4 {
		t.Fatalf("ssl must get the escalation plus its reminder, got %v", got)
	}
	if got := store.bodiesForNotifier("alert"); len(got) != 2 {
		t.Fatalf("alert must get the emergency trigger plus a shared reminder, got %v", got)
	}
}

func TestWebhookSenderAttemptCount(t *testing.T) {
	// GIVEN: эндпоинт, который всегда отвечает 500 и считает попытки. Семантика
	// retries — «дополнительные попытки после первой», значит всего попыток
	// retries+1. retries: 0 обязано означать ровно одну доставку.
	cases := []struct {
		name        string
		retries     int
		wantCalls   int
		wantErrPart string
	}{
		{"zero retries is one attempt", 0, 1, "after 1 attempt(s)"},
		{"one retry is two attempts", 1, 2, "after 2 attempt(s)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer srv.Close()

			retries := tc.retries
			s, err := NewWebhookSender(config.AlertConfig{
				URL: srv.URL, Method: "POST",
				Timeout: config.Duration(2 * time.Second), Retries: &retries,
			})
			if err != nil {
				t.Fatal(err)
			}
			s.after = func(time.Duration) <-chan time.Time { return closedTimeChan() }

			// WHEN: доставка идёт против постоянно падающего эндпоинта
			err = s.Send(context.Background(), []byte("{}"))

			// THEN: число попыток равно retries+1, а ошибка называет их количество
			if calls != tc.wantCalls {
				t.Errorf("attempts: got %d, want %d", calls, tc.wantCalls)
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErrPart) {
				t.Errorf("want error containing %q, got %v", tc.wantErrPart, err)
			}
		})
	}
}
