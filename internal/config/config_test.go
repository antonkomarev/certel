package config

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// minimalNotifier defines one notifier and routes every target to it via
// target_defaults, so appended targets resolve without repeating the selector.
const minimalNotifier = `
notifiers:
  default:
    url: https://example.com/alert
    body: {host: "${alert.Host}"}
target_defaults:
  notifiers: [default]
`

func TestLoadAppliesDefaults(t *testing.T) {
	// GIVEN: конфиг с минимумом полей — интервал, порты и пороги должны взяться из умолчаний,
	// а цели покрывают разные протоколы и один явно заданный порт с переопределённым порогом
	t.Setenv("ALERT_TOKEN", "secret-token")

	// WHEN: конфиг загружен
	cfg, err := Load(writeConfig(t, minimalNotifier+`
targets:
  - address: example.com
  - address: mail.example.com
    protocol: smtp
  - address: db.example.com:15432
    protocol: postgres
    warning_days: 45
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// THEN: не заданные значения заполнены умолчаниями, а явно указанные — сохранены
	if cfg.Probe.CheckInterval.Std() != 5*time.Minute {
		t.Errorf("check_interval default = %v, want 5m", cfg.Probe.CheckInterval.Std())
	}
	if cfg.Notifiers["default"].Concurrency != 10 {
		t.Errorf("notifier concurrency default = %d, want 10", cfg.Notifiers["default"].Concurrency)
	}
	if got := cfg.Targets[0].Address; got != "example.com:443" {
		t.Errorf("tls default port: got %q, want example.com:443", got)
	}
	if got := cfg.Targets[1].Address; got != "mail.example.com:587" {
		t.Errorf("smtp default port: got %q, want mail.example.com:587", got)
	}
	if got := cfg.Targets[2].Address; got != "db.example.com:15432" {
		t.Errorf("explicit port must be kept: got %q", got)
	}
	if *cfg.Targets[0].WarningDays != 30 || *cfg.Targets[0].CriticalDays != 7 {
		t.Errorf("threshold defaults not applied: warning=%d critical=%d",
			*cfg.Targets[0].WarningDays, *cfg.Targets[0].CriticalDays)
	}
	if *cfg.Targets[2].WarningDays != 45 {
		t.Errorf("per-target warning_days override lost: got %d", *cfg.Targets[2].WarningDays)
	}
	wantDB := filepath.Join("db", "certel.sqlite")
	if !strings.HasSuffix(cfg.Database.Path, wantDB) {
		t.Errorf("database.path default = %q, want a path ending in %q", cfg.Database.Path, wantDB)
	}
	if exe, err := os.Executable(); err == nil {
		if got, want := filepath.Dir(filepath.Dir(cfg.Database.Path)), filepath.Dir(exe); got != want {
			t.Errorf("database.path default must sit next to the binary: got dir %q, want %q", got, want)
		}
	}
	if cfg.Database.ProbeLogRetention.Std() != 90*24*time.Hour {
		t.Errorf("database.probe_log_retention default = %v, want 2160h", cfg.Database.ProbeLogRetention.Std())
	}
	if cfg.Database.AlertLogRetention.Std() != 365*24*time.Hour {
		t.Errorf("database.alert_log_retention default = %v, want 8760h", cfg.Database.AlertLogRetention.Std())
	}
}

func TestNotifierSelector(t *testing.T) {
	// GIVEN: два нотификатора; target_defaults указывает на один, отдельная цель переопределяет на другой
	t.Setenv("ALERT_TOKEN", "secret-token")
	cfg, err := Load(writeConfig(t, `
notifiers:
  default:
    url: https://chat.example.com/hook
    body: {text: x}
  pager:
    url: https://pager.example.com/enqueue
    body: {text: y}
target_defaults:
  notifiers: [default]
targets:
  - address: example.com
  - address: db.example.com
    protocol: postgres
    notifiers: [pager]
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// THEN: цель без селектора наследует target_defaults.notifiers, а переопределивший — свой
	if got := cfg.Targets[0].Notifiers; len(got) != 1 || got[0] != "default" {
		t.Errorf("target_defaults.notifiers must fill an omitting target, got %v", got)
	}
	if got := cfg.Targets[1].Notifiers; len(got) != 1 || got[0] != "pager" {
		t.Errorf("per-target notifiers override must win, got %v", got)
	}
}

func TestNotifierFanOutList(t *testing.T) {
	// GIVEN: target_defaults задаёт список нотификаторов, одна цель его переопределяет
	// своим списком из нескольких, другая — своим списком из одного
	cfg, err := Load(writeConfig(t, `
notifiers:
  ssl_chat:
    url: https://chat.example.com/hooks/ssl
    body: {text: x}
  alert_chat:
    url: https://chat.example.com/hooks/alerts
    body: {text: y}
target_defaults:
  notifiers: [ssl_chat]
targets:
  - address: example.com
  - address: shop.example.com
    notifiers: [ssl_chat, alert_chat]
  - address: db.example.com
    notifiers: [alert_chat]
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Targets[0].Notifiers; len(got) != 1 || got[0] != "ssl_chat" {
		t.Errorf("target must inherit target_defaults.notifiers, got %v", got)
	}
	if got := cfg.Targets[1].Notifiers; len(got) != 2 || got[0] != "ssl_chat" || got[1] != "alert_chat" {
		t.Errorf("per-target notifiers list must win, got %v", got)
	}
	if got := cfg.Targets[2].Notifiers; len(got) != 1 || got[0] != "alert_chat" {
		t.Errorf("one-element per-target notifiers list must win, got %v", got)
	}
}

func TestMinSeverityDefaultAndOverride(t *testing.T) {
	// GIVEN: один нотификатор задаёт min_severity: emergency, другой оставляет по умолчанию
	cfg, err := Load(writeConfig(t, `
notifiers:
  ssl_chat:
    url: https://chat.example.com/hooks/ssl
    body: {text: x}
  alert_chat:
    url: https://chat.example.com/hooks/alerts
    body: {text: y}
    min_severity: emergency
target_defaults:
  notifiers: [ssl_chat]
targets:
  - address: example.com
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Notifiers["ssl_chat"].MinSeverity; got != "warning" {
		t.Errorf("min_severity default must be warning, got %q", got)
	}
	if got := cfg.Notifiers["alert_chat"].MinSeverity; got != "emergency" {
		t.Errorf("min_severity override lost, got %q", got)
	}
}

func TestPerNotifierDefaultsIndependent(t *testing.T) {
	// GIVEN: два нотификатора — один задаёт часть полей явно (включая retries: 0),
	// другой полностью на умолчаниях
	cfg, err := Load(writeConfig(t, `
notifiers:
  explicit:
    url: https://a.example.com/hook
    body: {text: x}
    method: PUT
    retries: 0
    min_severity: emergency
    concurrency: 3
  bare:
    url: https://b.example.com/hook
    body: {text: y}
target_defaults:
  notifiers: [explicit]
targets:
  - address: example.com
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// THEN: явные значения одного нотификатора не протекают в другой, а его retries: 0 переживает дефолтинг
	ex := cfg.Notifiers["explicit"]
	if ex.Method != "PUT" || ex.Retries == nil || *ex.Retries != 0 || ex.Concurrency != 3 || ex.MinSeverity != "emergency" {
		t.Errorf("explicit notifier defaults clobbered: %+v (retries=%v)", ex, ex.Retries)
	}
	bare := cfg.Notifiers["bare"]
	if bare.Method != "POST" || !bare.SendRecoveryEnabled() || bare.Concurrency != 10 ||
		bare.Retries == nil || *bare.Retries != 2 || bare.MinSeverity != "warning" ||
		bare.Timeout.Std() != 10*time.Second {
		t.Errorf("bare notifier did not receive independent defaults: %+v (retries=%v)", bare, bare.Retries)
	}
}

func TestAlertRepeatIntervalPerSeverityMap(t *testing.T) {
	// GIVEN: target_defaults задаёт alert_repeat_interval полной картой по
	// серьёзности, а одна цель переопределяет его скалярной формой (одинаковый
	// интервал для всех) — каденция живёт на цели, не на нотификаторе
	cfg, err := Load(writeConfig(t, minimalNotifier+`
  alert_repeat_interval:
    warning: 3d
    critical: 1d
    emergency: 2h
targets:
  - address: mapped.example.com
  - address: flat.example.com
    alert_repeat_interval: 6h
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// THEN: карта разобрана по серьёзности, а скаляр применён ко всем серьёзностям
	mapped := cfg.Targets[0].AlertRepeatInterval
	if got := mapped.For("warning"); got != 3*24*time.Hour {
		t.Errorf("warning cadence: got %v, want 72h", got)
	}
	if got := mapped.For("critical"); got != 24*time.Hour {
		t.Errorf("critical cadence: got %v, want 24h", got)
	}
	if got := mapped.For("emergency"); got != 2*time.Hour {
		t.Errorf("emergency cadence: got %v, want 2h", got)
	}
	flat := cfg.Targets[1].AlertRepeatInterval
	for _, sev := range []string{"warning", "critical", "emergency"} {
		if got := flat.For(sev); got != 6*time.Hour {
			t.Errorf("scalar form %s cadence: got %v, want 6h", sev, got)
		}
	}
}

func TestAlertRepeatIntervalNever(t *testing.T) {
	// GIVEN: одна цель отключает повтор для warning через "never" в карте, другая
	// задаёт "never" скаляром (раз и без напоминаний для всех серьёзностей)
	cfg, err := Load(writeConfig(t, minimalNotifier+`
  alert_repeat_interval:
    warning: never
    critical: 1d
    emergency: 1h
targets:
  - address: warn-once.example.com
  - address: all-once.example.com
    alert_repeat_interval: never
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// THEN: "never" превращается в сентинел repeatNever (огромная каденция, до
	// которой сравнение в Process не дотягивается), а остальные записи — обычные
	never := time.Duration(math.MaxInt64)
	mapped := cfg.Targets[0].AlertRepeatInterval
	if got := mapped.For("warning"); got != never {
		t.Errorf("warning cadence: got %v, want repeatNever (%v)", got, never)
	}
	if got := mapped.For("critical"); got != 24*time.Hour {
		t.Errorf("critical cadence: got %v, want 24h", got)
	}
	if got := mapped.For("emergency"); got != time.Hour {
		t.Errorf("emergency cadence: got %v, want 1h", got)
	}
	scalar := cfg.Targets[1].AlertRepeatInterval
	for _, sev := range []string{"warning", "critical", "emergency"} {
		if got := scalar.For(sev); got != never {
			t.Errorf("scalar never %s cadence: got %v, want repeatNever", sev, got)
		}
	}
}

func TestFlapStreakDefaultAndFallback(t *testing.T) {
	// GIVEN: target_defaults задаёт flap_streak, одна цель переопределяет его
	cfg, err := Load(writeConfig(t, `
notifiers:
  default:
    url: https://e.com/a
    body: {text: x}
target_defaults:
  notifiers: [default]
  flap_streak: 3
targets:
  - address: inherits.com
  - address: overrides.com
    flap_streak: 1
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// THEN: цель без своего значения наследует target_defaults, переопределившая — своё
	if cfg.Targets[0].FlapStreak == nil || *cfg.Targets[0].FlapStreak != 3 {
		t.Errorf("target must inherit target_defaults.flap_streak=3, got %v", cfg.Targets[0].FlapStreak)
	}
	if cfg.Targets[1].FlapStreak == nil || *cfg.Targets[1].FlapStreak != 1 {
		t.Errorf("per-target flap_streak override must win, got %v", cfg.Targets[1].FlapStreak)
	}
}

func TestFlapStreakDefaultsToTwo(t *testing.T) {
	// GIVEN: конфиг без единого упоминания flap_streak
	cfg, err := Load(writeConfig(t, minimalNotifier+"targets:\n  - address: a.com\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// THEN: применяется дефолт 2 — один сетевой блип не поднимает тревогу
	if cfg.Targets[0].FlapStreak == nil || *cfg.Targets[0].FlapStreak != 2 {
		t.Errorf("flap_streak must default to 2, got %v", cfg.Targets[0].FlapStreak)
	}
}

func TestHeaderEnvExpansion(t *testing.T) {
	// GIVEN: заголовок нотификатора ссылается на переменную окружения через ${...}
	t.Setenv("ALERT_TOKEN", "secret-token")

	// WHEN: конфиг загружен
	cfg, err := Load(writeConfig(t, `
notifiers:
  default:
    url: https://example.com/alert
    body: {text: x}
    headers:
      Authorization: "Bearer ${env.ALERT_TOKEN}"
target_defaults:
  notifiers: [default]
targets:
  - address: example.com
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// THEN: плейсхолдер подставлен значением переменной окружения
	if got := cfg.Notifiers["default"].Headers["Authorization"]; got != "Bearer secret-token" {
		t.Errorf("header expansion: got %q", got)
	}
}

func TestEnvExpansionInURLAndBody(t *testing.T) {
	// GIVEN: секреты живут в url (токен бота) и в теле, в т.ч. во вложенном ключе —
	// две ключевые правки редизайна (токен Telegram в URL, латентный баг PagerDuty).
	t.Setenv("TELEGRAM_TOKEN", "bot-tok")
	t.Setenv("TELEGRAM_CHAT_ID", "-100500")
	t.Setenv("PAGERDUTY_KEY", "pd-key")

	// WHEN: конфиг загружен
	cfg, err := Load(writeConfig(t, `
notifiers:
  telegram:
    url: https://api.telegram.org/bot${env.TELEGRAM_TOKEN}/sendMessage
    body:
      chat_id: ${env.TELEGRAM_CHAT_ID}
      text: hi
  pager:
    url: https://events.pagerduty.com/v2/enqueue
    body:
      payload:
        routing_key: ${env.PAGERDUTY_KEY}
target_defaults:
  notifiers: [telegram, pager]
targets:
  - address: example.com
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// THEN: секрет в url подставлен
	if got := cfg.Notifiers["telegram"].URL; got != "https://api.telegram.org/botbot-tok/sendMessage" {
		t.Errorf("url expansion: got %q", got)
	}
	// THEN: секрет в строке верхнего уровня тела подставлен
	if got := cfg.Notifiers["telegram"].Body["chat_id"]; got != "-100500" {
		t.Errorf("body expansion: got %q", got)
	}
	// THEN: секрет во вложенном ключе тела подставлен (латентный баг PagerDuty)
	payload, _ := cfg.Notifiers["pager"].Body["payload"].(map[string]any)
	if got := payload["routing_key"]; got != "pd-key" {
		t.Errorf("nested body expansion: got %q", got)
	}
}

func TestUnsetEnvVariableFailsAtLoad(t *testing.T) {
	// GIVEN: заголовок ссылается на переменную окружения, которой нет в окружении

	// WHEN: конфиг загружен
	_, err := Load(writeConfig(t, `
notifiers:
  default:
    url: https://example.com/alert
    body: {text: x}
    headers:
      Authorization: "Bearer ${env.CERTEL_TEST_UNSET_VAR}"
target_defaults:
  notifiers: [default]
targets:
  - address: example.com
`))

	// THEN: загрузка падает с ошибкой, называющей отсутствующую переменную
	if err == nil || !strings.Contains(err.Error(), "CERTEL_TEST_UNSET_VAR") {
		t.Errorf("want error naming the unset variable, got %v", err)
	}
}

func TestValidationErrors(t *testing.T) {
	// GIVEN: набор заведомо некорректных конфигов; каждая строка описывает свой изъян и ожидаемую подстроку ошибки
	cases := []struct {
		name, body, wantErr string
	}{
		{"no targets", minimalNotifier + "targets: []", "no targets"},
		{"no notifiers", "target_defaults:\n  notifiers: [default]\ntargets:\n  - address: a.com", "no notifiers defined"},
		{"empty notifier name", "notifiers:\n  \"\":\n    url: https://e.com/a\n    body: {text: x}\ntargets:\n  - address: a.com\n    notifiers: [default]", "notifier name must not be empty"},
		{"missing notifier url", "notifiers:\n  default:\n    body: {text: x}\ntarget_defaults:\n  notifiers: [default]\ntargets:\n  - address: a.com", "notifiers[default].url is required"},
		{"missing notifier body", "notifiers:\n  default:\n    url: https://e.com/a\ntarget_defaults:\n  notifiers: [default]\ntargets:\n  - address: a.com", "notifiers[default].body is required"},
		{"bad notifier url", "notifiers:\n  default:\n    url: not-a-url\n    body: {text: x}\ntarget_defaults:\n  notifiers: [default]\ntargets:\n  - address: a.com", "notifiers[default].url"},
		{"bad notifier method", "notifiers:\n  default:\n    url: https://e.com/a\n    body: {text: x}\n    method: PYST\ntarget_defaults:\n  notifiers: [default]\ntargets:\n  - address: a.com", "notifiers[default].method"},
		{"negative notifier timeout", "notifiers:\n  default:\n    url: https://e.com/a\n    body: {text: x}\n    timeout: -1s\ntarget_defaults:\n  notifiers: [default]\ntargets:\n  - address: a.com", "notifiers[default].timeout must be positive"},
		{"negative alert_repeat_interval", minimalNotifier + "targets:\n  - address: a.com\n    alert_repeat_interval: -1h", "alert_repeat_interval must be positive"},
		{"alert_repeat_interval below check_interval", minimalNotifier + "probe:\n  check_interval: 6h\ntargets:\n  - address: a.com\n    alert_repeat_interval: 1m", "must not be shorter than probe.check_interval"},
		{"alert_repeat_interval map incomplete", minimalNotifier + "targets:\n  - address: a.com\n    alert_repeat_interval:\n      warning: 3d\n      critical: 1d", "missing severity entr(ies): emergency"},
		{"alert_repeat_interval map unknown key", minimalNotifier + "targets:\n  - address: a.com\n    alert_repeat_interval:\n      warning: 3d\n      critical: 1d\n      emergency: 1d\n      catastrophe: 1h", "unknown severity key(s): catastrophe"},
		{"alert_repeat_interval map entry below check_interval", minimalNotifier + "probe:\n  check_interval: 30m\ntargets:\n  - address: a.com\n    alert_repeat_interval:\n      warning: 3d\n      critical: 1h\n      emergency: 1m", "alert_repeat_interval[emergency] (1m0s) must not be shorter"},
		{"alert_repeat_interval map negative entry", minimalNotifier + "targets:\n  - address: a.com\n    alert_repeat_interval:\n      warning: 3d\n      critical: 1d\n      emergency: -1h", "alert_repeat_interval[emergency] must be positive"},
		{"negative notifier retries", "notifiers:\n  default:\n    url: https://e.com/a\n    body: {text: x}\n    retries: -1\ntarget_defaults:\n  notifiers: [default]\ntargets:\n  - address: a.com", "notifiers[default].retries must not be negative"},
		{"invalid notifier min_severity", "notifiers:\n  default:\n    url: https://e.com/a\n    body: {text: x}\n    min_severity: ok\ntarget_defaults:\n  notifiers: [default]\ntargets:\n  - address: a.com", "notifiers[default].min_severity"},
		{"unknown notifier on target", minimalNotifier + "targets:\n  - address: a.com\n    notifiers: [nope]", "unknown notifier \"nope\""},
		{"target with no notifier", "notifiers:\n  default:\n    url: https://e.com/a\n    body: {text: x}\ntargets:\n  - address: a.com", "no notifier"},
		{"empty target notifier", minimalNotifier + "targets:\n  - address: a.com\n    notifiers: [\"\"]", "notifier must not be empty"},
		{"duplicate notifier on target", "notifiers:\n  default:\n    url: https://e.com/a\n    body: {text: x}\ntargets:\n  - address: a.com\n    notifiers: [default, default]", "duplicate notifier \"default\""},
		{"bad protocol", minimalNotifier + "targets:\n  - address: a.com\n    protocol: gopher", "unknown protocol"},
		{"critical above warning", minimalNotifier + "targets:\n  - address: a.com\n    warning_days: 5\n    critical_days: 10", "must not exceed"},
		{"duplicate target", minimalNotifier + "targets:\n  - address: a.com:443\n  - address: a.com:443", "duplicate"},
		{"unknown field", minimalNotifier + "targets:\n  - address: a.com\ntypo_field: 1", "typo_field"},
		{"negative check_interval", minimalNotifier + "probe:\n  check_interval: -5m\ntargets:\n  - address: a.com", "check_interval must be positive"},
		{"negative jitter", minimalNotifier + "probe:\n  jitter: -1s\ntargets:\n  - address: a.com", "jitter must not be negative"},
		{"negative probe_log_retention", minimalNotifier + "database:\n  probe_log_retention: -1h\ntargets:\n  - address: a.com", "probe_log_retention must be positive"},
		{"negative alert_log_retention", minimalNotifier + "database:\n  alert_log_retention: -1h\ntargets:\n  - address: a.com", "alert_log_retention must be positive"},
		{"zero target timeout", minimalNotifier + "targets:\n  - address: a.com\n    timeout: 0s", "timeout must be positive"},
		{"negative target connect_retries", minimalNotifier + "targets:\n  - address: a.com\n    connect_retries: -1", "connect_retries must not be negative"},
		{"zero flap_streak", minimalNotifier + "targets:\n  - address: a.com\n    flap_streak: 0", "flap_streak must be at least 1"},
		{"negative flap_streak", minimalNotifier + "targets:\n  - address: a.com\n    flap_streak: -1", "flap_streak must be at least 1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// WHEN: некорректный конфиг загружается
			_, err := Load(writeConfig(t, tc.body))

			// THEN: загрузка отклонена с ошибкой, указывающей на конкретную причину
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestZeroRetriesAndJitterLoad(t *testing.T) {
	// GIVEN: конфиг с легитимными нулями — jitter: 0s (без разброса),
	// notifier retries: 0 (доставить один раз, без повторов) и target
	// connect_retries: 0 (одна попытка соединения). Ни один из них не должен
	// отвергаться и не должен перетираться умолчанием.
	cfg, err := Load(writeConfig(t, `
notifiers:
  default:
    url: https://example.com/alert
    body: {text: x}
    retries: 0
target_defaults:
  notifiers: [default]
probe:
  jitter: 0s
targets:
  - address: a.com
    connect_retries: 0
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// THEN: явные нули сохранены, а не заменены умолчаниями (2)
	if r := cfg.Notifiers["default"].Retries; r == nil || *r != 0 {
		t.Errorf("notifier retries: explicit 0 must survive defaulting, got %v", r)
	}
	if cfg.Targets[0].ConnectRetries == nil || *cfg.Targets[0].ConnectRetries != 0 {
		t.Errorf("target connect_retries: explicit 0 must survive defaulting, got %v", cfg.Targets[0].ConnectRetries)
	}
	if cfg.Probe.Jitter.Std() != 0 {
		t.Errorf("jitter: explicit 0s must load, got %v", cfg.Probe.Jitter.Std())
	}
}

func TestDurationDayUnit(t *testing.T) {
	// GIVEN: строки длительности с новым суффиксом "d" и в комбинации со стандартными единицами
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"90d", 90 * 24 * time.Hour},
		{"1d", 24 * time.Hour},
		{"1d12h", 36 * time.Hour},
		{"2160h", 2160 * time.Hour}, // прежний формат по-прежнему работает
		{"5m", 5 * time.Minute},
		{"-1d", -24 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			// WHEN: строка загружается как поле retention
			cfg, err := Load(writeConfig(t, minimalNotifier+"database:\n  alert_log_retention: "+tc.in+"\ntargets:\n  - address: a.com"))
			// THEN: значение разобрано в ожидаемую длительность (для отрицательного — отвергнуто валидацией как непозитивное)
			if tc.want < 0 {
				if err == nil || !strings.Contains(err.Error(), "alert_log_retention must be positive") {
					t.Fatalf("negative retention must be rejected, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := cfg.Database.AlertLogRetention.Std(); got != tc.want {
				t.Errorf("parsed %q = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestEffectiveServername(t *testing.T) {
	// GIVEN: цель с явно заданным servername при IP-адресе
	h := Target{Address: "10.0.0.5:8443", Servername: "internal.example.com"}

	// WHEN/THEN: явный servername имеет приоритет над адресом
	if got := h.EffectiveServername(); got != "internal.example.com" {
		t.Errorf("explicit servername: got %q", got)
	}

	// WHEN: servername не задан
	h = Target{Address: "example.com:443"}

	// THEN: имя выводится из адреса без порта
	if got := h.EffectiveServername(); got != "example.com" {
		t.Errorf("derived servername: got %q", got)
	}
}
