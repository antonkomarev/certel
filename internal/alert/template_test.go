package alert

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/antonkomarev/certel/internal/config"
	"github.com/antonkomarev/certel/internal/probe"
)

// renderBody is a test helper: compile a body and render it against a payload,
// returning the JSON bytes.
func renderBody(t *testing.T, body, recovery map[string]any, p Payload) []byte {
	t.Helper()
	b, err := ParseBody(body, recovery)
	if err != nil {
		t.Fatalf("ParseBody: %v", err)
	}
	out, err := b.Render(p)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	return out
}

func TestRenderEscapesHostileMessage(t *testing.T) {
	// GIVEN: сообщение с переносами строк, кавычками и обратными слэшами,
	// интерполируемое в строку тела
	p := NewPayload(probe.Result{
		Target:  config.Target{Address: "example.com:443", Protocol: config.ProtoTLS},
		Message: "line one\nwith \"quotes\" and \\backslash",
	}, false)

	// WHEN: тело отрендерено
	out := renderBody(t, map[string]any{
		"host":    "${alert.Host}",
		"message": "${alert.Message}",
	}, nil, p)

	// THEN: результат — валидный JSON, а сообщение переживает round-trip без искажений
	var parsed map[string]string
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("rendered body is not valid JSON: %v\nbody: %s", err, out)
	}
	if parsed["message"] != "line one\nwith \"quotes\" and \\backslash" {
		t.Errorf("message round-trip mismatch: %q", parsed["message"])
	}
	if parsed["host"] != "example.com" {
		t.Errorf("host: got %q", parsed["host"])
	}
}

func TestWholeScalarKeepsNativeType(t *testing.T) {
	// GIVEN: поля-ссылки, занимающие всё значение целиком (число, булево), и
	// интерполяция внутри большей строки
	p := NewPayload(probe.Result{
		Target:   config.Target{Address: "example.com:443", Protocol: config.ProtoTLS},
		DaysLeft: 14,
	}, true)

	out := renderBody(t, map[string]any{
		"days_left": "${alert.DaysLeft}",     // whole scalar -> JSON number
		"recovered": "${alert.Recovered}",    // whole scalar -> JSON bool
		"embedded":  "in ${alert.DaysLeft}d", // embedded -> string
	}, nil, p)

	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out)
	}
	if n, ok := parsed["days_left"].(float64); !ok || n != 14 {
		t.Errorf("days_left must be a JSON number 14, got %#v", parsed["days_left"])
	}
	if b, ok := parsed["recovered"].(bool); !ok || !b {
		t.Errorf("recovered must be a JSON bool true, got %#v", parsed["recovered"])
	}
	if s, ok := parsed["embedded"].(string); !ok || s != "in 14d" {
		t.Errorf("embedded interpolation must be a string \"in 14d\", got %#v", parsed["embedded"])
	}
}

func TestNestedAndPassthroughValues(t *testing.T) {
	// GIVEN: тело с вложенной картой и не-строковыми значениями (bool/number),
	// которые проходят к json.Marshal неизменными
	p := samplePayload()
	out := renderBody(t, map[string]any{
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
		"payload": map[string]any{
			"summary":  "${alert.Host} ${alert.Status}",
			"severity": "critical",
		},
	}, nil, p)

	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out)
	}
	if parsed["disable_web_page_preview"] != true {
		t.Errorf("bool must pass through, got %#v", parsed["disable_web_page_preview"])
	}
	nested, ok := parsed["payload"].(map[string]any)
	if !ok {
		t.Fatalf("nested map lost: %#v", parsed["payload"])
	}
	if nested["summary"] != "example.com expiring_soon" {
		t.Errorf("nested interpolation: got %#v", nested["summary"])
	}
}

func TestDateFormats(t *testing.T) {
	// GIVEN: одна временная метка, отформатированная каждым пресетом и strftime
	ts := time.Date(2026, 4, 27, 7, 47, 0, 0, time.UTC)
	p := NewPayload(probe.Result{
		Target: config.Target{Address: "example.com:443", Protocol: config.ProtoTLS},
		Cert:   &probe.CertInfo{NotAfter: ts},
	}, false)

	cases := map[string]string{
		"${alert.Cert.NotAfter}":                   "2026-04-27 07:47:00", // default datetime
		"${alert.Cert.NotAfter | date}":            "2026-04-27",
		"${alert.Cert.NotAfter | time}":            "07:47:00",
		"${alert.Cert.NotAfter | human}":           "Apr 27, 2026 07:47",
		"${alert.Cert.NotAfter | rfc3339}":         "2026-04-27T07:47:00Z",
		"${alert.Cert.NotAfter | %Y-%m-%d}":        "2026-04-27",
		"${alert.Cert.NotAfter | %b %d, %Y %H:%M}": "Apr 27, 2026 07:47",
	}
	for ref, want := range cases {
		out := renderBody(t, map[string]any{"v": ref}, nil, p)
		var parsed map[string]string
		if err := json.Unmarshal(out, &parsed); err != nil {
			t.Fatalf("%s: not valid JSON: %v", ref, err)
		}
		if parsed["v"] != want {
			t.Errorf("%s => %q, want %q", ref, parsed["v"], want)
		}
	}
}

func TestNilCertRendersEmpty(t *testing.T) {
	// GIVEN: результат без сертификата (рукопожатие не состоялось)
	p := NewPayload(probe.Result{
		Target: config.Target{Address: "example.com:443", Protocol: config.ProtoTLS},
	}, false)

	// THEN: ссылки на Cert.* дают пустые значения, а не ошибку
	out := renderBody(t, map[string]any{
		"cn":        "${alert.Cert.SubjectCN}",
		"not_after": "${alert.Cert.NotAfter}",
	}, nil, p)
	var parsed map[string]string
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out)
	}
	if parsed["cn"] != "" || parsed["not_after"] != "" {
		t.Errorf("nil cert fields must render empty, got %#v", parsed)
	}
}

func TestRecoveryBodyDeepMerge(t *testing.T) {
	// GIVEN: тело с несколькими ключами и разреженный recovery_body,
	// переопределяющий лишь один
	body := map[string]any{
		"chat_id":    "123",
		"parse_mode": "HTML",
		"text":       "firing ${alert.Host}",
	}
	recovery := map[string]any{
		"text": "recovered ${alert.Host}",
	}
	b, err := ParseBody(body, recovery)
	if err != nil {
		t.Fatalf("ParseBody: %v", err)
	}

	firing := NewPayload(probe.Result{Target: config.Target{Address: "a.com:443", Protocol: config.ProtoTLS}}, false)
	recovered := NewPayload(probe.Result{Target: config.Target{Address: "a.com:443", Protocol: config.ProtoTLS}}, true)

	// THEN: при firing берётся исходный текст; при recovery — только text
	// переопределён, остальные ключи унаследованы
	fireOut := mustRender(t, b, firing)
	if fireOut["text"] != "firing a.com" || fireOut["parse_mode"] != "HTML" {
		t.Errorf("firing body: %#v", fireOut)
	}
	recOut := mustRender(t, b, recovered)
	if recOut["text"] != "recovered a.com" {
		t.Errorf("recovery text override lost: %#v", recOut)
	}
	if recOut["chat_id"] != "123" || recOut["parse_mode"] != "HTML" {
		t.Errorf("recovery must inherit un-overridden keys: %#v", recOut)
	}
}

func mustRender(t *testing.T, b *Body, p Payload) map[string]any {
	t.Helper()
	out, err := b.Render(p)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out)
	}
	return parsed
}

func TestSinglePassInertness(t *testing.T) {
	// GIVEN: значение поля, само похожее на ссылку (${alert.Host}, ${env.X})
	p := NewPayload(probe.Result{
		Target:  config.Target{Address: "example.com:443", Protocol: config.ProtoTLS},
		Message: "${alert.Host} and ${env.SECRET}",
	}, false)

	// THEN: интерполированное значение не пере-сканируется — оно попадает в вывод
	// дословно, ни секрет, ни самоссылка не раскрываются
	out := renderBody(t, map[string]any{"m": "${alert.Message}"}, nil, p)
	var parsed map[string]string
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if parsed["m"] != "${alert.Host} and ${env.SECRET}" {
		t.Errorf("interpolated value must be inert, got %q", parsed["m"])
	}
}

func TestEscapedLiteralReference(t *testing.T) {
	// GIVEN: экранированная ссылка $${alert.Host} должна остаться литералом
	p := NewPayload(probe.Result{Target: config.Target{Address: "example.com:443", Protocol: config.ProtoTLS}}, false)
	out := renderBody(t, map[string]any{"m": "literal $${alert.Host}"}, nil, p)
	var parsed map[string]string
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if parsed["m"] != "literal ${alert.Host}" {
		t.Errorf("escaped reference must render literally, got %q", parsed["m"])
	}
}

func TestParseBodyRejectsUnknownField(t *testing.T) {
	// GIVEN: тело, ссылающееся на несуществующее поле
	_, err := ParseBody(map[string]any{"x": "${alert.NoSuchField}"}, nil)
	if err == nil || !strings.Contains(err.Error(), "NoSuchField") {
		t.Errorf("want error naming the unknown field, got %v", err)
	}
}

func TestParseBodyRejectsFormatOnNonTimestamp(t *testing.T) {
	// GIVEN: суффикс формата на не-временном поле
	_, err := ParseBody(map[string]any{"x": "${alert.Host | human}"}, nil)
	if err == nil || !strings.Contains(err.Error(), "non-timestamp") {
		t.Errorf("want error about format on non-timestamp, got %v", err)
	}
}

func TestParseBodyRejectsEmpty(t *testing.T) {
	// GIVEN: пустое тело
	if _, err := ParseBody(map[string]any{}, nil); err == nil {
		t.Error("want error for empty body")
	}
}

func TestParseBodyRejectsBadNamespace(t *testing.T) {
	// GIVEN: ссылки с неизвестным пространством имён и без него — опечатки,
	// которые не должны молча уходить в вывод
	cases := map[string]string{
		"unknown namespace": "${allert.Host}",
		"no namespace":      "${HOST}",
	}
	for name, ref := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseBody(map[string]any{"x": ref}, nil); err == nil {
				t.Errorf("want error for %q", ref)
			}
		})
	}
}

func TestTelegramNoticeParity(t *testing.T) {
	// GIVEN: тело Telegram из config.example и полезная нагрузка komarev.com —
	// воспроизводим целевое уведомление из telegram-notification-template.
	p := NewPayload(probe.Result{
		Target:   config.Target{Address: "komarev.com:443", Protocol: config.ProtoTLS},
		DaysLeft: 14,
		Cert: &probe.CertInfo{
			CN:                 "komarev.com",
			IssuerCN:           "R13",
			IssuerOrg:          "Let's Encrypt",
			SignatureAlgorithm: "SHA-256 with RSA encryption",
			NotBefore:          time.Date(2026, 4, 27, 7, 47, 0, 0, time.UTC),
			NotAfter:           time.Date(2026, 7, 26, 7, 47, 0, 0, time.UTC),
		},
	}, false)

	body := map[string]any{
		"chat_id":    "123",
		"parse_mode": "HTML",
		"text": "<b>SSL expiration notice</b> ⌛\n" +
			"https://${alert.Host}/\n" +
			"The SSL certificate served by ${alert.Host} will expire in ${alert.DaysLeft} days\n\n" +
			"🔒 <b>Certificate:</b>\n" +
			"subject:   ${alert.Cert.SubjectCN}\n" +
			"validity:  ${alert.Cert.NotBefore | human} — ${alert.Cert.NotAfter | human}\n" +
			"algorithm: ${alert.Cert.SigAlg}\n" +
			"issuer:    ${alert.Cert.IssuerCN} (${alert.Cert.IssuerOrg})",
	}
	parsed := mustRender(t, mustBody(t, body, nil), p)
	text, _ := parsed["text"].(string)

	for _, want := range []string{
		"https://komarev.com/",
		"will expire in 14 days",
		"subject:   komarev.com",
		"validity:  Apr 27, 2026 07:47 — Jul 26, 2026 07:47",
		"algorithm: SHA-256 with RSA encryption",
		"issuer:    R13 (Let's Encrypt)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("notice missing %q\nfull text:\n%s", want, text)
		}
	}
}

func mustBody(t *testing.T, body, recovery map[string]any) *Body {
	t.Helper()
	b, err := ParseBody(body, recovery)
	if err != nil {
		t.Fatalf("ParseBody: %v", err)
	}
	return b
}
