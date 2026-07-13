package alert

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/antonkomarev/certel/internal/config"
)

// closedTimeChan returns a channel that has already fired, so an injected
// backoff resolves immediately and tests never sleep for real.
func closedTimeChan() <-chan time.Time {
	ch := make(chan time.Time, 1)
	ch <- time.Time{}
	return ch
}

func TestWebhookSenderSucceedsAfterRetry(t *testing.T) {
	// GIVEN: эндпоинт, который дважды отвечает 500, а на третьей попытке — 200
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	retries := 5
	s, err := NewWebhookSender(config.AlertConfig{
		URL: srv.URL, Method: "POST",
		Timeout: config.Duration(2 * time.Second), Retries: &retries,
	})
	if err != nil {
		t.Fatal(err)
	}
	var backoffs []time.Duration
	s.after = func(d time.Duration) <-chan time.Time {
		backoffs = append(backoffs, d)
		return closedTimeChan()
	}

	// WHEN: доставка идёт против эндпоинта, выздоравливающего после двух отказов
	if err := s.Send(context.Background(), []byte("{}")); err != nil {
		t.Fatalf("want success after retries, got %v", err)
	}

	// THEN: ровно три попытки — доставка останавливается на первом 2xx
	if calls != 3 {
		t.Errorf("attempts: got %d, want 3", calls)
	}
	// THEN: между тремя попытками — два ожидания, растущих экспоненциально
	want := []time.Duration{time.Second, 2 * time.Second}
	if len(backoffs) != len(want) {
		t.Fatalf("backoff waits: got %v, want %v", backoffs, want)
	}
	for i, w := range want {
		if backoffs[i] != w {
			t.Errorf("backoff[%d]: got %s, want %s", i, backoffs[i], w)
		}
	}
}

func TestWebhookSenderTLSTrust(t *testing.T) {
	// GIVEN: эндпоинт с самоподписанным сертификатом (httptest gen) вне системных корней
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	retries := 0
	base := config.AlertConfig{
		URL: srv.URL, Method: "POST",
		Timeout: config.Duration(2 * time.Second), Retries: &retries,
	}

	// WHEN: доставка без ca_file — сертификат не в системном доверии
	s, err := NewWebhookSender(base)
	if err != nil {
		t.Fatal(err)
	}
	// THEN: доставка падает на проверке цепочки
	if err := s.Send(context.Background(), []byte("{}")); err == nil {
		t.Fatal("want TLS verification failure without ca_file")
	}

	// GIVEN: сертификат сервера, записанный как PEM-якорь доверия
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	// WHEN: доставка с ca_file, указывающим на этот сертификат
	withCA := base
	withCA.CAFile = caPath
	s2, err := NewWebhookSender(withCA)
	if err != nil {
		t.Fatal(err)
	}
	// THEN: доставка проходит
	if err := s2.Send(context.Background(), []byte("{}")); err != nil {
		t.Fatalf("want success with ca_file, got %v", err)
	}

	// WHEN: доставка с insecure вместо ca_file
	ins := base
	ins.Insecure = true
	s3, err := NewWebhookSender(ins)
	if err != nil {
		t.Fatal(err)
	}
	// THEN: проверка пропущена, доставка проходит
	if err := s3.Send(context.Background(), []byte("{}")); err != nil {
		t.Fatalf("want success with insecure, got %v", err)
	}
}

func TestNewWebhookSenderRejectsBadCAFile(t *testing.T) {
	// GIVEN: ca_file, не содержащий валидных сертификатов
	caPath := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(caPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	retries := 0

	// WHEN: конструируется sender
	_, err := NewWebhookSender(config.AlertConfig{
		URL: "https://alerts.internal/hook", Method: "POST",
		Timeout: config.Duration(2 * time.Second), Retries: &retries, CAFile: caPath,
	})
	// THEN: ошибка называет проблему явно, а не откладывает её до первой доставки
	if err == nil {
		t.Fatal("want error for ca_file with no certificates")
	}
}
