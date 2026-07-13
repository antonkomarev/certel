package alert

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/antonkomarev/certel/internal/config"
)

// Sender delivers a rendered alert body. Implemented by WebhookSender;
// stubbed in tests.
type Sender interface {
	Send(ctx context.Context, body []byte) error
}

// WebhookSender POSTs alert bodies to the configured endpoint with retries
// and exponential backoff.
type WebhookSender struct {
	cfg    config.AlertConfig
	client *http.Client
	// after returns a channel that fires after d. Injectable so tests can
	// observe backoff growth without real sleeps; defaults to time.After.
	after func(d time.Duration) <-chan time.Time
}

// NewWebhookSender builds a sender for the configured endpoint. It returns an
// error only for a malformed ca_file — the endpoint's trust settings are
// resolved once here rather than on every delivery.
func NewWebhookSender(cfg config.AlertConfig) (*WebhookSender, error) {
	client := &http.Client{Timeout: cfg.Timeout.Std()}
	if cfg.CAFile != "" || cfg.Insecure {
		tlsCfg := &tls.Config{InsecureSkipVerify: cfg.Insecure}
		if cfg.CAFile != "" {
			pem, err := os.ReadFile(cfg.CAFile)
			if err != nil {
				return nil, fmt.Errorf("reading alert ca_file: %w", err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("alert ca_file %s contains no valid certificates", cfg.CAFile)
			}
			tlsCfg.RootCAs = roots
		}
		// Clone the default transport so proxy and connection-pool defaults are
		// preserved; only the TLS config is overridden.
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = tlsCfg
		client.Transport = tr
	}
	return &WebhookSender{cfg: cfg, client: client, after: time.After}, nil
}

func (s *WebhookSender) Send(ctx context.Context, body []byte) error {
	// retries counts extra attempts after the first, matching target retries;
	// total deliveries attempted is retries+1.
	retries := *s.cfg.Retries
	backoff := time.Second
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, s.cfg.Method, s.cfg.URL, bytes.NewReader(body))
		if err != nil {
			return err
		}
		// Default the body content type, then let configured headers override it —
		// a notifier can set its own Content-Type via headers without every JSON
		// notifier having to hand-write the common case.
		req.Header.Set("Content-Type", "application/json")
		for k, v := range s.cfg.Headers {
			req.Header.Set(k, v)
		}
		resp, err := s.client.Do(req)
		if err == nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
			lastErr = fmt.Errorf("endpoint returned %s", resp.Status)
		} else {
			lastErr = err
		}
		if attempt < retries {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-s.after(backoff):
				backoff *= 2
			}
		}
	}
	return fmt.Errorf("after %d attempt(s): %w", retries+1, lastErr)
}
