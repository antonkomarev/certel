package main

import (
	"strings"
	"testing"
	"time"

	"github.com/antonkomarev/certel/internal/config"
	"github.com/antonkomarev/certel/internal/probe"
)

// validParams returns a checkParams that passes buildCheckTarget, for tests to
// break one field at a time.
func validParams() checkParams {
	return checkParams{
		address:      "example.com:443",
		protocol:     "tls",
		timeout:      10 * time.Second,
		retries:      0,
		warningDays:  30,
		criticalDays: 7,
	}
}

func TestBuildCheckTargetDefaultsPortByProtocol(t *testing.T) {
	cases := []struct {
		protocol string
		want     string
	}{
		{"tls", "example.com:443"},
		{"smtp", "example.com:587"},
		{"postgres", "example.com:5432"},
	}
	for _, c := range cases {
		p := validParams()
		p.address = "example.com"
		p.protocol = c.protocol
		target, err := buildCheckTarget(p)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", c.protocol, err)
		}
		if target.Address != c.want {
			t.Errorf("%s: address = %q, want %q", c.protocol, target.Address, c.want)
		}
	}
}

func TestBuildCheckTargetKeepsExplicitPort(t *testing.T) {
	p := validParams()
	p.address = "example.com:8443"
	target, err := buildCheckTarget(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.Address != "example.com:8443" {
		t.Errorf("address = %q, want example.com:8443", target.Address)
	}
}

func TestBuildCheckTargetWiresParams(t *testing.T) {
	p := validParams()
	p.servername = "internal.example.com"
	p.insecure = true
	p.timeout = 3 * time.Second
	p.retries = 2
	p.warningDays = 14
	p.criticalDays = 3
	target, err := buildCheckTarget(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.Servername != "internal.example.com" || !target.Insecure {
		t.Errorf("servername/insecure not wired: %+v", target)
	}
	if target.Timeout.Std() != 3*time.Second || *target.ConnectRetries != 2 {
		t.Errorf("timeout/retries not wired: timeout=%s retries=%d", target.Timeout.Std(), *target.ConnectRetries)
	}
	if *target.WarningDays != 14 || *target.CriticalDays != 3 {
		t.Errorf("thresholds not wired: warning=%d critical=%d", *target.WarningDays, *target.CriticalDays)
	}
}

func TestBuildCheckTargetRejectsBadParams(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*checkParams)
		wantErr string
	}{
		{"unknown protocol", func(p *checkParams) { p.protocol = "quic" }, "unknown protocol"},
		{"empty address", func(p *checkParams) { p.address = "" }, "address is required"},
		{"zero timeout", func(p *checkParams) { p.timeout = 0 }, "timeout must be positive"},
		{"negative retries", func(p *checkParams) { p.retries = -1 }, "retries must not be negative"},
		{"critical above warning", func(p *checkParams) { p.criticalDays = 40 }, "must not exceed"},
		{"missing ca-file", func(p *checkParams) { p.caFile = "/nonexistent/ca.pem" }, "ca-file"},
	}
	for _, c := range cases {
		p := validParams()
		c.mutate(&p)
		_, err := buildCheckTarget(p)
		if err == nil {
			t.Errorf("%s: expected error, got none", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: error %q does not contain %q", c.name, err, c.wantErr)
		}
	}
}

func TestToCheckOutputWithCertificate(t *testing.T) {
	notAfter := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	res := probe.Result{
		Target:           config.Target{Address: "example.com:443", Protocol: config.ProtoTLS},
		Status:           probe.StatusOK,
		Severity:         probe.SeverityOK,
		Message:          "certificate valid, expires in 53 day(s)",
		CheckedAt:        time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC),
		Duration:         1500 * time.Millisecond,
		Attempts:         1,
		VerifyOK:         true,
		VerifiedNotAfter: notAfter,
		DaysLeft:         53,
		Cert: &probe.CertInfo{
			CN:               "example.com",
			NotAfter:         notAfter,
			EarliestNotAfter: notAfter,
			EarliestSubject:  "example.com",
		},
	}
	out := toCheckOutput(res)
	if out.Servername != "example.com" {
		t.Errorf("servername = %q, want example.com", out.Servername)
	}
	if out.DurationMS != 1500 {
		t.Errorf("duration_ms = %d, want 1500", out.DurationMS)
	}
	if out.NotAfter == nil || !out.NotAfter.Equal(notAfter) {
		t.Errorf("not_after = %v, want %s", out.NotAfter, notAfter)
	}
	if out.Cert == nil || out.Cert.CN != "example.com" {
		t.Errorf("cert not mapped: %+v", out.Cert)
	}
}

func TestToCheckOutputUnreachableOmitsCert(t *testing.T) {
	res := probe.Result{
		Target:   config.Target{Address: "example.com:443", Protocol: config.ProtoTLS},
		Status:   probe.StatusUnreachable,
		Severity: probe.SeverityCritical,
		Message:  "connection failed",
		Attempts: 3,
	}
	out := toCheckOutput(res)
	if out.Cert != nil {
		t.Errorf("cert = %+v, want nil", out.Cert)
	}
	if out.NotAfter != nil {
		t.Errorf("not_after = %v, want nil", out.NotAfter)
	}
}

func TestCheckExitCode(t *testing.T) {
	if got := checkExitCode(probe.SeverityOK); got != 0 {
		t.Errorf("ok = %d, want 0", got)
	}
	if got := checkExitCode(probe.SeverityWarning); got != 1 {
		t.Errorf("warning = %d, want 1", got)
	}
	if got := checkExitCode(probe.SeverityCritical); got != 2 {
		t.Errorf("critical = %d, want 2", got)
	}
}
