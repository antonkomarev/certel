package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/antonkomarev/certel/internal/config"
	"github.com/antonkomarev/certel/internal/probe"
)

// checkParams are the knobs of a one-off check — the per-target subset of the
// monitor config, taken from flags instead of YAML.
type checkParams struct {
	address      string
	servername   string
	protocol     string
	caFile       string
	insecure     bool
	timeout      time.Duration
	retries      int
	warningDays  int
	criticalDays int
}

// checkCert is the JSON shape of probe.CertInfo. Field names are part of the
// command's output contract, so they are pinned here rather than borrowed from
// the internal struct.
type checkCert struct {
	Subject          string    `json:"subject"`
	CN               string    `json:"cn"`
	Issuer           string    `json:"issuer"`
	SANs             []string  `json:"sans,omitempty"`
	Serial           string    `json:"serial"`
	NotBefore        time.Time `json:"not_before"`
	NotAfter         time.Time `json:"not_after"`
	EarliestNotAfter time.Time `json:"earliest_not_after"`
	EarliestSubject  string    `json:"earliest_subject"`
}

// checkOutput is the JSON document `certel check` prints: the probe verdict
// plus the inspected certificate when the handshake completed.
type checkOutput struct {
	Address    string         `json:"address"`
	Protocol   string         `json:"protocol"`
	Servername string         `json:"servername"`
	Status     probe.Status   `json:"status"`
	Severity   probe.Severity `json:"severity"`
	Message    string         `json:"message"`
	CheckedAt  time.Time      `json:"checked_at"`
	DurationMS int64          `json:"duration_ms"`
	Attempts   int            `json:"attempts"`
	VerifyOK   bool           `json:"verify_ok"`
	DaysLeft   int            `json:"days_left"`
	// NotAfter is the effective expiry the status is based on (earliest in the
	// verified chain when one built, otherwise earliest in the presented
	// chain); absent when no certificate was inspected.
	NotAfter *time.Time `json:"not_after,omitempty"`
	Cert     *checkCert `json:"cert,omitempty"`
}

// buildCheckTarget turns the flag values into the same Target the monitor
// would build from YAML: default port by protocol, thresholds validated with
// the same rules, so a one-off check reproduces exactly what the monitor sees.
func buildCheckTarget(p checkParams) (config.Target, error) {
	proto := config.Protocol(p.protocol)
	port, ok := config.DefaultPort(proto)
	if !ok {
		return config.Target{}, fmt.Errorf("unknown protocol %q (supported: tls, smtp, imap, pop3, ftp, postgres)", p.protocol)
	}
	if p.address == "" {
		return config.Target{}, fmt.Errorf("address is required")
	}
	addr := p.address
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, port)
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return config.Target{}, fmt.Errorf("invalid address %q: %v", p.address, err)
		}
	}
	if p.timeout <= 0 {
		return config.Target{}, fmt.Errorf("timeout must be positive (got %s)", p.timeout)
	}
	if p.retries < 0 {
		return config.Target{}, fmt.Errorf("retries must not be negative (got %d)", p.retries)
	}
	if p.criticalDays > p.warningDays {
		return config.Target{}, fmt.Errorf("critical-days (%d) must not exceed warning-days (%d)", p.criticalDays, p.warningDays)
	}
	if p.caFile != "" {
		if _, err := os.Stat(p.caFile); err != nil {
			return config.Target{}, fmt.Errorf("ca-file: %v", err)
		}
	}
	timeout := config.Duration(p.timeout)
	return config.Target{
		Address:    addr,
		Servername: p.servername,
		Protocol:   proto,
		CAFile:     p.caFile,
		Insecure:   p.insecure,
		TargetParams: config.TargetParams{
			WarningDays:    &p.warningDays,
			CriticalDays:   &p.criticalDays,
			Timeout:        &timeout,
			ConnectRetries: &p.retries,
		},
	}, nil
}

func toCheckOutput(res probe.Result) checkOutput {
	out := checkOutput{
		Address:    res.Target.Address,
		Protocol:   string(res.Target.Protocol),
		Servername: res.Target.EffectiveServername(),
		Status:     res.Status,
		Severity:   res.Severity,
		Message:    res.Message,
		CheckedAt:  res.CheckedAt,
		DurationMS: res.Duration.Milliseconds(),
		Attempts:   res.Attempts,
		VerifyOK:   res.VerifyOK,
		DaysLeft:   res.DaysLeft,
	}
	if na := res.EffectiveNotAfter(); !na.IsZero() {
		out.NotAfter = &na
	}
	if c := res.Cert; c != nil {
		out.Cert = &checkCert{
			Subject:          c.Subject,
			CN:               c.CN,
			Issuer:           c.Issuer,
			SANs:             c.SANs,
			Serial:           c.Serial,
			NotBefore:        c.NotBefore,
			NotAfter:         c.NotAfter,
			EarliestNotAfter: c.EarliestNotAfter,
			EarliestSubject:  c.EarliestSubject,
		}
	}
	return out
}

// checkExitCode maps the probe severity onto the exit code contract
// documented in the usage text: 0 ok, 1 warning, 2 critical.
func checkExitCode(sev probe.Severity) int {
	switch sev {
	case probe.SeverityOK:
		return 0
	case probe.SeverityWarning:
		return 1
	default:
		return 2
	}
}

// runCheck probes a single ad-hoc target once and prints the verdict as JSON
// on stdout. Nothing is written to the database, no metrics are exported and
// no notifier is involved — the command is safe to run next to a live monitor.
func runCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	p := checkParams{}
	fs.StringVar(&p.protocol, "protocol", "tls", "how to establish TLS: tls, smtp, imap, pop3, ftp, postgres")
	fs.StringVar(&p.servername, "servername", "", "name used for SNI and hostname verification (default: host from address)")
	fs.StringVar(&p.caFile, "ca-file", "", "PEM bundle to verify the chain against instead of the system roots")
	fs.BoolVar(&p.insecure, "insecure", false, "skip chain and hostname verification; expiry is still checked")
	fs.DurationVar(&p.timeout, "timeout", 10*time.Second, "per-attempt timeout")
	fs.IntVar(&p.retries, "retries", 0, "extra attempts after a connection failure")
	fs.IntVar(&p.warningDays, "warning-days", 30, "days before expiry that count as warning")
	fs.IntVar(&p.criticalDays, "critical-days", 7, "days before expiry that count as critical")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: certel check [flags] <host[:port]>

Probe one target once and print the result as JSON on stdout. Nothing is
written to the database and no alert is sent.

Exit code: 0 ok, 1 warning, 2 critical (also unreachable, invalid or a usage error).

flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	p.address = fs.Arg(0)

	target, err := buildCheckTarget(p)
	if err != nil {
		fmt.Fprintln(os.Stderr, "certel check:", err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	res := probe.New().Check(ctx, target)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(toCheckOutput(res)); err != nil {
		fmt.Fprintln(os.Stderr, "certel check:", err)
		return 2
	}
	return checkExitCode(res.Severity)
}
