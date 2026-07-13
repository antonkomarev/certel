// Package probe establishes TLS sessions (directly or via STARTTLS) and
// evaluates the certificates a server presents.
package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/antonkomarev/certel/internal/config"
)

// Prober checks targets. Safe for concurrent use.
type Prober struct {
	// Now is stubbed in tests; defaults to time.Now.
	Now func() time.Time
}

func New() *Prober { return &Prober{Now: time.Now} }

// Check probes a target, retrying transient connection failures. Certificate
// problems are never retried — the answer will not change.
func (p *Prober) Check(ctx context.Context, t config.Target) Result {
	start := p.Now()
	retries := *t.ConnectRetries
	var res Result
	for attempt := 1; attempt <= retries+1; attempt++ {
		res = p.checkOnce(ctx, t)
		res.Attempts = attempt
		if res.Status != StatusUnreachable || ctx.Err() != nil {
			break
		}
		// Brief pause between attempts to ride out a network blip.
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
	res.CheckedAt = start
	res.Duration = p.Now().Sub(start)
	return res
}

func (p *Prober) checkOnce(ctx context.Context, t config.Target) Result {
	timeout := t.Timeout.Std()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", t.Address)
	if err != nil {
		return Result{Target: t, Status: StatusUnreachable, Severity: SeverityCritical,
			Message: fmt.Sprintf("connection failed: %v", err)}
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)

	// For explicit-TLS protocols, run the plaintext dialog up to the point
	// where the TLS handshake can begin.
	if t.Protocol != config.ProtoTLS {
		if err := starttls(conn, t.Protocol); err != nil {
			if _, ok := err.(*errTLSUnsupported); ok {
				return Result{Target: t, Status: StatusTLSUnavailable, Severity: SeverityCritical,
					Message: fmt.Sprintf("server does not offer STARTTLS: %v", err)}
			}
			return Result{Target: t, Status: StatusUnreachable, Severity: SeverityCritical,
				Message: fmt.Sprintf("%s STARTTLS negotiation failed: %v", t.Protocol, err)}
		}
	}

	// Handshake with verification disabled so an expired or untrusted
	// certificate can still be inspected; trust is verified manually below.
	// Accept legacy TLS 1.0/1.1 endpoints (old appliances, embedded management
	// interfaces, legacy mail servers) — exactly the fleet a self-hosted
	// monitor gets pointed at. Their certificates expire too, and a read-only
	// prober that transmits nothing sensitive and verifies the chain manually
	// has little to lose by lowering the floor below Go's TLS 1.2 default.
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         t.EffectiveServername(),
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return Result{Target: t, Status: StatusUnreachable, Severity: SeverityCritical,
			Message: fmt.Sprintf("TLS handshake failed: %v", err)}
	}
	peers := tlsConn.ConnectionState().PeerCertificates
	if len(peers) == 0 {
		return Result{Target: t, Status: StatusInvalid, Severity: SeverityEmergency,
			Message: "server presented no certificates"}
	}
	return p.evaluate(t, peers)
}

func (p *Prober) evaluate(t config.Target, peers []*x509.Certificate) Result {
	now := p.Now()
	leaf := peers[0]
	res := Result{Target: t}

	// Verify first: trust decides which certificates matter. A server may
	// present expired extraneous certs (a stale AddTrust root, a leftover
	// cross-sign) that chain to nothing; those must not drive the diagnosis.
	verifiedChain, verifyErr := p.verify(t, peers, now)
	res.VerifyOK = verifyErr == nil

	// Scope: the certificates the status decision and CertInfo may consider.
	// The verified chain when one built; otherwise the certs reachable from
	// the leaf by issuer links. Never the raw peer set — that is exactly how
	// an extraneous expired cert leaks into the diagnosis or the reported
	// CertInfo.
	scope := verifiedChain
	if scope == nil {
		scope = leafChain(peers)
	}
	if res.VerifyOK {
		res.VerifiedNotAfter = earliestNotAfter(verifiedChain)
	}
	res.Cert = certInfo(leaf, scope)
	// One source of truth for the number: the effective expiry is settled now
	// (verified chain when trusted, leaf chain otherwise), so compute days once
	// and let every downstream consumer read res.DaysLeft.
	res.DaysLeft = daysUntil(res.EffectiveNotAfter(), now)

	// Expiry takes precedence over trust errors: an expired certificate also
	// fails verification, but "expired" is the actionable diagnosis. Scoped to
	// the leaf chain, so an expired extraneous cert cannot false-fire; applies
	// to insecure targets too (a genuinely expired leaf is still expired). A
	// verified chain never contains an expired cert, so this is only reachable
	// when verification failed.
	if expired := earliestExpired(scope, now); expired != nil {
		res.Status = StatusExpired
		res.Severity = SeverityEmergency
		res.Message = fmt.Sprintf("certificate %q expired on %s",
			expired.Subject.CommonName, expired.NotAfter.Format(time.RFC3339))
		return res
	}

	// A trusted target whose chain does not build gets a trust diagnosis.
	// Insecure targets ignore trust entirely and fall through to thresholds.
	if !res.VerifyOK && !t.Insecure {
		switch {
		case weakSignatureCert(peers) != nil:
			res.Severity = SeverityCritical
			// The chain contains a certificate signed with an algorithm Go's
			// verifier refuses to validate (SHA-1 or older), so trust could
			// not be confirmed — but the certificate is otherwise live.
			// x509.Verify buries the InsecureAlgorithmError inside an
			// UnknownAuthorityError's unexported hint, so the chain is
			// inspected directly instead of unwrapping the error. Report it as
			// its own status and still surface the expiry from the leaf chain
			// so a legacy host is not mistaken for a genuinely untrusted one.
			weak := weakSignatureCert(peers)
			res.Status = StatusWeakSignature
			res.Message = fmt.Sprintf("chain unverifiable: certificate %q uses a weak signature algorithm (%v); certificate expires in %d day(s), on %s",
				weak.Subject.CommonName, weak.SignatureAlgorithm, res.DaysLeft, res.EffectiveNotAfter().Format(time.RFC3339))
		case errors.As(verifyErr, new(x509.HostnameError)):
			res.Status = StatusInvalid
			res.Severity = SeverityEmergency
			res.Message = fmt.Sprintf("hostname mismatch: certificate is valid for %v, not %q",
				leaf.DNSNames, t.EffectiveServername())
		default:
			res.Status = StatusInvalid
			res.Severity = SeverityEmergency
			res.Message = fmt.Sprintf("certificate verification failed: %v", verifyErr)
		}
		return res
	}

	days := res.DaysLeft
	switch {
	case days < *t.CriticalDays:
		res.Status = StatusExpiringSoon
		res.Severity = SeverityCritical
		res.Message = fmt.Sprintf("certificate expires in %d day(s), on %s",
			days, res.EffectiveNotAfter().Format(time.RFC3339))
	case days < *t.WarningDays:
		res.Status = StatusExpiringSoon
		res.Severity = SeverityWarning
		res.Message = fmt.Sprintf("certificate expires in %d day(s), on %s",
			days, res.EffectiveNotAfter().Format(time.RFC3339))
	default:
		res.Status = StatusOK
		res.Severity = SeverityOK
		res.Message = fmt.Sprintf("certificate valid, expires in %d day(s)", days)
	}
	return res
}

// daysUntil returns whole days from now until exp, truncating toward zero: an
// expiry 12 hours in the past reads 0, not -1, and an expiry 12 hours ahead
// reads 0, not 1. A zero exp (no certificate expiry observed) yields 0.
func daysUntil(exp, now time.Time) int {
	if exp.IsZero() {
		return 0
	}
	return int(exp.Sub(now).Hours() / 24)
}

// verify builds trust chains and returns the "best" one — the chain whose
// earliest NotAfter is latest, mirroring ssl_exporter's chain_no=0 — or a
// non-nil error when no chain builds. Verification runs at `now`, so every
// certificate in the returned chain is live: an expired cert can never be part
// of a verified chain. The caller derives VerifiedNotAfter from the chain.
func (p *Prober) verify(t config.Target, peers []*x509.Certificate, now time.Time) ([]*x509.Certificate, error) {
	opts := x509.VerifyOptions{
		Intermediates: x509.NewCertPool(),
		CurrentTime:   now,
	}
	if !t.Insecure {
		opts.DNSName = t.EffectiveServername()
	}
	for _, ic := range peers[1:] {
		opts.Intermediates.AddCert(ic)
	}
	if t.CAFile != "" {
		pem, err := os.ReadFile(t.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading ca_file: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file %s contains no valid certificates", t.CAFile)
		}
		opts.Roots = roots
	}
	chains, err := peers[0].Verify(opts)
	if err != nil {
		return nil, err
	}
	best := chains[0]
	bestEarliest := earliestNotAfter(best)
	for _, chain := range chains[1:] {
		if earliest := earliestNotAfter(chain); earliest.After(bestEarliest) {
			best, bestEarliest = chain, earliest
		}
	}
	return best, nil
}

// earliestNotAfter returns the soonest NotAfter across a chain — an
// intermediate can expire before the leaf. Zero for an empty chain.
func earliestNotAfter(chain []*x509.Certificate) time.Time {
	if len(chain) == 0 {
		return time.Time{}
	}
	earliest := chain[0].NotAfter
	for _, c := range chain[1:] {
		if c.NotAfter.Before(earliest) {
			earliest = c.NotAfter
		}
	}
	return earliest
}

// leafChain returns the leaf together with the presented certificates reachable
// from it by following issuer links — the candidate path — and nothing else.
// Servers routinely bundle extraneous certs (an expired AddTrust root, a stale
// cross-sign) that chain to nothing; excluding them keeps an expired straggler
// from being blamed for an unrelated verification failure or leaking into the
// reported CertInfo. Used when no verified chain is available.
func leafChain(peers []*x509.Certificate) []*x509.Certificate {
	chain := []*x509.Certificate{peers[0]}
	rest := peers[1:]
	used := make([]bool, len(rest))
	current := peers[0]
	// Stop at a self-signed cert (issuer == subject) or when no presented cert
	// issued the current one. `used` guards against a cross-signed cycle.
	for !bytes.Equal(current.RawIssuer, current.RawSubject) {
		next := -1
		for i, c := range rest {
			if !used[i] && bytes.Equal(current.RawIssuer, c.RawSubject) {
				next = i
				break
			}
		}
		if next == -1 {
			break
		}
		used[next] = true
		current = rest[next]
		chain = append(chain, current)
	}
	return chain
}

func earliestExpired(peers []*x509.Certificate, now time.Time) *x509.Certificate {
	for _, c := range peers {
		if now.After(c.NotAfter) {
			return c
		}
	}
	return nil
}

// weakSignatureCert returns the first presented certificate signed with an
// algorithm Go's verifier rejects outright (SHA-1 and older), which makes the
// whole chain unverifiable. A self-signed root's own signature is never checked
// during verification, so it cannot be the cause and is skipped.
func weakSignatureCert(peers []*x509.Certificate) *x509.Certificate {
	for _, c := range peers {
		switch c.SignatureAlgorithm {
		case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA,
			x509.DSAWithSHA1, x509.ECDSAWithSHA1:
			if bytes.Equal(c.RawIssuer, c.RawSubject) {
				continue
			}
			return c
		}
	}
	return nil
}

// opensslSigAlg renders an x509 signature algorithm in the OpenSSL long form
// ("SHA-256 with RSA encryption") that certificate viewers and the alert notice
// use, rather than Go's terse "SHA256-RSA". Unknown algorithms fall back to the
// stdlib string so a future algorithm still renders something meaningful.
func opensslSigAlg(a x509.SignatureAlgorithm) string {
	switch a {
	case x509.SHA256WithRSA:
		return "SHA-256 with RSA encryption"
	case x509.SHA384WithRSA:
		return "SHA-384 with RSA encryption"
	case x509.SHA512WithRSA:
		return "SHA-512 with RSA encryption"
	case x509.SHA1WithRSA:
		return "SHA-1 with RSA encryption"
	case x509.SHA256WithRSAPSS:
		return "SHA-256 with RSA-PSS"
	case x509.SHA384WithRSAPSS:
		return "SHA-384 with RSA-PSS"
	case x509.SHA512WithRSAPSS:
		return "SHA-512 with RSA-PSS"
	case x509.ECDSAWithSHA256:
		return "ECDSA with SHA-256"
	case x509.ECDSAWithSHA384:
		return "ECDSA with SHA-384"
	case x509.ECDSAWithSHA512:
		return "ECDSA with SHA-512"
	case x509.ECDSAWithSHA1:
		return "ECDSA with SHA-1"
	case x509.PureEd25519:
		return "Ed25519"
	default:
		return a.String()
	}
}

func certInfo(leaf *x509.Certificate, peers []*x509.Certificate) *CertInfo {
	var issuerOrg string
	if len(leaf.Issuer.Organization) > 0 {
		issuerOrg = leaf.Issuer.Organization[0]
	}
	info := &CertInfo{
		Subject:            leaf.Subject.String(),
		CN:                 leaf.Subject.CommonName,
		Issuer:             leaf.Issuer.String(),
		IssuerCN:           leaf.Issuer.CommonName,
		IssuerOrg:          issuerOrg,
		SignatureAlgorithm: opensslSigAlg(leaf.SignatureAlgorithm),
		SANs:               leaf.DNSNames,
		Serial:             leaf.SerialNumber.String(),
		NotBefore:          leaf.NotBefore,
		NotAfter:           leaf.NotAfter,
		EarliestNotAfter:   leaf.NotAfter,
		EarliestSubject:    leaf.Subject.CommonName,
	}
	for _, c := range peers {
		if c.NotAfter.Before(info.EarliestNotAfter) {
			info.EarliestNotAfter = c.NotAfter
			info.EarliestSubject = c.Subject.CommonName
		}
	}
	return info
}
