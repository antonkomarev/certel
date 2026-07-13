package probe

import (
	"time"

	"github.com/antonkomarev/certel/internal/config"
)

// Status classifies the outcome of a single check.
type Status string

const (
	// StatusOK: certificate verified, expiry beyond the warning threshold.
	StatusOK Status = "ok"
	// StatusExpiringSoon: valid but expires within warning/critical days.
	StatusExpiringSoon Status = "expiring_soon"
	// StatusExpired: a certificate in the chain has already expired.
	StatusExpired Status = "expired"
	// StatusInvalid: chain is untrusted or the hostname does not match.
	StatusInvalid Status = "invalid"
	// StatusWeakSignature: the chain could not be verified because a
	// certificate in it is signed with an algorithm Go refuses to validate
	// (e.g. SHA-1). Distinct from StatusInvalid so a live-but-legacy
	// certificate is not confused with a genuinely untrusted one; the expiry
	// is still reported from the presented chain.
	StatusWeakSignature Status = "weak_signature"
	// StatusTLSUnavailable: the server did not offer STARTTLS.
	StatusTLSUnavailable Status = "tls_unavailable"
	// StatusUnreachable: connection or protocol failure — the certificate
	// could not be inspected at all. Distinct from certificate problems.
	StatusUnreachable Status = "unreachable"
)

// Severity is the alerting level derived from Status and thresholds.
type Severity string

// The values form a strictly ordered escalation ladder that is append-only at
// the top; the metrics encoding (certel_probe_severity) mirrors this order.
const (
	SeverityOK       Severity = "ok"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
	// SeverityEmergency: already failing and the signal is trustworthy — an
	// expired or untrusted certificate is breaking clients right now, a
	// sharper emergency than an approaching deadline. Named after syslog's top
	// severity, extending the ok/warning/critical ladder in the same
	// vocabulary. The noisier, less reliable failures (unreachable,
	// tls_unavailable, weak_signature) stay critical.
	SeverityEmergency Severity = "emergency"
)

// Result is the outcome of probing one target.
type Result struct {
	Target    config.Target
	Status    Status
	Severity  Severity
	Message   string
	CheckedAt time.Time
	Duration  time.Duration
	Attempts  int
	Cert      *CertInfo // nil when the handshake never completed
	VerifyOK  bool
	// VerifiedNotAfter is the earliest expiry within the best verified
	// chain; zero when verification failed.
	VerifiedNotAfter time.Time
	// DaysLeft is whole days until the effective expiry (negative if past),
	// computed once at evaluation from the prober's clock so it agrees with
	// the threshold decision. Zero when no certificate expiry was observed.
	DaysLeft int
}

// CertInfo describes the leaf certificate presented by the server.
type CertInfo struct {
	Subject string // full DN
	CN      string
	Issuer  string // full DN
	// IssuerCN and IssuerOrg are the issuer's common name and first
	// organization, split from the DN at probe time so the alert templater
	// needs no runtime DN parser (e.g. "R13" and "Let's Encrypt").
	IssuerCN  string
	IssuerOrg string
	// SignatureAlgorithm is the leaf's signature algorithm rendered in the
	// OpenSSL style ("SHA-256 with RSA encryption") for notice parity.
	SignatureAlgorithm string
	SANs               []string
	Serial             string
	NotBefore          time.Time
	NotAfter           time.Time
	// EarliestNotAfter is the soonest expiry across the presented chain
	// (leaf and intermediates) — an intermediate can expire before the leaf.
	EarliestNotAfter time.Time
	EarliestSubject  string
}

// EffectiveNotAfter is the expiry the status decision is based on: the
// earliest certificate in the verified chain when available, otherwise the
// earliest in the presented chain.
func (r Result) EffectiveNotAfter() time.Time {
	if !r.VerifiedNotAfter.IsZero() {
		return r.VerifiedNotAfter
	}
	if r.Cert != nil {
		return r.Cert.EarliestNotAfter
	}
	return time.Time{}
}
