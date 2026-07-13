// tls10server re-enables the Go TLS *server's* ability to negotiate TLS 1.0,
// gated behind a GODEBUG since Go 1.22. Only the in-process test server needs
// it; the probe (the client) accepts TLS 1.0 unconditionally via MinVersion.
// Real legacy endpoints speak TLS 1.0 natively, so no such flag is needed in
// production.
//go:debug tls10server=1

package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/antonkomarev/certel/internal/config"
)

// testCA is a throwaway CA plus helpers to mint leaf certificates.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "certel test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{
		cert: cert, key: key,
		pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// newTestCAExpiring is newTestCA with an explicit CA NotAfter, for exercising a
// short-lived in-path issuer whose expiry should drive the decision.
func newTestCAExpiring(t *testing.T, notAfter time.Time) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "certel test CA (short-lived)"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{
		cert: cert, key: key,
		pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

func (ca *testCA) file(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, ca.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// leaf issues a server certificate for the given DNS name and validity window.
func (ca *testCA) leaf(t *testing.T, dnsName string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key}
}

// leafSHA1 issues a leaf signed by the CA with the deprecated ECDSA-SHA1
// algorithm — the kind of certificate Go's verifier refuses to validate.
func (ca *testCA) leafSHA1(t *testing.T, dnsName string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:       big.NewInt(time.Now().UnixNano()),
		Subject:            pkix.Name{CommonName: dnsName},
		DNSNames:           []string{dnsName},
		IPAddresses:        []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SignatureAlgorithm: x509.ECDSAWithSHA1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key}
}

// selfSignedCA mints a throwaway self-signed CA certificate with an explicit
// validity window — used to fabricate the expired extraneous certs servers
// bundle into a presented chain.
func selfSignedCA(t *testing.T, cn string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

// withExtraCerts appends extraneous certificates to a server's presented chain,
// mimicking a stale fullchain.pem that carries certs verifiers ignore.
func withExtraCerts(base tls.Certificate, extra ...*x509.Certificate) tls.Certificate {
	for _, c := range extra {
		base.Certificate = append(base.Certificate, c.Raw)
	}
	return base
}

// tlsServer accepts connections, completes the handshake and closes.
func tlsServer(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.(*tls.Conn).Handshake()
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// tlsServerMaxVersion is tlsServer pinned to a maximum negotiated version, for
// exercising legacy endpoints the probe must still be able to monitor.
func tlsServerMaxVersion(t *testing.T, cert tls.Certificate, max uint16) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MaxVersion:   max,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.(*tls.Conn).Handshake()
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func testTarget(address string, mutate ...func(*config.Target)) config.Target {
	warning, critical, retries := 30, 7, 0
	timeout := config.Duration(3 * time.Second)
	h := config.Target{
		Address:  address,
		Protocol: config.ProtoTLS,
		TargetParams: config.TargetParams{
			WarningDays: &warning, CriticalDays: &critical,
			Timeout: &timeout, ConnectRetries: &retries,
		},
	}
	for _, m := range mutate {
		m(&h)
	}
	return h
}

func TestHealthyCertificate(t *testing.T) {
	// GIVEN: сервер с действующим сертификатом (ещё ~89 дней до истечения), доверенным тестовому CA
	ca := newTestCA(t)
	addr := tlsServer(t, ca.leaf(t, "good.test", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)))
	h := testTarget(addr, func(h *config.Target) {
		h.Servername = "good.test"
		h.CAFile = ca.file(t)
	})

	// WHEN: пробинг проверяет цель
	r := New().Check(context.Background(), h)

	// THEN: статус и severity — «всё в порядке», цепочка проверена, срок жизни рассчитан верно
	if r.Status != StatusOK || r.Severity != SeverityOK {
		t.Fatalf("want ok/ok, got %s/%s (%s)", r.Status, r.Severity, r.Message)
	}
	if !r.VerifyOK {
		t.Error("chain should verify against the test CA")
	}
	if got := r.DaysLeft; got < 88 || got > 90 {
		t.Errorf("DaysLeft = %d, want ~89", got)
	}
}

func TestDaysLeftUsesInjectedClock(t *testing.T) {
	// GIVEN: замороженные часы пробера и лист, истекающий ровно через 89 дней и 12 часов от этого момента
	ca := newTestCA(t)
	frozen := time.Date(2020, 6, 1, 0, 0, 0, 0, time.UTC)
	cert := ca.leaf(t, "frozen.test", frozen.Add(-time.Hour), frozen.Add(89*24*time.Hour+12*time.Hour))
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	p := &Prober{Now: func() time.Time { return frozen }}
	h := testTarget("frozen.test:443", func(h *config.Target) { h.Insecure = true })

	// WHEN: цепочка оценивается напрямую — в обход сети и стенных часов
	r := p.evaluate(h, []*x509.Certificate{leaf})

	// THEN: DaysLeft вычислен из инъецированных часов и усечён к нулю (12 часов отброшены), независимо от time.Now()
	if r.DaysLeft != 89 {
		t.Fatalf("DaysLeft = %d, want exactly 89 computed from the injected clock", r.DaysLeft)
	}
}

func TestExpiringSoonThresholds(t *testing.T) {
	ca := newTestCA(t)
	// таблица: остаток срока и ожидаемая severity — 10 дней попадает в предупреждение, 3 дня в критическую зону
	for _, tc := range []struct {
		days     int
		severity Severity
	}{
		{10, SeverityWarning}, {3, SeverityCritical},
	} {
		// GIVEN: сервер с сертификатом, истекающим через tc.days дней, доверенным тестовому CA
		addr := tlsServer(t, ca.leaf(t, "soon.test", time.Now().Add(-time.Hour),
			time.Now().Add(time.Duration(tc.days)*24*time.Hour+time.Hour)))
		h := testTarget(addr, func(h *config.Target) {
			h.Servername = "soon.test"
			h.CAFile = ca.file(t)
		})

		// WHEN: пробинг проверяет цель
		r := New().Check(context.Background(), h)

		// THEN: статус — «скоро истекает», а severity соответствует порогу остатка срока
		if r.Status != StatusExpiringSoon || r.Severity != tc.severity {
			t.Errorf("%d days left: want expiring_soon/%s, got %s/%s (%s)",
				tc.days, tc.severity, r.Status, r.Severity, r.Message)
		}
	}
}

func TestThresholdBoundarySemantics(t *testing.T) {
	// The contract: `warning_days: N` fires when STRICTLY FEWER than N days
	// remain (`critical_days` likewise). It rests on two halves at once — the
	// strict `<` in the threshold switch AND daysUntil truncating toward zero —
	// and for an integer threshold floor(remaining) < N ⟺ remaining < N×24h
	// exactly. Nothing else pins the fire/no-fire decision at the boundary: the
	// other tests assert the DaysLeft number, never the decision one second to
	// either side of a threshold. Flip either half (an innocent `<=`, a
	// well-meaning math.Round) and one of these cases breaks.
	ca := newTestCA(t)
	frozen := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	const warningDays, criticalDays = 30, 7
	const day = 24 * time.Hour

	for _, tc := range []struct {
		name      string
		remaining time.Duration
		status    Status
		severity  Severity
	}{
		// Warning threshold: fewer than 30 days → warning; 30 days or more → ok.
		{"1s inside warning", warningDays*day - time.Second, StatusExpiringSoon, SeverityWarning},
		{"exactly warning", warningDays * day, StatusOK, SeverityOK},
		{"1s outside warning", warningDays*day + time.Second, StatusOK, SeverityOK},
		// Critical threshold: fewer than 7 days → critical; 7 days or more → warning.
		{"1s inside critical", criticalDays*day - time.Second, StatusExpiringSoon, SeverityCritical},
		{"exactly critical", criticalDays * day, StatusExpiringSoon, SeverityWarning},
		{"1s outside critical", criticalDays*day + time.Second, StatusExpiringSoon, SeverityWarning},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// GIVEN: замороженные часы и лист, истекающий ровно через tc.remaining от них;
			// insecure отключает доверие, чтобы решение приняла именно ветка порогов
			cert := ca.leaf(t, "boundary.test", frozen.Add(-time.Hour), frozen.Add(tc.remaining))
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			p := &Prober{Now: func() time.Time { return frozen }}
			warning, critical := warningDays, criticalDays
			h := testTarget("boundary.test:443", func(h *config.Target) {
				h.Insecure = true
				h.WarningDays = &warning
				h.CriticalDays = &critical
			})

			// WHEN: цепочка оценивается напрямую — в обход сети и стенных часов
			r := p.evaluate(h, []*x509.Certificate{leaf})

			// THEN: срабатывание/несрабатывание совпадает с контрактом «строго меньше N дней»
			if r.Status != tc.status || r.Severity != tc.severity {
				t.Fatalf("remaining %v: want %s/%s, got %s/%s (%s)",
					tc.remaining, tc.status, tc.severity, r.Status, r.Severity, r.Message)
			}
		})
	}
}

func TestThresholdBoundaryAlreadyExpired(t *testing.T) {
	// GIVEN: лист, истёкший 12 часов назад — отрицательный остаток срока
	ca := newTestCA(t)
	frozen := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	cert := ca.leaf(t, "expired.test", frozen.Add(-48*time.Hour), frozen.Add(-12*time.Hour))
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	p := &Prober{Now: func() time.Time { return frozen }}
	h := testTarget("expired.test:443", func(h *config.Target) { h.Insecure = true })

	// WHEN: цепочка оценивается напрямую
	r := p.evaluate(h, []*x509.Certificate{leaf})

	// THEN: expired перебивает любой порог, а усечение к нулю читает −12ч как день 0, а не −1
	if r.Status != StatusExpired || r.Severity != SeverityEmergency {
		t.Fatalf("want expired/emergency, got %s/%s (%s)", r.Status, r.Severity, r.Message)
	}
	if r.DaysLeft != 0 {
		t.Errorf("truncation toward zero must read −12h remaining as day 0, got %d", r.DaysLeft)
	}
}

func TestExpiredCertificate(t *testing.T) {
	// GIVEN: сервер с уже просроченным сертификатом, доверенным тестовому CA
	ca := newTestCA(t)
	addr := tlsServer(t, ca.leaf(t, "old.test", time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)))
	h := testTarget(addr, func(h *config.Target) {
		h.Servername = "old.test"
		h.CAFile = ca.file(t)
	})

	// WHEN: пробинг проверяет цель
	r := New().Check(context.Background(), h)

	// THEN: статус — «истёк», severity — emergency
	if r.Status != StatusExpired || r.Severity != SeverityEmergency {
		t.Fatalf("want expired/emergency, got %s/%s (%s)", r.Status, r.Severity, r.Message)
	}
}

func TestHostnameMismatch(t *testing.T) {
	// GIVEN: сертификат выписан на actual.test, но проверяем под именем expected.test
	ca := newTestCA(t)
	addr := tlsServer(t, ca.leaf(t, "actual.test", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)))
	h := testTarget(addr, func(h *config.Target) {
		h.Servername = "expected.test"
		h.CAFile = ca.file(t)
	})

	// WHEN: пробинг проверяет цель
	r := New().Check(context.Background(), h)

	// THEN: несовпадение имени делает сертификат невалидным (severity emergency)
	if r.Status != StatusInvalid || r.Severity != SeverityEmergency {
		t.Fatalf("want invalid/emergency, got %s/%s (%s)", r.Status, r.Severity, r.Message)
	}
}

func TestUntrustedChainWithoutCAFile(t *testing.T) {
	// GIVEN: сертификат от тестового CA, но CAFile не задан — проверять придётся по системным корням
	ca := newTestCA(t)
	addr := tlsServer(t, ca.leaf(t, "selfmade.test", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)))
	h := testTarget(addr, func(h *config.Target) { h.Servername = "selfmade.test" })

	// WHEN: пробинг проверяет цель
	r := New().Check(context.Background(), h)

	// THEN: цепочка не доверена системным корням, сертификат невалиден (severity emergency)
	if r.Status != StatusInvalid || r.Severity != SeverityEmergency {
		t.Fatalf("want invalid/emergency against system roots, got %s/%s (%s)", r.Status, r.Severity, r.Message)
	}
}

func TestInsecureSkipsTrustButChecksExpiry(t *testing.T) {
	// GIVEN: недоверенный сервер, несовпадающее имя и включённый insecure-режим — проверки доверия отключены
	ca := newTestCA(t)
	addr := tlsServer(t, ca.leaf(t, "selfmade.test", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)))
	h := testTarget(addr, func(h *config.Target) {
		h.Servername = "whatever.test" // mismatch must be ignored in insecure mode
		h.Insecure = true
	})

	// WHEN: пробинг проверяет цель
	r := New().Check(context.Background(), h)

	// THEN: недоверие и несовпадение имени игнорируются, но действующий срок оставляет статус ok
	if r.Status != StatusOK {
		t.Fatalf("insecure mode: want ok, got %s (%s)", r.Status, r.Message)
	}
}

func TestLegacyTLS10Endpoint(t *testing.T) {
	// GIVEN: сервер с действующим сертификатом, но говорящий максимум по TLS 1.0 —
	// такие легаси-эндпоинты Go по умолчанию (пол TLS 1.2) отверг бы на хендшейке
	ca := newTestCA(t)
	addr := tlsServerMaxVersion(t,
		ca.leaf(t, "legacy.test", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)),
		tls.VersionTLS10)
	h := testTarget(addr, func(h *config.Target) {
		h.Servername = "legacy.test"
		h.CAFile = ca.file(t)
	})

	// WHEN: пробинг проверяет цель
	r := New().Check(context.Background(), h)

	// THEN: хендшейк проходит по TLS 1.0, сертификат инспектируется, а не unreachable
	if r.Status != StatusOK || r.Severity != SeverityOK {
		t.Fatalf("legacy TLS 1.0 endpoint: want ok/ok, got %s/%s (%s)", r.Status, r.Severity, r.Message)
	}
}

func TestWeakSignatureCertificate(t *testing.T) {
	// GIVEN: живой сертификат (~89 дней), доверенный CA, но подписанный SHA-1 —
	// такой Go-верификатор проверять отказывается
	ca := newTestCA(t)
	addr := tlsServer(t, ca.leafSHA1(t, "legacy.test", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)))
	h := testTarget(addr, func(h *config.Target) {
		h.Servername = "legacy.test"
		h.CAFile = ca.file(t)
	})

	// WHEN: пробинг проверяет цель
	r := New().Check(context.Background(), h)

	// THEN: выделенный статус weak_signature вместо invalid, severity critical,
	// а срок всё равно виден из предъявленной цепочки
	if r.Status != StatusWeakSignature || r.Severity != SeverityCritical {
		t.Fatalf("want weak_signature/critical, got %s/%s (%s)", r.Status, r.Severity, r.Message)
	}
	if got := r.DaysLeft; got < 88 || got > 90 {
		t.Errorf("expiry should still be reported for a weak-signature cert: DaysLeft = %d, want ~89", got)
	}
}

func TestWeakSignatureIgnoredInInsecureMode(t *testing.T) {
	// GIVEN: тот же SHA-1 сертификат, но цель в insecure-режиме
	ca := newTestCA(t)
	addr := tlsServer(t, ca.leafSHA1(t, "legacy.test", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)))
	h := testTarget(addr, func(h *config.Target) {
		h.Servername = "legacy.test"
		h.Insecure = true
	})

	// WHEN: пробинг проверяет цель
	r := New().Check(context.Background(), h)

	// THEN: insecure отключает проверку доверия целиком, слабая подпись игнорируется,
	// действующий срок оставляет статус ok
	if r.Status != StatusOK {
		t.Fatalf("insecure mode: want ok, got %s (%s)", r.Status, r.Message)
	}
}

func TestExpiredExtraneousCertIgnored(t *testing.T) {
	// GIVEN: сервер отдаёт [действующий лист, действующий CA, просроченный посторонний CA] —
	// такой хвост (устаревший AddTrust/DST-кросс-сайн) верификаторы просто игнорируют
	ca := newTestCA(t)
	extraneous := selfSignedCA(t, "Expired Extraneous Root", time.Now().Add(-2*365*24*time.Hour), time.Now().Add(-365*24*time.Hour))
	addr := tlsServer(t, withExtraCerts(
		ca.leaf(t, "good.test", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)),
		extraneous))
	h := testTarget(addr, func(h *config.Target) {
		h.Servername = "good.test"
		h.CAFile = ca.file(t)
	})

	// WHEN: пробинг проверяет цель
	r := New().Check(context.Background(), h)

	// THEN: цепочка верифицируется, посторонний просроченный сертификат не даёт ложного expired
	if r.Status != StatusOK || r.Severity != SeverityOK {
		t.Fatalf("want ok/ok, got %s/%s (%s)", r.Status, r.Severity, r.Message)
	}
	// AND: посторонний сертификат не протекает и в отображаемый CertInfo
	if r.Cert.EarliestSubject == "Expired Extraneous Root" {
		t.Errorf("extraneous cert leaked into CertInfo.EarliestSubject = %q", r.Cert.EarliestSubject)
	}
}

func TestExpiredExtraneousCertIgnoredInsecure(t *testing.T) {
	// GIVEN: та же цепочка с посторонним просроченным CA, но цель в insecure-режиме
	ca := newTestCA(t)
	extraneous := selfSignedCA(t, "Expired Extraneous Root", time.Now().Add(-2*365*24*time.Hour), time.Now().Add(-365*24*time.Hour))
	addr := tlsServer(t, withExtraCerts(
		ca.leaf(t, "good.test", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)),
		extraneous))
	h := testTarget(addr, func(h *config.Target) {
		h.Servername = "good.test"
		h.Insecure = true
	})

	// WHEN: пробинг проверяет цель
	r := New().Check(context.Background(), h)

	// THEN: insecure тоже опирается на цепочку от листа, а не на все peers → ok
	if r.Status != StatusOK {
		t.Fatalf("insecure with extraneous expired cert: want ok, got %s (%s)", r.Status, r.Message)
	}
}

func TestExpiredExtraneousDoesNotMaskHostnameMismatch(t *testing.T) {
	// GIVEN: лист выписан на actual.test, посторонний просроченный CA в хвосте, проверяем под expected.test
	ca := newTestCA(t)
	extraneous := selfSignedCA(t, "Expired Extraneous Root", time.Now().Add(-2*365*24*time.Hour), time.Now().Add(-365*24*time.Hour))
	addr := tlsServer(t, withExtraCerts(
		ca.leaf(t, "actual.test", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)),
		extraneous))
	h := testTarget(addr, func(h *config.Target) {
		h.Servername = "expected.test"
		h.CAFile = ca.file(t)
	})

	// WHEN: пробинг проверяет цель
	r := New().Check(context.Background(), h)

	// THEN: настоящая проблема — несовпадение имени, а не посторонняя просрочка
	if r.Status != StatusInvalid {
		t.Fatalf("want invalid (hostname), got %s (%s)", r.Status, r.Message)
	}
	if strings.Contains(r.Message, "Extraneous") {
		t.Errorf("diagnosis blamed the extraneous expired cert: %q", r.Message)
	}
}

func TestExpiredLeafBeatsWeakSignature(t *testing.T) {
	// GIVEN: лист подписан SHA-1 И уже просрочен — оба дефекта сразу
	ca := newTestCA(t)
	addr := tlsServer(t, ca.leafSHA1(t, "legacy.test", time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)))
	h := testTarget(addr, func(h *config.Target) {
		h.Servername = "legacy.test"
		h.CAFile = ca.file(t)
	})

	// WHEN: пробинг проверяет цель
	r := New().Check(context.Background(), h)

	// THEN: expired сохраняет приоритет над weak_signature (как и до инверсии порядка)
	if r.Status != StatusExpired || r.Severity != SeverityEmergency {
		t.Fatalf("want expired/emergency, got %s/%s (%s)", r.Status, r.Severity, r.Message)
	}
}

func TestInsecureInPathIntermediateExpiryDrivesDecision(t *testing.T) {
	// GIVEN: insecure-цель, где действующий лист (~90 дней) выписан CA, истекающим через 3 дня —
	// промежуточный-в-пути истекает раньше листа
	ca := newTestCAExpiring(t, time.Now().Add(3*24*time.Hour))
	addr := tlsServer(t, ca.leaf(t, "good.test", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)))
	h := testTarget(addr, func(h *config.Target) {
		h.Servername = "good.test"
		h.Insecure = true
	})

	// WHEN: пробинг проверяет цель
	r := New().Check(context.Background(), h)

	// THEN: срок промежуточного-в-пути (а не только листа) двигает решение — критический порог
	if r.Status != StatusExpiringSoon || r.Severity != SeverityCritical {
		t.Fatalf("want expiring_soon/critical from the in-path issuer, got %s/%s (%s)", r.Status, r.Severity, r.Message)
	}
}

func TestUnreachableHost(t *testing.T) {
	// GIVEN: адрес закрытого слушателя (соединение будет отвергнуто) и одна повторная попытка
	// A listener that is immediately closed yields a refused connection.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	retries := 1
	h := testTarget(addr, func(h *config.Target) { h.ConnectRetries = &retries })

	// WHEN: пробинг проверяет цель
	r := New().Check(context.Background(), h)

	// THEN: цель признана недоступной, а неудачное соединение было повторено (всего попыток retries+1)
	if r.Status != StatusUnreachable {
		t.Fatalf("want unreachable, got %s (%s)", r.Status, r.Message)
	}
	if r.Attempts != retries+1 {
		t.Errorf("connection failures must be retried: attempts=%d, want %d", r.Attempts, retries+1)
	}
}
