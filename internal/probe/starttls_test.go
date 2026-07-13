package probe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/antonkomarev/certel/internal/config"
)

// fakeSMTPServer speaks just enough SMTP to reach the TLS handshake.
// When offerStartTLS is false it omits the capability from the EHLO reply.
func fakeSMTPServer(t *testing.T, cert tls.Certificate, offerStartTLS bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
				r := bufio.NewReader(c)
				fmt.Fprintf(c, "220 fake.test ESMTP ready\r\n")
				line, err := r.ReadString('\n')
				if err != nil || !strings.HasPrefix(strings.ToUpper(line), "EHLO") {
					return
				}
				if offerStartTLS {
					fmt.Fprintf(c, "250-fake.test\r\n250-STARTTLS\r\n250 OK\r\n")
				} else {
					fmt.Fprintf(c, "250-fake.test\r\n250 OK\r\n")
					return
				}
				line, err = r.ReadString('\n')
				if err != nil || !strings.HasPrefix(strings.ToUpper(line), "STARTTLS") {
					return
				}
				fmt.Fprintf(c, "220 Go ahead\r\n")
				tlsConn := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
				_ = tlsConn.Handshake()
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// fakePostgresServer answers the SSLRequest with the given byte and, for 'S',
// proceeds to a TLS handshake.
func fakePostgresServer(t *testing.T, cert tls.Certificate, answer byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
				buf := make([]byte, 8)
				if _, err := c.Read(buf); err != nil {
					return
				}
				if binary.BigEndian.Uint32(buf[4:8]) != 80877103 {
					return
				}
				c.Write([]byte{answer})
				if answer == 'S' {
					tlsConn := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
					_ = tlsConn.Handshake()
				}
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func starttlsTarget(addr string, proto config.Protocol, ca *testCA, t *testing.T) config.Target {
	return testTarget(addr, func(h *config.Target) {
		h.Protocol = proto
		h.Servername = "starttls.test"
		h.CAFile = ca.file(t)
	})
}

func TestSMTPStartTLS(t *testing.T) {
	// GIVEN: SMTP-сервер, объявляющий STARTTLS и предъявляющий валидный сертификат
	ca := newTestCA(t)
	cert := ca.leaf(t, "starttls.test", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	addr := fakeSMTPServer(t, cert, true)

	// WHEN: цель пробится по протоколу SMTP
	r := New().Check(context.Background(), starttlsTarget(addr, config.ProtoSMTP, ca, t))

	// THEN: STARTTLS доводится до успешного рукопожатия, сертификат признан валидным
	if r.Status != StatusOK {
		t.Fatalf("want ok via SMTP STARTTLS, got %s (%s)", r.Status, r.Message)
	}
}

func TestSMTPWithoutStartTLSIsReported(t *testing.T) {
	// GIVEN: SMTP-сервер, не предлагающий STARTTLS в ответе на EHLO
	ca := newTestCA(t)
	cert := ca.leaf(t, "starttls.test", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	addr := fakeSMTPServer(t, cert, false)

	// WHEN: цель пробится по протоколу SMTP
	r := New().Check(context.Background(), starttlsTarget(addr, config.ProtoSMTP, ca, t))

	// THEN: отсутствие TLS распознаётся явно, а не маскируется под ошибку соединения
	if r.Status != StatusTLSUnavailable {
		t.Fatalf("want tls_unavailable when STARTTLS is not advertised, got %s (%s)", r.Status, r.Message)
	}
}

func TestPostgresSSLRequest(t *testing.T) {
	// GIVEN: Postgres-сервер, соглашающийся на TLS ответом 'S' на SSLRequest
	ca := newTestCA(t)
	cert := ca.leaf(t, "starttls.test", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	addr := fakePostgresServer(t, cert, 'S')

	// WHEN: цель пробится по протоколу Postgres
	r := New().Check(context.Background(), starttlsTarget(addr, config.ProtoPostgres, ca, t))

	// THEN: SSLRequest переходит в успешное TLS-рукопожатие
	if r.Status != StatusOK {
		t.Fatalf("want ok via postgres SSLRequest, got %s (%s)", r.Status, r.Message)
	}
}

func TestPostgresSSLDisabled(t *testing.T) {
	// GIVEN: Postgres-сервер, отклоняющий TLS ответом 'N' на SSLRequest
	ca := newTestCA(t)
	cert := ca.leaf(t, "starttls.test", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	addr := fakePostgresServer(t, cert, 'N')

	// WHEN: цель пробится по протоколу Postgres
	r := New().Check(context.Background(), starttlsTarget(addr, config.ProtoPostgres, ca, t))

	// THEN: отказ сервера от TLS распознаётся как недоступность шифрования
	if r.Status != StatusTLSUnavailable {
		t.Fatalf("want tls_unavailable on 'N' answer, got %s (%s)", r.Status, r.Message)
	}
}

func TestSTARTTLSOversizedResponseIsCapped(t *testing.T) {
	// GIVEN: сервер, бесконечно льющий байты без перевода строки, чтобы буфер пробера рос неограниченно
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		flood := bytes.Repeat([]byte("A"), 4096) // no '\n', forever
		for {
			if _, err := conn.Write(flood); err != nil {
				return
			}
		}
	}()

	// WHEN: цель пробится с коротким таймаутом, который зависание гарантированно превысит
	ca := newTestCA(t)
	h := starttlsTarget(ln.Addr().String(), config.ProtoSMTP, ca, t)
	short := config.Duration(3 * time.Second) // a hang would blow this
	h.Timeout = &short
	r := New().Check(context.Background(), h)

	// THEN: чтение упирается в предел и проба быстро падает как недоступная, а не съедает память
	if r.Status != StatusUnreachable {
		t.Fatalf("want unreachable on oversized STARTTLS response, got %s (%s)", r.Status, r.Message)
	}
	if !strings.Contains(r.Message, "oversized") {
		t.Fatalf("want an oversized-response diagnostic, got %q", r.Message)
	}
}

func TestImplicitTLSPortWithSMTPProtocol(t *testing.T) {
	// GIVEN: порт с неявным TLS (сервер говорит TLS с первого байта), опрашиваемый по протоколу с STARTTLS
	ca := newTestCA(t)
	addr := tlsServer(t, ca.leaf(t, "starttls.test", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)))
	h := starttlsTarget(addr, config.ProtoSMTP, ca, t)
	short := config.Duration(500 * time.Millisecond)
	h.Timeout = &short

	// WHEN: цель пробится по протоколу SMTP, ожидающему открытого приветствия
	r := New().Check(context.Background(), h)

	// THEN: рассогласование протоколов даёт понятную ошибку, а не зависание до таймаута
	if r.Status != StatusUnreachable && r.Status != StatusTLSUnavailable {
		t.Fatalf("want a protocol failure, got %s (%s)", r.Status, r.Message)
	}
}
