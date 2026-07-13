package probe

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/antonkomarev/certel/internal/config"
)

// A monitoring tool aims at untrusted endpoints by design, so a probed server
// must not be able to choose the prober's memory usage. The connection
// deadline bounds the time a STARTTLS dialog may take; these bound the bytes.
const (
	maxSTARTTLSBytes     = 64 << 10 // total plaintext read per negotiation
	maxContinuationLines = 100      // multiline "250-"/untagged replies
)

// errOversized reports a server that streamed past the byte budget without
// completing the dialog (e.g. a newline-free flood or endless continuation
// lines). Treated as unreachable, not tls_unavailable.
var errOversized = fmt.Errorf("oversized STARTTLS response (exceeded %d bytes)", maxSTARTTLSBytes)

// errTLSUnsupported means the server answered the plaintext dialog but
// declined or did not advertise TLS. Reported as tls_unavailable — a
// configuration regression or a possible STARTTLS-stripping attack.
type errTLSUnsupported struct{ reason string }

func (e *errTLSUnsupported) Error() string { return e.reason }

// limitedReader wraps a connection so no single STARTTLS negotiation can read
// more than maxSTARTTLSBytes. readLine reports errOversized (rather than a
// bare io.EOF) once the budget is spent without a terminating newline.
type limitedReader struct {
	br *bufio.Reader
	lr *io.LimitedReader
}

func newReader(conn net.Conn) *limitedReader {
	lr := &io.LimitedReader{R: conn, N: maxSTARTTLSBytes}
	return &limitedReader{br: bufio.NewReader(lr), lr: lr}
}

func (r *limitedReader) readLine() (string, error) {
	line, err := r.br.ReadString('\n')
	if err != nil && r.lr.N <= 0 && !strings.HasSuffix(line, "\n") {
		// The budget is exhausted and no newline arrived: the server, not the
		// network, ended the read.
		return line, errOversized
	}
	return line, err
}

// starttls drives the protocol-specific plaintext dialog up to the point
// where the TLS handshake can start on conn.
func starttls(conn net.Conn, proto config.Protocol) error {
	switch proto {
	case config.ProtoSMTP:
		return starttlsSMTP(conn)
	case config.ProtoIMAP:
		return starttlsIMAP(conn)
	case config.ProtoPOP3:
		return starttlsPOP3(conn)
	case config.ProtoFTP:
		return starttlsFTP(conn)
	case config.ProtoPostgres:
		return starttlsPostgres(conn)
	default:
		return fmt.Errorf("protocol %q does not support STARTTLS", proto)
	}
}

// readSMTPResponse consumes one (possibly multiline "250-...") SMTP reply
// and returns its three-digit code and the joined text.
func readSMTPResponse(r *limitedReader) (string, string, error) {
	var lines []string
	for {
		if len(lines) >= maxContinuationLines {
			return "", "", fmt.Errorf("response exceeded %d continuation lines", maxContinuationLines)
		}
		line, err := r.readLine()
		if err != nil {
			return "", "", fmt.Errorf("reading response: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		if len(line) < 4 || line[3] != '-' {
			if len(line) < 3 {
				return "", "", fmt.Errorf("malformed response line %q", line)
			}
			return line[:3], strings.Join(lines, "\n"), nil
		}
	}
}

func starttlsSMTP(conn net.Conn) error {
	r := newReader(conn)
	if code, text, err := readSMTPResponse(r); err != nil {
		return err
	} else if code != "220" {
		return fmt.Errorf("unexpected greeting %s %q (an implicit-TLS port? try protocol: tls)", code, text)
	}
	// TODO: make the EHLO name configurable (global default + per-target
	// override) instead of the hardcoded "certel.monitor". It is the only
	// place the prober identifies itself to the remote end, so a deployment
	// should be able to set a name their mail admins recognise. When done,
	// thread the value through starttls()/starttlsSMTP() from config.Target.
	if _, err := fmt.Fprintf(conn, "EHLO certel.monitor\r\n"); err != nil {
		return err
	}
	code, text, err := readSMTPResponse(r)
	if err != nil {
		return err
	}
	if code != "250" {
		return fmt.Errorf("EHLO rejected: %s %q", code, text)
	}
	if !strings.Contains(strings.ToUpper(text), "STARTTLS") {
		return &errTLSUnsupported{"STARTTLS not advertised in EHLO response"}
	}
	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		return err
	}
	if code, text, err := readSMTPResponse(r); err != nil {
		return err
	} else if code != "220" {
		return &errTLSUnsupported{fmt.Sprintf("STARTTLS refused: %s %q", code, text)}
	}
	return nil
}

func starttlsIMAP(conn net.Conn) error {
	r := newReader(conn)
	greeting, err := r.readLine()
	if err != nil {
		return fmt.Errorf("reading greeting: %w", err)
	}
	if !strings.HasPrefix(greeting, "* OK") && !strings.HasPrefix(greeting, "* PREAUTH") {
		return fmt.Errorf("unexpected greeting %q (an implicit-TLS port? try protocol: tls)", strings.TrimSpace(greeting))
	}
	if _, err := fmt.Fprintf(conn, "a1 STARTTLS\r\n"); err != nil {
		return err
	}
	for seen := 0; ; seen++ {
		if seen >= maxContinuationLines {
			return fmt.Errorf("STARTTLS response exceeded %d untagged lines", maxContinuationLines)
		}
		line, err := r.readLine()
		if err != nil {
			return fmt.Errorf("reading STARTTLS response: %w", err)
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "a1 OK") {
			return nil
		}
		if strings.HasPrefix(line, "a1 ") {
			return &errTLSUnsupported{fmt.Sprintf("STARTTLS refused: %q", line)}
		}
	}
}

func starttlsPOP3(conn net.Conn) error {
	r := newReader(conn)
	greeting, err := r.readLine()
	if err != nil {
		return fmt.Errorf("reading greeting: %w", err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		return fmt.Errorf("unexpected greeting %q (an implicit-TLS port? try protocol: tls)", strings.TrimSpace(greeting))
	}
	if _, err := fmt.Fprintf(conn, "STLS\r\n"); err != nil {
		return err
	}
	resp, err := r.readLine()
	if err != nil {
		return fmt.Errorf("reading STLS response: %w", err)
	}
	if !strings.HasPrefix(resp, "+OK") {
		return &errTLSUnsupported{fmt.Sprintf("STLS refused: %q", strings.TrimSpace(resp))}
	}
	return nil
}

func starttlsFTP(conn net.Conn) error {
	r := newReader(conn)
	if code, text, err := readSMTPResponse(r); err != nil { // FTP replies share the SMTP wire shape
		return err
	} else if code != "220" {
		return fmt.Errorf("unexpected greeting %s %q", code, text)
	}
	if _, err := fmt.Fprintf(conn, "AUTH TLS\r\n"); err != nil {
		return err
	}
	code, text, err := readSMTPResponse(r)
	if err != nil {
		return err
	}
	if code != "234" {
		return &errTLSUnsupported{fmt.Sprintf("AUTH TLS refused: %s %q", code, text)}
	}
	return nil
}

// starttlsPostgres sends the 8-byte SSLRequest message (RFC: PostgreSQL
// protocol 3.0). The server answers a single byte: 'S' to proceed with TLS,
// 'N' if SSL is not supported.
func starttlsPostgres(conn net.Conn) error {
	msg := make([]byte, 8)
	binary.BigEndian.PutUint32(msg[0:4], 8)
	binary.BigEndian.PutUint32(msg[4:8], 80877103)
	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("sending SSLRequest: %w", err)
	}
	resp := make([]byte, 1)
	if _, err := conn.Read(resp); err != nil {
		return fmt.Errorf("reading SSLRequest response: %w", err)
	}
	switch resp[0] {
	case 'S':
		return nil
	case 'N':
		return &errTLSUnsupported{"server answered 'N' to SSLRequest (SSL not enabled)"}
	default:
		return fmt.Errorf("unexpected SSLRequest response byte %q", resp[0])
	}
}
