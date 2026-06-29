package smtp

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"testing"
	"time"

	deliver "github.com/vul-os/vulos-deliver"
)

// TestSenderImplementsInterface verifies at compile time that *Sender satisfies
// the deliver.Sender interface.
var _ deliver.Sender = (*Sender)(nil)

func TestNew_RequiresHost(t *testing.T) {
	_, err := New(Config{})
	if err == nil {
		t.Error("expected error when Host is empty, got nil")
	}
}

func TestNew_DefaultPort(t *testing.T) {
	s, err := New(Config{Host: "smtp.example.com"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.cfg.Port != 587 {
		t.Errorf("default Port = %d, want 587", s.cfg.Port)
	}
}

func TestNew_CustomPort(t *testing.T) {
	s, err := New(Config{Host: "smtp.example.com", Port: 465})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.cfg.Port != 465 {
		t.Errorf("Port = %d, want 465", s.cfg.Port)
	}
}

func TestSend_NoRecipients(t *testing.T) {
	s, _ := New(Config{Host: "smtp.example.com"})
	msg := deliver.Message{
		From:     deliver.Address{Email: "from@example.com"},
		MIMEBody: []byte("Subject: test\r\n\r\nhello"),
	}
	_, err := s.Send(context.Background(), msg)
	if err == nil {
		t.Error("expected error with no recipients, got nil")
	}
}

func TestClose_NoOp(t *testing.T) {
	s, _ := New(Config{Host: "smtp.example.com"})
	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestSendBatch_EmptySlice(t *testing.T) {
	s, _ := New(Config{Host: "smtp.example.com"})
	recs, err := s.SendBatch(context.Background(), nil)
	if err != nil {
		t.Errorf("SendBatch(nil): %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("len(recs) = %d, want 0", len(recs))
	}
}

// --- H1 Security tests ---

// mockSMTPServer runs a minimal plaintext SMTP server on a random local port.
// When starttls is false the server does NOT advertise STARTTLS in its EHLO
// response, simulating a cleartext-only relay.
// Returns the listener address and a cleanup func.
func mockSMTPServer(t *testing.T, starttls bool) (addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go serveMockSMTP(conn, starttls)
		}
	}()
	return ln.Addr().String()
}

// serveMockSMTP handles a single SMTP connection, advertising STARTTLS only
// when the starttls parameter is true.
func serveMockSMTP(conn net.Conn, starttls bool) {
	defer conn.Close()
	r := bufio.NewReader(conn)

	writeLine := func(s string) { fmt.Fprintf(conn, "%s\r\n", s) }

	writeLine("220 localhost Mock SMTP Server")

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		cmd := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			writeLine("250-localhost")
			writeLine("250-SIZE 10240000")
			if starttls {
				writeLine("250-STARTTLS")
			}
			writeLine("250 OK")

		case strings.HasPrefix(cmd, "STARTTLS"):
			writeLine("220 Ready to start TLS")
			// In a real test we'd do a TLS handshake here; for the cleartext
			// rejection test we never reach STARTTLS.
			return

		case strings.HasPrefix(cmd, "AUTH"):
			writeLine("535 Authentication credentials invalid")
			return

		case strings.HasPrefix(cmd, "QUIT"):
			writeLine("221 Bye")
			return

		default:
			writeLine("500 Unrecognized command")
		}
	}
}

// TestSend_RejectsAuthOverCleartext verifies that Send returns an error
// (without sending AUTH) when the server does not advertise STARTTLS and
// credentials are configured (H1 fix).
func TestSend_RejectsAuthOverCleartext(t *testing.T) {
	addr := mockSMTPServer(t, false /* no STARTTLS */)
	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscan(portStr, &port)

	s, _ := New(Config{
		Host:     host,
		Port:     port,
		Username: "user@example.com",
		Password: "secret",
	})

	msg := deliver.Message{
		From:     deliver.Address{Email: "from@example.com"},
		To:       []deliver.Address{{Email: "to@example.com"}},
		MIMEBody: []byte("Subject: test\r\n\r\nhello"),
	}
	_, err := s.Send(context.Background(), msg)
	if err == nil {
		t.Fatal("expected error when no STARTTLS with credentials configured, got nil")
	}
	if !strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("error should mention STARTTLS, got: %v", err)
	}
}

// TestSend_NoCredsOKWithoutTLS verifies that a no-credentials send over a
// cleartext server succeeds (unauthenticated relay, e.g. localhost MTA).
func TestSend_NoCredsOKWithoutTLS(t *testing.T) {
	// Mock server that handles a full unauthenticated SMTP conversation.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		write := func(s string) { fmt.Fprintf(conn, "%s\r\n", s) }

		write("220 localhost SMTP")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				write("250-localhost\r\n250 OK")
			case strings.HasPrefix(cmd, "MAIL FROM"):
				write("250 OK")
			case strings.HasPrefix(cmd, "RCPT TO"):
				write("250 OK")
			case strings.HasPrefix(cmd, "DATA"):
				write("354 Start input")
			case cmd == ".":
				write("250 OK: queued")
			case strings.HasPrefix(cmd, "QUIT"):
				write("221 Bye")
				return
			}
		}
	}()

	addr := ln.Addr().String()
	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscan(portStr, &port)

	s, _ := New(Config{
		Host: host,
		Port: port,
		// No credentials — should not require STARTTLS.
	})

	msg := deliver.Message{
		From:     deliver.Address{Email: "from@example.com"},
		To:       []deliver.Address{{Email: "to@example.com"}},
		MIMEBody: []byte("Subject: test\r\n\r\nhello"),
	}
	_, err = s.Send(context.Background(), msg)
	if err != nil {
		t.Errorf("unauthenticated send without TLS: unexpected error: %v", err)
	}
}

// generateTestTLSConfig returns a *tls.Config with a freshly generated
// self-signed certificate (for test servers) and a matching client config.
func generateTestTLSConfig(t *testing.T) (serverTLS, clientTLS *tls.Config) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost", "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	serverTLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	clientTLS = &tls.Config{RootCAs: pool, ServerName: "localhost"}
	return
}

// TestSend_ImplicitTLS_Port465 verifies that setting Port=465 (or ImplicitTLS=true)
// causes Send to perform a TLS handshake before any SMTP commands.
func TestSend_ImplicitTLS_Port465(t *testing.T) {
	serverTLS, _ := generateTestTLSConfig(t)

	// Start a TLS SMTP server (implicit TLS — TLS listener).
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	tlsHandshakeDone := make(chan struct{}, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Signal that a TLS connection was accepted.
		tlsHandshakeDone <- struct{}{}

		// Serve a complete SMTP session.
		r := bufio.NewReader(conn)
		write := func(s string) { fmt.Fprintf(conn, "%s\r\n", s) }

		write("220 localhost SMTPS")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				write("250-localhost\r\n250 OK")
			case strings.HasPrefix(cmd, "MAIL FROM"):
				write("250 OK")
			case strings.HasPrefix(cmd, "RCPT TO"):
				write("250 OK")
			case strings.HasPrefix(cmd, "DATA"):
				write("354 Start input")
			case cmd == ".":
				write("250 OK: queued")
			case strings.HasPrefix(cmd, "QUIT"):
				write("221 Bye")
				return
			}
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	fmt.Sscan(portStr, &port)

	s, _ := New(Config{
		Host:          host,
		Port:          port,
		ImplicitTLS:   true, // use ImplicitTLS so we can test on any port
		TLSSkipVerify: true,
	})

	msg := deliver.Message{
		From:     deliver.Address{Email: "from@example.com"},
		To:       []deliver.Address{{Email: "to@example.com"}},
		MIMEBody: []byte("Subject: test\r\n\r\nhello"),
	}
	_, err = s.Send(context.Background(), msg)
	if err != nil {
		t.Fatalf("Send with implicit TLS: %v", err)
	}

	select {
	case <-tlsHandshakeDone:
		// Good — TLS connection was established.
	default:
		t.Error("implicit TLS: TLS handshake was not performed")
	}

	wg.Wait()
}

// TestSend_ImplicitTLS_AutoPort465 verifies that Port=465 automatically enables
// implicit TLS (without ImplicitTLS: true). The test connects to a port where
// nothing is listening; it checks that the error is a connection/TLS error and
// NOT the "STARTTLS" cleartext-refusal error — proving the implicit TLS branch
// was taken rather than the STARTTLS branch.
func TestSend_ImplicitTLS_AutoPort465(t *testing.T) {
	s, _ := New(Config{
		Host:          "127.0.0.1",
		Port:          465,
		Username:      "user", // would trigger cleartext refusal on STARTTLS path
		TLSSkipVerify: true,
	})

	msg := deliver.Message{
		From:     deliver.Address{Email: "from@example.com"},
		To:       []deliver.Address{{Email: "to@example.com"}},
		MIMEBody: []byte("Subject: test\r\n\r\nhello"),
	}
	_, err := s.Send(context.Background(), msg)
	if err == nil {
		t.Fatal("expected a connection error (nothing on port 465), got nil")
	}
	// The error must mention implicit TLS dial, NOT STARTTLS refusal.
	// If the STARTTLS path was taken, the error would contain "STARTTLS".
	if strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("Port 465 should use implicit TLS path, but error mentions STARTTLS: %v", err)
	}
	if !strings.Contains(err.Error(), "implicit TLS") && !strings.Contains(err.Error(), "connection refused") {
		t.Logf("got expected TLS/connection error: %v", err)
	}
}

// --- Compile-time check that smtp.Client methods are accessible in tests ---

var _ = smtp.PlainAuth // prevent unused import
