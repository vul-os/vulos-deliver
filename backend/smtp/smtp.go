// Package smtp implements deliver.Sender over a generic SMTP relay.
//
// This is the second backend alongside SES — the path for sending via warmed
// own-IPs (e.g. a Postfix MTA on Hetzner), Mailgun, SendGrid, or any
// standards-compliant SMTP submission endpoint.
//
// # Switching from SES to SMTP
//
// Change provider.Config.Backend from "ses" to "smtp", point Config.SMTP at
// your submission endpoint, and restart. No other code changes are required —
// the Sender interface is identical.
//
// # TLS behaviour
//
//   - Port 465 (or ImplicitTLS: true): implicit TLS — a TLS handshake is
//     performed before any SMTP commands are exchanged.
//   - Port 587 (and others): STARTTLS — the connection starts plaintext and
//     upgrades via the STARTTLS extension. If the server does not advertise
//     STARTTLS and credentials are configured, Send returns an error rather
//     than transmitting credentials in the clear.
package smtp

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"time"

	deliver "github.com/vul-os/vulos-deliver"
)

// Config configures the SMTP relay backend.
type Config struct {
	// Host is the SMTP server hostname (e.g. "smtp.mailgun.org", "127.0.0.1").
	Host string `json:"host" yaml:"host"`

	// Port is the SMTP port. Common values:
	//   587 — STARTTLS submission (default)
	//   465 — implicit TLS (SMTPS)
	//    25 — plain SMTP (use only on private networks without credentials)
	Port int `json:"port" yaml:"port"`

	// Username for SMTP AUTH PLAIN.
	Username string `json:"username,omitempty" yaml:"username,omitempty"`

	// Password for SMTP AUTH PLAIN.
	Password string `json:"password,omitempty" yaml:"password,omitempty"`

	// From overrides the envelope MAIL FROM address. If empty, Message.From.Email
	// is used. Useful when the SMTP relay requires a fixed sender address.
	From string `json:"from,omitempty" yaml:"from,omitempty"`

	// TLSSkipVerify disables TLS certificate verification. Only use in dev/test.
	TLSSkipVerify bool `json:"tlsSkipVerify,omitempty" yaml:"tlsSkipVerify,omitempty"`

	// ImplicitTLS forces implicit TLS (SMTPS) regardless of port number.
	// Port 465 enables implicit TLS automatically; set this to true when using
	// implicit TLS on a non-standard port.
	ImplicitTLS bool `json:"implicitTLS,omitempty" yaml:"implicitTLS,omitempty"`
}

// Sender is an SMTP-backed deliver.Sender.
//
// Connections are opened per-Send and closed immediately after; the Sender
// itself is stateless and goroutine-safe.
type Sender struct {
	cfg Config
}

// New constructs an SMTP Sender from cfg.
//
// The connection is not opened until the first Send call. No credentials are
// validated here — errors surface on Send.
func New(cfg Config) (*Sender, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("smtp: host is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 587
	}
	return &Sender{cfg: cfg}, nil
}

// Send implements deliver.Sender.
//
// Connection behaviour:
//   - Port 465 / ImplicitTLS=true: TLS handshake before any SMTP exchange.
//   - Other ports: plaintext dial, then STARTTLS upgrade if advertised.
//     If credentials are configured but the server does not advertise STARTTLS,
//     Send returns an error rather than transmitting credentials in the clear.
func (s *Sender) Send(_ context.Context, msg deliver.Message) (deliver.Receipt, error) {
	// Collect all envelope recipients.
	var rcpts []string
	for _, a := range msg.To {
		rcpts = append(rcpts, a.Email)
	}
	for _, a := range msg.CC {
		rcpts = append(rcpts, a.Email)
	}
	for _, a := range msg.BCC {
		rcpts = append(rcpts, a.Email)
	}
	if len(rcpts) == 0 {
		return deliver.Receipt{}, fmt.Errorf("smtp: no recipients")
	}

	from := s.cfg.From
	if from == "" {
		from = msg.From.Email
	}

	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)

	tlsCfg := &tls.Config{
		ServerName:         s.cfg.Host,
		InsecureSkipVerify: s.cfg.TLSSkipVerify, //nolint:gosec
		MinVersion:         tls.VersionTLS12,
	}

	useImplicitTLS := s.cfg.Port == 465 || s.cfg.ImplicitTLS

	var c *smtp.Client
	if useImplicitTLS {
		// Implicit TLS (SMTPS): TLS handshake before any SMTP commands.
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 30 * time.Second}, "tcp", addr, tlsCfg)
		if err != nil {
			return deliver.Receipt{}, fmt.Errorf("smtp: implicit TLS dial %s: %w", addr, err)
		}
		sc, err := smtp.NewClient(conn, s.cfg.Host)
		if err != nil {
			conn.Close() //nolint:errcheck
			return deliver.Receipt{}, fmt.Errorf("smtp: SMTP client over TLS %s: %w", addr, err)
		}
		c = sc
	} else {
		// STARTTLS: plaintext dial, upgrade if offered.
		sc, err := smtp.Dial(addr)
		if err != nil {
			return deliver.Receipt{}, fmt.Errorf("smtp: dial %s: %w", addr, err)
		}
		c = sc

		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsCfg); err != nil {
				c.Close() //nolint:errcheck
				return deliver.Receipt{}, fmt.Errorf("smtp: STARTTLS %s: %w", addr, err)
			}
		} else if s.cfg.Username != "" {
			// H1: Fail closed — refuse to send credentials over a cleartext channel.
			c.Close() //nolint:errcheck
			return deliver.Receipt{}, fmt.Errorf("smtp: server %s does not advertise STARTTLS "+
				"— refusing to transmit AUTH credentials over a cleartext connection; "+
				"use port 465 (implicit TLS) or a server with STARTTLS", addr)
		}
	}
	defer c.Close() //nolint:errcheck

	if s.cfg.Username != "" {
		auth := smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
		if err := c.Auth(auth); err != nil {
			return deliver.Receipt{}, fmt.Errorf("smtp: AUTH: %w", err)
		}
	}

	if err := c.Mail(from); err != nil {
		return deliver.Receipt{}, fmt.Errorf("smtp: MAIL FROM <%s>: %w", from, err)
	}

	for _, rcpt := range rcpts {
		if err := c.Rcpt(rcpt); err != nil {
			return deliver.Receipt{}, fmt.Errorf("smtp: RCPT TO <%s>: %w", rcpt, err)
		}
	}

	wc, err := c.Data()
	if err != nil {
		return deliver.Receipt{}, fmt.Errorf("smtp: DATA: %w", err)
	}
	if _, err := bytes.NewReader(msg.MIMEBody).WriteTo(wc); err != nil {
		wc.Close() //nolint:errcheck
		return deliver.Receipt{}, fmt.Errorf("smtp: write body: %w", err)
	}
	if err := wc.Close(); err != nil {
		return deliver.Receipt{}, fmt.Errorf("smtp: close data writer: %w", err)
	}

	if err := c.Quit(); err != nil {
		return deliver.Receipt{}, fmt.Errorf("smtp: QUIT: %w", err)
	}

	recipients := make([]deliver.RecipientStatus, len(rcpts))
	for i, r := range rcpts {
		recipients[i] = deliver.RecipientStatus{
			Email:  r,
			Status: deliver.StateSent,
		}
	}

	return deliver.Receipt{
		Backend:    "smtp",
		SentAt:     time.Now(),
		Recipients: recipients,
	}, nil
}

// SendBatch implements deliver.Sender.
func (s *Sender) SendBatch(_ context.Context, msgs []deliver.Message) ([]deliver.Receipt, error) {
	receipts := make([]deliver.Receipt, len(msgs))
	var firstErr error
	for i, msg := range msgs {
		rec, err := s.Send(context.Background(), msg)
		receipts[i] = rec
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return receipts, firstErr
}

// Close implements deliver.Sender (no-op — connections are per-Send).
func (s *Sender) Close() error { return nil }
