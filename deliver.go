// Package deliver provides the core types and seam for the Vulos deliverability
// engine. Backend implementations (SES, SMTP) satisfy the Sender interface; the
// provider package wires them together from config.
package deliver

import (
	"context"
	"fmt"
	"net/mail"
	"time"
)

// Address is an RFC 5322 mailbox with an optional display name.
type Address struct {
	Name  string
	Email string
}

// String returns the RFC 5322 encoded address string.
func (a Address) String() string {
	if a.Name == "" {
		return a.Email
	}
	return (&mail.Address{Name: a.Name, Address: a.Email}).String()
}

// Message is an outbound email message.
//
// The caller is responsible for constructing a valid MIME body in MIMEBody;
// the backends deliver it verbatim. Use the standard library's mime/multipart
// or a MIME builder to compose text/plain + text/html alternatives.
type Message struct {
	// TenantID identifies the customer tenant this message belongs to.
	// Used for per-tenant throttling, identity selection, and audit logging.
	TenantID string

	From Address
	To   []Address
	CC   []Address
	BCC  []Address

	// Subject is metadata only — it is NOT injected into the message by any
	// backend. If you want a Subject header in the email, include it in MIMEBody.
	// This field may be used by callers for logging, routing, or audit purposes.
	Subject string

	// Headers is metadata only — it is NOT injected into the message by any
	// backend. If you want additional headers in the email, include them in
	// MIMEBody. This field may be used by callers for logging or audit purposes.
	Headers map[string][]string

	// MIMEBody is the pre-composed MIME message body. It must include all
	// required headers (Subject, Content-Type, From, To, Date, Message-ID, etc.)
	// as well as the message content. The backend writes it verbatim into the
	// SMTP DATA phase / SES raw message field.
	MIMEBody []byte

	// ConfigurationSet is the SES configuration set name (SES backend only).
	// Ignored by other backends.
	ConfigurationSet string
}

// RecipientState is the delivery outcome for a single recipient.
type RecipientState string

const (
	StateSent       RecipientState = "sent"
	StateSuppressed RecipientState = "suppressed"
	StateFailed     RecipientState = "failed"
)

// RecipientStatus records the send outcome for one recipient address.
type RecipientStatus struct {
	Email  string
	Status RecipientState
	Err    error // non-nil only when Status == StateFailed
}

// Receipt is the result of a successful Send or SendBatch call.
type Receipt struct {
	// MessageID is the backend-assigned identifier (e.g. SES message ID).
	MessageID string

	// Backend identifies which backend produced this receipt ("ses", "smtp", …).
	Backend string

	// SentAt is the wall-clock time at which the message was accepted by the backend.
	SentAt time.Time

	// Recipients records per-recipient outcomes. Always populated when some
	// addresses were suppressed or the send was a batch.
	Recipients []RecipientStatus
}

// Sender is the core deliverability seam.
//
// All backend implementations (SES, SMTP, …) satisfy this interface. The
// vulos-deliver library intentionally never imports vulos-cloud; callers
// construct a Sender via provider.New and inject it where needed.
type Sender interface {
	// Send delivers a single Message. It returns an error only when the message
	// could not be dispatched to *any* recipient. Suppressed addresses are
	// skipped silently and recorded in Receipt.Recipients.
	Send(ctx context.Context, msg Message) (Receipt, error)

	// SendBatch delivers multiple independent Messages. A failure on one message
	// does not abort subsequent ones; per-message errors are recorded in each
	// Receipt.Recipients[].Err.
	SendBatch(ctx context.Context, msgs []Message) ([]Receipt, error)

	// Close releases backend resources (connections, goroutines, rate-limiter
	// tickers, etc.). After Close the Sender must not be used.
	Close() error
}

// ErrSuppressed is returned (possibly wrapped) when every To address in a
// message is on the suppression list, making the message a no-op.
var ErrSuppressed = fmt.Errorf("deliver: all recipients suppressed")

// ErrSandboxMode is returned when the SES backend is in sandbox mode and a
// non-verified recipient address was supplied.
var ErrSandboxMode = fmt.Errorf("deliver: SES sandbox mode — only verified addresses can receive mail; " +
	"request production access at https://console.aws.amazon.com/ses/home#/account")
