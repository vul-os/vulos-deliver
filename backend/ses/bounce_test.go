package ses

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// noopVerify bypasses SNS signature verification in tests that exercise
// bounce/complaint business logic rather than security properties.
func noopVerify(_ SNSEnvelope) error { return nil }

func newTestHandler(sl SuppressionList) *BounceWebhookHandler {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	h := NewBounceWebhookHandler(sl, logger, false)
	h.verifySNS = noopVerify
	return h
}

func snsPost(t *testing.T, h http.Handler, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/bounce", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func makeEnvelope(msgType string, message any) []byte {
	msgBytes, _ := json.Marshal(message)
	env := SNSEnvelope{
		Type:    msgType,
		Message: string(msgBytes),
	}
	b, _ := json.Marshal(env)
	return b
}

// --- Existing business-logic tests (sig verification bypassed via noopVerify) ---

func TestBounceWebhook_PermanentBounce(t *testing.T) {
	sl := NewMemorySuppressionList()
	h := newTestHandler(sl)

	notif := sesNotification{
		NotificationType: "Bounce",
		Bounce: &sesBouncePaylod{
			BounceType: "Permanent",
			BouncedRecipients: []sesEmailAddr{
				{EmailAddress: "bounced@example.com"},
				{EmailAddress: "also-bounced@example.com"},
			},
		},
	}

	rr := snsPost(t, h, makeEnvelope("Notification", notif))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}

	for _, email := range []string{"bounced@example.com", "also-bounced@example.com"} {
		ok, entry, _ := sl.IsSuppressed(email)
		if !ok {
			t.Errorf("%q should be suppressed after permanent bounce", email)
		}
		if entry.Reason != ReasonBounce {
			t.Errorf("%q reason = %q, want bounce", email, entry.Reason)
		}
	}
}

func TestBounceWebhook_TransientBounce_NotSuppressed(t *testing.T) {
	sl := NewMemorySuppressionList()
	h := newTestHandler(sl)

	notif := sesNotification{
		NotificationType: "Bounce",
		Bounce: &sesBouncePaylod{
			BounceType: "Transient",
			BouncedRecipients: []sesEmailAddr{
				{EmailAddress: "tmp@example.com"},
			},
		},
	}

	rr := snsPost(t, h, makeEnvelope("Notification", notif))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}

	ok, _, _ := sl.IsSuppressed("tmp@example.com")
	if ok {
		t.Error("transient bounce should NOT suppress address")
	}
}

func TestBounceWebhook_Complaint(t *testing.T) {
	sl := NewMemorySuppressionList()
	h := newTestHandler(sl)

	notif := sesNotification{
		NotificationType: "Complaint",
		Complaint: &sesComplaintPayload{
			ComplainedRecipients: []sesEmailAddr{
				{EmailAddress: "spam-reporter@example.com"},
			},
			ComplaintFeedbackType: "abuse",
		},
	}

	rr := snsPost(t, h, makeEnvelope("Notification", notif))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}

	ok, entry, _ := sl.IsSuppressed("spam-reporter@example.com")
	if !ok {
		t.Error("complained address should be suppressed")
	}
	if entry.Reason != ReasonComplaint {
		t.Errorf("reason = %q, want complaint", entry.Reason)
	}
}

func TestBounceWebhook_SubscriptionConfirmation(t *testing.T) {
	sl := NewMemorySuppressionList()
	h := newTestHandler(sl) // confirmSubscriptions=false

	env := SNSEnvelope{
		Type:         "SubscriptionConfirmation",
		TopicArn:     "arn:aws:sns:us-east-1:123:ses-events",
		SubscribeURL: "https://sns.amazonaws.com/confirm",
	}
	body, _ := json.Marshal(env)

	rr := snsPost(t, h, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
}

func TestBounceWebhook_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(NewMemorySuppressionList())
	req := httptest.NewRequest(http.MethodGet, "/bounce", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

func TestBounceWebhook_BadJSON(t *testing.T) {
	h := newTestHandler(NewMemorySuppressionList())
	rr := snsPost(t, h, []byte(`not-json`))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// --- C1/C2 Security tests ---

// TestBounceWebhook_RejectsInvalidSignature verifies that the handler returns
// 403 when the SNS message has a non-AWS SigningCertURL (no network call is
// made — the URL host check fails immediately).
func TestBounceWebhook_RejectsInvalidSignature(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	// Handler with real VerifySNSMessage (no noopVerify override)
	h := NewBounceWebhookHandler(NewMemorySuppressionList(), logger, false)

	notif := sesNotification{
		NotificationType: "Bounce",
		Bounce: &sesBouncePaylod{
			BounceType: "Permanent",
			BouncedRecipients: []sesEmailAddr{
				{EmailAddress: "victim@example.com"},
			},
		},
	}
	msgBytes, _ := json.Marshal(notif)
	env := SNSEnvelope{
		Type:             "Notification",
		MessageID:        "msg-1",
		TopicArn:         "arn:aws:sns:us-east-1:123:topic",
		Message:          string(msgBytes),
		Timestamp:        "2024-01-01T00:00:00Z",
		SignatureVersion: "1",
		Signature:        "Zm9yZ2Vk", // base64("forged") — wrong signature
		// Non-AWS cert URL: URL host validation rejects this without a network call.
		SigningCertURL: "https://evil.example.com/fake.pem",
	}
	body, _ := json.Marshal(env)

	rr := snsPost(t, h, body)
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for message with non-AWS SigningCertURL", rr.Code)
	}
}

// TestBounceWebhook_RejectsHTTPCertURL verifies that a http:// (non-TLS)
// SigningCertURL is rejected even if the hostname looks like AWS.
func TestBounceWebhook_RejectsHTTPCertURL(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	h := NewBounceWebhookHandler(NewMemorySuppressionList(), logger, false)

	env := SNSEnvelope{
		Type:             "Notification",
		MessageID:        "msg-2",
		TopicArn:         "arn:aws:sns:us-east-1:123:topic",
		Message:          `{"notificationType":"Bounce"}`,
		Timestamp:        "2024-01-01T00:00:00Z",
		SignatureVersion: "1",
		Signature:        "Zm9yZ2Vk",
		SigningCertURL:   "http://sns.us-east-1.amazonaws.com/cert.pem", // http not https
	}
	body, _ := json.Marshal(env)

	rr := snsPost(t, h, body)
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for http:// SigningCertURL", rr.Code)
	}
}

// TestValidateSubscribeURL_RejectsNonAWS confirms that validateSubscribeURL
// refuses non-SNS hosts (C2: SSRF prevention).
func TestValidateSubscribeURL_RejectsNonAWS(t *testing.T) {
	cases := []string{
		"https://evil.com/confirm",
		"http://sns.us-east-1.amazonaws.com/confirm", // http, not https
		"https://not-sns.amazonaws.com/confirm",
		"https://attacker.sns.us-east-1.amazonaws.com.evil.com/x",
		"ftp://sns.us-east-1.amazonaws.com/confirm",
	}
	for _, u := range cases {
		if err := validateSubscribeURL(u); err == nil {
			t.Errorf("validateSubscribeURL(%q): expected error, got nil", u)
		}
	}
}

// TestValidateSubscribeURL_AcceptsAWS confirms that valid SNS subscribe URLs pass.
func TestValidateSubscribeURL_AcceptsAWS(t *testing.T) {
	cases := []string{
		"https://sns.us-east-1.amazonaws.com/confirm?Action=ConfirmSubscription&Token=abc",
		"https://sns.eu-west-1.amazonaws.com/confirm?Token=xyz",
		"https://sns.ap-southeast-2.amazonaws.com/something",
	}
	for _, u := range cases {
		if err := validateSubscribeURL(u); err != nil {
			t.Errorf("validateSubscribeURL(%q): unexpected error: %v", u, err)
		}
	}
}
