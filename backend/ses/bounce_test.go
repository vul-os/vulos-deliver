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

func newTestHandler(sl SuppressionList) *BounceWebhookHandler {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return NewBounceWebhookHandler(sl, logger, false)
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
	env := snsEnvelope{
		Type:    msgType,
		Message: string(msgBytes),
	}
	b, _ := json.Marshal(env)
	return b
}

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

	env := snsEnvelope{
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
