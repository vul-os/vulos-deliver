package ses

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"

	deliver "github.com/vul-os/vulos-deliver"
)

func newTestSender(t *testing.T, client SESEmailClient) *Sender {
	t.Helper()
	s, err := New(Config{
		Region: "us-east-1",
		Client: client,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func testMsg() deliver.Message {
	return deliver.Message{
		TenantID: "tenant-1",
		From:     deliver.Address{Email: "noreply@example.com"},
		To:       []deliver.Address{{Email: "user@example.com"}},
		Subject:  "Test",
		MIMEBody: []byte("Subject: Test\r\n\r\nHello"),
	}
}

func TestSend_OK(t *testing.T) {
	mc := &mockSESClient{}
	s := newTestSender(t, mc)

	rec, err := s.Send(context.Background(), testMsg())
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if rec.Backend != "ses" {
		t.Errorf("Backend = %q, want %q", rec.Backend, "ses")
	}
	if rec.MessageID != "mock-msg-id" {
		t.Errorf("MessageID = %q, want mock-msg-id", rec.MessageID)
	}
	if len(rec.Recipients) != 1 || rec.Recipients[0].Status != deliver.StateSent {
		t.Errorf("unexpected recipients: %+v", rec.Recipients)
	}
}

func TestSend_SuppressedAddress(t *testing.T) {
	mc := &mockSESClient{}
	s := newTestSender(t, mc)

	// Suppress the recipient before sending.
	_ = s.suppression.Add("user@example.com", ReasonBounce)

	rec, err := s.Send(context.Background(), testMsg())
	if !errors.Is(err, deliver.ErrSuppressed) {
		t.Fatalf("expected ErrSuppressed, got %v", err)
	}
	if len(rec.Recipients) != 1 || rec.Recipients[0].Status != deliver.StateSuppressed {
		t.Errorf("expected suppressed recipient, got %+v", rec.Recipients)
	}
}

func TestSend_PartialSuppression(t *testing.T) {
	var gotInput *sesv2.SendEmailInput
	mc := &mockSESClient{
		SendEmailFn: func(ctx context.Context, in *sesv2.SendEmailInput, opts ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error) {
			gotInput = in
			return &sesv2.SendEmailOutput{MessageId: aws.String("partial-send")}, nil
		},
	}
	s := newTestSender(t, mc)

	// Add a second recipient and suppress only the first.
	_ = s.suppression.Add("bounced@example.com", ReasonBounce)

	msg := testMsg()
	msg.To = append(msg.To, deliver.Address{Email: "bounced@example.com"})

	rec, err := s.Send(context.Background(), msg)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Should have sent to user@example.com only.
	if gotInput == nil || len(gotInput.Destination.ToAddresses) != 1 || gotInput.Destination.ToAddresses[0] != "user@example.com" {
		t.Errorf("unexpected To addresses: %v", gotInput)
	}

	// Receipt should include one sent + one suppressed.
	var sent, suppressed int
	for _, r := range rec.Recipients {
		switch r.Status {
		case deliver.StateSent:
			sent++
		case deliver.StateSuppressed:
			suppressed++
		}
	}
	if sent != 1 || suppressed != 1 {
		t.Errorf("want 1 sent + 1 suppressed, got sent=%d suppressed=%d", sent, suppressed)
	}
}

func TestSend_BackendError(t *testing.T) {
	mc := &mockSESClient{
		SendEmailFn: func(_ context.Context, _ *sesv2.SendEmailInput, _ ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error) {
			return nil, errors.New("SES: MessageRejected")
		},
	}
	s := newTestSender(t, mc)

	_, err := s.Send(context.Background(), testMsg())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestSend_ConfigurationSet(t *testing.T) {
	var gotInput *sesv2.SendEmailInput
	mc := &mockSESClient{
		SendEmailFn: func(_ context.Context, in *sesv2.SendEmailInput, _ ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error) {
			gotInput = in
			return &sesv2.SendEmailOutput{MessageId: aws.String("x")}, nil
		},
	}
	s, _ := New(Config{
		Region:           "us-east-1",
		Client:           mc,
		ConfigurationSet: "default-set",
	})

	msg := testMsg()
	msg.ConfigurationSet = "override-set"
	_, _ = s.Send(context.Background(), msg)

	if gotInput == nil || gotInput.ConfigurationSetName == nil {
		t.Fatal("ConfigurationSetName not set")
	}
	if *gotInput.ConfigurationSetName != "override-set" {
		t.Errorf("ConfigurationSetName = %q, want override-set", *gotInput.ConfigurationSetName)
	}
}

func TestSendBatch(t *testing.T) {
	callCount := 0
	mc := &mockSESClient{
		SendEmailFn: func(_ context.Context, _ *sesv2.SendEmailInput, _ ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error) {
			callCount++
			return &sesv2.SendEmailOutput{MessageId: aws.String("batch-id")}, nil
		},
	}
	s := newTestSender(t, mc)

	msgs := []deliver.Message{testMsg(), testMsg(), testMsg()}
	recs, err := s.SendBatch(context.Background(), msgs)
	if err != nil {
		t.Fatalf("SendBatch: %v", err)
	}
	if len(recs) != 3 {
		t.Errorf("len(recs) = %d, want 3", len(recs))
	}
	if callCount != 3 {
		t.Errorf("SendEmail called %d times, want 3", callCount)
	}
}

func TestDetectSandbox_Production(t *testing.T) {
	mc := &mockSESClient{} // default: ProductionAccessEnabled=true
	s := newTestSender(t, mc)

	if err := s.DetectSandbox(context.Background()); err != nil {
		t.Fatalf("DetectSandbox: %v", err)
	}
	if s.IsSandbox() {
		t.Error("expected IsSandbox()=false for production account")
	}
}

func TestDetectSandbox_Sandbox(t *testing.T) {
	mc := &mockSESClient{
		GetAccountFn: func(_ context.Context, _ *sesv2.GetAccountInput, _ ...func(*sesv2.Options)) (*sesv2.GetAccountOutput, error) {
			return &sesv2.GetAccountOutput{
				ProductionAccessEnabled: false,
				SendingEnabled:          true,
			}, nil
		},
	}
	s := newTestSender(t, mc)

	if err := s.DetectSandbox(context.Background()); err != nil {
		t.Fatalf("DetectSandbox: %v", err)
	}
	if !s.IsSandbox() {
		t.Error("expected IsSandbox()=true for sandbox account")
	}
}

func TestSenderClose(t *testing.T) {
	s := newTestSender(t, &mockSESClient{})
	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestSenderImplementsInterface verifies at compile time that *Sender satisfies
// deliver.Sender. This assertion is enforced by the type system, not at runtime.
var _ deliver.Sender = (*Sender)(nil)
