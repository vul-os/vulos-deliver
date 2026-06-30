package ses

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"

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

func TestSend_CcBccInDestination(t *testing.T) {
	var gotInput *sesv2.SendEmailInput
	mc := &mockSESClient{
		SendEmailFn: func(_ context.Context, in *sesv2.SendEmailInput, _ ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error) {
			gotInput = in
			return &sesv2.SendEmailOutput{MessageId: aws.String("ccbcc")}, nil
		},
	}
	s := newTestSender(t, mc)

	msg := testMsg()
	msg.CC = []deliver.Address{{Email: "cc1@example.com"}, {Email: "cc2@example.com"}}
	msg.BCC = []deliver.Address{{Email: "bcc1@example.com"}}

	rec, err := s.Send(context.Background(), msg)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotInput == nil || gotInput.Destination == nil {
		t.Fatal("no Destination captured")
	}
	if got := gotInput.Destination.ToAddresses; len(got) != 1 || got[0] != "user@example.com" {
		t.Errorf("ToAddresses = %v, want [user@example.com]", got)
	}
	if got := gotInput.Destination.CcAddresses; len(got) != 2 || got[0] != "cc1@example.com" || got[1] != "cc2@example.com" {
		t.Errorf("CcAddresses = %v, want [cc1@example.com cc2@example.com]", got)
	}
	if got := gotInput.Destination.BccAddresses; len(got) != 1 || got[0] != "bcc1@example.com" {
		t.Errorf("BccAddresses = %v, want [bcc1@example.com]", got)
	}

	// Every allowed recipient across To/Cc/Bcc should be marked sent.
	var sent int
	for _, r := range rec.Recipients {
		if r.Status == deliver.StateSent {
			sent++
		}
	}
	if sent != 4 {
		t.Errorf("want 4 sent recipients, got %d (%+v)", sent, rec.Recipients)
	}
}

func TestSend_SuppressedCcBccFiltered(t *testing.T) {
	var gotInput *sesv2.SendEmailInput
	mc := &mockSESClient{
		SendEmailFn: func(_ context.Context, in *sesv2.SendEmailInput, _ ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error) {
			gotInput = in
			return &sesv2.SendEmailOutput{MessageId: aws.String("supp")}, nil
		},
	}
	s := newTestSender(t, mc)

	_ = s.suppression.Add("cc-bad@example.com", ReasonComplaint)
	_ = s.suppression.Add("bcc-bad@example.com", ReasonBounce)

	msg := testMsg()
	msg.CC = []deliver.Address{{Email: "cc-bad@example.com"}, {Email: "cc-ok@example.com"}}
	msg.BCC = []deliver.Address{{Email: "bcc-bad@example.com"}}

	rec, err := s.Send(context.Background(), msg)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotInput == nil {
		t.Fatal("no Destination captured")
	}
	// Suppressed Cc removed; the good one remains.
	if got := gotInput.Destination.CcAddresses; len(got) != 1 || got[0] != "cc-ok@example.com" {
		t.Errorf("CcAddresses = %v, want [cc-ok@example.com]", got)
	}
	// The only Bcc was suppressed → BccAddresses must be empty.
	if got := gotInput.Destination.BccAddresses; len(got) != 0 {
		t.Errorf("BccAddresses = %v, want empty", got)
	}

	var suppressed int
	for _, r := range rec.Recipients {
		if r.Status == deliver.StateSuppressed {
			suppressed++
		}
	}
	if suppressed != 2 {
		t.Errorf("want 2 suppressed, got %d (%+v)", suppressed, rec.Recipients)
	}
}

func TestSend_AllSuppressedAcrossSets(t *testing.T) {
	mc := &mockSESClient{
		SendEmailFn: func(_ context.Context, _ *sesv2.SendEmailInput, _ ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error) {
			t.Fatal("SendEmail must not be called when every recipient is suppressed")
			return nil, nil
		},
	}
	s := newTestSender(t, mc)

	_ = s.suppression.Add("user@example.com", ReasonBounce)
	_ = s.suppression.Add("cc@example.com", ReasonBounce)
	_ = s.suppression.Add("bcc@example.com", ReasonBounce)

	msg := testMsg()
	msg.CC = []deliver.Address{{Email: "cc@example.com"}}
	msg.BCC = []deliver.Address{{Email: "bcc@example.com"}}

	rec, err := s.Send(context.Background(), msg)
	if !errors.Is(err, deliver.ErrSuppressed) {
		t.Fatalf("expected ErrSuppressed, got %v", err)
	}
	var suppressed int
	for _, r := range rec.Recipients {
		if r.Status == deliver.StateSuppressed {
			suppressed++
		}
	}
	if suppressed != 3 {
		t.Errorf("want 3 suppressed, got %d (%+v)", suppressed, rec.Recipients)
	}
}

// TestSend_NoBccHeaderLeak confirms the library does not inject a Bcc header into
// the rendered message. Bcc recipients are carried only in the SES Destination
// envelope (BccAddresses); the MIMEBody is delivered verbatim, so blind-copy
// semantics depend solely on the caller not supplying a Bcc header.
func TestSend_NoBccHeaderLeak(t *testing.T) {
	var gotInput *sesv2.SendEmailInput
	mc := &mockSESClient{
		SendEmailFn: func(_ context.Context, in *sesv2.SendEmailInput, _ ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error) {
			gotInput = in
			return &sesv2.SendEmailOutput{MessageId: aws.String("leak")}, nil
		},
	}
	s := newTestSender(t, mc)

	msg := testMsg()
	msg.BCC = []deliver.Address{{Email: "secret@example.com"}}

	if _, err := s.Send(context.Background(), msg); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotInput == nil || gotInput.Content == nil || gotInput.Content.Raw == nil {
		t.Fatal("no raw content captured")
	}
	raw := strings.ToLower(string(gotInput.Content.Raw.Data))
	if strings.Contains(raw, "bcc:") {
		t.Errorf("rendered MIME leaked a Bcc header: %q", string(gotInput.Content.Raw.Data))
	}
	if strings.Contains(raw, "secret@example.com") {
		t.Errorf("rendered MIME leaked the Bcc recipient address")
	}
}

func TestSend_RequireVerifiedIdentity_Blocks(t *testing.T) {
	mc := &mockSESClient{
		GetEmailIdentityFn: func(_ context.Context, _ *sesv2.GetEmailIdentityInput, _ ...func(*sesv2.Options)) (*sesv2.GetEmailIdentityOutput, error) {
			return &sesv2.GetEmailIdentityOutput{
				DkimAttributes: &types.DkimAttributes{Status: types.DkimStatusPending},
			}, nil
		},
		SendEmailFn: func(_ context.Context, _ *sesv2.SendEmailInput, _ ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error) {
			t.Fatal("SendEmail must not be called for an unverified sender domain")
			return nil, nil
		},
	}
	s, err := New(Config{Region: "us-east-1", Client: mc, RequireVerifiedIdentity: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = s.Send(context.Background(), testMsg())
	if !errors.Is(err, deliver.ErrUnverifiedSender) {
		t.Fatalf("expected ErrUnverifiedSender, got %v", err)
	}
}

func TestSend_RequireVerifiedIdentity_Allows(t *testing.T) {
	mc := &mockSESClient{} // default GetEmailIdentity returns SUCCESS
	s, err := New(Config{Region: "us-east-1", Client: mc, RequireVerifiedIdentity: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := s.Send(context.Background(), testMsg()); err != nil {
		t.Fatalf("Send (verified) should succeed, got %v", err)
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
