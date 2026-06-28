package provider

import (
	"testing"

	"github.com/vul-os/vulos-deliver/backend/ses"
	"github.com/vul-os/vulos-deliver/backend/smtp"
)

func TestNew_UnknownBackend(t *testing.T) {
	_, err := New(Config{Backend: "sendgrid"})
	if err == nil {
		t.Error("expected error for unknown backend, got nil")
	}
}

func TestNew_SES_WithRegion(t *testing.T) {
	// New() only fails if there is no region configured; it defers AWS credential
	// errors to call-time, so this succeeds without real credentials.
	cfg := Config{
		Backend: "ses",
		SES:     ses.Config{Region: "us-east-1"},
	}
	sender, err := New(cfg)
	if err != nil {
		t.Fatalf("New(ses): %v", err)
	}
	if sender == nil {
		t.Error("New(ses): returned nil sender")
	}
	_ = sender.Close()
}

func TestNew_SMTP(t *testing.T) {
	cfg := Config{
		Backend: "smtp",
		SMTP:    smtp.Config{Host: "smtp.example.com", Port: 587},
	}
	sender, err := New(cfg)
	if err != nil {
		t.Fatalf("New(smtp): %v", err)
	}
	if sender == nil {
		t.Error("New(smtp): returned nil sender")
	}
	_ = sender.Close()
}

func TestNew_DefaultsToSES(t *testing.T) {
	// Backend empty — should default to "ses".
	cfg := Config{
		SES: ses.Config{Region: "eu-west-1"},
	}
	sender, err := New(cfg)
	if err != nil {
		t.Fatalf("New(default backend): %v", err)
	}
	_ = sender.Close()
}

func TestNew_SMTP_NoHost_Error(t *testing.T) {
	cfg := Config{
		Backend: "smtp",
		SMTP:    smtp.Config{}, // host missing → should error
	}
	_, err := New(cfg)
	if err == nil {
		t.Error("expected error for smtp with no host, got nil")
	}
}
