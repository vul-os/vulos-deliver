package smtp

import (
	"context"
	"testing"

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
