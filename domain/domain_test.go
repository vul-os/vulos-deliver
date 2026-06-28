package domain

import (
	"strings"
	"testing"
)

func TestGenerateDKIMKeyPair(t *testing.T) {
	kp, err := GenerateDKIMKeyPair("2026-06")
	if err != nil {
		t.Fatalf("GenerateDKIMKeyPair: %v", err)
	}

	if kp.Selector != "2026-06" {
		t.Errorf("Selector = %q, want 2026-06", kp.Selector)
	}
	if len(kp.PrivateKeyPEM) == 0 {
		t.Error("PrivateKeyPEM is empty")
	}
	if !strings.Contains(string(kp.PrivateKeyPEM), "RSA PRIVATE KEY") {
		t.Error("PrivateKeyPEM does not look like a PEM block")
	}
	if len(kp.PublicKeyBase64) == 0 {
		t.Error("PublicKeyBase64 is empty")
	}
}

func TestGenerateDKIMKeyPair_EmptySelector(t *testing.T) {
	_, err := GenerateDKIMKeyPair("")
	if err == nil {
		t.Error("expected error for empty selector, got nil")
	}
}

func TestParsePrivateKeyPEM_RoundTrip(t *testing.T) {
	kp, err := GenerateDKIMKeyPair("test")
	if err != nil {
		t.Fatalf("GenerateDKIMKeyPair: %v", err)
	}

	key, err := ParsePrivateKeyPEM(kp.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM: %v", err)
	}
	if key == nil {
		t.Fatal("parsed key is nil")
	}
	if key.N.BitLen() != 2048 {
		t.Errorf("key size = %d bits, want 2048", key.N.BitLen())
	}
}

func TestParsePrivateKeyPEM_Invalid(t *testing.T) {
	_, err := ParsePrivateKeyPEM([]byte("not-a-pem-block"))
	if err == nil {
		t.Error("expected error parsing invalid PEM")
	}
}

func TestGenerateSMTPDomainSetup(t *testing.T) {
	kp, _ := GenerateDKIMKeyPair("sel1")
	setup := GenerateSMTPDomainSetup("example.com", kp, "ip4:1.2.3.4 ~all")

	if setup.Domain != "example.com" {
		t.Errorf("Domain = %q", setup.Domain)
	}

	// DKIM record
	if setup.DKIMRecord.Type != "TXT" {
		t.Errorf("DKIMRecord.Type = %q, want TXT", setup.DKIMRecord.Type)
	}
	if !strings.HasPrefix(setup.DKIMRecord.Name, "sel1._domainkey.") {
		t.Errorf("DKIMRecord.Name = %q, should start with sel1._domainkey.", setup.DKIMRecord.Name)
	}
	if !strings.Contains(setup.DKIMRecord.Value, "v=DKIM1") {
		t.Errorf("DKIMRecord.Value missing v=DKIM1: %q", setup.DKIMRecord.Value)
	}

	// SPF record
	if setup.SPFRecord.Type != "TXT" {
		t.Errorf("SPFRecord.Type = %q, want TXT", setup.SPFRecord.Type)
	}
	if setup.SPFRecord.Name != "example.com" {
		t.Errorf("SPFRecord.Name = %q, want example.com", setup.SPFRecord.Name)
	}
	if !strings.Contains(setup.SPFRecord.Value, "v=spf1") {
		t.Errorf("SPFRecord.Value missing v=spf1: %q", setup.SPFRecord.Value)
	}

	// DMARC record
	if setup.DMARCRecord.Type != "TXT" {
		t.Errorf("DMARCRecord.Type = %q, want TXT", setup.DMARCRecord.Type)
	}
	if !strings.HasPrefix(setup.DMARCRecord.Name, "_dmarc.") {
		t.Errorf("DMARCRecord.Name = %q, should start with _dmarc.", setup.DMARCRecord.Name)
	}
	if !strings.Contains(setup.DMARCRecord.Value, "v=DMARC1") {
		t.Errorf("DMARCRecord.Value missing v=DMARC1: %q", setup.DMARCRecord.Value)
	}
}

func TestGenerateSMTPDomainSetup_DefaultSPF(t *testing.T) {
	kp, _ := GenerateDKIMKeyPair("s1")
	setup := GenerateSMTPDomainSetup("example.com", kp, "")
	if !strings.Contains(setup.SPFRecord.Value, "~all") {
		t.Errorf("SPFRecord with empty mechanism should contain ~all: %q", setup.SPFRecord.Value)
	}
}

func TestFormatOnboardingInstructions(t *testing.T) {
	kp, _ := GenerateDKIMKeyPair("sel")
	setup := GenerateSMTPDomainSetup("acme.com", kp, "~all")
	instructions := FormatOnboardingInstructions(setup)

	if !strings.Contains(instructions, "acme.com") {
		t.Error("instructions should contain domain name")
	}
	if !strings.Contains(instructions, "DKIM") {
		t.Error("instructions should mention DKIM")
	}
	if !strings.Contains(instructions, "SPF") {
		t.Error("instructions should mention SPF")
	}
	if !strings.Contains(instructions, "DMARC") {
		t.Error("instructions should mention DMARC")
	}
}

func TestKeyPairsAreUnique(t *testing.T) {
	kp1, _ := GenerateDKIMKeyPair("s1")
	kp2, _ := GenerateDKIMKeyPair("s2")

	if kp1.PublicKeyBase64 == kp2.PublicKeyBase64 {
		t.Error("two independently generated key pairs should have different public keys")
	}
}
