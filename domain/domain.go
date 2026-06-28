// Package domain provides backend-agnostic DNS record generation and DKIM key
// management for custom sending domains.
//
// It is used by the Vulos platform's tenant onboarding flow to generate the
// DNS records a customer must publish before their custom domain can send mail.
//
// For SES backends: CreateDomainIdentity in the ses package returns SES-specific
// CNAME records; call domain.GenerateSMTPDomainSetup only for self-hosted senders.
//
// For own-IP/SMTP backends: generate a DKIM keypair with GenerateDKIMKeyPair,
// store the private key in your secrets manager, then return the DomainSetup
// to the tenant as onboarding instructions.
package domain

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
)

// DNSRecord is a single DNS record the domain owner must publish.
type DNSRecord struct {
	Type  string // "TXT", "CNAME", "MX"
	Name  string // fully-qualified DNS name
	Value string // record data
	TTL   int    // recommended TTL in seconds
}

// DomainSetup describes all DNS records needed for a custom sending domain
// on a self-hosted (own-IP/SMTP) stack.
//
// For SES, the ses.DomainSetupResult type carries the equivalent information
// with SES-specific CNAME records instead of the DKIM TXT record here.
type DomainSetup struct {
	Domain string

	// DKIMRecord is the TXT record the customer must publish for DKIM verification.
	// Format: <selector>._domainkey.<domain> TXT "v=DKIM1; k=rsa; p=<pubkey>"
	DKIMRecord DNSRecord

	// SPFRecord is the TXT record at the domain apex authorising the sender's IPs.
	SPFRecord DNSRecord

	// DMARCRecord is the DMARC policy TXT record at _dmarc.<domain>.
	DMARCRecord DNSRecord
}

// DKIMKeyPair is a generated RSA DKIM key pair.
type DKIMKeyPair struct {
	// PrivateKeyPEM is the PKCS#1 RSA private key in PEM format.
	// Store this in a secrets manager; it is used by the MTA to sign outbound mail.
	PrivateKeyPEM []byte

	// PublicKeyBase64 is the base64-encoded PKIX public key for the DNS TXT record.
	PublicKeyBase64 string

	// Selector is the DKIM selector subdomain label.
	Selector string
}

// GenerateDKIMKeyPair generates a 2048-bit RSA DKIM key pair for the given selector.
//
// The selector appears in the DNS name: <selector>._domainkey.<domain>
// Convention: use the year-month (e.g. "2026-06") as the selector so rotation
// is unambiguous.
func GenerateDKIMKeyPair(selector string) (*DKIMKeyPair, error) {
	if selector == "" {
		return nil, fmt.Errorf("domain: DKIM selector cannot be empty")
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("domain: generate RSA 2048 key: %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("domain: marshal PKIX public key: %w", err)
	}
	pubBase64 := base64.StdEncoding.EncodeToString(pubDER)

	return &DKIMKeyPair{
		PrivateKeyPEM:   privPEM,
		PublicKeyBase64: pubBase64,
		Selector:        selector,
	}, nil
}

// ParsePrivateKeyPEM parses a PKCS#1 PEM-encoded RSA private key.
// Useful for loading a stored key pair.
func ParsePrivateKeyPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("domain: failed to decode PEM block")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("domain: parse PKCS1 private key: %w", err)
	}
	return key, nil
}

// GenerateSMTPDomainSetup returns the DNS records needed for a self-hosted
// SMTP sender (own IP, Postfix, Haraka, etc.).
//
// spfMechanism is the SPF mechanism string appended to "v=spf1 " — typically
// something like "ip4:1.2.3.4 ~all" or "include:spf.yourdomain.com ~all".
// If empty, defaults to "~all" (soft-fail everything — likely too restrictive
// for production; supply a real mechanism).
func GenerateSMTPDomainSetup(domain string, dkim *DKIMKeyPair, spfMechanism string) DomainSetup {
	if spfMechanism == "" {
		spfMechanism = "~all"
	}

	dkimValue := fmt.Sprintf(`"v=DKIM1; k=rsa; p=%s"`, dkim.PublicKeyBase64)

	return DomainSetup{
		Domain: domain,
		DKIMRecord: DNSRecord{
			Type:  "TXT",
			Name:  fmt.Sprintf("%s._domainkey.%s", dkim.Selector, domain),
			Value: dkimValue,
			TTL:   300,
		},
		SPFRecord: DNSRecord{
			Type:  "TXT",
			Name:  domain,
			Value: fmt.Sprintf(`"v=spf1 %s"`, spfMechanism),
			TTL:   300,
		},
		DMARCRecord: DNSRecord{
			Type:  "TXT",
			Name:  fmt.Sprintf("_dmarc.%s", domain),
			Value: fmt.Sprintf(`"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@%s; adkim=s; aspf=s"`, domain),
			TTL:   300,
		},
	}
}

// FormatOnboardingInstructions returns human-readable DNS configuration
// instructions for display in tenant onboarding UIs, emails, or admin panels.
func FormatOnboardingInstructions(setup DomainSetup) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("DNS records required for custom sending domain: %s\n", setup.Domain))
	sb.WriteString("\n")
	sb.WriteString("1. DKIM (email authentication)\n")
	writeRecord(&sb, setup.DKIMRecord)
	sb.WriteString("\n")
	sb.WriteString("2. SPF (sender authorisation)\n")
	writeRecord(&sb, setup.SPFRecord)
	sb.WriteString("\n")
	sb.WriteString("3. DMARC (policy enforcement + reporting)\n")
	writeRecord(&sb, setup.DMARCRecord)
	sb.WriteString("\n")
	sb.WriteString("After publishing all records, verification typically completes within 72 hours.\n")
	return sb.String()
}

func writeRecord(sb *strings.Builder, r DNSRecord) {
	sb.WriteString(fmt.Sprintf("   Type:  %s\n", r.Type))
	sb.WriteString(fmt.Sprintf("   Name:  %s\n", r.Name))
	sb.WriteString(fmt.Sprintf("   Value: %s\n", r.Value))
	sb.WriteString(fmt.Sprintf("   TTL:   %d\n", r.TTL))
}
