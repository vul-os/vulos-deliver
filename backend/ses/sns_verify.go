// Package ses — SNS message signature verification.
//
// VerifySNSMessage implements AWS SNS SignatureVersion 1 (RSA-SHA1) and is
// exported so that other packages (e.g. vesend) can verify SNS messages without
// duplicating this logic.
package ses

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA1 is mandated by AWS SNS SignatureVersion 1
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// snsHostRe matches the hostname of a valid AWS SNS endpoint.
// Only sns.<region>.amazonaws.com is trusted.
var snsHostRe = regexp.MustCompile(`^sns\.[a-z0-9-]+\.amazonaws\.com$`)

// snsDefaultHTTPClient is used by VerifySNSMessage to fetch signing certs.
// It is a package-level var so tests can replace it with a test-server-backed
// client without exposing it in the public API.
var snsDefaultHTTPClient = &http.Client{Timeout: 10 * time.Second}

// snsCertCache caches RSA public keys keyed by the signing-cert URL to avoid
// redundant round trips for the same AWS SNS key rotation epoch.
var snsCertCache sync.Map // map[string]*rsa.PublicKey

// SNSEnvelope is the outer JSON document that AWS SNS POSTs to webhook endpoints.
//
// Parse the raw HTTP body into this type and pass it to VerifySNSMessage before
// acting on any field — all fields are attacker-supplied until the signature is
// verified.
type SNSEnvelope struct {
	Type             string `json:"Type"`
	MessageID        string `json:"MessageId"`
	TopicArn         string `json:"TopicArn"`
	Subject          string `json:"Subject,omitempty"`
	Message          string `json:"Message"`
	Timestamp        string `json:"Timestamp"`
	SubscribeURL     string `json:"SubscribeURL,omitempty"`
	UnsubscribeURL   string `json:"UnsubscribeURL,omitempty"`
	Token            string `json:"Token,omitempty"`
	SignatureVersion string `json:"SignatureVersion"`
	Signature        string `json:"Signature"`
	SigningCertURL   string `json:"SigningCertURL"`
}

// VerifySNSMessage verifies the RSA-SHA1 signature on an SNS envelope
// (SignatureVersion 1).
//
// Verification steps:
//  1. Confirms SignatureVersion == "1".
//  2. Validates SigningCertURL: HTTPS + host matching sns.<region>.amazonaws.com.
//  3. Fetches and caches the DER-encoded X.509 signing certificate.
//  4. Verifies the RSA-PKCS1v15 / SHA-1 signature over the canonical
//     string-to-sign defined by the SNS documentation.
//
// Returns nil if valid. Callers MUST NOT act on any envelope field until this
// returns nil.
func VerifySNSMessage(env SNSEnvelope) error {
	return verifySNSMessageWithFetcher(env, func(certURL string) (*rsa.PublicKey, error) {
		return snsFetchCertPubKey(certURL, snsDefaultHTTPClient)
	})
}

// verifySNSMessageWithFetcher is the testable core of VerifySNSMessage.
// Tests inject a custom fetcher to avoid real network calls and host-name
// constraints (the SNS host check is still performed on SigningCertURL itself).
func verifySNSMessageWithFetcher(env SNSEnvelope, fetcher func(string) (*rsa.PublicKey, error)) error {
	if env.SignatureVersion != "1" {
		return fmt.Errorf("sns: unsupported SignatureVersion %q (only \"1\" is supported)", env.SignatureVersion)
	}

	if err := validateSNSCertURL(env.SigningCertURL); err != nil {
		return err
	}

	pubKey, err := fetcher(env.SigningCertURL)
	if err != nil {
		return fmt.Errorf("sns: obtain signing cert: %w", err)
	}

	sts := snsStringToSign(env)

	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		return fmt.Errorf("sns: base64-decode Signature: %w", err)
	}

	//nolint:gosec // SHA1 is mandated by the AWS SNS SignatureVersion 1 spec
	h := sha1.Sum([]byte(sts))
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA1, h[:], sig); err != nil {
		return fmt.Errorf("sns: signature verification failed: %w", err)
	}
	return nil
}

// validateSNSCertURL returns an error if rawURL is not a trusted AWS SNS
// signing-cert endpoint (must be https://sns.<region>.amazonaws.com/...).
func validateSNSCertURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || !snsHostRe.MatchString(u.Host) {
		return fmt.Errorf("sns: SigningCertURL %q is not a trusted SNS endpoint "+
			"(expected https://sns.<region>.amazonaws.com/...)", rawURL)
	}
	return nil
}

// validateSubscribeURL returns an error if rawURL is not a trusted AWS SNS
// subscription endpoint (must be https://sns.<region>.amazonaws.com/...).
func validateSubscribeURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || !snsHostRe.MatchString(u.Host) {
		return fmt.Errorf("sns: SubscribeURL %q is not a trusted SNS endpoint "+
			"(expected https://sns.<region>.amazonaws.com/...)", rawURL)
	}
	return nil
}

// snsFetchCertPubKey fetches the X.509 PEM certificate at certURL and returns
// its RSA public key. Results are cached in snsCertCache to limit round trips.
func snsFetchCertPubKey(certURL string, client *http.Client) (*rsa.PublicKey, error) {
	if cached, ok := snsCertCache.Load(certURL); ok {
		return cached.(*rsa.PublicKey), nil
	}

	resp, err := client.Get(certURL) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", certURL, err)
	}
	defer resp.Body.Close()

	pemData, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10)) // 64 KiB max
	if err != nil {
		return nil, fmt.Errorf("read signing cert body: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in signing cert from %s", certURL)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse signing cert: %w", err)
	}

	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("signing cert at %s does not contain an RSA public key", certURL)
	}

	snsCertCache.Store(certURL, rsaPub)
	return rsaPub, nil
}

// snsStringToSign builds the canonical string-to-sign for SNS SignatureVersion 1.
// The set of fields and their order depend on the message type, per the AWS spec:
// https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html
func snsStringToSign(env SNSEnvelope) string {
	var b strings.Builder
	add := func(key, val string) {
		b.WriteString(key)
		b.WriteByte('\n')
		b.WriteString(val)
		b.WriteByte('\n')
	}

	switch env.Type {
	case "SubscriptionConfirmation", "UnsubscribeConfirmation":
		add("Message", env.Message)
		add("MessageId", env.MessageID)
		add("SubscribeURL", env.SubscribeURL)
		add("Timestamp", env.Timestamp)
		add("Token", env.Token)
		add("TopicArn", env.TopicArn)
		add("Type", env.Type)
	default: // "Notification"
		add("Message", env.Message)
		add("MessageId", env.MessageID)
		if env.Subject != "" {
			add("Subject", env.Subject)
		}
		add("Timestamp", env.Timestamp)
		add("TopicArn", env.TopicArn)
		add("Type", env.Type)
	}
	return b.String()
}
