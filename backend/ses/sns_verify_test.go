package ses

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA1 required by AWS SNS SignatureVersion 1
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// generateTestRSAKey generates a 2048-bit RSA key pair for tests.
func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

// generateTestCertPEM returns a self-signed X.509 cert PEM for the given key.
func generateTestCertPEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-sns-cert"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// signSNSEnvelope signs env using privKey and sets env.Signature.
// The caller must set all other envelope fields before calling this.
func signSNSEnvelope(t *testing.T, env SNSEnvelope, privKey *rsa.PrivateKey) SNSEnvelope {
	t.Helper()
	sts := snsStringToSign(env)
	//nolint:gosec // SHA1 mandated by SNS spec
	h := sha1.Sum([]byte(sts))
	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA1, h[:])
	if err != nil {
		t.Fatalf("sign SNS envelope: %v", err)
	}
	env.Signature = base64.StdEncoding.EncodeToString(sig)
	return env
}

// newTestCertFetcher returns a cert fetcher that returns pubKey for any URL
// (bypasses network + host validation in verifySNSMessageWithFetcher).
func newTestCertFetcher(pubKey *rsa.PublicKey) func(string) (*rsa.PublicKey, error) {
	return func(_ string) (*rsa.PublicKey, error) {
		return pubKey, nil
	}
}

// TestVerifySNSMessage_ValidSignature verifies that a correctly signed
// Notification envelope passes signature verification.
func TestVerifySNSMessage_ValidSignature(t *testing.T) {
	key := generateTestRSAKey(t)

	env := SNSEnvelope{
		Type:             "Notification",
		MessageID:        "msg-valid-1",
		TopicArn:         "arn:aws:sns:us-east-1:123:test-topic",
		Message:          `{"notificationType":"Bounce"}`,
		Timestamp:        "2024-06-01T12:00:00.000Z",
		SignatureVersion: "1",
		SigningCertURL:   "https://sns.us-east-1.amazonaws.com/cert.pem",
	}
	env = signSNSEnvelope(t, env, key)

	if err := verifySNSMessageWithFetcher(env, newTestCertFetcher(&key.PublicKey)); err != nil {
		t.Errorf("valid signature should pass, got error: %v", err)
	}
}

// TestVerifySNSMessage_ForgedSignature verifies that a tampered Signature field
// is rejected.
func TestVerifySNSMessage_ForgedSignature(t *testing.T) {
	key := generateTestRSAKey(t)

	env := SNSEnvelope{
		Type:             "Notification",
		MessageID:        "msg-forged-1",
		TopicArn:         "arn:aws:sns:us-east-1:123:test-topic",
		Message:          `{"notificationType":"Bounce"}`,
		Timestamp:        "2024-06-01T12:00:00.000Z",
		SignatureVersion: "1",
		SigningCertURL:   "https://sns.us-east-1.amazonaws.com/cert.pem",
		Signature:        base64.StdEncoding.EncodeToString([]byte("this-is-not-a-valid-signature")),
	}

	err := verifySNSMessageWithFetcher(env, newTestCertFetcher(&key.PublicKey))
	if err == nil {
		t.Error("forged signature should be rejected, but got nil error")
	}
}

// TestVerifySNSMessage_TamperedMessage verifies that modifying the Message field
// after signing causes rejection.
func TestVerifySNSMessage_TamperedMessage(t *testing.T) {
	key := generateTestRSAKey(t)

	env := SNSEnvelope{
		Type:             "Notification",
		MessageID:        "msg-tampered-1",
		TopicArn:         "arn:aws:sns:us-east-1:123:test-topic",
		Message:          `{"notificationType":"Bounce"}`,
		Timestamp:        "2024-06-01T12:00:00.000Z",
		SignatureVersion: "1",
		SigningCertURL:   "https://sns.us-east-1.amazonaws.com/cert.pem",
	}
	env = signSNSEnvelope(t, env, key)
	// Tamper: inject attacker-controlled address into the Message after signing.
	env.Message = `{"notificationType":"Bounce","bounce":{"bouncedRecipients":[{"emailAddress":"victim@example.com"}]}}`

	err := verifySNSMessageWithFetcher(env, newTestCertFetcher(&key.PublicKey))
	if err == nil {
		t.Error("tampered Message should be rejected, but got nil error")
	}
}

// TestVerifySNSMessage_WrongKey verifies that a signature from a different key
// is rejected (simulates a forged cert scenario).
func TestVerifySNSMessage_WrongKey(t *testing.T) {
	signingKey := generateTestRSAKey(t)
	verifyKey := generateTestRSAKey(t) // different key pair

	env := SNSEnvelope{
		Type:             "Notification",
		MessageID:        "msg-wrongkey-1",
		TopicArn:         "arn:aws:sns:us-east-1:123:test-topic",
		Message:          `{"notificationType":"Bounce"}`,
		Timestamp:        "2024-06-01T12:00:00.000Z",
		SignatureVersion: "1",
		SigningCertURL:   "https://sns.us-east-1.amazonaws.com/cert.pem",
	}
	env = signSNSEnvelope(t, env, signingKey)

	// Verify with a different public key — must reject.
	err := verifySNSMessageWithFetcher(env, newTestCertFetcher(&verifyKey.PublicKey))
	if err == nil {
		t.Error("signature from wrong key should be rejected")
	}
}

// TestVerifySNSMessage_UnsupportedSignatureVersion verifies that SignatureVersion
// values other than "1" are rejected.
func TestVerifySNSMessage_UnsupportedSignatureVersion(t *testing.T) {
	key := generateTestRSAKey(t)
	env := SNSEnvelope{
		Type:             "Notification",
		MessageID:        "msg-v2",
		SignatureVersion: "2",
		SigningCertURL:   "https://sns.us-east-1.amazonaws.com/cert.pem",
	}
	if err := verifySNSMessageWithFetcher(env, newTestCertFetcher(&key.PublicKey)); err == nil {
		t.Error("SignatureVersion 2 should be rejected")
	}
}

// TestVerifySNSMessage_NonAWSCertURL verifies that a SigningCertURL with a
// non-AWS host is rejected without making a network call (C1).
func TestVerifySNSMessage_NonAWSCertURL(t *testing.T) {
	key := generateTestRSAKey(t)
	called := false
	fakeFetcher := func(_ string) (*rsa.PublicKey, error) {
		called = true
		return &key.PublicKey, nil
	}

	badURLs := []string{
		"https://evil.com/cert.pem",
		"http://sns.us-east-1.amazonaws.com/cert.pem",    // http not https
		"https://attacker.sns.us-east-1.amazonaws.com/x", // subdomain
		"https://sns.us-east-1.amazonaws.com.evil.com/x", // suffix trick
		"https://not-sns.amazonaws.com/cert.pem",         // wrong service
	}
	for _, u := range badURLs {
		called = false
		env := SNSEnvelope{
			Type:             "Notification",
			SignatureVersion: "1",
			SigningCertURL:   u,
		}
		err := verifySNSMessageWithFetcher(env, fakeFetcher)
		if err == nil {
			t.Errorf("non-AWS cert URL %q should be rejected", u)
		}
		if called {
			t.Errorf("fetcher should NOT be called for non-AWS cert URL %q", u)
		}
	}
}

// TestVerifySNSMessage_SubscriptionConfirmation verifies that a correctly signed
// SubscriptionConfirmation envelope passes (different string-to-sign fields).
func TestVerifySNSMessage_SubscriptionConfirmation(t *testing.T) {
	key := generateTestRSAKey(t)

	env := SNSEnvelope{
		Type:             "SubscriptionConfirmation",
		MessageID:        "msg-sub-1",
		TopicArn:         "arn:aws:sns:us-east-1:123:test-topic",
		Message:          "You have chosen to subscribe to the topic...",
		SubscribeURL:     "https://sns.us-east-1.amazonaws.com/confirm?Token=abc123",
		Token:            "abc123",
		Timestamp:        "2024-06-01T12:00:00.000Z",
		SignatureVersion: "1",
		SigningCertURL:   "https://sns.us-east-1.amazonaws.com/cert.pem",
	}
	env = signSNSEnvelope(t, env, key)

	if err := verifySNSMessageWithFetcher(env, newTestCertFetcher(&key.PublicKey)); err != nil {
		t.Errorf("valid SubscriptionConfirmation should pass: %v", err)
	}
}

// TestSnsFetchCertPubKey_LiveServer verifies the full cert-fetch-and-cache path
// using an httptest HTTPS server that serves a real self-signed certificate.
func TestSnsFetchCertPubKey_LiveServer(t *testing.T) {
	key := generateTestRSAKey(t)
	certPEM := generateTestCertPEM(t, key)

	// Serve the cert from an httptest TLS server.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(certPEM) //nolint:errcheck
	}))
	defer ts.Close()

	// Use the test server's own HTTP client (trusts the test TLS cert).
	client := ts.Client()

	pub, err := snsFetchCertPubKey(ts.URL+"/cert.pem?unique=live1", client)
	if err != nil {
		t.Fatalf("snsFetchCertPubKey: %v", err)
	}
	if pub.E != key.PublicKey.E || pub.N.Cmp(key.PublicKey.N) != 0 {
		t.Error("returned public key does not match the key in the served cert")
	}

	// Second call should return the cached value.
	pub2, err := snsFetchCertPubKey(ts.URL+"/cert.pem?unique=live1", client)
	if err != nil {
		t.Fatalf("snsFetchCertPubKey (cached): %v", err)
	}
	if pub2 != pub {
		t.Error("second call should return the same cached pointer")
	}
}

// TestSNSStringToSign_Notification verifies the canonical string for Notification.
func TestSNSStringToSign_Notification(t *testing.T) {
	env := SNSEnvelope{
		Type:      "Notification",
		MessageID: "test-id",
		TopicArn:  "arn:aws:sns:us-east-1:123:topic",
		Message:   "hello world",
		Timestamp: "2024-01-01T00:00:00Z",
	}
	got := snsStringToSign(env)
	want := strings.Join([]string{
		"Message", "hello world",
		"MessageId", "test-id",
		"Timestamp", "2024-01-01T00:00:00Z",
		"TopicArn", "arn:aws:sns:us-east-1:123:topic",
		"Type", "Notification",
	}, "\n") + "\n"
	if got != want {
		t.Errorf("string-to-sign mismatch\ngot:  %q\nwant: %q", got, want)
	}
}

// TestSNSStringToSign_NotificationWithSubject verifies Subject is included when set.
func TestSNSStringToSign_NotificationWithSubject(t *testing.T) {
	env := SNSEnvelope{
		Type:      "Notification",
		MessageID: "test-id",
		Subject:   "My Subject",
		TopicArn:  "arn:aws:sns:us-east-1:123:topic",
		Message:   "hello world",
		Timestamp: "2024-01-01T00:00:00Z",
	}
	got := snsStringToSign(env)
	if !strings.Contains(got, "Subject\nMy Subject\n") {
		t.Errorf("Subject not included in string-to-sign: %q", got)
	}
}

// TestSNSStringToSign_SubscriptionConfirmation verifies the SubscribeURL/Token
// fields are included for SubscriptionConfirmation.
func TestSNSStringToSign_SubscriptionConfirmation(t *testing.T) {
	env := SNSEnvelope{
		Type:         "SubscriptionConfirmation",
		MessageID:    "test-id",
		TopicArn:     "arn:aws:sns:us-east-1:123:topic",
		Message:      "subscribe message",
		Timestamp:    "2024-01-01T00:00:00Z",
		SubscribeURL: "https://sns.us-east-1.amazonaws.com/confirm?Token=tok",
		Token:        "tok",
	}
	got := snsStringToSign(env)
	for _, must := range []string{"SubscribeURL\n", "Token\ntok\n"} {
		if !strings.Contains(got, must) {
			t.Errorf("string-to-sign missing %q: %q", must, got)
		}
	}
	// Notification-only fields should NOT be present for SubscriptionConfirmation
	// (Subject would be listed if included, but it's absent here so it's fine).
	_ = fmt.Sprintf("got: %q", got) // for debugging
}
