// Package ses — SNS bounce/complaint webhook handler.
//
// Wire this handler to the HTTP endpoint you register as your SES SNS
// subscription. When SES detects a bounce or spam complaint it publishes
// an SNS notification; this handler decodes it and adds affected addresses
// to the suppression list so they are never re-sent to.
package ses

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

// --- SNS notification payload types ---

// sesNotification is the SES notification decoded from SNSEnvelope.Message.
type sesNotification struct {
	NotificationType string               `json:"notificationType"`
	Bounce           *sesBouncePaylod     `json:"bounce,omitempty"`
	Complaint        *sesComplaintPayload `json:"complaint,omitempty"`
	Mail             *sesMail             `json:"mail,omitempty"`
}

type sesBouncePaylod struct {
	BounceType        string         `json:"bounceType"` // "Permanent" | "Transient"
	BounceSubType     string         `json:"bounceSubType"`
	BouncedRecipients []sesEmailAddr `json:"bouncedRecipients"`
	Timestamp         string         `json:"timestamp"`
	FeedbackID        string         `json:"feedbackId"`
}

type sesComplaintPayload struct {
	ComplainedRecipients  []sesEmailAddr `json:"complainedRecipients"`
	Timestamp             string         `json:"timestamp"`
	FeedbackID            string         `json:"feedbackId"`
	ComplaintFeedbackType string         `json:"complaintFeedbackType"`
}

type sesEmailAddr struct {
	EmailAddress string `json:"emailAddress"`
}

type sesMail struct {
	MessageID string `json:"messageId"`
	Source    string `json:"source"`
}

// --- Handler ---

// BounceWebhookHandler is an http.Handler that processes AWS SNS bounce and
// complaint notifications published by SES and updates the suppression list.
//
// Mount on any path, then register that URL as the subscription endpoint in
// your SES configuration set's event destinations (via SNS topic).
//
// All incoming SNS messages are verified with VerifySNSMessage (RSA-SHA1,
// SignatureVersion 1) before any action is taken. SubscribeURL auto-confirm
// is only performed after signature verification and URL host validation.
//
// Production checklist:
//  1. Enable ConfirmSubscriptions so the handler auto-confirms the SNS topic.
//  2. Back the SuppressionList with a persistent store (Postgres, Redis) so
//     suppressions survive restarts.
type BounceWebhookHandler struct {
	suppression          SuppressionList
	logger               *slog.Logger
	confirmSubscriptions bool
	// verifySNS is the signature-verification function. When nil, VerifySNSMessage
	// is used. Inject a no-op in unit tests that exercise bounce/complaint logic
	// without needing real AWS-signed payloads.
	verifySNS func(SNSEnvelope) error
}

// NewBounceWebhookHandler creates an http.Handler for SNS bounce/complaint events.
//
// Set confirmSubscriptions=true in production so new SNS subscriptions are
// automatically confirmed without manual console intervention.
func NewBounceWebhookHandler(suppression SuppressionList, logger *slog.Logger, confirmSubscriptions bool) *BounceWebhookHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &BounceWebhookHandler{
		suppression:          suppression,
		logger:               logger,
		confirmSubscriptions: confirmSubscriptions,
	}
}

// ServeHTTP implements http.Handler.
func (h *BounceWebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB max
	if err != nil {
		h.logger.Error("sns webhook: read body", "err", err)
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	var env SNSEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		h.logger.Error("sns webhook: parse envelope", "err", err)
		http.Error(w, "bad JSON", http.StatusBadRequest)
		return
	}

	// C1: Verify the SNS message signature BEFORE acting on any field.
	verify := h.verifySNS
	if verify == nil {
		verify = VerifySNSMessage
	}
	if err := verify(env); err != nil {
		h.logger.Warn("sns webhook: signature verification failed — rejecting message",
			"err", err,
			"type", env.Type,
			"topic", env.TopicArn,
		)
		http.Error(w, fmt.Sprintf("signature verification failed: %v", err), http.StatusForbidden)
		return
	}

	switch env.Type {
	case "SubscriptionConfirmation":
		h.handleSubscriptionConfirmation(w, env)
	case "Notification":
		h.handleNotification(w, env)
	case "UnsubscribeConfirmation":
		// Acknowledge silently.
		w.WriteHeader(http.StatusOK)
	default:
		h.logger.Warn("sns webhook: unknown message type", "type", env.Type)
		w.WriteHeader(http.StatusOK)
	}
}

func (h *BounceWebhookHandler) handleSubscriptionConfirmation(w http.ResponseWriter, env SNSEnvelope) {
	if !h.confirmSubscriptions {
		h.logger.Info("sns subscription confirmation received (auto-confirm disabled — visit SubscribeURL manually)",
			"topic", env.TopicArn,
			"subscribeURL", env.SubscribeURL,
		)
		w.WriteHeader(http.StatusOK)
		return
	}

	// C2: Validate SubscribeURL host before fetching it.
	// Signature has already been verified above, but we still enforce the host
	// allowlist here as a defence-in-depth measure against URL manipulation.
	if err := validateSubscribeURL(env.SubscribeURL); err != nil {
		h.logger.Error("sns webhook: SubscribeURL host is not a trusted SNS endpoint",
			"subscribeURL", env.SubscribeURL,
			"err", err,
		)
		http.Error(w, "invalid SubscribeURL", http.StatusBadRequest)
		return
	}

	// Auto-confirm: GET the verified SubscribeURL.
	resp, err := http.Get(env.SubscribeURL) //nolint:noctx
	if err != nil {
		h.logger.Error("sns webhook: subscription confirmation failed", "err", err)
		http.Error(w, "confirmation failed", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	h.logger.Info("sns subscription confirmed", "topic", env.TopicArn)
	w.WriteHeader(http.StatusOK)
}

func (h *BounceWebhookHandler) handleNotification(w http.ResponseWriter, env SNSEnvelope) {
	var notif sesNotification
	if err := json.Unmarshal([]byte(env.Message), &notif); err != nil {
		h.logger.Error("sns webhook: parse SES notification", "err", err)
		http.Error(w, "bad notification JSON", http.StatusBadRequest)
		return
	}

	switch notif.NotificationType {
	case "Bounce":
		h.handleBounce(notif)
	case "Complaint":
		h.handleComplaint(notif)
	default:
		h.logger.Debug("sns webhook: unhandled notification type", "type", notif.NotificationType)
	}

	w.WriteHeader(http.StatusOK)
}

// handleBounce suppresses permanently-bounced addresses.
// Transient bounces (e.g. mailbox-full) are logged but not suppressed — the
// queue retries those.
func (h *BounceWebhookHandler) handleBounce(notif sesNotification) {
	if notif.Bounce == nil {
		return
	}
	if !strings.EqualFold(notif.Bounce.BounceType, "Permanent") {
		h.logger.Debug("sns webhook: ignoring transient bounce",
			"bounceType", notif.Bounce.BounceType,
			"bounceSubType", notif.Bounce.BounceSubType,
		)
		return
	}
	for _, r := range notif.Bounce.BouncedRecipients {
		if r.EmailAddress == "" {
			continue
		}
		if err := h.suppression.Add(r.EmailAddress, ReasonBounce); err != nil {
			h.logger.Error("sns webhook: suppression add (bounce)", "email", r.EmailAddress, "err", err)
			continue
		}
		h.logger.Info("sns webhook: suppressed permanently-bounced address",
			"email", r.EmailAddress,
			"subType", notif.Bounce.BounceSubType,
		)
	}
}

// handleComplaint suppresses all addresses that filed a spam/abuse complaint.
// Any complaint — regardless of feedbackType — triggers suppression to protect
// sender reputation.
func (h *BounceWebhookHandler) handleComplaint(notif sesNotification) {
	if notif.Complaint == nil {
		return
	}
	for _, r := range notif.Complaint.ComplainedRecipients {
		if r.EmailAddress == "" {
			continue
		}
		if err := h.suppression.Add(r.EmailAddress, ReasonComplaint); err != nil {
			h.logger.Error("sns webhook: suppression add (complaint)", "email", r.EmailAddress, "err", err)
			continue
		}
		h.logger.Info("sns webhook: suppressed complained-about address",
			"email", r.EmailAddress,
			"feedbackType", notif.Complaint.ComplaintFeedbackType,
		)
	}
}
