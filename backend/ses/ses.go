// Package ses implements deliver.Sender over AWS SES v2.
//
// It handles:
//   - Multi-tenant custom-domain identities (DKIM/SPF/DMARC via IdentityManager)
//   - The 10,000-identity-per-region cap with usage metrics and graceful scale-out
//   - Sandbox vs. production detection (surfaced via IsSandbox)
//   - Per-account token-bucket send-rate limiting (default 14 sends/sec)
//   - Bounce/complaint-driven suppression list (via BounceWebhookHandler)
//
// To switch to a self-hosted SMTP stack later: change provider.Config.Backend
// to "smtp" and point it at your SMTP submission endpoint — no other code changes.
package ses

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"

	deliver "github.com/vul-os/vulos-deliver"
)

// RegionConfig configures a single SES region for multi-region deployments.
//
// Multi-region design: SES allows 10,000 identities per region. When you
// approach that cap, add a second RegionConfig entry in Config.Regions. Route
// tenants to regions by consistent hash or round-robin; each region's
// IdentityManager tracks its own count independently.
type RegionConfig struct {
	Region          string `json:"region"          yaml:"region"`
	AccessKeyID     string `json:"accessKeyId"     yaml:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey" yaml:"secretAccessKey"`

	// WarnThreshold is the identity count at which this region logs a warning.
	// Defaults to DefaultWarnThreshold (9000) when zero.
	WarnThreshold int `json:"warnThreshold,omitempty" yaml:"warnThreshold,omitempty"`
}

// Config configures the SES Sender.
//
// Single-region shorthand: set Region/AccessKeyID/SecretAccessKey.
// Multi-region: populate Regions instead; the first entry is primary.
type Config struct {
	// --- Single-region shorthand ---
	Region          string `json:"region"          yaml:"region"`
	AccessKeyID     string `json:"accessKeyId"     yaml:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey" yaml:"secretAccessKey"`

	// --- Multi-region (overrides single-region fields when non-empty) ---
	// Populate this when region A approaches 10,000 identities.
	Regions []RegionConfig `json:"regions,omitempty" yaml:"regions,omitempty"`

	// SendRate is the maximum sends/second (token-bucket). Defaults to 14,
	// which is the conservative starting quota for new SES production accounts.
	// Raise this to match your actual SES send-rate quota.
	SendRate float64 `json:"sendRate,omitempty" yaml:"sendRate,omitempty"`

	// WarnThreshold is the identity count at which to warn. Defaults to 9000.
	WarnThreshold int `json:"warnThreshold,omitempty" yaml:"warnThreshold,omitempty"`

	// ConfigurationSet is the default SES configuration set name. Applied to
	// every message that does not override it in Message.ConfigurationSet.
	ConfigurationSet string `json:"configurationSet,omitempty" yaml:"configurationSet,omitempty"`

	// Suppression is the suppression list backend. If nil, a new
	// MemorySuppressionList is allocated (not persistent across restarts).
	Suppression SuppressionList `json:"-" yaml:"-"`

	// Logger is the structured logger. Defaults to slog.Default().
	Logger *slog.Logger `json:"-" yaml:"-"`

	// Client injects a custom SESEmailClient implementation (for testing).
	// When nil, a real *sesv2.Client is constructed from the credentials above.
	Client SESEmailClient `json:"-" yaml:"-"`
}

// effectiveRegions normalises Config into a []RegionConfig.
func (cfg Config) effectiveRegions() []RegionConfig {
	if len(cfg.Regions) > 0 {
		return cfg.Regions
	}
	if cfg.Region != "" {
		return []RegionConfig{{
			Region:          cfg.Region,
			AccessKeyID:     cfg.AccessKeyID,
			SecretAccessKey: cfg.SecretAccessKey,
			WarnThreshold:   cfg.WarnThreshold,
		}}
	}
	return nil
}

// defaultSendRate is the conservative starting SES production quota.
const defaultSendRate = 14.0

// Sender is an SES-backed deliver.Sender.
type Sender struct {
	cfg         Config
	client      SESEmailClient
	identity    *IdentityManager
	rateLimiter *TokenBucket
	suppression SuppressionList
	logger      *slog.Logger

	// sandbox is set by DetectSandbox. true means this account is in SES sandbox.
	sandbox bool
}

// New constructs an SES Sender from cfg.
//
// The Sender is ready to use immediately. Call DetectSandbox(ctx) to populate
// the sandbox flag and log account quota information.
func New(cfg Config) (*Sender, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	suppression := cfg.Suppression
	if suppression == nil {
		suppression = NewMemorySuppressionList()
	}

	rate := cfg.SendRate
	if rate <= 0 {
		rate = defaultSendRate
	}

	client := cfg.Client
	if client == nil {
		regions := cfg.effectiveRegions()
		if len(regions) == 0 {
			return nil, fmt.Errorf("ses: no region configured")
		}
		primary := regions[0]

		var (
			awsCfg aws.Config
			err    error
		)
		if primary.AccessKeyID != "" && primary.SecretAccessKey != "" {
			awsCfg, err = awsconfig.LoadDefaultConfig(context.Background(),
				awsconfig.WithRegion(primary.Region),
				awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
					primary.AccessKeyID, primary.SecretAccessKey, "",
				)),
			)
		} else {
			// Fall back to the standard AWS credential chain (env vars, IAM role, etc.).
			awsCfg, err = awsconfig.LoadDefaultConfig(context.Background(),
				awsconfig.WithRegion(primary.Region),
			)
		}
		if err != nil {
			return nil, fmt.Errorf("ses: load AWS config: %w", err)
		}
		client = sesv2.NewFromConfig(awsCfg)
	}

	region := cfg.Region
	warnThreshold := cfg.WarnThreshold
	if len(cfg.Regions) > 0 {
		region = cfg.Regions[0].Region
		if cfg.Regions[0].WarnThreshold > 0 {
			warnThreshold = cfg.Regions[0].WarnThreshold
		}
	}

	return &Sender{
		cfg:         cfg,
		client:      client,
		identity:    NewIdentityManager(client, region, warnThreshold, logger),
		rateLimiter: NewTokenBucket(rate),
		suppression: suppression,
		logger:      logger,
	}, nil
}

// DetectSandbox probes the SES account and sets the sandbox flag.
//
// Call this once during startup. If the account is in sandbox mode, the
// Sender logs a warning with instructions to request production access.
// Returns a non-nil error only if the GetAccount API call fails.
func (s *Sender) DetectSandbox(ctx context.Context) error {
	out, err := s.client.GetAccount(ctx, &sesv2.GetAccountInput{})
	if err != nil {
		return fmt.Errorf("ses: get account: %w", err)
	}
	s.sandbox = !out.ProductionAccessEnabled
	if s.sandbox {
		s.logger.Warn("SES account is in SANDBOX MODE",
			"limitation", "200 messages/day to verified addresses only",
			"action", "Request production access: https://console.aws.amazon.com/ses/home#/account",
		)
	}
	if out.SendQuota != nil {
		s.logger.Info("SES account quota",
			"maxSendRate", out.SendQuota.MaxSendRate,
			"max24h", out.SendQuota.Max24HourSend,
			"sentLast24h", out.SendQuota.SentLast24Hours,
			"sandbox", s.sandbox,
		)
	}
	return nil
}

// IsSandbox returns true if the SES account is in sandbox mode. The result is
// only meaningful after DetectSandbox has been called.
func (s *Sender) IsSandbox() bool { return s.sandbox }

// IdentityManager returns the underlying IdentityManager for domain/identity
// management operations (CreateDomainIdentity, GetDomainVerificationStatus, etc.).
func (s *Sender) IdentityManager() *IdentityManager { return s.identity }

// Suppression returns the active SuppressionList (for manual additions/removals).
func (s *Sender) Suppression() SuppressionList { return s.suppression }

// Send implements deliver.Sender.
func (s *Sender) Send(ctx context.Context, msg deliver.Message) (deliver.Receipt, error) {
	allowed, suppressed, err := s.filterSuppressed(msg.To)
	if err != nil {
		return deliver.Receipt{}, err
	}

	rec := deliver.Receipt{
		Backend: "ses",
		SentAt:  time.Now(),
	}
	for _, a := range suppressed {
		rec.Recipients = append(rec.Recipients, deliver.RecipientStatus{
			Email:  a,
			Status: deliver.StateSuppressed,
		})
	}

	if len(allowed) == 0 {
		return rec, deliver.ErrSuppressed
	}

	// Respect the SES send-rate limit.
	if err := s.rateLimiter.Wait(ctx); err != nil {
		return deliver.Receipt{}, fmt.Errorf("ses: rate limiter: %w", err)
	}

	toAddrs := make([]string, len(allowed))
	for i, a := range allowed {
		toAddrs[i] = a.Email
	}

	input := &sesv2.SendEmailInput{
		FromEmailAddress: aws.String(msg.From.String()),
		Destination: &types.Destination{
			ToAddresses: toAddrs,
		},
		Content: &types.EmailContent{
			Raw: &types.RawMessage{
				Data: msg.MIMEBody,
			},
		},
	}

	// Apply configuration set (message-level override, then backend default).
	if msg.ConfigurationSet != "" {
		input.ConfigurationSetName = aws.String(msg.ConfigurationSet)
	} else if s.cfg.ConfigurationSet != "" {
		input.ConfigurationSetName = aws.String(s.cfg.ConfigurationSet)
	}

	out, err := s.client.SendEmail(ctx, input)
	if err != nil {
		return deliver.Receipt{}, fmt.Errorf("ses: SendEmail: %w", err)
	}

	if out.MessageId != nil {
		rec.MessageID = *out.MessageId
	}
	for _, a := range allowed {
		rec.Recipients = append(rec.Recipients, deliver.RecipientStatus{
			Email:  a.Email,
			Status: deliver.StateSent,
		})
	}

	return rec, nil
}

// SendBatch implements deliver.Sender. Each message is sent independently;
// a failure on one does not abort subsequent ones.
func (s *Sender) SendBatch(ctx context.Context, msgs []deliver.Message) ([]deliver.Receipt, error) {
	receipts := make([]deliver.Receipt, len(msgs))
	var firstErr error
	for i, msg := range msgs {
		rec, err := s.Send(ctx, msg)
		receipts[i] = rec
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return receipts, firstErr
}

// Close implements deliver.Sender. The SES client is stateless; this is a no-op.
func (s *Sender) Close() error { return nil }

// filterSuppressed partitions addresses into allowed and suppressed.
func (s *Sender) filterSuppressed(addrs []deliver.Address) (allowed []deliver.Address, suppressedEmails []string, err error) {
	for _, a := range addrs {
		ok, _, e := s.suppression.IsSuppressed(a.Email)
		if e != nil {
			return nil, nil, e
		}
		if ok {
			suppressedEmails = append(suppressedEmails, a.Email)
		} else {
			allowed = append(allowed, a)
		}
	}
	return allowed, suppressedEmails, nil
}
