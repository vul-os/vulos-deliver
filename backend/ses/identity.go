package ses

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

const (
	// MaxIdentitiesPerRegion is the hard SES limit on email identities per region.
	// At this limit, CreateEmailIdentity calls will be rejected by AWS.
	// See: https://docs.aws.amazon.com/ses/latest/dg/quotas.html
	MaxIdentitiesPerRegion = 10_000

	// DefaultWarnThreshold is the identity count at which IdentityManager
	// logs a warning and surfaces NearCap=true in IdentityUsage.
	DefaultWarnThreshold = 9_000

	// identityCacheTTL is how long the cached identity count is trusted before
	// a fresh ListEmailIdentities call is made.
	identityCacheTTL = 5 * time.Minute
)

// IdentityUsage describes identity quota usage for a single SES region.
type IdentityUsage struct {
	Region   string
	Count    int
	Max      int
	Headroom int
	NearCap  bool // true when Count >= WarnThreshold
	AtCap    bool // true when Count >= Max
}

// DomainSetupResult carries all DNS records the customer must publish for a
// custom sending domain to work with SES.
type DomainSetupResult struct {
	Domain string
	Region string

	// DKIMCNAMEs are the 3 AWS-managed CNAME records for DKIM verification.
	// Each must be published as: <Name> CNAME <Value>
	DKIMCNAMEs []DNSRecord

	// SPFRecord is the TXT record for SPF at the domain apex.
	SPFRecord DNSRecord

	// DMARCRecord is the DMARC policy TXT record at _dmarc.<domain>.
	DMARCRecord DNSRecord

	// CustomMAILFROMRecords enables a custom MAIL FROM subdomain (mail.<domain>)
	// for cleaner bounce attribution. Contains an MX record and an SPF TXT record.
	CustomMAILFROMRecords []DNSRecord

	// VerificationStatus is the SES DKIM verification status at time of creation.
	// It is typically "PENDING" immediately after CreateDomainIdentity; poll
	// GetDomainVerificationStatus until it becomes "SUCCESS" (usually < 72 h).
	VerificationStatus string
}

// DNSRecord is a single DNS record the customer must publish.
type DNSRecord struct {
	Type  string // "TXT", "CNAME", "MX"
	Name  string // fully-qualified DNS name
	Value string // record value / data
	TTL   int    // seconds
}

// IdentityManager manages SES domain identities within the 10,000/region cap.
//
// Multi-region design: when the primary region approaches capacity, add a
// second region to Config.Regions. Route tenants to regions by consistent
// hash or round-robin; each IdentityManager instance tracks one region.
type IdentityManager struct {
	client        SESEmailClient
	region        string
	warnThreshold int

	// identity count cache
	mu          sync.Mutex
	cachedCount int
	cacheExpiry time.Time

	logger *slog.Logger
}

// NewIdentityManager returns an IdentityManager for the given SES region.
// warnThreshold defaults to DefaultWarnThreshold when <= 0.
func NewIdentityManager(client SESEmailClient, region string, warnThreshold int, logger *slog.Logger) *IdentityManager {
	if warnThreshold <= 0 {
		warnThreshold = DefaultWarnThreshold
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &IdentityManager{
		client:        client,
		region:        region,
		warnThreshold: warnThreshold,
		logger:        logger,
	}
}

// Usage returns the current identity quota usage for this region.
// The count is cached for identityCacheTTL to avoid constant API calls.
func (m *IdentityManager) Usage(ctx context.Context) (IdentityUsage, error) {
	count, err := m.identityCount(ctx)
	if err != nil {
		return IdentityUsage{}, err
	}
	return IdentityUsage{
		Region:   m.region,
		Count:    count,
		Max:      MaxIdentitiesPerRegion,
		Headroom: MaxIdentitiesPerRegion - count,
		NearCap:  count >= m.warnThreshold,
		AtCap:    count >= MaxIdentitiesPerRegion,
	}, nil
}

// identityCount returns a (possibly cached) identity count.
func (m *IdentityManager) identityCount(ctx context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if time.Now().Before(m.cacheExpiry) {
		return m.cachedCount, nil
	}

	count, err := m.fetchIdentityCount(ctx)
	if err != nil {
		return 0, err
	}
	m.cachedCount = count
	m.cacheExpiry = time.Now().Add(identityCacheTTL)
	return count, nil
}

// fetchIdentityCount pages through ListEmailIdentities and sums all entries.
func (m *IdentityManager) fetchIdentityCount(ctx context.Context) (int, error) {
	count := 0
	var nextToken *string
	for {
		out, err := m.client.ListEmailIdentities(ctx, &sesv2.ListEmailIdentitiesInput{
			NextToken: nextToken,
		})
		if err != nil {
			return 0, fmt.Errorf("ses/identity: list identities: %w", err)
		}
		count += len(out.EmailIdentities)
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	return count, nil
}

// invalidateCache expires the cached count so the next call re-fetches.
func (m *IdentityManager) invalidateCache() {
	m.mu.Lock()
	m.cacheExpiry = time.Time{}
	m.mu.Unlock()
}

// CreateDomainIdentity registers a custom domain with SES and returns the DNS
// records the customer must publish.
//
// It enforces the 10,000 identity cap: if the region is at or near capacity,
// it returns an error with guidance to add a second region to Config.Regions.
//
// The DKIM CNAME records returned are AWS-managed (Easy DKIM). After the
// customer publishes them, poll GetDomainVerificationStatus until it returns
// "SUCCESS" before sending from the domain.
func (m *IdentityManager) CreateDomainIdentity(ctx context.Context, domain string) (DomainSetupResult, error) {
	usage, err := m.Usage(ctx)
	if err != nil {
		return DomainSetupResult{}, err
	}

	if usage.AtCap {
		return DomainSetupResult{}, fmt.Errorf(
			"ses/identity: region %s is at the %d-identity cap (%d/%d); "+
				"add a second SES region to Config.Regions to accommodate more tenants",
			m.region, MaxIdentitiesPerRegion, usage.Count, MaxIdentitiesPerRegion,
		)
	}

	if usage.NearCap {
		m.logger.Warn("SES identity count approaching regional cap — plan to add a second region",
			"region", m.region,
			"count", usage.Count,
			"cap", MaxIdentitiesPerRegion,
			"headroom", usage.Headroom,
		)
	}

	out, err := m.client.CreateEmailIdentity(ctx, &sesv2.CreateEmailIdentityInput{
		EmailIdentity: aws.String(domain),
		DkimSigningAttributes: &types.DkimSigningAttributes{
			NextSigningKeyLength: types.DkimSigningKeyLengthRsa2048Bit,
		},
	})
	if err != nil {
		return DomainSetupResult{}, fmt.Errorf("ses/identity: create %q: %w", domain, err)
	}

	m.invalidateCache()

	result := DomainSetupResult{
		Domain: domain,
		Region: m.region,
	}

	// Build DKIM CNAME records from SES-supplied tokens.
	// SES returns 3 tokens; each becomes a CNAME:
	//   <token>._domainkey.<domain> CNAME <token>.dkim.amazonses.com
	if out.DkimAttributes != nil {
		for _, token := range out.DkimAttributes.Tokens {
			result.DKIMCNAMEs = append(result.DKIMCNAMEs, DNSRecord{
				Type:  "CNAME",
				Name:  fmt.Sprintf("%s._domainkey.%s", token, domain),
				Value: fmt.Sprintf("%s.dkim.amazonses.com", token),
				TTL:   300,
			})
		}
		result.VerificationStatus = string(out.DkimAttributes.Status)
	}

	// SPF at domain apex — authorises SES to send on behalf of the domain.
	result.SPFRecord = DNSRecord{
		Type:  "TXT",
		Name:  domain,
		Value: `"v=spf1 include:amazonses.com ~all"`,
		TTL:   300,
	}

	// DMARC — quarantine policy with aggregate reporting.
	result.DMARCRecord = DNSRecord{
		Type:  "TXT",
		Name:  fmt.Sprintf("_dmarc.%s", domain),
		Value: fmt.Sprintf(`"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@%s; adkim=s; aspf=s"`, domain),
		TTL:   300,
	}

	// Custom MAIL FROM subdomain — mail.<domain> — so that bounces are
	// attributable to this domain rather than amazonses.com. Optional but
	// recommended for DMARC alignment.
	mailFromDomain := fmt.Sprintf("mail.%s", domain)
	result.CustomMAILFROMRecords = []DNSRecord{
		{
			Type:  "MX",
			Name:  mailFromDomain,
			Value: fmt.Sprintf("10 feedback-smtp.%s.amazonses.com", m.region),
			TTL:   300,
		},
		{
			Type:  "TXT",
			Name:  mailFromDomain,
			Value: `"v=spf1 include:amazonses.com ~all"`,
			TTL:   300,
		},
	}

	return result, nil
}

// GetDomainVerificationStatus returns the DKIM verification status for a domain.
// Expected values: "PENDING", "SUCCESS", "FAILED", "TEMPORARY_FAILURE", "NOT_STARTED".
func (m *IdentityManager) GetDomainVerificationStatus(ctx context.Context, domain string) (string, error) {
	out, err := m.client.GetEmailIdentity(ctx, &sesv2.GetEmailIdentityInput{
		EmailIdentity: aws.String(domain),
	})
	if err != nil {
		return "", fmt.Errorf("ses/identity: get %q: %w", domain, err)
	}
	if out.DkimAttributes != nil {
		return string(out.DkimAttributes.Status), nil
	}
	return "UNKNOWN", nil
}

// DeleteDomainIdentity removes a domain identity from SES (e.g. when a tenant
// is offboarded). It invalidates the cached count.
func (m *IdentityManager) DeleteDomainIdentity(ctx context.Context, domain string) error {
	_, err := m.client.DeleteEmailIdentity(ctx, &sesv2.DeleteEmailIdentityInput{
		EmailIdentity: aws.String(domain),
	})
	if err != nil {
		return fmt.Errorf("ses/identity: delete %q: %w", domain, err)
	}
	m.invalidateCache()
	return nil
}
