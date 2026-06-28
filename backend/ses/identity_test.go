package ses

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

func newTestIdentityManager(client SESEmailClient) *IdentityManager {
	return NewIdentityManager(client, "us-east-1", DefaultWarnThreshold, nil)
}

func TestIdentityUsage_Empty(t *testing.T) {
	mc := &mockSESClient{} // default: 0 identities
	mgr := newTestIdentityManager(mc)

	usage, err := mgr.Usage(context.Background())
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	if usage.Count != 0 {
		t.Errorf("Count = %d, want 0", usage.Count)
	}
	if usage.Max != MaxIdentitiesPerRegion {
		t.Errorf("Max = %d, want %d", usage.Max, MaxIdentitiesPerRegion)
	}
	if usage.NearCap {
		t.Error("NearCap should be false with 0 identities")
	}
	if usage.AtCap {
		t.Error("AtCap should be false with 0 identities")
	}
}

func TestIdentityUsage_NearCap(t *testing.T) {
	// Return 9100 identities (above the 9000 warn threshold).
	mc := &mockSESClient{
		ListEmailIdentitiesFn: func(_ context.Context, _ *sesv2.ListEmailIdentitiesInput, _ ...func(*sesv2.Options)) (*sesv2.ListEmailIdentitiesOutput, error) {
			ids := make([]types.IdentityInfo, 9100)
			for i := range ids {
				ids[i] = types.IdentityInfo{IdentityName: strPtr("domain.com")}
			}
			return &sesv2.ListEmailIdentitiesOutput{EmailIdentities: ids}, nil
		},
	}
	mgr := newTestIdentityManager(mc)

	usage, err := mgr.Usage(context.Background())
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	if !usage.NearCap {
		t.Error("NearCap should be true at 9100 identities")
	}
	if usage.AtCap {
		t.Error("AtCap should be false at 9100 identities")
	}
	if usage.Headroom != MaxIdentitiesPerRegion-9100 {
		t.Errorf("Headroom = %d, want %d", usage.Headroom, MaxIdentitiesPerRegion-9100)
	}
}

func TestIdentityUsage_AtCap(t *testing.T) {
	mc := &mockSESClient{
		ListEmailIdentitiesFn: func(_ context.Context, _ *sesv2.ListEmailIdentitiesInput, _ ...func(*sesv2.Options)) (*sesv2.ListEmailIdentitiesOutput, error) {
			ids := make([]types.IdentityInfo, MaxIdentitiesPerRegion)
			return &sesv2.ListEmailIdentitiesOutput{EmailIdentities: ids}, nil
		},
	}
	mgr := newTestIdentityManager(mc)

	usage, err := mgr.Usage(context.Background())
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	if !usage.AtCap {
		t.Error("AtCap should be true at max identities")
	}
}

func TestCreateDomainIdentity_OK(t *testing.T) {
	mc := &mockSESClient{} // default CreateEmailIdentity returns 3 tokens
	mgr := newTestIdentityManager(mc)

	result, err := mgr.CreateDomainIdentity(context.Background(), "acme.com")
	if err != nil {
		t.Fatalf("CreateDomainIdentity: %v", err)
	}

	if result.Domain != "acme.com" {
		t.Errorf("Domain = %q, want acme.com", result.Domain)
	}
	if len(result.DKIMCNAMEs) != 3 {
		t.Errorf("DKIMCNAMEs count = %d, want 3", len(result.DKIMCNAMEs))
	}

	// Verify CNAME format
	for _, rec := range result.DKIMCNAMEs {
		if rec.Type != "CNAME" {
			t.Errorf("DKIM record type = %q, want CNAME", rec.Type)
		}
	}

	if result.SPFRecord.Type != "TXT" {
		t.Errorf("SPF record type = %q, want TXT", result.SPFRecord.Type)
	}
	if result.DMARCRecord.Type != "TXT" {
		t.Errorf("DMARC record type = %q, want TXT", result.DMARCRecord.Type)
	}
	if len(result.CustomMAILFROMRecords) != 2 {
		t.Errorf("CustomMAILFROMRecords count = %d, want 2", len(result.CustomMAILFROMRecords))
	}
}

func TestCreateDomainIdentity_AtCap(t *testing.T) {
	mc := &mockSESClient{
		ListEmailIdentitiesFn: func(_ context.Context, _ *sesv2.ListEmailIdentitiesInput, _ ...func(*sesv2.Options)) (*sesv2.ListEmailIdentitiesOutput, error) {
			ids := make([]types.IdentityInfo, MaxIdentitiesPerRegion)
			return &sesv2.ListEmailIdentitiesOutput{EmailIdentities: ids}, nil
		},
	}
	mgr := newTestIdentityManager(mc)

	_, err := mgr.CreateDomainIdentity(context.Background(), "blocked.com")
	if err == nil {
		t.Fatal("expected error at identity cap, got nil")
	}
}

func TestCreateDomainIdentity_SESError(t *testing.T) {
	mc := &mockSESClient{
		CreateEmailIdentityFn: func(_ context.Context, _ *sesv2.CreateEmailIdentityInput, _ ...func(*sesv2.Options)) (*sesv2.CreateEmailIdentityOutput, error) {
			return nil, errors.New("already exists")
		},
	}
	mgr := newTestIdentityManager(mc)

	_, err := mgr.CreateDomainIdentity(context.Background(), "exists.com")
	if err == nil {
		t.Fatal("expected error from SES, got nil")
	}
}

func TestGetDomainVerificationStatus(t *testing.T) {
	mc := &mockSESClient{} // default: DkimStatus=SUCCESS
	mgr := newTestIdentityManager(mc)

	status, err := mgr.GetDomainVerificationStatus(context.Background(), "acme.com")
	if err != nil {
		t.Fatalf("GetDomainVerificationStatus: %v", err)
	}
	if status != "SUCCESS" {
		t.Errorf("status = %q, want SUCCESS", status)
	}
}

func TestDeleteDomainIdentity(t *testing.T) {
	deleted := ""
	mc := &mockSESClient{
		DeleteEmailIdentityFn: func(_ context.Context, in *sesv2.DeleteEmailIdentityInput, _ ...func(*sesv2.Options)) (*sesv2.DeleteEmailIdentityOutput, error) {
			deleted = *in.EmailIdentity
			return &sesv2.DeleteEmailIdentityOutput{}, nil
		},
	}
	mgr := newTestIdentityManager(mc)

	if err := mgr.DeleteDomainIdentity(context.Background(), "bye.com"); err != nil {
		t.Fatalf("DeleteDomainIdentity: %v", err)
	}
	if deleted != "bye.com" {
		t.Errorf("deleted domain = %q, want bye.com", deleted)
	}
}

func TestIdentityCountCaching(t *testing.T) {
	calls := 0
	mc := &mockSESClient{
		ListEmailIdentitiesFn: func(_ context.Context, _ *sesv2.ListEmailIdentitiesInput, _ ...func(*sesv2.Options)) (*sesv2.ListEmailIdentitiesOutput, error) {
			calls++
			return &sesv2.ListEmailIdentitiesOutput{
				EmailIdentities: []types.IdentityInfo{{IdentityName: strPtr("a.com")}},
			}, nil
		},
	}
	mgr := newTestIdentityManager(mc)

	// Two calls to Usage should result in only one API call (second is cached).
	_, _ = mgr.Usage(context.Background())
	_, _ = mgr.Usage(context.Background())

	if calls != 1 {
		t.Errorf("ListEmailIdentities called %d times, want 1 (should be cached)", calls)
	}
}

func TestIdentityCacheInvalidatedOnCreate(t *testing.T) {
	calls := 0
	mc := &mockSESClient{
		ListEmailIdentitiesFn: func(_ context.Context, _ *sesv2.ListEmailIdentitiesInput, _ ...func(*sesv2.Options)) (*sesv2.ListEmailIdentitiesOutput, error) {
			calls++
			return &sesv2.ListEmailIdentitiesOutput{}, nil
		},
	}
	mgr := newTestIdentityManager(mc)

	_, _ = mgr.Usage(context.Background())
	// CreateDomainIdentity should invalidate cache
	_, _ = mgr.CreateDomainIdentity(context.Background(), "new.com")
	_, _ = mgr.Usage(context.Background())

	if calls < 2 {
		t.Errorf("ListEmailIdentities should be called at least twice after create, got %d", calls)
	}
}

func strPtr(s string) *string { return &s }
