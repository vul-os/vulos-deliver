package ses

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

// mockSESClient is a configurable stub implementing SESEmailClient.
// All methods default to a successful no-op; override individual Fn fields
// in each test to inject specific behaviour or errors.
type mockSESClient struct {
	SendEmailFn           func(ctx context.Context, in *sesv2.SendEmailInput, opts ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error)
	CreateEmailIdentityFn func(ctx context.Context, in *sesv2.CreateEmailIdentityInput, opts ...func(*sesv2.Options)) (*sesv2.CreateEmailIdentityOutput, error)
	GetEmailIdentityFn    func(ctx context.Context, in *sesv2.GetEmailIdentityInput, opts ...func(*sesv2.Options)) (*sesv2.GetEmailIdentityOutput, error)
	PutMailFromFn         func(ctx context.Context, in *sesv2.PutEmailIdentityMailFromAttributesInput, opts ...func(*sesv2.Options)) (*sesv2.PutEmailIdentityMailFromAttributesOutput, error)
	ListEmailIdentitiesFn func(ctx context.Context, in *sesv2.ListEmailIdentitiesInput, opts ...func(*sesv2.Options)) (*sesv2.ListEmailIdentitiesOutput, error)
	DeleteEmailIdentityFn func(ctx context.Context, in *sesv2.DeleteEmailIdentityInput, opts ...func(*sesv2.Options)) (*sesv2.DeleteEmailIdentityOutput, error)
	GetAccountFn          func(ctx context.Context, in *sesv2.GetAccountInput, opts ...func(*sesv2.Options)) (*sesv2.GetAccountOutput, error)
}

func (m *mockSESClient) SendEmail(ctx context.Context, in *sesv2.SendEmailInput, opts ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error) {
	if m.SendEmailFn != nil {
		return m.SendEmailFn(ctx, in, opts...)
	}
	return &sesv2.SendEmailOutput{MessageId: aws.String("mock-msg-id")}, nil
}

func (m *mockSESClient) CreateEmailIdentity(ctx context.Context, in *sesv2.CreateEmailIdentityInput, opts ...func(*sesv2.Options)) (*sesv2.CreateEmailIdentityOutput, error) {
	if m.CreateEmailIdentityFn != nil {
		return m.CreateEmailIdentityFn(ctx, in, opts...)
	}
	return &sesv2.CreateEmailIdentityOutput{
		DkimAttributes: &types.DkimAttributes{
			Status:         types.DkimStatusPending,
			SigningEnabled: true,
			Tokens:         []string{"tok1abc", "tok2def", "tok3ghi"},
		},
		VerifiedForSendingStatus: false,
	}, nil
}

func (m *mockSESClient) GetEmailIdentity(ctx context.Context, in *sesv2.GetEmailIdentityInput, opts ...func(*sesv2.Options)) (*sesv2.GetEmailIdentityOutput, error) {
	if m.GetEmailIdentityFn != nil {
		return m.GetEmailIdentityFn(ctx, in, opts...)
	}
	return &sesv2.GetEmailIdentityOutput{
		DkimAttributes: &types.DkimAttributes{
			Status: types.DkimStatusSuccess,
		},
	}, nil
}

func (m *mockSESClient) PutEmailIdentityMailFromAttributes(ctx context.Context, in *sesv2.PutEmailIdentityMailFromAttributesInput, opts ...func(*sesv2.Options)) (*sesv2.PutEmailIdentityMailFromAttributesOutput, error) {
	if m.PutMailFromFn != nil {
		return m.PutMailFromFn(ctx, in, opts...)
	}
	return &sesv2.PutEmailIdentityMailFromAttributesOutput{}, nil
}

func (m *mockSESClient) ListEmailIdentities(ctx context.Context, in *sesv2.ListEmailIdentitiesInput, opts ...func(*sesv2.Options)) (*sesv2.ListEmailIdentitiesOutput, error) {
	if m.ListEmailIdentitiesFn != nil {
		return m.ListEmailIdentitiesFn(ctx, in, opts...)
	}
	return &sesv2.ListEmailIdentitiesOutput{
		EmailIdentities: []types.IdentityInfo{},
	}, nil
}

func (m *mockSESClient) DeleteEmailIdentity(ctx context.Context, in *sesv2.DeleteEmailIdentityInput, opts ...func(*sesv2.Options)) (*sesv2.DeleteEmailIdentityOutput, error) {
	if m.DeleteEmailIdentityFn != nil {
		return m.DeleteEmailIdentityFn(ctx, in, opts...)
	}
	return &sesv2.DeleteEmailIdentityOutput{}, nil
}

func (m *mockSESClient) GetAccount(ctx context.Context, in *sesv2.GetAccountInput, opts ...func(*sesv2.Options)) (*sesv2.GetAccountOutput, error) {
	if m.GetAccountFn != nil {
		return m.GetAccountFn(ctx, in, opts...)
	}
	return &sesv2.GetAccountOutput{
		ProductionAccessEnabled: true,
		SendingEnabled:          true,
		SendQuota: &types.SendQuota{
			Max24HourSend:   50000,
			MaxSendRate:     14,
			SentLast24Hours: 0,
		},
	}, nil
}
