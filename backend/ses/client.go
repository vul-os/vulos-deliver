package ses

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/sesv2"
)

// SESEmailClient is the subset of the AWS SES v2 API used by this backend.
//
// The real implementation is a *sesv2.Client (returned by sesv2.NewFromConfig).
// Tests inject a stub that implements this interface without making any real
// AWS API calls — keeping the test suite fully hermetic.
type SESEmailClient interface {
	SendEmail(ctx context.Context, in *sesv2.SendEmailInput, opts ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error)
	CreateEmailIdentity(ctx context.Context, in *sesv2.CreateEmailIdentityInput, opts ...func(*sesv2.Options)) (*sesv2.CreateEmailIdentityOutput, error)
	GetEmailIdentity(ctx context.Context, in *sesv2.GetEmailIdentityInput, opts ...func(*sesv2.Options)) (*sesv2.GetEmailIdentityOutput, error)
	ListEmailIdentities(ctx context.Context, in *sesv2.ListEmailIdentitiesInput, opts ...func(*sesv2.Options)) (*sesv2.ListEmailIdentitiesOutput, error)
	DeleteEmailIdentity(ctx context.Context, in *sesv2.DeleteEmailIdentityInput, opts ...func(*sesv2.Options)) (*sesv2.DeleteEmailIdentityOutput, error)
	GetAccount(ctx context.Context, in *sesv2.GetAccountInput, opts ...func(*sesv2.Options)) (*sesv2.GetAccountOutput, error)
}
