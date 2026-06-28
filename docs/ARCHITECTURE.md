# Architecture — vulos-deliver

## Overview

`vulos-deliver` is the deliverability/sender engine shared by **vulos-mail** (as the smarthost backend) and the future **vulos-send** product. It is fully open-source, has zero dependency on `vulos-cloud`, and is designed to be cloud-neutral: the active backend is a config switch, not a code change.

## Package Map

```
github.com/vul-os/vulos-deliver         (package deliver)
  deliver.go      — Message, Receipt, Address, Sender interface, error sentinels

github.com/vul-os/vulos-deliver/backend/ses   (package ses)
  ses.go          — Sender implementation over AWS SES v2
  client.go       — SESEmailClient interface (mockable seam for tests)
  identity.go     — Multi-tenant domain identity management + 10 k-cap logic
  ratelimit.go    — Token-bucket send-rate limiter
  suppression.go  — SuppressionList interface + MemorySuppressionList
  bounce.go       — SNS bounce/complaint webhook → suppression feed

github.com/vul-os/vulos-deliver/backend/smtp  (package smtp)
  smtp.go         — Sender implementation over a generic SMTP relay

github.com/vul-os/vulos-deliver/domain        (package domain)
  domain.go       — Backend-agnostic DNS record generation + DKIM key gen

github.com/vul-os/vulos-deliver/provider      (package provider)
  provider.go     — Config-driven Sender factory (selects SES or SMTP)
```

## The Sender Seam

The `deliver.Sender` interface is the central seam:

```go
type Sender interface {
    Send(ctx context.Context, msg Message) (Receipt, error)
    SendBatch(ctx context.Context, msgs []Message) ([]Receipt, error)
    Close() error
}
```

All callers program against this interface. Backend selection is entirely internal to the `provider` package. vulos-mail holds a `deliver.Sender` and calls `Send`; it never knows whether SES or SMTP is underneath.

## Data Flow

```
vulos-mail / vulos-send
        │
        │  deliver.Message{TenantID, From, To, MIMEBody, …}
        ▼
  provider.New(Config{Backend: "ses", SES: …})
        │
        ▼
  ses.Sender.Send(ctx, msg)
        │
        ├─── SuppressionList.IsSuppressed(to) ──► skip suppressed addresses
        │
        ├─── TokenBucket.Wait(ctx) ──────────────► respect SES send rate
        │
        └─── SESEmailClient.SendEmail(ctx, …) ──► AWS SES v2 API
                                                      │
                                        SES publishes bounce/complaint events
                                                      │
                                                      ▼
                                        BounceWebhookHandler (HTTP)
                                                      │
                                        SuppressionList.Add(email, reason)
```

## Multi-Tenant Custom Domains

Each customer domain becomes a separate SES identity (up to 10,000 per region). The `IdentityManager` owns:

1. **Provisioning**: `CreateDomainIdentity(domain)` calls `CreateEmailIdentity` with Easy DKIM (AWS-managed RSA 2048 CNAME records) and returns all DNS records the customer must publish.
2. **Cap management**: Tracks identity count with a 5-minute cache. Returns an error at cap; logs a warning above the configurable threshold (default 9,000). Designed for a second region to be added to `Config.Regions`.
3. **Verification polling**: `GetDomainVerificationStatus(domain)` wraps `GetEmailIdentity` — call this until the status is `"SUCCESS"`.

## SES → Own-IP Migration Path

Switching from SES to a self-hosted Postfix/Haraka stack on Hetzner (or any SMTP relay) is a single config change:

```yaml
backend: smtp           # was: ses
smtp:
  host: mail.vulos.example
  port: 587
  username: postmaster@vulos.example
  password: secret
```

The `deliver.Sender` contract is identical. The `domain` package generates the equivalent DKIM/SPF/DMARC records for the own-IP case.

## Suppression List

The suppression list protects sender reputation by preventing re-delivery to addresses that have permanently bounced or filed a spam complaint. The `SuppressionList` interface has a default in-memory implementation. For production multi-instance deployments, replace it with a Postgres- or Redis-backed implementation passed via `Config.SES.Suppression`.

## Rate Limiting

The `TokenBucket` in `backend/ses` implements a classic token-bucket algorithm. It starts with `SendRate` tokens (default 14, matching the conservative SES production starting quota) and refills at that rate per second. Call `DetectSandbox(ctx)` at startup to read the actual account quota from the `GetAccount` API and log it.

## Testing Strategy

All tests are hermetic — no real AWS calls:

- `backend/ses`: `SESEmailClient` interface is injected via `Config.Client`; tests pass a `mockSESClient` stub.
- `backend/smtp`: Tests validate configuration validation and the interface contract; actual SMTP dials are not exercised (they require a live server).
- `domain`: Exercises the RSA key generator, DNS record formatting, and PEM round-trip with `crypto/rand`.
- `provider`: Exercises factory routing; SES constructor accepts a region without credentials (errors defer to call-time).

## No Cloud Dependency

`vulos-deliver` imports zero packages from `vulos-cloud`. The caller (vulos-mail's smarthost package, vulos-send) injects credentials and config. This keeps the library free of billing, auth, and tenant-management concerns.
