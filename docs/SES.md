# SES Backend — Limits, Custom Domains, and Migration

This document covers the AWS SES–specific details of `vulos-deliver`. It is
essential reading for anyone operating the SES backend in a multi-tenant
deployment.

---

## Service Limits

| Limit | Value | Notes |
|---|---|---|
| Email identities per region | **10,000** | Hard limit — cannot be raised |
| Starting send rate (production) | ~14 sends/sec | Raiseable via console / support |
| Daily send quota (production) | 50,000+ | Raiseable |
| Daily send quota (sandbox) | **200** | To verified addresses only |
| Regions per account | Many | No limit on multi-region use |

### The 10,000-Identity Cap

SES allows at most **10,000 email identities (domains + addresses) per region**.
In a multi-tenant deployment where each customer's domain becomes an SES identity,
this means a single SES region supports up to 10,000 custom sending domains.

`vulos-deliver` handles this transparently:

1. **Usage tracking**: `IdentityManager.Usage(ctx)` pages through
   `ListEmailIdentities` and returns `IdentityUsage{Count, Max, Headroom, NearCap, AtCap}`.
   The count is cached for 5 minutes.

2. **Warning at threshold**: When `Count >= WarnThreshold` (default 9,000),
   `CreateDomainIdentity` logs a structured warning. Override with
   `Config.WarnThreshold`.

3. **Hard cap**: When `Count >= 10,000`, `CreateDomainIdentity` returns an error
   rather than letting the AWS call fail silently.

4. **Multi-region scale-out**: Add a second region to `Config.Regions`:

   ```go
   ses.Config{
       Regions: []ses.RegionConfig{
           {Region: "us-east-1", AccessKeyID: "…", SecretAccessKey: "…"},
           {Region: "eu-west-1", AccessKeyID: "…", SecretAccessKey: "…"},
       },
   }
   ```

   Route tenants to regions by consistent hash, round-robin, or headroom — the
   `IdentityManager` tracks each region independently. A second AWS account is
   another option for complete isolation.

---

## Sandbox vs. Production Mode

New SES accounts start in **sandbox mode**:
- Only verified sender addresses and recipient addresses can be used.
- Daily sending limit: 200 messages.
- Sandbox status: `GetAccount.ProductionAccessEnabled == false`.

Call `sender.DetectSandbox(ctx)` at startup. It:
1. Calls `GetAccount` to read sandbox status and send quota.
2. Logs a `WARN` with instructions when sandbox mode is detected.
3. Sets `sender.IsSandbox()`.

To request production access, visit the SES console → Account dashboard →
"Request production access". Typical review time: 24–48 hours.

---

## Custom-Domain / DKIM Management Flow

Each customer domain goes through the following lifecycle:

```
1. Tenant onboards with custom domain "acme.com"
                    │
                    ▼
2. Call IdentityManager.CreateDomainIdentity(ctx, "acme.com")
   ├─ Checks identity count < 10,000
   ├─ Calls SES CreateEmailIdentity (Easy DKIM, RSA 2048)
   └─ Returns DomainSetupResult with DNS records
                    │
                    ▼
3. Show DNS records to customer
   ├─ 3 × CNAME  <token>._domainkey.acme.com → <token>.dkim.amazonses.com
   ├─ 1 × TXT    acme.com → "v=spf1 include:amazonses.com ~all"
   ├─ 1 × TXT    _dmarc.acme.com → "v=DMARC1; p=quarantine; …"
   ├─ 1 × MX     mail.acme.com → 10 feedback-smtp.<region>.amazonses.com
   └─ 1 × TXT    mail.acme.com → "v=spf1 include:amazonses.com ~all"
                    │
                    ▼
4. Poll IdentityManager.GetDomainVerificationStatus(ctx, "acme.com")
   until status == "SUCCESS" (typically < 72 hours)
                    │
                    ▼
5. Mark domain as verified in your tenant database — now safe to send from it
```

### DNS Records Explained

| Record | Purpose |
|---|---|
| `<tok>._domainkey.acme.com CNAME` | Easy DKIM — SES rotates keys automatically |
| `acme.com TXT v=spf1 …` | SPF — authorises SES to send on behalf of domain |
| `_dmarc.acme.com TXT v=DMARC1 …` | DMARC — policy + aggregate reporting |
| `mail.acme.com MX 10 feedback-smtp…` | Custom MAIL FROM — bounce attribution |
| `mail.acme.com TXT v=spf1 …` | SPF for the custom MAIL FROM subdomain |

### Custom MAIL FROM

Using `mail.<domain>` as the custom MAIL FROM subdomain improves DMARC alignment
(`aspf=s` requires the MAIL FROM domain to match the From header domain). Without
it, SES uses `amazonses.com` in the MAIL FROM, causing DMARC `aspf=r` (relaxed)
alignment only.

---

## Bounce and Complaint Handling

SES publishes bounce and complaint events via SNS. Mount `BounceWebhookHandler`
on an HTTP endpoint and register it as the SNS subscription:

```go
h := ses.NewBounceWebhookHandler(sender.Suppression(), logger, true)
http.Handle("/webhooks/ses/bounce", h)
```

Wire in your SES console:
1. SES → Configuration sets → your set → Event destinations → Add destination
2. Type: SNS; Events: Bounces, Complaints
3. SNS topic ARN → create a new topic subscribed to your endpoint URL

### What the handler does

| SNS message type | Action |
|---|---|
| `SubscriptionConfirmation` | GETs `SubscribeURL` to auto-confirm (when `confirmSubscriptions=true`) |
| `Notification` / bounce type `Permanent` | Adds all bounced addresses to the suppression list |
| `Notification` / bounce type `Transient` | Logged only — no suppression (queue retries these) |
| `Notification` / Complaint | Adds all complained-about addresses to the suppression list |

Suppressed addresses are filtered **before** `SendEmail` is called — they never
reach SES and therefore never count toward bounce/complaint rates.

### Production hardening

The handler does **not** verify the SNS message signature (to avoid coupling the
library to a specific HTTP middleware). In production:
1. Verify signatures using `github.com/aws/aws-sdk-go-v2` SNS message validation
   or the AWS-provided SNS message validator Go package.
2. Restrict the endpoint to SNS IP ranges via your edge/WAF.
3. Back the `SuppressionList` with a persistent store (Postgres, Redis) so
   suppressions survive restarts and are shared across instances.

---

## SES → Own-IP Migration

When the SES cost/complexity trade-off shifts, or for regulatory reasons, switch
to a self-hosted Postfix/Haraka stack by changing one config field:

```go
// Before:
provider.Config{
    Backend: "ses",
    SES: ses.Config{Region: "us-east-1", AccessKeyID: "…", SecretAccessKey: "…"},
}

// After:
provider.Config{
    Backend: "smtp",
    SMTP: smtp.Config{
        Host:     "mail.yourdomain.com",  // your Postfix/Haraka MTA
        Port:     587,
        Username: "postmaster@yourdomain.com",
        Password: "secret",
    },
}
```

No application code changes. DNS changes required:
1. Generate DKIM key pairs with `domain.GenerateDKIMKeyPair("selector")`.
2. Store the private key in your secrets manager; configure your MTA to sign with it.
3. Replace the SES CNAME records with a TXT record:
   `<selector>._domainkey.<domain> TXT "v=DKIM1; k=rsa; p=<pubkey>"`
4. Update SPF: replace `include:amazonses.com` with your MTA's IP(s).
5. DMARC record stays the same.

The `domain.GenerateSMTPDomainSetup` helper produces all required records.
