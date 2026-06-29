<div align="center">

<img src="docs/assets/vulos-logo.png" alt="Vulos" width="80" height="80" />

# vulos-deliver

### A research project in self-hosted mail deliverability

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Language: Go](https://img.shields.io/badge/language-Go-00ADD8.svg)
[![Status: research](https://img.shields.io/badge/status-research-orange.svg)](#status)
[![Go Reference](https://pkg.go.dev/badge/github.com/vul-os/vulos-deliver.svg)](https://pkg.go.dev/github.com/vul-os/vulos-deliver)

<sub>Part of <strong><a href="https://vulos.org">VulOS</a></strong> — the open, self-hostable web OS &amp; app suite.</sub>

</div>

---

## Status

> **vulos-deliver is a research project — not production-recommended yet.**
>
> Running your own mail delivery is genuinely hard. IP warming, sender reputation,
> feedback loops, blocklist monitoring and per-provider throttling are a constantly
> moving target that takes real, ongoing operational investment to get right.
> vulos-deliver is our long-term bet on *owning* that stack — but it is not
> battle-tested at scale.
>
> **For now, we recommend Amazon SES** (or another managed relay) for real sending.
> Conveniently, that's exactly what vulos-deliver gives you today: its **SES backend**
> is a clean, multi-tenant wrapper (custom domains, DKIM, identity-cap handling,
> rate limiting, suppression) behind a swappable `Sender` interface.
>
> **Vulos itself runs on SES today** — we do *not* yet use the own-IP delivery path
> in production. The plan is to migrate to fully self-hosted delivery as the engine
> matures and our volume justifies owning the IP reputation. Until then, treat the
> own-IP SMTP backend as **experimental**, and use the SES backend for anything real.
>
> Follow along, kick the tyres, and contribute — sovereign mail delivery is a
> problem worth solving, just not one to rush.

---

## What is vulos-deliver?

`vulos-deliver` is the shared deliverability/sender engine used by **vulos-mail** (as its smarthost backend) and the future **vulos-send** product. It provides:

- A clean `Sender` interface that decouples application code from the underlying mail infrastructure
- An **AWS SES v2 backend** with production-grade multi-tenant features (custom-domain management, identity cap handling, rate limiting, bounce/complaint suppression)
- A **generic SMTP relay backend** for sending via own-IPs (Postfix, Haraka, Mailgun, etc.)
- A **backend-agnostic DNS/DKIM module** for tenant onboarding
- A config-driven factory — switching from SES to own-IP is a single YAML change

`vulos-deliver` is **fully open-source** and has **zero dependency on vulos-cloud**. Credentials, config, and secrets are injected by the caller.

---

## Part of VulOS

[VulOS](https://vulos.org) is an open, self-hostable web OS + app suite. `vulos-deliver` is a shared infrastructure library:

| Product | Role of vulos-deliver |
|---|---|
| **vulos-mail** | Smarthost backend — outbound mail delivery |
| **vulos-send** | Core engine — the transactional/bulk send product |

---

## Quick Start

```go
import (
    "context"

    deliver "github.com/vul-os/vulos-deliver"
    "github.com/vul-os/vulos-deliver/provider"
    "github.com/vul-os/vulos-deliver/backend/ses"
)

// Create a Sender (SES backend).
// SecretAccessKey is excluded from JSON/YAML serialisation; always set it
// programmatically from an env var or secrets manager to prevent leakage.
sender, err := provider.New(provider.Config{
    Backend: "ses",
    SES: ses.Config{
        Region:          "us-east-1",
        AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
        SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"), // not marshalled to JSON/YAML
        SendRate:        14, // sends/second (raise after SES quota increase)
    },
})
if err != nil {
    log.Fatal(err)
}
defer sender.Close()

// Detect sandbox mode at startup
if s, ok := sender.(*ses.Sender); ok {
    _ = s.DetectSandbox(context.Background())
}

// Send a message.
// MIMEBody must be fully pre-composed and include all headers (Subject,
// Content-Type, From, To, Date, Message-ID, …). The Subject field on
// deliver.Message is metadata only and is NOT injected by any backend.
rec, err := sender.Send(context.Background(), deliver.Message{
    TenantID: "tenant-acme",
    From:     deliver.Address{Name: "Acme Notifications", Email: "noreply@acme.com"},
    To:       []deliver.Address{{Email: "user@example.com"}},
    MIMEBody: mimeBody, // must contain Subject: header and all other headers
})
```

---

## Custom Domain Onboarding (SES)

```go
import "github.com/vul-os/vulos-deliver/backend/ses"

sesSender, _ := ses.New(ses.Config{Region: "us-east-1", /* … */})

// Register a tenant's custom domain
result, err := sesSender.IdentityManager().CreateDomainIdentity(ctx, "acme.com")

// result.DKIMCNAMEs — 3 CNAME records to publish
// result.SPFRecord  — TXT at domain apex
// result.DMARCRecord — TXT at _dmarc.acme.com
// result.CustomMAILFROMRecords — MX + TXT at mail.acme.com

// Poll until verified (typically < 72 h)
status, _ := sesSender.IdentityManager().GetDomainVerificationStatus(ctx, "acme.com")
// status: "PENDING" → "SUCCESS"
```

---

## Bounce / Complaint Webhook

```go
import "github.com/vul-os/vulos-deliver/backend/ses"

h := ses.NewBounceWebhookHandler(sesSender.Suppression(), logger, true)
http.Handle("/webhooks/ses/bounce", h)
```

Register the endpoint URL as an SNS subscription on your SES configuration set.
Permanently bounced and complained-about addresses are automatically added to the
suppression list and skipped on future sends.

---

## Switching to Own-IP (SMTP)

```go
provider.New(provider.Config{
    Backend: "smtp",
    SMTP: smtp.Config{
        Host:     "mail.yourdomain.com",
        Port:     587,
        Username: "postmaster@yourdomain.com",
        Password: "secret",
    },
})
```

No application code changes. See [docs/SES.md](docs/SES.md) for DNS migration steps.

---

## Package Overview

| Package | Purpose |
|---|---|
| `github.com/vul-os/vulos-deliver` | `Message`, `Receipt`, `Sender` interface |
| `.../backend/ses` | SES backend (identity mgmt, rate limiter, suppression, bounce webhook) |
| `.../backend/smtp` | Generic SMTP relay backend |
| `.../domain` | DNS record generation + DKIM key pair management |
| `.../provider` | Config-driven `Sender` factory |

---

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — package map, data flow, design decisions
- [docs/SES.md](docs/SES.md) — SES limits, 10,000-identity cap, custom-domain flow, SES→SMTP migration

---

## Development

```sh
go test ./...        # all tests (hermetic — no real AWS)
go build ./...       # all packages
gofmt -l .           # should print nothing
```

Tests cover: Sender contract, SES identity/cap logic (mock SES client), token-bucket rate limiter, suppression list, bounce/complaint webhook handler, DNS record generation, and the config-driven factory.

---

## License

MIT — see [LICENSE](LICENSE).

*Vulos — rooted in **vula**, the Zulu and Xhosa word for **open**.*
