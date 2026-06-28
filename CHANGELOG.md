# Changelog

All notable changes to `vulos-deliver` are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [0.1.0] — 2026-06-28

Initial release. Deliverability/sender engine extracted as a shared library,
designed to be consumed by vulos-mail (smarthost) and the future vulos-send product.

### Added

- **`deliver.Sender` interface** — the central seam: `Send(ctx, Message) (Receipt, error)`,
  `SendBatch`, `Close`. All backends implement this interface; callers are decoupled
  from the underlying infrastructure.

- **`deliver.Message`** — outbound message type carrying TenantID, From, To, CC,
  BCC, Subject, MIME body, extra headers, and an optional SES configuration set name.

- **`deliver.Receipt` / `RecipientStatus`** — send result with per-recipient outcomes
  (`sent`, `suppressed`, `failed`) and backend-assigned message ID.

- **`backend/ses` — AWS SES v2 backend** (`ses.Sender`):
  - Sends via `sesv2.SendEmailInput` with raw MIME body.
  - **Multi-tenant domain identity management** (`IdentityManager`):
    - `CreateDomainIdentity` — provisions an SES domain identity with Easy DKIM
      (AWS-managed RSA 2048 CNAME records) and returns all DNS records the tenant
      must publish (DKIM CNAMEs, SPF, DMARC, custom MAIL FROM).
    - `GetDomainVerificationStatus` — polls DKIM verification status.
    - `DeleteDomainIdentity` — offboards a tenant domain.
  - **10,000-identity cap handling**: cached `ListEmailIdentities` count, configurable
    warning threshold (default 9,000), hard error at cap, `IdentityUsage` struct with
    `Headroom` and `NearCap`/`AtCap` flags for metrics.
  - **Multi-region design**: `Config.Regions []RegionConfig` for scale-out beyond
    the per-region cap.
  - **Sandbox detection**: `DetectSandbox(ctx)` calls `GetAccount`, sets
    `IsSandbox()`, logs the send quota.
  - **Token-bucket rate limiter** (`TokenBucket`): configurable sends/second
    (default 14, matching the SES production starting quota).
  - **Suppression list** (`SuppressionList` interface + `MemorySuppressionList`):
    blocked addresses are filtered before `SendEmail` is called.
  - **SNS bounce/complaint webhook** (`BounceWebhookHandler`): HTTP handler that
    decodes SNS notifications, adds permanently bounced / complained-about addresses
    to the suppression list, and ignores transient bounces.
  - `SESEmailClient` interface for hermetic testing (inject mock; no real AWS calls).
  - `Config.Client SESEmailClient` injection point.

- **`backend/smtp` — generic SMTP relay backend** (`smtp.Sender`):
  - Sends via `net/smtp` with STARTTLS and PLAIN AUTH.
  - Configurable host, port (default 587), credentials, envelope From override.
  - Stateless (connection per Send); no persistent state.
  - The SES→own-IP switch: change `provider.Config.Backend` to `"smtp"`.

- **`domain` package — backend-agnostic DNS/DKIM management**:
  - `GenerateDKIMKeyPair(selector)` — RSA 2048 key generation; returns private key
    PEM + base64 public key for the DNS TXT record.
  - `ParsePrivateKeyPEM` — PKCS#1 PEM parse for loading stored keys.
  - `GenerateSMTPDomainSetup(domain, keypair, spfMechanism)` — produces DKIM TXT,
    SPF, and DMARC records for own-IP senders.
  - `FormatOnboardingInstructions` — human-readable record listing for tenant UIs.

- **`provider` package — config-driven factory**:
  - `provider.Config{Backend, SES, SMTP}` — selects and configures the backend.
  - `provider.New(Config) (deliver.Sender, error)` — factory; defaults to `"ses"`.

- **Hermetic test suite** — 43 tests across 4 packages with zero real AWS calls:
  - SES: mock `SESEmailClient`, Sender contract, suppression, partial suppression,
    batch, configuration set propagation, sandbox detection.
  - Identity: cap enforcement, near-cap warning, cache hit/miss, cache invalidation
    on create/delete, verification status.
  - Rate limiter: immediate grant, rate enforcement, context cancellation, cap.
  - Suppression: add/check/remove, case-insensitivity, idempotent add, count.
  - Bounce webhook: permanent bounce suppression, transient bounce pass-through,
    complaint suppression, subscription confirmation, method enforcement, bad JSON.
  - SMTP: config validation, no-recipients error, batch, close.
  - Domain: key generation, PEM round-trip, record format, uniqueness.
  - Provider: factory routing, unknown backend, SMTP no-host error.

- **Documentation**: `docs/ARCHITECTURE.md` (package map, data flow, testing strategy),
  `docs/SES.md` (limits, cap handling, custom-domain flow, SES→SMTP migration).
