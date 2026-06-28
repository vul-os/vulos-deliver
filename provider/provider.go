// Package provider is the config-driven entry point for vulos-deliver.
//
// It constructs a deliver.Sender from a Config struct that selects the backend
// ("ses" or "smtp") and carries its settings. Import this package (and only
// this package) when you want automatic backend selection; import the backend
// packages directly if you need backend-specific operations such as
// ses.Sender.IdentityManager().
//
// vulos-deliver never imports vulos-cloud. Cloud infrastructure details
// (credentials, config, secrets) are injected by the caller.
package provider

import (
	"fmt"

	deliver "github.com/vul-os/vulos-deliver"
	"github.com/vul-os/vulos-deliver/backend/ses"
	"github.com/vul-os/vulos-deliver/backend/smtp"
)

// Config selects and configures the active Sender backend.
type Config struct {
	// Backend selects the implementation. Supported values: "ses", "smtp".
	// Defaults to "ses" if empty.
	Backend string `json:"backend" yaml:"backend"`

	// SES holds SES-specific configuration. Ignored when Backend != "ses".
	SES ses.Config `json:"ses,omitempty" yaml:"ses,omitempty"`

	// SMTP holds SMTP-relay configuration. Ignored when Backend != "smtp".
	SMTP smtp.Config `json:"smtp,omitempty" yaml:"smtp,omitempty"`
}

// New constructs a deliver.Sender from cfg.
//
// The returned Sender is ready to use. Call Close() when done to release
// backend resources. Backend-specific operations (e.g. SES domain management)
// require a direct reference to the concrete backend type; in that case,
// construct the backend directly via ses.New / smtp.New.
func New(cfg Config) (deliver.Sender, error) {
	backend := cfg.Backend
	if backend == "" {
		backend = "ses"
	}

	switch backend {
	case "ses":
		return ses.New(cfg.SES)
	case "smtp":
		return smtp.New(cfg.SMTP)
	default:
		return nil, fmt.Errorf("provider: unknown backend %q (supported: ses, smtp)", backend)
	}
}
