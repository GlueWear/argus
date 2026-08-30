package main

// Gateway configuration.
//
// The warden's location is deployment-specific and is therefore REQUIRED
// configuration, never a compiled-in default. An earlier version hard-coded
// one operator's production host, which meant anyone building from source
// silently pointed their gateway at somebody else's warden.
//
// Exactly one value is needed: the warden's base URL. The /command and
// /readyz endpoints are derived from it, so the URL and the TLS ServerName
// can never disagree.

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// EnvWardenBase overrides the config file. Useful for tests and for
// operators who prefer environment configuration.
const EnvWardenBase = "ARGUS_WARDEN_BASE"

// ConfigName is read from $GW_DIR.
const ConfigName = "warden.conf"

type gatewayConfig struct {
	// Base is the validated warden base URL with no trailing slash,
	// e.g. https://calls.example.com/warden/v1
	Base string
	// Host is Base's hostname, used as the TLS ServerName.
	Host string
	// CommandURL and ReadyzURL are derived; a caller can never supply one.
	CommandURL string
	ReadyzURL  string
}

// loadGatewayConfig resolves configuration from the environment first, then
// from $GW_DIR/warden.conf. Absent configuration is a fatal error, not a
// fallback: a gateway that does not know where its warden is must not start
// and guess.
func loadGatewayConfig(dir string) (*gatewayConfig, error) {
	raw := strings.TrimSpace(os.Getenv(EnvWardenBase))
	src := EnvWardenBase
	if raw == "" {
		p := filepath.Join(dir, ConfigName)
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("no warden configuration: set %s or create %s: %w",
				EnvWardenBase, p, err)
		}
		raw = parseKV(string(b), "warden_base")
		src = p
		if raw == "" {
			return nil, fmt.Errorf("%s: warden_base is missing or empty", p)
		}
	}
	cfg, err := buildConfig(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", src, err)
	}
	return cfg, nil
}

// parseKV reads a trivial "key = value" file. '#' begins a comment.
func parseKV(body, want string) string {
	for _, line := range strings.Split(body, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(k) == want {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// buildConfig validates a base URL and derives everything else from it.
//
// https is required. The gateway exists precisely because the Urbit runtime
// does not verify TLS; allowing a plain-http warden here would give that
// weakness back.
func buildConfig(raw string) (*gatewayConfig, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if raw == "" {
		return nil, fmt.Errorf("warden_base is empty")
	}
	if len(raw) > 512 {
		return nil, fmt.Errorf("warden_base is unreasonably long")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("warden_base is not a URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("warden_base must be https, got %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("warden_base has no host")
	}
	if u.User != nil {
		return nil, fmt.Errorf("warden_base must not embed credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("warden_base must not carry a query or fragment")
	}
	return &gatewayConfig{
		Base:       raw,
		Host:       u.Hostname(),
		CommandURL: raw + "/command",
		ReadyzURL:  raw + "/readyz",
	}, nil
}
