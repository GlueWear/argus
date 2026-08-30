package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildConfigDerivesEndpoints(t *testing.T) {
	cfg, err := buildConfig("https://calls.example.com/warden/v1")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "calls.example.com" {
		t.Fatalf("host %q", cfg.Host)
	}
	if cfg.CommandURL != "https://calls.example.com/warden/v1/command" {
		t.Fatalf("command %q", cfg.CommandURL)
	}
	if cfg.ReadyzURL != "https://calls.example.com/warden/v1/readyz" {
		t.Fatalf("readyz %q", cfg.ReadyzURL)
	}
}

func TestBuildConfigNormalisesTrailingSlash(t *testing.T) {
	a, err := buildConfig("https://calls.example.com/warden/v1/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := buildConfig("https://calls.example.com/warden/v1")
	if a.CommandURL != b.CommandURL {
		t.Fatalf("trailing slash changed the endpoint: %q vs %q", a.CommandURL, b.CommandURL)
	}
}

// Every rejection here is a property the gateway depends on. http would give
// back the very TLS weakness the gateway exists to remove; embedded
// credentials would put a secret in a config value that gets logged as a
// host; a query or fragment means the operator meant something we do not
// implement.
func TestBuildConfigRejects(t *testing.T) {
	for _, tc := range []struct{ name, in string }{
		{"empty", ""},
		{"plain http", "http://calls.example.com/warden/v1"},
		{"no scheme", "calls.example.com/warden/v1"},
		{"no host", "https:///warden/v1"},
		{"embedded credentials", "https://user:pass@calls.example.com/warden/v1"},
		{"query", "https://calls.example.com/warden/v1?x=1"},
		{"fragment", "https://calls.example.com/warden/v1#f"},
		{"absurdly long", "https://calls.example.com/" + string(make([]byte, 600))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := buildConfig(tc.in); err == nil {
				t.Fatalf("accepted %q", tc.in)
			}
		})
	}
}

func TestLoadGatewayConfigRequiresConfiguration(t *testing.T) {
	t.Setenv(EnvWardenBase, "")
	dir := t.TempDir()
	if _, err := loadGatewayConfig(dir); err == nil {
		t.Fatal("started with no warden configuration at all")
	}
}

func TestLoadGatewayConfigFromFile(t *testing.T) {
	t.Setenv(EnvWardenBase, "")
	dir := t.TempDir()
	body := "# argus gateway\nwarden_base = https://calls.example.com/warden/v1   # trailing comment\n"
	if err := os.WriteFile(filepath.Join(dir, ConfigName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadGatewayConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "calls.example.com" {
		t.Fatalf("host %q", cfg.Host)
	}
}

func TestEnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ConfigName),
		[]byte("warden_base = https://from-file.example.com/w\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvWardenBase, "https://from-env.example.com/w")
	cfg, err := loadGatewayConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "from-env.example.com" {
		t.Fatalf("environment did not take precedence: %q", cfg.Host)
	}
}

// No production hostname may be reachable without configuration.
func TestNoCompiledInDefault(t *testing.T) {
	t.Setenv(EnvWardenBase, "")
	if _, err := loadGatewayConfig(t.TempDir()); err == nil {
		t.Fatal("a default warden endpoint exists somewhere")
	}
}
