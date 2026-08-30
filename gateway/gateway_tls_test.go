package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// P5-5: config audit. These properties are asserted, not eyeballed.
func TestStrictClientConfig(t *testing.T) {
	// remoteHost is configured at startup, so give it a value here or the
	// ServerName assertion below would compare two empty strings and pass
	// without proving anything.
	prev := remoteHost
	remoteHost = "warden.test"
	defer func() { remoteHost = prev }()

	c := strictClient()
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatal("transport is not *http.Transport")
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify is TRUE - unacceptable")
	}
	if tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("MinVersion below TLS 1.2: %x", tr.TLSClientConfig.MinVersion)
	}
	if tr.TLSClientConfig.ServerName != remoteHost {
		t.Fatalf("ServerName not pinned to the configured warden host %q: %q",
			remoteHost, tr.TLSClientConfig.ServerName)
	}
	if tr.TLSClientConfig.RootCAs != nil {
		t.Fatal("RootCAs overridden; system trust roots expected")
	}
	if tr.TLSClientConfig.VerifyPeerCertificate != nil || tr.TLSClientConfig.VerifyConnection != nil {
		t.Fatal("custom verification hook present")
	}
	if tr.Proxy != nil {
		t.Fatal("Proxy is set; environment proxy inheritance must be disabled")
	}
	if c.CheckRedirect == nil {
		t.Fatal("CheckRedirect nil; redirects would be followed")
	}
	if err := c.CheckRedirect(nil, nil); err == nil {
		t.Fatal("CheckRedirect does not refuse")
	}
}

// P5-3: a self-signed / unknown-CA server must be rejected.
// ServerName is set to the test host so the failure is CA trust, not hostname.
func TestSelfSignedRejected(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c := strictClient()
	tr := c.Transport.(*http.Transport)
	tr.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: "127.0.0.1", // isolate CA trust as the failing property
	}
	_, err := c.Get(srv.URL)
	if err == nil {
		t.Fatal("self-signed certificate was ACCEPTED")
	}
	t.Logf("self-signed rejected: %v", err)
}

// P5-4: a redirect must be refused, so no credential follows it.
func TestRedirectRejected(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If the client ever lands here it has followed a redirect.
		if r.Header.Get("Authorization") != "" {
			t.Error("credential was forwarded to a redirect target")
		}
		w.WriteHeader(200)
	}))
	defer target.Close()

	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redir.Close()

	c := strictClient()
	c.Transport = &http.Transport{Proxy: nil} // plain HTTP; redirect is the property under test
	_, err := c.Get(redir.URL)
	if err == nil {
		t.Fatal("redirect was FOLLOWED")
	}
	if !strings.Contains(err.Error(), "redirects are disabled") {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Logf("redirect refused: %v", err)
}

// P5-2: hostname verification. HERMETIC. The test server's certificate is
// trusted explicitly, so CA trust cannot be the reason this fails -- the only
// property under test is that a name outside the certificate's SANs is
// refused. Previously this reached a production host by IP, which meant the
// default test run contacted live infrastructure and could not pass for
// anyone else.
func TestHostnameMismatchRejected(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request reached the server despite a hostname mismatch")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	c := strictClient()
	tr := c.Transport.(*http.Transport)
	tr.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool, // CA trust is satisfied on purpose
		// httptest's certificate carries example.com AND *.example.com, so a
		// single-label subdomain would MATCH the wildcard. This name is
		// outside both.
		ServerName: "mismatch.invalid",
	}
	_, err := c.Get(srv.URL)
	if err == nil {
		t.Fatal("hostname mismatch was ACCEPTED")
	}
	if !strings.Contains(err.Error(), "certificate is valid for") &&
		!strings.Contains(err.Error(), "x509") {
		t.Fatalf("failed for the wrong reason: %v", err)
	}
	t.Logf("hostname mismatch rejected: %v", err)
}

// The same certificate under its CORRECT name must succeed, otherwise the
// test above would pass even if the client rejected everything.
func TestMatchingHostnameAccepted(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	defer srv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	c := strictClient()
	tr := c.Transport.(*http.Transport)
	tr.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
		ServerName: "example.com", // httptest's certificate carries this SAN
	}
	res, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("valid certificate under its own name was rejected: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 204 {
		t.Fatalf("status %d", res.StatusCode)
	}
}

// OPT-IN live probe against a real deployment. Never runs by default, so a
// plain `go test ./...` contacts nothing.
//
//	ARGUS_LIVE_PROBE=1 ARGUS_LIVE_HOST=203.0.113.10 go test -run LiveProbe ./...
//
// The host is deliberately supplied by the operator: no deployment address is
// compiled into this repository.
func TestLiveProbeHostnameMismatch(t *testing.T) {
	if os.Getenv("ARGUS_LIVE_PROBE") != "1" {
		t.Skip("live probe disabled; set ARGUS_LIVE_PROBE=1 and ARGUS_LIVE_HOST")
	}
	host := os.Getenv("ARGUS_LIVE_HOST")
	if host == "" {
		t.Skip("ARGUS_LIVE_HOST not set")
	}
	c := strictClient()
	tr := c.Transport.(*http.Transport)
	tr.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: host, // an IP literal is deliberately not a DNS SAN
	}
	_, err := c.Get("https://" + host + "/")
	if err == nil {
		t.Fatal("hostname mismatch was ACCEPTED against the live host")
	}
	t.Logf("live hostname mismatch rejected: %v", err)
}
