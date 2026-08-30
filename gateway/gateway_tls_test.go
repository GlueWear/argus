package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// P5-5: config audit. These properties are asserted, not eyeballed.
func TestStrictClientConfig(t *testing.T) {
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
		t.Fatalf("ServerName not pinned to %s: %q", remoteHost, tr.TLSClientConfig.ServerName)
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

// P5-2: hostname mismatch. Connecting to the numeric IP must fail because
// the certificate carries only DNS SANs. No bearer is sent.
func TestHostnameMismatchRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	c := strictClient()
	tr := c.Transport.(*http.Transport)
	tr.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: "129.212.197.135", // deliberately not a SAN
	}
	_, err := c.Get("https://129.212.197.135/warden-poc/identity-proof")
	if err == nil {
		t.Fatal("hostname mismatch was ACCEPTED")
	}
	t.Logf("hostname mismatch rejected: %v", err)
}
