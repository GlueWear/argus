// noltbook-call-gateway-poc: loopback-only bridge for W0.1.
//
// Why this exists: Vere/Iris was shown not to enforce TLS hostname
// verification, so a Gall agent must never carry a reusable remote
// credential to an external HTTPS URL. This process is the only thing
// that holds the remote bearer, and it is reachable only from 127.0.0.1.
//
// PROOF OF CONCEPT. Not the production warden.
package main

import (
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	listenAddr = "127.0.0.1:8899"
	maxBody    = 4096
	maxResp    = 8192
)

// Destination is fixed at STARTUP from configuration and is never taken from
// a request. A caller can still never supply a URL; the difference is only
// that the operator, rather than this source file, decides which warden.
var (
	remoteURL      string
	remoteHost     string
	remoteReadyURL string
)

var shipRe = regexp.MustCompile(`^~[a-z-]{3,60}$`)

type req struct {
	Req         string `json:"req"`
	Op          string `json:"op"`
	Room        string `json:"room"`
	Participant string `json:"participant,omitempty"`
	TTL         int    `json:"ttl,omitempty"` // lease seconds; warden clamps
	Subject     string `json:"subject"`
}

var (
	localKey    []byte
	remoteToken string

	mu        sync.Mutex
	nForward  int // requests actually forwarded to the droplet
	nAccepted int // local requests accepted from argus
)

// strictClient: system roots, explicit hostname, TLS 1.2 floor, no
// redirects, no environment proxy. There is no InsecureSkipVerify.
func strictClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: nil, // do NOT inherit HTTP(S)_PROXY
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				// pinned to the configured warden host, so a DNS or
				// routing surprise cannot be silently accepted
				ServerName: remoteHost,
			},
			TLSHandshakeTimeout:   8 * time.Second,
			ResponseHeaderTimeout: 8 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects are disabled")
		},
	}
}

func readSecret(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", fmt.Errorf("empty secret file %s", p)
	}
	return s, nil
}

func say(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		say(w, http.StatusMethodNotAllowed, map[string]any{"error": "method"})
		return
	}
	mu.Lock()
	defer mu.Unlock()
	say(w, http.StatusOK, map[string]any{
		"accepted": nAccepted, "forwarded": nForward,
	})
}

func handleProof(w http.ResponseWriter, r *http.Request) {
	// POST only. OPTIONS and everything else are refused, and no CORS
	// headers are ever emitted.
	if r.Method != http.MethodPost {
		log.Printf("outcome=reject-method")
		say(w, http.StatusMethodNotAllowed, map[string]any{"error": "method-not-allowed"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Argus-Key")), localKey) != 1 {
		log.Printf("outcome=reject-local-key")
		say(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	if ct := strings.Split(r.Header.Get("Content-Type"), ";")[0]; strings.TrimSpace(ct) != "application/json" {
		log.Printf("outcome=reject-ctype")
		say(w, http.StatusUnsupportedMediaType, map[string]any{"error": "unsupported-media-type"})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		log.Printf("outcome=reject-size")
		say(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "body-too-large"})
		return
	}
	var in req
	if err := json.Unmarshal(body, &in); err != nil {
		log.Printf("outcome=reject-json")
		say(w, http.StatusBadRequest, map[string]any{"error": "malformed-json"})
		return
	}
	if in.Op == "" || in.Req == "" || in.Room == "" || !shipRe.MatchString(in.Subject) {
		log.Printf("outcome=reject-shape")
		say(w, http.StatusBadRequest, map[string]any{"error": "bad-request"})
		return
	}

	mu.Lock()
	nAccepted++
	mu.Unlock()

	// Build the outbound request ourselves. No header from the caller is
	// forwarded, and the destination is the compiled-in constant.
	// Rebuilt from validated fields only. The subject is the ship argus
	// derived from src.bowl; no caller header or extra field is forwarded.
	out, _ := json.Marshal(req{Req: in.Req, Op: in.Op, Room: in.Room,
		Participant: in.Participant, TTL: in.TTL, Subject: in.Subject})
	hreq, err := http.NewRequest(http.MethodPost, remoteURL, bytes.NewReader(out))
	if err != nil {
		say(w, http.StatusInternalServerError, map[string]any{"error": "build-failed"})
		return
	}
	hreq.Header.Set("Authorization", "Bearer "+remoteToken)
	hreq.Header.Set("Content-Type", "application/json")

	mu.Lock()
	nForward++
	mu.Unlock()

	hres, err := strictClient().Do(hreq)
	if err != nil {
		// Never include the error verbatim in the client-visible body if it
		// could echo credentials; it cannot here, but keep it terse anyway.
		log.Printf("outcome=upstream-error subject=%s req=%s detail=%v", in.Subject, in.Req, err)
		say(w, http.StatusBadGateway, map[string]any{"error": "upstream-unreachable"})
		return
	}
	defer hres.Body.Close()

	rb, err := io.ReadAll(io.LimitReader(hres.Body, maxResp+1))
	if err != nil || len(rb) > maxResp {
		log.Printf("outcome=upstream-oversize subject=%s req=%s", in.Subject, in.Req)
		say(w, http.StatusBadGateway, map[string]any{"error": "upstream-oversize"})
		return
	}
	if hres.StatusCode != http.StatusOK {
		log.Printf("outcome=upstream-status subject=%s req=%s status=%d", in.Subject, in.Req, hres.StatusCode)
		say(w, http.StatusBadGateway, map[string]any{"error": "upstream-status"})
		return
	}
	// Validate the ENVELOPE, then forward the warden's own bytes VERBATIM.
	//
	// This used to unmarshal into a local struct and re-serialise it, which
	// silently dropped every field this file did not know about. That is
	// how the entire call-access response (sfu, ice, turn credentials) went
	// missing, and how `clients:0` vanished to omitempty. The gateway has no
	// business knowing the response schema: its job is authentication,
	// strict TLS, and proving the answer belongs to the request it sent.
	var env struct {
		OK        bool   `json:"ok"`
		Req       string `json:"req"`
		Subject   string `json:"subject"`
		Duplicate bool   `json:"duplicate"`
	}
	if err := json.Unmarshal(rb, &env); err != nil {
		log.Printf("outcome=upstream-malformed subject=%s req=%s", in.Subject, in.Req)
		say(w, http.StatusBadGateway, map[string]any{"error": "upstream-malformed"})
		return
	}
	// The answer must be about the request we actually sent.
	if env.Req != in.Req || env.Subject != in.Subject {
		log.Printf("outcome=upstream-mismatch subject=%s req=%s", in.Subject, in.Req)
		say(w, http.StatusBadGateway, map[string]any{"error": "upstream-mismatch"})
		return
	}
	log.Printf("outcome=ok subject=%s req=%s op=%s ok=%v duplicate=%v",
		in.Subject, in.Req, in.Op, env.OK, env.Duplicate)
	// rb may carry a join token and TURN credentials. It is written to the
	// loopback client and NEVER logged.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(rb)
}

// handleReady reports the whole chain and distinguishes every stage, so a
// failure names the hop that failed instead of collapsing to a bare false.
// It is authenticated: readiness detail describes internal state.
func handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		say(w, http.StatusMethodNotAllowed, map[string]any{"error": "method-not-allowed"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Argus-Key")), localKey) != 1 {
		log.Printf("outcome=reject-local-key path=readyz")
		say(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	out := map[string]any{
		"configured":            len(localKey) > 0 && remoteToken != "",
		"gateway_authenticated": true,
		"warden_reachable":      false,
		"warden_authenticated":  false,
		"warden_db_ready":       false,
		"galene_reachable":      false,
		"ok":                    false,
	}

	hreq, err := http.NewRequest(http.MethodGet, remoteReadyURL, nil)
	if err != nil {
		out["stage"] = "build"
		say(w, http.StatusServiceUnavailable, out)
		return
	}
	hreq.Header.Set("Authorization", "Bearer "+remoteToken)

	hres, err := strictClient().Do(hreq)
	if err != nil {
		out["stage"] = "transport"
		log.Printf("outcome=readyz-upstream-error detail=%v", err)
		say(w, http.StatusServiceUnavailable, out)
		return
	}
	defer hres.Body.Close()
	out["warden_reachable"] = true

	if hres.StatusCode == http.StatusUnauthorized {
		out["stage"] = "warden-auth"
		say(w, http.StatusServiceUnavailable, out)
		return
	}
	// 200 and 503 are the warden's OWN answers. Anything else came from the
	// reverse proxy or an error page, so the warden was not actually
	// reached and we must not claim it authenticated us.
	if hres.StatusCode != http.StatusOK && hres.StatusCode != http.StatusServiceUnavailable {
		out["warden_reachable"] = false
		out["stage"] = "upstream-status"
		log.Printf("outcome=readyz-upstream-status status=%d", hres.StatusCode)
		say(w, http.StatusServiceUnavailable, out)
		return
	}
	out["warden_authenticated"] = true

	rb, err := io.ReadAll(io.LimitReader(hres.Body, maxResp+1))
	if err != nil || len(rb) > maxResp {
		out["stage"] = "upstream-oversize"
		say(w, http.StatusServiceUnavailable, out)
		return
	}
	var up struct {
		OK       bool  `json:"ok"`
		DBReady  bool  `json:"db_ready"`
		Galene   bool  `json:"galene_reachable"`
		ProbeAge int64 `json:"db_probe_age_sec"`
	}
	if json.Unmarshal(rb, &up) != nil {
		out["stage"] = "upstream-malformed"
		say(w, http.StatusServiceUnavailable, out)
		return
	}
	out["warden_db_ready"] = up.DBReady
	out["galene_reachable"] = up.Galene
	out["warden_db_probe_age_sec"] = up.ProbeAge
	out["ok"] = up.OK && up.DBReady && up.Galene
	code := http.StatusOK
	if out["ok"] != true {
		code = http.StatusServiceUnavailable
		out["stage"] = "warden-not-ready"
	}
	say(w, code, out)
}

func main() {
	dir := os.Getenv("GW_DIR")
	if dir == "" {
		exe, _ := os.Executable()
		dir = filepath.Dir(exe)
	}
	cfg, err := loadGatewayConfig(dir)
	if err != nil {
		log.Fatalf("configuration: %v", err)
	}
	remoteURL, remoteHost, remoteReadyURL = cfg.CommandURL, cfg.Host, cfg.ReadyzURL
	log.Printf("warden endpoint configured host=%s", remoteHost)

	lk, err := readSecret(filepath.Join(dir, "secrets", "local.key"))
	if err != nil {
		log.Fatalf("local key: %v", err)
	}
	localKey = []byte(lk)
	remoteToken, err = readSecret(filepath.Join(dir, "secrets", "remote.bearer"))
	if err != nil {
		log.Fatalf("remote bearer: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/command", handleProof)
	mux.HandleFunc("/stats", handleStats)
	// /healthz claims ONLY that this process is up, because that is all it
	// checks. The previous version returned {"ok":true} unconditionally,
	// which asserted a healthy chain it had never contacted.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		say(w, http.StatusOK, map[string]any{"ok": true, "scope": "process-liveness-only"})
	})
	mux.HandleFunc("/readyz", handleReady)

	ln, err := net.Listen("tcp", listenAddr) // loopback only, never 0.0.0.0
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	log.Printf("gateway listening on %s (loopback only)", listenAddr)
	log.Fatal(srv.Serve(ln))
}
