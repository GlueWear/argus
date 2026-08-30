package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtures = "../protocol/v1/fixtures"

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtures, name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return b
}

// withUpstream stands a fake warden in front of the gateway handler and
// returns the gateway's own response plus everything it logged.
func withUpstream(t *testing.T, status int, body []byte, cmd []byte) (*httptest.ResponseRecorder, string) {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	defer up.Close()

	prevURL, prevTok := remoteURL, remoteToken
	remoteURL, remoteToken = up.URL, "test-bearer-value"
	defer func() { remoteURL, remoteToken = prevURL, prevTok }()

	prevKey := localKey
	localKey = []byte("test-local-key")
	defer func() { localKey = prevKey }()

	var logs bytes.Buffer
	prevOut := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(prevOut)

	req := httptest.NewRequest(http.MethodPost, "/command", bytes.NewReader(cmd))
	req.Header.Set("X-Argus-Key", "test-local-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleProof(rec, req)
	return rec, logs.String()
}

// THE regression this contract exists for. The gateway must forward the
// warden's bytes untouched. It once unmarshalled into a local struct and
// re-serialised, which silently deleted every field that struct did not
// know -- the whole access grant -- and dropped clients:0 to omitempty.
func TestGatewayPreservesEveryAccessField(t *testing.T) {
	body := fixture(t, "result-issue-access.json")
	cmd := fixture(t, "command-issue-access.json")
	rec, _ := withUpstream(t, 200, body, cmd)

	if rec.Code != 200 {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
	var want, got map[string]any
	if err := json.Unmarshal(body, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("gateway emitted unparseable JSON: %v", err)
	}
	for k, v := range want {
		g, ok := got[k]
		if !ok {
			t.Errorf("field %q was DROPPED by the gateway", k)
			continue
		}
		wj, _ := json.Marshal(v)
		gj, _ := json.Marshal(g)
		if !bytes.Equal(wj, gj) {
			t.Errorf("field %q was reinterpreted: want %s got %s", k, wj, gj)
		}
	}
	if len(got) != len(want) {
		t.Errorf("field count changed: want %d got %d", len(want), len(got))
	}
}

// clients:0 must arrive as 0, not vanish.
func TestGatewayPreservesZeroClients(t *testing.T) {
	body := fixture(t, "result-room-status-zero-clients.json")
	rec, _ := withUpstream(t, 200, body, fixture(t, "command-room-status.json"))
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	v, ok := got["clients"]
	if !ok {
		t.Fatal("clients:0 was dropped")
	}
	if n, _ := v.(float64); n != 0 {
		t.Fatalf("clients = %v", v)
	}
	for _, k := range []string{"state", "gen", "deadline"} {
		if _, ok := got[k]; !ok {
			t.Errorf("zero-valued %q was dropped", k)
		}
	}
}

// A business rejection is a definitive answer; its reason must survive.
func TestGatewayPreservesBusinessRejection(t *testing.T) {
	body := fixture(t, "result-business-rejection.json")
	cmd := []byte(`{"req":"r-0004","op":"issue-ticket","room":"nb-3fa9c2","subject":"~mignes-magtel"}`)
	rec, _ := withUpstream(t, 200, body, cmd)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["error"] != "ticket-quota-room" {
		t.Fatalf("reason lost: %v", got["error"])
	}
}

// A non-200 upstream is infrastructure failure: the body is discarded and a
// terse category returned.
func TestGatewayRejectsNon200Upstream(t *testing.T) {
	rec, _ := withUpstream(t, 502, fixture(t, "result-issue-access.json"),
		fixture(t, "command-issue-access.json"))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "EXAMPLE-JOIN-TOKEN") {
		t.Fatal("a discarded upstream body leaked to the caller")
	}
}

// The answer must belong to the request that was sent.
func TestGatewayRejectsMismatchedEnvelope(t *testing.T) {
	for _, f := range []string{"result-malformed-wrong-req.json", "result-malformed-missing-envelope.json"} {
		rec, _ := withUpstream(t, 200, fixture(t, f), fixture(t, "command-ensure-room.json"))
		if rec.Code != http.StatusBadGateway {
			t.Errorf("%s: accepted with status %d", f, rec.Code)
		}
	}
}

func TestGatewayRejectsUnparseableUpstream(t *testing.T) {
	rec, _ := withUpstream(t, 200, []byte("{not json"), fixture(t, "command-ensure-room.json"))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d", rec.Code)
	}
}

// REDACTION. No join token, TURN credential or bearer may ever reach a log.
func TestGatewayNeverLogsCredentials(t *testing.T) {
	body := fixture(t, "result-issue-access.json")
	_, logs := withUpstream(t, 200, body, fixture(t, "command-issue-access.json"))
	for _, secret := range []string{
		"EXAMPLE-JOIN-TOKEN-NOT-REAL",
		"EXAMPLE-TURN-CREDENTIAL-NOT-REAL",
		"1790000000:example",
		"test-bearer-value",
		"test-local-key",
	} {
		if strings.Contains(logs, secret) {
			t.Errorf("a credential reached the log: %q", secret)
		}
	}
	if !strings.Contains(logs, "outcome=ok") {
		t.Errorf("expected an outcome line, got: %q", logs)
	}
}

// Authentication is a precondition, not an afterthought.
func TestGatewayRejectsWrongLocalKey(t *testing.T) {
	prev := localKey
	localKey = []byte("correct-key")
	defer func() { localKey = prev }()

	req := httptest.NewRequest(http.MethodPost, "/command",
		bytes.NewReader(fixture(t, "command-ensure-room.json")))
	req.Header.Set("X-Argus-Key", "wrong-key")
	rec := httptest.NewRecorder()
	var logs bytes.Buffer
	prevOut := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(prevOut)
	handleProof(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatal("a wrong local key was accepted")
	}
	if strings.Contains(logs.String(), "correct-key") {
		t.Error("the expected key was logged")
	}
	_, _ = io.Copy(io.Discard, rec.Body)
}
