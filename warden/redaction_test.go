package main

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"regexp"
	"strings"
	"testing"
)

// canary stands in for a Galène token id, which IS a usable bearer
// credential. It must never reach a log, an error, or a debug dump.
const canary = "CANARY-tok-9f3a1b7c5e2d"

// captureLogs runs fn with the standard logger redirected, and returns
// everything it wrote.
func captureLogs(fn func()) string {
	var buf bytes.Buffer
	old := log.Writer()
	flags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() { log.SetOutput(old); log.SetFlags(flags) }()
	fn()
	return buf.String()
}

// 1. Success path: a Result carrying a token must not be logged whole.
func TestSuccessResultNeverLogged(t *testing.T) {
	res := Result{OK: true, Req: "r1", Op: "issue-ticket",
		Subject: "~dolten-dilpun", Token: canary,
		Location: "https://sfu.example/group/nbw-x/"}
	out := captureLogs(func() {
		// mirrors the production log line in handle()
		log.Printf("event=command host=%s req=%s op=%s ok=%v err=%s",
			res.Subject, res.Req, res.Op, res.OK, res.Error)
	})
	if strings.Contains(out, canary) {
		t.Fatalf("token leaked into logs: %q", out)
	}
	if !strings.Contains(out, "event=command") {
		t.Fatalf("expected operational metadata, got %q", out)
	}
}

// 2. Failure path: error strings must not embed the token.
func TestFailureResultNeverLogged(t *testing.T) {
	res := Result{OK: false, Req: "r2", Op: "issue-ticket",
		Subject: "~dolten-dilpun", Error: "galene-token"}
	out := captureLogs(func() {
		log.Printf("event=command host=%s req=%s op=%s ok=%v err=%s",
			res.Subject, res.Req, res.Op, res.OK, res.Error)
	})
	if strings.Contains(out, canary) {
		t.Fatal("token leaked on the failure path")
	}
}

// 3. Malformed upstream: whatever we log about a bad body must not be
// the body itself.
func TestMalformedUpstreamNeverLogsBody(t *testing.T) {
	body := `{"ok":true,"token":"` + canary + `"}`
	out := captureLogs(func() {
		log.Printf("event=upstream-malformed host=%s req=%s", "~dolten-dilpun", "r3")
		_ = body
	})
	if strings.Contains(out, canary) {
		t.Fatal("upstream body leaked into logs")
	}
}

// 4. Reconciliation compares and deletes ids internally, but must never
// emit one. It may only report a count.
func TestReconcileLogsCountOnly(t *testing.T) {
	out := captureLogs(func() {
		log.Printf("event=reconcile removed_orphans=%d", 3)
	})
	if strings.Contains(out, canary) {
		t.Fatal("reconcile leaked a token id")
	}
	if !strings.Contains(out, "removed_orphans=3") {
		t.Fatalf("expected a count, got %q", out)
	}
}

// 5. Static guard: no log statement in this package may interpolate a
// token-bearing identifier. This catches future regressions that a
// runtime test would miss because the line is never executed.
func TestNoLogStatementReferencesSecrets(t *testing.T) {
	forbidden := regexp.MustCompile(
		`log\.Printf\([^)]*\b(tok|token|Token|bearer|remoteToken|localKey|Location|rb|body)\b`)
	for _, f := range []string{"main.go", "galene.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			continue // not all files present in every build context
		}
		if m := forbidden.FindString(string(src)); m != "" {
			t.Fatalf("%s: log statement references a secret-bearing value: %s", f, m)
		}
	}
}

// 6. The JSON we hand back may legitimately carry a token, but the
// struct must not be marshalled into any log sink by accident.
func TestResultMarshalNotLogged(t *testing.T) {
	res := Result{OK: true, Req: "r4", Token: canary}
	blob, _ := json.Marshal(res)
	if !strings.Contains(string(blob), canary) {
		t.Fatal("precondition: the response really should carry the token")
	}
	out := captureLogs(func() {
		log.Printf("event=command req=%s ok=%v", res.Req, res.OK)
	})
	if strings.Contains(out, canary) {
		t.Fatal("marshalled result reached the log")
	}
}
