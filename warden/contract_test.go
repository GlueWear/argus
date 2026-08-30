package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtures = "../protocol/v1/fixtures"

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtures, name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return b
}

// The three envelope-and-room fields carry meaning at zero and must survive a
// round trip. `clients` reaching the ship as absent instead of 0 is exactly
// how an earlier omitempty turned a healthy empty room into %malformed.
func TestResultKeepsZeroValuedFields(t *testing.T) {
	b, err := json.Marshal(Result{Req: "r", Op: "room-status", Subject: "~mignes-magtel"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"ok", "req", "op", "subject", "state", "clients", "gen", "deadline"} {
		if _, ok := m[k]; !ok {
			t.Errorf("field %q vanished at its zero value; omitempty must not be set on it", k)
		}
	}
}

// Optional fields must stay optional, or every room-level answer would carry
// empty credential keys.
func TestResultOmitsAbsentOptionalFields(t *testing.T) {
	b, _ := json.Marshal(Result{Req: "r", Op: "room-status", Subject: "~s"})
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for _, k := range []string{"token", "sfu", "ice", "turn_username", "turn_credential",
		"stun_urls", "turn_urls", "access_expires", "renew_after", "error", "duplicate"} {
		if _, ok := m[k]; ok {
			t.Errorf("optional field %q present when unset", k)
		}
	}
}

// Every field the access fixture documents must exist on Result, so a rename
// or deletion in Go breaks here rather than silently at a browser.
func TestAccessFixtureRoundTrips(t *testing.T) {
	raw := readFixture(t, "result-issue-access.json")
	var r Result
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	b, _ := json.Marshal(r)
	_ = json.Unmarshal(b, &back)

	var want map[string]any
	_ = json.Unmarshal(raw, &want)
	for k := range want {
		if _, ok := back[k]; !ok {
			t.Errorf("field %q was dropped by the Go round trip", k)
		}
	}
	if len(r.ICE) != 2 {
		t.Fatalf("ice entries: %d", len(r.ICE))
	}
	if r.ICE[1].Username == "" || r.ICE[1].Credential == "" {
		t.Error("TURN entry lost its credential fields")
	}
	if r.AccessExpires == 0 || r.RenewAfter == 0 {
		t.Error("expiry fields lost")
	}
	if r.RenewAfter >= r.AccessExpires {
		t.Error("renew_after must precede access_expires")
	}
}

// A business rejection is a definitive answer and must reach the ship with
// its reason intact; only infrastructure failure is a gateway-level error.
func TestStatusForSeparatesBusinessFromInfrastructure(t *testing.T) {
	for _, e := range []string{"ticket-quota-room", "room-quota", "rate-limited-rooms",
		"no-such-room", "room-ended", "participant-quota", "in-progress"} {
		if got := statusFor(Result{OK: false, Error: e}); got != 200 {
			t.Errorf("business error %q returned %d; the reason would not survive the gateway", e, got)
		}
	}
	for _, e := range []string{"galene-token", "db-ticket", "", "something-unexpected"} {
		if got := statusFor(Result{OK: false, Error: e}); got != 502 {
			t.Errorf("infrastructure error %q returned %d; it would be read as a definitive answer", e, got)
		}
	}
	if statusFor(Result{OK: true}) != 200 {
		t.Error("success is not 200")
	}
}

// Fixtures are the contract. If one stops parsing into Result, the contract
// and the code have diverged.
func TestAllResultFixturesParse(t *testing.T) {
	ents, err := os.ReadDir(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), "result-") {
			continue
		}
		var r Result
		if err := json.Unmarshal(readFixture(t, e.Name()), &r); err != nil {
			t.Errorf("%s: %v", e.Name(), err)
		}
		n++
	}
	if n == 0 {
		t.Fatal("no result fixtures found")
	}
}

func TestCommandFixturesParse(t *testing.T) {
	for _, n := range []string{"command-ensure-room.json", "command-issue-access.json",
		"command-room-status.json"} {
		var c Command
		if err := json.Unmarshal(readFixture(t, n), &c); err != nil {
			t.Errorf("%s: %v", n, err)
		}
		if c.Subject == "" || c.Req == "" || c.Op == "" || c.Room == "" {
			t.Errorf("%s: a required field did not survive parsing", n)
		}
	}
}
