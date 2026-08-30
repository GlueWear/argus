package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// baseConf is a known-valid configuration. Tests mutate single lines of it
// so each failure is attributable to exactly one changed relationship.
const baseConf = `
meta.global_slots                = 32
meta.host_slots                  = 8
meta.admit_wait                  = 2s
roster.global_slots              = 6
roster.host_slots                = 2
roster.admit_wait                = 5s
rooms.active_global              = 150
rooms.active_per_host            = 25
participants.global              = 32
participants.per_room            = 16
tickets.live_per_room            = 32
tickets.live_per_host            = 200
lease.min_ttl                    = 30s
lease.default_ttl                = 30m
lease.max_ttl                    = 12h
room.max_lifetime                = 24h
ticket.ttl                       = 5m
operator.token_ttl               = 2m
access.credential_ttl            = 1h
rate.rooms_per_host_per_min      = 30
rate.rooms_burst                 = 10
rate.tickets_per_host_per_min    = 120
rate.tickets_burst               = 30
rate.roster_per_host_per_min     = 20
rate.roster_burst                = 5
rate.requests_per_host_per_min   = 300
rate.requests_burst              = 60
caps.command_rows_per_host       = 20000
retain.ended_rooms               = 168h
retain.tickets                   = 168h
retain.commands_full             = 48h
retain.command_tombstones        = 720h
db.wal_truncate_threshold_bytes  = 16777216
db.prune_batch                   = 500
db.prune_interval                = 5m
`

func writeConf(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "limits.conf")
	if err := os.WriteFile(p, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	return p
}

// replace swaps the value of one key, leaving everything else valid.
func replace(conf, key, val string) string {
	out := []string{}
	for _, line := range strings.Split(conf, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, key+" ") || strings.HasPrefix(trimmed, key+"=") {
			out = append(out, key+" = "+val)
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func TestValidConfigLoads(t *testing.T) {
	l, err := LoadLimits(writeConf(t, baseConf))
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if l.MetaGlobalSlots != 32 || l.MetaHostSlots != 8 || l.MetaAdmitWait != 2*time.Second {
		t.Fatalf("meta admission mis-parsed: %+v", l)
	}
	if l.RosterGlobalSlots != 6 || l.RosterHostSlots != 2 || l.RosterAdmitWait != 5*time.Second {
		t.Fatalf("roster admission mis-parsed: %+v", l)
	}
	if l.ParticipantsGlobal != 32 || l.ParticipantsPerRoom != 16 {
		t.Fatalf("participants mis-parsed: %+v", l)
	}
	if l.RoomMaxLifetime != 24*time.Hour {
		t.Fatalf("room lifetime mis-parsed: %v", l.RoomMaxLifetime)
	}
	if l.RetainCommandsFull != 48*time.Hour || l.RetainCommandTombstones != 720*time.Hour {
		t.Fatalf("retention mis-parsed: %+v", l)
	}
	if l.RetainEndedRooms != 168*time.Hour || l.RetainTickets != 168*time.Hour {
		t.Fatalf("7-day retention mis-parsed: %+v", l)
	}
}

// Each case must be rejected, and the message must name the offending key
// without reproducing the file.
func TestInvalidRelationshipsRejected(t *testing.T) {
	cases := []struct {
		name, key, val, wantSubstr string
	}{
		{"malformed duration", "meta.admit_wait", "2 seconds", "not a duration"},
		{"malformed integer", "meta.global_slots", "thirty-two", "not an integer"},
		{"zero limit", "roster.global_slots", "0", "must be > 0"},
		{"negative limit", "rooms.active_global", "-5", "must be > 0"},
		{"zero duration", "meta.admit_wait", "0s", "must be > 0"},
		{"negative duration", "lease.min_ttl", "-30s", "must be > 0"},

		{"meta host == global", "meta.host_slots", "32", "must be <"},
		{"meta host > global", "meta.host_slots", "64", "must be <"},
		{"roster host == global", "roster.host_slots", "6", "must be <"},
		{"roster host > global", "roster.host_slots", "9", "must be <"},

		{"participants per_room > global", "participants.per_room", "64", "must be <="},
		{"rooms per_host > global", "rooms.active_per_host", "500", "must be <="},

		{"ticket retention < commands_full", "retain.tickets", "1h", "must be >="},
		{"tombstone retention < commands_full", "retain.command_tombstones", "1h", "must be >="},

		{"lease default below min", "lease.default_ttl", "1s", "must be within"},
		{"lease default above max", "lease.default_ttl", "48h", "must be within"},
		{"lease min above max", "lease.min_ttl", "24h", "must be within"},

		{"room lifetime < lease max", "room.max_lifetime", "1h", "must be >="},
		{"ticket ttl > lease max", "ticket.ttl", "24h", "must be <="},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadLimits(writeConf(t, replace(baseConf, c.key, c.val)))
			if err == nil {
				t.Fatalf("accepted invalid %s = %s", c.key, c.val)
			}
			if !strings.Contains(err.Error(), c.wantSubstr) {
				t.Fatalf("error %q does not mention %q", err.Error(), c.wantSubstr)
			}
		})
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	_, err := LoadLimits(writeConf(t, baseConf+"\nmeta.globl_slots = 4\n"))
	if err == nil {
		t.Fatal("unknown key accepted -- a typo would silently use the default")
	}
	if !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

func TestDuplicateKeyRejected(t *testing.T) {
	_, err := LoadLimits(writeConf(t, baseConf+"\nmeta.global_slots = 99\n"))
	if err == nil {
		t.Fatal("duplicate key accepted")
	}
	if !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

func TestMissingKeyRejected(t *testing.T) {
	conf := strings.ReplaceAll(baseConf, "participants.global              = 32", "")
	_, err := LoadLimits(writeConf(t, conf))
	if err == nil {
		t.Fatal("missing key accepted -- partial config must never load")
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

func TestMissingFileRejected(t *testing.T) {
	_, err := LoadLimits(filepath.Join(t.TempDir(), "does-not-exist.conf"))
	if err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestMalformedLineRejected(t *testing.T) {
	_, err := LoadLimits(writeConf(t, baseConf+"\nthis line has no equals sign\n"))
	if err == nil {
		t.Fatal("malformed line accepted")
	}
}

// The error must be concise and must never echo the file back.
func TestErrorIsBoundedAndQuiet(t *testing.T) {
	broken := baseConf
	for _, k := range []string{"meta.global_slots", "roster.global_slots",
		"rooms.active_global", "participants.global", "tickets.live_per_room"} {
		broken = replace(broken, k, "0")
	}
	_, err := LoadLimits(writeConf(t, broken))
	if err == nil {
		t.Fatal("expected rejection")
	}
	msg := err.Error()
	if !strings.Contains(msg, "more") {
		t.Fatalf("expected the message to be truncated with a count, got %q", msg)
	}
	if len(msg) > 300 {
		t.Fatalf("error message is not concise (%d bytes)", len(msg))
	}
	if strings.Contains(msg, "retain.ended_rooms") {
		t.Fatal("error dumped unrelated file content")
	}
}

// An invalid reload must leave the previous snapshot live, untouched.
func TestInvalidReloadKeepsLastKnownGood(t *testing.T) {
	good, err := LoadLimits(writeConf(t, baseConf))
	if err != nil {
		t.Fatal(err)
	}
	InstallLimits(good)

	bad := writeConf(t, replace(baseConf, "meta.host_slots", "999"))
	if _, err := LoadLimits(bad); err == nil {
		t.Fatal("invalid config loaded")
	}
	// Nothing was installed, so the live snapshot is still the good one.
	if CurrentLimits() != good {
		t.Fatal("live configuration changed despite a failed reload")
	}
	if CurrentLimits().MetaHostSlots != 8 {
		t.Fatalf("last-known-good corrupted: %d", CurrentLimits().MetaHostSlots)
	}
}

func TestValidReloadSwapsAtomically(t *testing.T) {
	first, err := LoadLimits(writeConf(t, baseConf))
	if err != nil {
		t.Fatal(err)
	}
	InstallLimits(first)

	second, err := LoadLimits(writeConf(t, replace(baseConf, "meta.admit_wait", "4s")))
	if err != nil {
		t.Fatal(err)
	}
	InstallLimits(second)

	if CurrentLimits().MetaAdmitWait != 4*time.Second {
		t.Fatalf("swap did not take: %v", CurrentLimits().MetaAdmitWait)
	}
	if first.MetaAdmitWait != 2*time.Second {
		t.Fatal("the previous snapshot was mutated; snapshots must be immutable")
	}
}

// Restart-only settings must be reported, never silently claimed as applied.
func TestRestartOnlyDifferencesReported(t *testing.T) {
	boot, err := LoadLimits(writeConf(t, baseConf))
	if err != nil {
		t.Fatal(err)
	}
	same, _ := LoadLimits(writeConf(t, replace(baseConf, "meta.admit_wait", "3s")))
	if got := same.RestartRequired(boot); len(got) != 0 {
		t.Fatalf("live-reloadable change wrongly demanded a restart: %v", got)
	}
	changed, err := LoadLimits(writeConf(t, replace(baseConf, "meta.global_slots", "48")))
	if err != nil {
		t.Fatal(err)
	}
	got := changed.RestartRequired(boot)
	if len(got) != 1 || got[0] != "meta.global_slots" {
		t.Fatalf("expected meta.global_slots to require a restart, got %v", got)
	}
}

// Readers must always observe a complete snapshot, never a mixture, while
// reloads run continuously. Run under -race.
func TestConcurrentReadsDuringReloads(t *testing.T) {
	a, err := LoadLimits(writeConf(t, baseConf))
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadLimits(writeConf(t, replace(
		replace(baseConf, "meta.global_slots", "64"), "meta.host_slots", "16")))
	if err != nil {
		t.Fatal(err)
	}
	InstallLimits(a)

	var stop atomic.Bool
	var wg sync.WaitGroup

	// writer: swap back and forth as fast as it can
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			if i%2 == 0 {
				InstallLimits(a)
			} else {
				InstallLimits(b)
			}
		}
	}()

	// readers: every observation must be internally consistent
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				l := CurrentLimits()
				if l == nil {
					t.Error("nil snapshot observed")
					return
				}
				// a torn snapshot would pair one config's global with the
				// other's host value
				switch l.MetaGlobalSlots {
				case 32:
					if l.MetaHostSlots != 8 {
						t.Errorf("torn snapshot: global=32 host=%d", l.MetaHostSlots)
						return
					}
				case 64:
					if l.MetaHostSlots != 16 {
						t.Errorf("torn snapshot: global=64 host=%d", l.MetaHostSlots)
						return
					}
				default:
					t.Errorf("impossible global slots %d", l.MetaGlobalSlots)
					return
				}
				if l.MetaHostSlots >= l.MetaGlobalSlots {
					t.Error("observed snapshot violates its own invariant")
					return
				}
			}
		}()
	}

	time.Sleep(300 * time.Millisecond)
	stop.Store(true)
	wg.Wait()
}

// The shipped file must itself be valid, so a deploy cannot install a
// configuration the loader would reject.
func TestShippedConfigIsValid(t *testing.T) {
	for _, p := range []string{"limits.conf", "/etc/noltbook-warden/limits.conf"} {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		l, err := LoadLimits(p)
		if err != nil {
			t.Fatalf("%s is not loadable: %v", p, err)
		}
		if l.ParticipantsPerRoom != 16 || l.ParticipantsGlobal != 32 {
			t.Fatalf("%s: agreed participant limits missing: per_room=%d global=%d",
				p, l.ParticipantsPerRoom, l.ParticipantsGlobal)
		}
		if l.RoomMaxLifetime != 24*time.Hour {
			t.Fatalf("%s: agreed 24h room lifetime missing: %v", p, l.RoomMaxLifetime)
		}
		return
	}
	t.Skip("no shipped config present in this build context")
}
