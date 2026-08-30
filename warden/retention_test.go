package main

import (
	"fmt"
	"testing"
	"time"
)

func seedRoom(t *testing.T, host, key, state string, ageDays float64) {
	t.Helper()
	ts := time.Now().Add(-time.Duration(ageDays*24) * time.Hour).Unix()
	if _, err := db.Exec(`INSERT INTO rooms(host,room_key,group_name,state,gen,deadline,created,updated)
	  VALUES(?,?,?,?,1,0,?,?)`, host, key, "nbw-"+key, state, ts, ts); err != nil {
		t.Fatal(err)
	}
}

func seedCommand(t *testing.T, host, req, state string, ageHours float64) {
	t.Helper()
	ts := time.Now().Add(-time.Duration(ageHours * float64(time.Hour))).Unix()
	if _, err := db.Exec(`INSERT INTO commands(host,req,fingerprint,state,epoch,response,created,updated)
	  VALUES(?,?,'fp1',?,'ep',?,?,?)`, host, req, state, `{"ok":true}`, ts, ts); err != nil {
		t.Fatal(err)
	}
}

func seedTicket(t *testing.T, token, group string, revoked int, expiredHours, ageDays float64) {
	t.Helper()
	exp := time.Now().Add(-time.Duration(expiredHours * float64(time.Hour))).Unix()
	created := time.Now().Add(-time.Duration(ageDays*24) * time.Hour).Unix()
	if _, err := db.Exec(`INSERT INTO tickets(token,group_name,participant,expires,revoked,created,host,req,state)
	  VALUES(?,?,'~p',?,?,?,'~a',?,'issued')`, token, group, exp, revoked, created, token); err != nil {
		t.Fatal(err)
	}
}

func count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Every boundary tested just-inside and just-outside its window.
func TestRetentionBoundaries(t *testing.T) {
	testDB(t)
	InstallLimits(testLimits(t))

	// rooms: 7 days
	seedRoom(t, "~a", "insideroom01", "ended", 6.9)
	seedRoom(t, "~a", "outsideroom1", "ended", 7.1)
	// must NEVER be deleted regardless of age
	seedRoom(t, "~a", "activeroom001", "active", 30)
	seedRoom(t, "~a", "provroom00001", "provisioning", 30)
	seedRoom(t, "~a", "endingroom001", "ending", 30)

	// commands: full results 48h -> tombstone; tombstones 30d -> gone
	seedCommand(t, "~a", "cmd-inside", cmdDone, 47)
	seedCommand(t, "~a", "cmd-outside", cmdDone, 49)
	seedCommand(t, "~a", "tomb-inside", cmdRetired, 29*24)
	seedCommand(t, "~a", "tomb-outside", cmdRetired, 31*24)
	seedCommand(t, "~a", "stale-claim", cmdClaimed, 49)
	seedCommand(t, "~a", "fresh-claim", cmdClaimed, 1)

	// tickets: revoked AND expired AND older than 7 days
	seedTicket(t, "tok-old-revoked", "nbw-g", 1, 1, 7.1)
	seedTicket(t, "tok-new-revoked", "nbw-g", 1, 1, 6.9)
	seedTicket(t, "tok-live", "nbw-g", 0, -100, 30)      // unrevoked -> never
	seedTicket(t, "tok-unexpired", "nbw-g", 1, -100, 30) // not yet expired -> never

	prune()

	// rooms
	if count(t, `SELECT COUNT(*) FROM rooms WHERE room_key='insideroom01'`) != 1 {
		t.Error("room just inside the window was deleted")
	}
	if count(t, `SELECT COUNT(*) FROM rooms WHERE room_key='outsideroom1'`) != 0 {
		t.Error("room past retention survived")
	}
	for _, k := range []string{"activeroom001", "provroom00001", "endingroom001"} {
		if count(t, `SELECT COUNT(*) FROM rooms WHERE room_key=?`, k) != 1 {
			t.Errorf("%s was deleted: active/provisioning/ending must never be pruned", k)
		}
	}

	// commands
	if s := stateOf(t, "cmd-inside"); s != cmdDone {
		t.Errorf("command inside the full window became %q", s)
	}
	if s := stateOf(t, "cmd-outside"); s != cmdRetired {
		t.Errorf("command past the full window is %q, want tombstone", s)
	}
	var body *string
	db.QueryRow(`SELECT response FROM commands WHERE req='cmd-outside'`).Scan(&body)
	if body != nil {
		t.Error("tombstone still carries a result body")
	}
	if count(t, `SELECT COUNT(*) FROM commands WHERE req='tomb-inside'`) != 1 {
		t.Error("tombstone inside its window was purged")
	}
	if count(t, `SELECT COUNT(*) FROM commands WHERE req='tomb-outside'`) != 0 {
		t.Error("tombstone past 30 days survived")
	}
	if s := stateOf(t, "stale-claim"); s != cmdRetired {
		t.Errorf("stale claim is %q, want tombstone", s)
	}
	if s := stateOf(t, "fresh-claim"); s != cmdClaimed {
		t.Errorf("fresh claim was retired early (%q)", s)
	}

	// tickets
	if count(t, `SELECT COUNT(*) FROM tickets WHERE token='tok-old-revoked'`) != 0 {
		t.Error("old revoked+expired ticket survived")
	}
	for _, tk := range []string{"tok-new-revoked", "tok-live", "tok-unexpired"} {
		if count(t, `SELECT COUNT(*) FROM tickets WHERE token=?`, tk) != 1 {
			t.Errorf("%s was deleted; only revoked AND expired AND aged rows may go", tk)
		}
	}
}

func stateOf(t *testing.T, req string) string {
	t.Helper()
	var s string
	db.QueryRow(`SELECT state FROM commands WHERE req=?`, req).Scan(&s)
	return s
}

// Pruning must never exceed the configured batch in a single cycle.
func TestPruneRespectsBatchLimit(t *testing.T) {
	testDB(t)
	l := testLimits(t)
	l.PruneBatch = 10
	InstallLimits(l)
	for i := 0; i < 55; i++ {
		seedRoom(t, "~a", fmt.Sprintf("bulkroom%05d", i), "ended", 30)
	}
	st := prune()
	if st.RoomsDeleted > 10 {
		t.Fatalf("deleted %d rooms in one cycle, batch is 10", st.RoomsDeleted)
	}
	if remaining := count(t, `SELECT COUNT(*) FROM rooms`); remaining != 45 {
		t.Fatalf("expected 45 rooms left after one bounded cycle, got %d", remaining)
	}
}

// A tombstone must distinguish same-fingerprint replay from a conflict.
func TestTombstoneReplaySemantics(t *testing.T) {
	testDB(t)
	InstallLimits(testLimits(t))
	epoch = "ep-current"

	if _, err := db.Exec(`INSERT INTO commands(host,req,fingerprint,state,epoch,response,created,updated)
	  VALUES('~a','r1',?, ?, 'ep-old', NULL, ?, ?)`,
		fingerprint(Command{Op: "ensure-room", Room: "roomkey01", Subject: "~a"}),
		cmdRetired, time.Now().Unix(), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}

	same := Command{Req: "r1", Op: "ensure-room", Room: "roomkey01", Subject: "~a"}
	proceed, res := claim(same, fingerprint(same))
	if proceed {
		t.Fatal("a retired request id was allowed to execute again")
	}
	if res.Error != "request-retired" {
		t.Fatalf("same-fingerprint replay returned %q, want request-retired", res.Error)
	}

	diff := Command{Req: "r1", Op: "end-room", Room: "roomkey01", Subject: "~a"}
	proceed, res = claim(diff, fingerprint(diff))
	if proceed {
		t.Fatal("a conflicting request id was allowed to execute")
	}
	if res.Error != "request-id-reused-with-different-body" {
		t.Fatalf("conflicting replay returned %q, want a conflict", res.Error)
	}
}

// Tombstones keep command accounting bounded in the SAME table.
func TestTombstonesCountTowardCommandCap(t *testing.T) {
	testDB(t)
	l := testLimits(t)
	l.CapCommandRowsPerHost = 3
	InstallLimits(l)
	for i := 0; i < 3; i++ {
		seedCommand(t, "~a", fmt.Sprintf("t%d", i), cmdRetired, 1)
	}
	ins, capped, err := claimWithCap("~a", "new", "fp", "ep", l)
	if err != nil {
		t.Fatal(err)
	}
	if ins || !capped {
		t.Fatalf("tombstones did not count toward the cap: ins=%v capped=%v", ins, capped)
	}
}
