package main

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// testDB gives each test its own migrated database bound to the package
// global, so the real reservation SQL is exercised rather than a mock.
func testDB(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "t.db")
	d, err := sql.Open("sqlite", "file:"+path+
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	d.SetMaxOpenConns(8)
	d.SetMaxIdleConns(8)
	old := db
	db = d
	t.Cleanup(func() { d.Close(); db = old })
	if err := migrate(); err != nil {
		t.Fatal(err)
	}
}

func testLimits(t *testing.T) *Limits {
	t.Helper()
	l, err := LoadLimits(writeConf(t, baseConf))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// ------------------------------------------------------------ rate limiter

func TestRateLimiterBurstThenRefill(t *testing.T) {
	r := newRateLimiter()
	now := time.Now()
	for i := 0; i < 5; i++ {
		if !r.Allow("h", 60, 5, now) {
			t.Fatalf("burst token %d refused", i)
		}
	}
	if r.Allow("h", 60, 5, now) {
		t.Fatal("6th call allowed with a burst of 5")
	}
	// 60/min == 1/s, so one second buys exactly one token
	if !r.Allow("h", 60, 5, now.Add(time.Second)) {
		t.Fatal("refill did not restore a token")
	}
}

func TestRateLimiterUnconfiguredIsUnlimited(t *testing.T) {
	r := newRateLimiter()
	for i := 0; i < 100; i++ {
		if !r.Allow("h", 0, 0, time.Now()) {
			t.Fatal("unconfigured limiter denied a request")
		}
	}
}

// An attacker cycling subjects must not grow the bucket map without bound.
func TestRateLimiterMapIsBounded(t *testing.T) {
	r := newRateLimiter()
	r.max = 64
	now := time.Now()
	for i := 0; i < 5000; i++ {
		r.Allow(fmt.Sprintf("~host-%d", i), 60, 5, now)
	}
	if r.Size() > r.max {
		t.Fatalf("bucket map grew to %d, cap is %d", r.Size(), r.max)
	}
}

func TestRateLimiterHostsAreIndependent(t *testing.T) {
	r := newRateLimiter()
	now := time.Now()
	for i := 0; i < 5; i++ {
		r.Allow("a", 60, 5, now)
	}
	if r.Allow("a", 60, 5, now) {
		t.Fatal("host a should be exhausted")
	}
	if !r.Allow("b", 60, 5, now) {
		t.Fatal("host b was affected by host a's usage")
	}
}

// -------------------------------------------------------- room reservations

func TestRoomQuotaBoundaryAndRelease(t *testing.T) {
	testDB(t)
	l := testLimits(t)
	l.RoomsActivePerHost = 3
	l.RoomsActiveGlobal = 100

	for i := 0; i < 3; i++ {
		ok, err := reserveNewRoom("~a", fmt.Sprintf("room%08d", i), fmt.Sprintf("nbw-g%d", i), 1, 9e9, l)
		if err != nil || !ok {
			t.Fatalf("reservation %d refused at boundary: ok=%v err=%v", i, ok, err)
		}
		if err := activateRoom("~a", fmt.Sprintf("room%08d", i)); err != nil {
			t.Fatal(err)
		}
	}
	// boundary + 1
	ok, err := reserveNewRoom("~a", "room00000003", "nbw-g3", 1, 9e9, l)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("quota exceeded: a 4th room was reserved against a limit of 3")
	}
	if blame := roomQuotaBlame("~a", l); blame != "room-quota-host" {
		t.Fatalf("wrong blame: %s", blame)
	}
	// an unrelated host is unaffected
	if ok, _ := reserveNewRoom("~b", "room00000000", "nbw-gb", 1, 9e9, l); !ok {
		t.Fatal("a different host was refused by another host's quota")
	}
	// release capacity, then the same host may create again
	if _, err := db.Exec(`UPDATE rooms SET state='ended' WHERE host='~a' AND room_key='room00000000'`); err != nil {
		t.Fatal(err)
	}
	if ok, _ := reserveNewRoom("~a", "room00000003", "nbw-g3", 1, 9e9, l); !ok {
		t.Fatal("capacity was not released after a room ended")
	}
}

func TestRoomQuotaGlobalBoundary(t *testing.T) {
	testDB(t)
	l := testLimits(t)
	l.RoomsActiveGlobal = 4
	l.RoomsActivePerHost = 100
	for i := 0; i < 4; i++ {
		if ok, _ := reserveNewRoom(fmt.Sprintf("~h%d", i), "roomkey00", fmt.Sprintf("nbw-x%d", i), 1, 9e9, l); !ok {
			t.Fatalf("global reservation %d refused early", i)
		}
	}
	if ok, _ := reserveNewRoom("~h9", "roomkey00", "nbw-x9", 1, 9e9, l); ok {
		t.Fatal("global room quota exceeded")
	}
	if blame := roomQuotaBlame("~h9", l); blame != "room-quota-global" {
		t.Fatalf("wrong blame: %s", blame)
	}
}

// The whole point of reserving inside one statement: concurrency at the
// boundary must not overshoot.
func TestConcurrentRoomReservationsCannotExceedQuota(t *testing.T) {
	testDB(t)
	l := testLimits(t)
	l.RoomsActivePerHost = 5
	l.RoomsActiveGlobal = 5

	var granted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ok, err := reserveNewRoom("~a", fmt.Sprintf("room%08d", i), fmt.Sprintf("nbw-c%d", i), 1, 9e9, l)
			if err == nil && ok {
				granted.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if g := granted.Load(); g != 5 {
		t.Fatalf("granted %d reservations against a quota of 5", g)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM rooms WHERE state IN ('active','provisioning','ending')`).Scan(&n)
	if n != 5 {
		t.Fatalf("%d rows occupy quota, expected 5", n)
	}
}

func TestReleasedRoomReservationFreesCapacity(t *testing.T) {
	testDB(t)
	l := testLimits(t)
	l.RoomsActivePerHost = 1
	l.RoomsActiveGlobal = 10

	if ok, _ := reserveNewRoom("~a", "roomkey01", "nbw-r1", 1, 9e9, l); !ok {
		t.Fatal("first reservation refused")
	}
	if ok, _ := reserveNewRoom("~a", "roomkey02", "nbw-r2", 1, 9e9, l); ok {
		t.Fatal("quota exceeded")
	}
	// simulate a failed Galene creation
	releaseRoomReservation("~a", "roomkey01")
	if ok, _ := reserveNewRoom("~a", "roomkey02", "nbw-r2", 1, 9e9, l); !ok {
		t.Fatal("a released reservation did not free capacity")
	}
}

// ------------------------------------------------------ ticket reservations

func TestTicketQuotaBoundaryPerRoom(t *testing.T) {
	testDB(t)
	l := testLimits(t)
	l.TicketsLivePerRoom = 3
	l.TicketsLivePerHost = 100
	exp := time.Now().Add(time.Hour).Unix()

	for i := 0; i < 3; i++ {
		ok, err := reserveTicket("~a", fmt.Sprintf("req%d", i), "nbw-g", "~p", exp, l)
		if err != nil || !ok {
			t.Fatalf("ticket %d refused at boundary: %v", i, err)
		}
		if err := issueTicket("~a", fmt.Sprintf("req%d", i), fmt.Sprintf("tok%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if ok, _ := reserveTicket("~a", "req3", "nbw-g", "~p", exp, l); ok {
		t.Fatal("ticket quota exceeded")
	}
	if blame := ticketQuotaBlame("~a", "nbw-g", l); blame != "ticket-quota-room" {
		t.Fatalf("wrong blame: %s", blame)
	}
	// revoking frees capacity
	db.Exec(`UPDATE tickets SET revoked=1 WHERE token='tok0'`)
	if ok, _ := reserveTicket("~a", "req3", "nbw-g", "~p", exp, l); !ok {
		t.Fatal("revocation did not free ticket capacity")
	}
}

func TestConcurrentTicketReservationsCannotExceedQuota(t *testing.T) {
	testDB(t)
	l := testLimits(t)
	l.TicketsLivePerRoom = 4
	l.TicketsLivePerHost = 100
	exp := time.Now().Add(time.Hour).Unix()

	var granted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if ok, err := reserveTicket("~a", fmt.Sprintf("r%d", i), "nbw-g", "~p", exp, l); err == nil && ok {
				granted.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if g := granted.Load(); g != 4 {
		t.Fatalf("granted %d ticket reservations against a quota of 4", g)
	}
}

// An idempotent retry must not reserve a second time.
func TestTicketReservationIsIdempotentPerRequest(t *testing.T) {
	testDB(t)
	l := testLimits(t)
	l.TicketsLivePerRoom = 10
	exp := time.Now().Add(time.Hour).Unix()

	if ok, _ := reserveTicket("~a", "same-req", "nbw-g", "~p", exp, l); !ok {
		t.Fatal("first reservation refused")
	}
	if ok, _ := reserveTicket("~a", "same-req", "nbw-g", "~p", exp, l); ok {
		t.Fatal("the same request id reserved capacity twice")
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM tickets WHERE host='~a' AND req='same-req'`).Scan(&n)
	if n != 1 {
		t.Fatalf("%d rows for one request id", n)
	}
}

// A bare reservation is not a credential and must never be adopted.
func TestReservationIsNotAdoptable(t *testing.T) {
	testDB(t)
	l := testLimits(t)
	exp := time.Now().Add(time.Hour).Unix()
	if ok, _ := reserveTicket("~a", "req-x", "nbw-g", "~p", exp, l); !ok {
		t.Fatal("reservation refused")
	}
	var tok string
	err := db.QueryRow(`SELECT token FROM tickets
	  WHERE host=? AND req=? AND revoked=0 AND state='issued'`, "~a", "req-x").Scan(&tok)
	if err == nil {
		t.Fatalf("a reservation was adoptable as an issued ticket: %q", tok)
	}
	if err := issueTicket("~a", "req-x", "realtoken"); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT token FROM tickets
	  WHERE host=? AND req=? AND revoked=0 AND state='issued'`, "~a", "req-x").Scan(&tok); err != nil {
		t.Fatalf("issued ticket not adoptable: %v", err)
	}
	if tok != "realtoken" {
		t.Fatalf("adopted %q", tok)
	}
}

func TestReleasedTicketReservationFreesCapacity(t *testing.T) {
	testDB(t)
	l := testLimits(t)
	l.TicketsLivePerRoom = 1
	exp := time.Now().Add(time.Hour).Unix()
	if ok, _ := reserveTicket("~a", "r1", "nbw-g", "~p", exp, l); !ok {
		t.Fatal("first refused")
	}
	if ok, _ := reserveTicket("~a", "r2", "nbw-g", "~p", exp, l); ok {
		t.Fatal("quota exceeded")
	}
	releaseTicketReservation("~a", "r1")
	if ok, _ := reserveTicket("~a", "r2", "nbw-g", "~p", exp, l); !ok {
		t.Fatal("released reservation did not free capacity")
	}
}

// ------------------------------------------------------------ command caps

func TestCommandCapRejectsAndDuplicatesDoNot(t *testing.T) {
	testDB(t)
	l := testLimits(t)
	l.CapCommandRowsPerHost = 3

	for i := 0; i < 3; i++ {
		ins, capped, err := claimWithCap("~a", fmt.Sprintf("q%d", i), "fp", "ep1", l)
		if err != nil || !ins || capped {
			t.Fatalf("claim %d: ins=%v capped=%v err=%v", i, ins, capped, err)
		}
	}
	ins, capped, err := claimWithCap("~a", "q3", "fp", "ep1", l)
	if err != nil || ins || !capped {
		t.Fatalf("expected a cap rejection, got ins=%v capped=%v err=%v", ins, capped, err)
	}
	// A DUPLICATE of an existing row must not be treated as capped: it
	// consumes no new capacity.
	ins, capped, err = claimWithCap("~a", "q0", "fp", "ep1", l)
	if err != nil || ins || capped {
		t.Fatalf("duplicate mis-handled: ins=%v capped=%v err=%v", ins, capped, err)
	}
	// another host is unaffected
	if ins, capped, _ := claimWithCap("~b", "q0", "fp", "ep1", l); !ins || capped {
		t.Fatal("one host's command cap affected another host")
	}
}

// A FAILED command must stay retryable. The failure path stores epoch=NULL,
// and a bare `epoch = ''` comparison never matches NULL, which stranded
// every retry at "in-progress".
func TestFailedCommandStaysRetryable(t *testing.T) {
	testDB(t)
	l := testLimits(t)

	ins, capped, err := claimWithCap("~a", "r1", "fp", "epoch-1", l)
	if err != nil || !ins || capped {
		t.Fatalf("initial claim failed: ins=%v capped=%v err=%v", ins, capped, err)
	}
	// exactly what handle() writes when an operation fails
	if _, err := db.Exec(`UPDATE commands SET state='claimed',epoch=NULL,updated=?
	  WHERE host=? AND req=?`, time.Now().Unix(), "~a", "r1"); err != nil {
		t.Fatal(err)
	}

	var ep string
	if err := db.QueryRow(`SELECT COALESCE(epoch,'') FROM commands
	  WHERE host=? AND req=?`, "~a", "r1").Scan(&ep); err != nil {
		t.Fatal(err)
	}
	if ep != "" {
		t.Fatalf("expected an empty coalesced epoch, got %q", ep)
	}

	// the takeover a retry performs
	res, err := db.Exec(`UPDATE commands SET epoch=?,updated=?
	  WHERE host=? AND req=? AND COALESCE(epoch,'')=?`,
		"epoch-2", time.Now().Unix(), "~a", "r1", ep)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		t.Fatalf("takeover of a failed command affected %d rows; the retry is stranded", n)
	}
}
