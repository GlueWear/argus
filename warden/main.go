// noltbook-warden: managed call control plane (W1 + M2a).
//
// Trust boundary: the ONLY authority for "who is asking" is `subject`,
// which the loopback gateway sets from the Ames-authenticated sender.
// A caller can never supply a namespace, group path, or host.
//
// Galène token ids ARE token values. They are secrets: never logged.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

const (
	listenAddr = "127.0.0.1:8900"
	managedPfx = "nbw-" // the ONLY namespace this service may touch
	maxBody    = 8192
	ticketTTL  = 5 * time.Minute
	opTokenTTL = 2 * time.Minute

	// M2a concurrency admission (quotas proper are M2b)
	globalSlots = 8
	hostSlots   = 3
	// unique command rows across all hosts (2b.2)
	capCommandRowsGlobal = 200000
	admitWait            = 3 * time.Second
	opDeadline           = 60 * time.Second

	// leases
	leaseMinTTL     = 30 * time.Second
	leaseMaxTTL     = 12 * time.Hour
	leaseDefaultTTL = 30 * time.Minute
	sweepEvery      = 10 * time.Second
	// A room left in 'ending' for longer than one operation deadline was
	// abandoned by a dead worker, not left by one still running.
	endingGrace     = 90 * time.Second
	healthProbeFreq = 15 * time.Second
)

var (
	shipRe = regexp.MustCompile(`^~[a-z-]{3,60}$`)
	roomRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	reqRe  = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	b32    = base32.StdEncoding.WithPadding(base32.NoPadding)
)

type Command struct {
	Req         string `json:"req"`
	Op          string `json:"op"`
	Room        string `json:"room"`
	Participant string `json:"participant,omitempty"`
	TTL         int    `json:"ttl,omitempty"` // seconds, lease ops only
	Subject     string `json:"subject"`
}

type Result struct {
	OK        bool   `json:"ok"`
	Req       string `json:"req"`
	Op        string `json:"op"`
	Subject   string `json:"subject"`
	Duplicate bool   `json:"duplicate,omitempty"`
	Error     string `json:"error,omitempty"`
	Group     string `json:"group,omitempty"`
	Location  string `json:"location,omitempty"`
	Token     string `json:"token,omitempty"`
	State     string `json:"state"`
	Clients   int    `json:"clients"`
	Revoked   int    `json:"revoked,omitempty"`
	Kicked    int    `json:"kicked,omitempty"`
	Gen       int64  `json:"gen"`
	Deadline  int64  `json:"deadline"` // unix UTC

	// combined call access (never logged)
	SFU         string      `json:"sfu,omitempty"`
	Participant string      `json:"participant,omitempty"`
	ICE         []ICEServer `json:"ice,omitempty"`
	// flat forms, so a typed consumer need not parse nested optional objects
	StunURLs       []string `json:"stun_urls,omitempty"`
	TurnURLs       []string `json:"turn_urls,omitempty"`
	TurnUser       string   `json:"turn_username,omitempty"`
	TurnCredential string   `json:"turn_credential,omitempty"`
	AccessExpires  int64    `json:"access_expires,omitempty"`
	RenewAfter     int64    `json:"renew_after,omitempty"`
}

var (
	db     *sql.DB
	bearer []byte
	gal    *Galene
	rooms  = NewLockRegistry()
	// Two admission classes. Sizes come from configuration at startup and
	// are RESTART-ONLY: a running semaphore is never resized.
	metaGlobSem   *Semaphore
	metaHostSem   *HostSemaphores
	rosterGlobSem *Semaphore
	rosterHostSem *HostSemaphores
	// epoch identifies THIS process. A claim carrying a different epoch
	// was made by a process that is now gone, so it may be taken over.
	epoch    = strconv.FormatInt(time.Now().UnixNano(), 36)
	dbHealth atomic.Value // dbProbe
)

type dbProbe struct {
	OK       bool
	Readable bool
	At       time.Time
	Note     string
}

// lastWrite records the outcome of the most recent REAL command write, so
// readiness reports OBSERVED writability separately from the probe. It is
// tri-state on purpose: a plain false would read as "the last write
// failed" when it may only mean "no write has happened yet".
var lastWrite atomic.Value // string: "none-since-start" | "ok" | "failed"

func lastWriteState() string {
	if v, ok := lastWrite.Load().(string); ok {
		return v
	}
	return "none-since-start"
}

// ---------- namespace ----------

func hash12(s string) string { h := sha256.Sum256([]byte(s)); return b32.EncodeToString(h[:])[:12] }
func hash16(s string) string { h := sha256.Sum256([]byte(s)); return b32.EncodeToString(h[:])[:16] }

func groupFor(host, room string) string {
	return strings.ToLower(managedPfx + hash12(host) + "-" + hash16(host+"/"+room))
}

func isManaged(g string) bool { return strings.HasPrefix(g, managedPfx) }

// ---------- storage ----------

const schema = `
CREATE TABLE IF NOT EXISTS commands (
  host TEXT NOT NULL, req TEXT NOT NULL,
  fingerprint TEXT NOT NULL, state TEXT NOT NULL,
  epoch TEXT, response TEXT, created INTEGER, updated INTEGER,
  PRIMARY KEY (host, req));
CREATE TABLE IF NOT EXISTS rooms (
  host TEXT NOT NULL, room_key TEXT NOT NULL,
  group_name TEXT NOT NULL UNIQUE, state TEXT NOT NULL,
  created INTEGER, updated INTEGER,
  PRIMARY KEY (host, room_key));
CREATE TABLE IF NOT EXISTS tickets (
  token TEXT PRIMARY KEY, group_name TEXT NOT NULL,
  participant TEXT NOT NULL, expires INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0, created INTEGER);
CREATE INDEX IF NOT EXISTS tickets_group ON tickets(group_name);
CREATE TABLE IF NOT EXISTS health (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  ok INTEGER, at INTEGER, note TEXT);
INSERT OR IGNORE INTO health(id, ok, at, note) VALUES (1, 0, 0, 'init');
`

// migrate adds M2a lease columns without disturbing M1 rows.
func migrate() error {
	if _, err := db.Exec(schema); err != nil {
		return err
	}
	// CREATE TABLE IF NOT EXISTS does NOT add columns to a table that
	// already exists, so every new column needs an explicit ALTER.
	hasCol := func(table, col string) bool {
		var n int
		db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?`,
			table, col).Scan(&n)
		return n > 0
	}
	// commands.epoch identifies the process that claimed a request, so a
	// claim left by a dead process can be safely taken over.
	if !hasCol("commands", "epoch") {
		if _, err := db.Exec(`ALTER TABLE commands ADD COLUMN epoch TEXT`); err != nil {
			return err
		}
	}
	// A ticket records the command key that produced it, so a resumed
	// command can adopt its predecessor's ticket instead of minting a
	// second one. Backfilled NULL: pre-existing tickets adopt nothing.
	for _, col := range []string{"host", "req"} {
		if !hasCol("tickets", col) {
			if _, err := db.Exec(`ALTER TABLE tickets ADD COLUMN ` + col + ` TEXT`); err != nil {
				return err
			}
		}
	}
	// 2b.2: a ticket row is either a capacity RESERVATION or a real ISSUED
	// credential. Every pre-existing row is a real one.
	if !hasCol("tickets", "state") {
		if _, err := db.Exec(`ALTER TABLE tickets ADD COLUMN state TEXT NOT NULL DEFAULT 'issued'`); err != nil {
			return err
		}
		if _, err := db.Exec(`UPDATE tickets SET state='issued' WHERE state IS NULL OR state=''`); err != nil {
			return err
		}
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS rooms_state ON rooms(state)`); err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS commands_host ON commands(host)`); err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS tickets_cmd
	  ON tickets(host,req)`); err != nil {
		return err
	}
	cols := map[string]bool{}
	for _, c := range []string{"gen", "deadline"} {
		cols[c] = hasCol("rooms", c)
	}
	// gen: monotonic lease generation. deadline: durable UTC unix seconds.
	if !cols["gen"] {
		if _, err := db.Exec(`ALTER TABLE rooms ADD COLUMN gen INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	if !cols["deadline"] {
		if _, err := db.Exec(`ALTER TABLE rooms ADD COLUMN deadline INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	// Pre-existing M1 rooms have gen=0/deadline=0. Give them a live lease
	// so they are not swept the instant this version starts.
	_, err := db.Exec(`UPDATE rooms SET gen=1, deadline=?
	  WHERE state='active' AND deadline=0`, time.Now().Add(leaseDefaultTTL).Unix())
	// the old readyz probe table is no longer used
	db.Exec(`DROP TABLE IF EXISTS _probe`)
	return err
}

func fingerprint(c Command) string {
	return hash16(c.Op + "|" + c.Room + "|" + c.Participant + "|" +
		strconv.Itoa(c.TTL) + "|" + c.Subject)
}

// clampTTL uses the live configuration when one is loaded, so lease bounds
// are genuinely reloadable; it falls back to the compiled-in constants only
// before configuration exists (tests, early startup).
func clampTTL(sec int) time.Duration {
	minT, defT, maxT := leaseMinTTL, leaseDefaultTTL, leaseMaxTTL
	if l := CurrentLimits(); l != nil {
		minT, defT, maxT = l.LeaseMinTTL, l.LeaseDefaultTTL, l.LeaseMaxTTL
	}
	if sec <= 0 {
		return defT
	}
	d := time.Duration(sec) * time.Second
	if d < minT {
		return minT
	}
	if d > maxT {
		return maxT
	}
	return d
}

func opEnsureRoom(c Command) Result {
	l := CurrentLimits()
	g := groupFor(c.Subject, c.Room)
	var state string
	var gen, deadline int64
	err := db.QueryRow(`SELECT state,gen,deadline FROM rooms WHERE host=? AND room_key=?`,
		c.Subject, c.Room).Scan(&state, &gen, &deadline)
	fresh := errors.Is(err, sql.ErrNoRows)
	if err != nil && !fresh {
		return Result{Error: "db"}
	}
	// An ALREADY-ACTIVE room is confirmed, not renewed: ensure must never
	// extend a lease. This path consumes NO quota -- it creates nothing.
	if !fresh && state == "active" && deadline > time.Now().Unix() {
		return Result{OK: true, Group: g, State: "active", Gen: gen, Deadline: deadline}
	}
	// A reservation already exists for this key: either a sibling request is
	// mid-flight or a crashed one is awaiting recovery. Never double-reserve.
	if !fresh && state == "provisioning" {
		return Result{Error: "room-provisioning"}
	}

	now := time.Now()
	dl := now.Add(clampTTL(c.TTL)).Unix()
	newGen := gen + 1

	// RESERVE FIRST. Capacity is claimed by a single conditional statement
	// whose WHERE clause holds the counts, so two callers at the boundary
	// cannot both win. No transaction is open across the Galene call below.
	var got bool
	if fresh {
		got, err = reserveNewRoom(c.Subject, c.Room, g, newGen, dl, l)
	} else {
		got, err = reactivateRoom(c.Subject, c.Room, g, newGen, dl, l)
	}
	if err != nil {
		return Result{Error: "db-room"}
	}
	if !got {
		ctr.QuotaRoom.Add(1)
		return Result{Error: roomQuotaBlame(c.Subject, l)}
	}
	failpoint("EN-AFTER-RESERVE")

	// External creation. max-clients is Galene's OWN per-group cap, so the
	// per-room participant limit is enforced on actual connected clients
	// rather than approximated from issued tickets.
	if e := gal.PutGroup(g, map[string]any{
		"public": false, "auto-subgroups": false, "autokick": false,
		"max-clients": l.ParticipantsPerRoom,
	}); e != nil {
		ctr.GaleneFailures.Add(1)
		releaseRoomReservation(c.Subject, c.Room)
		return Result{Error: "galene-group"}
	}
	failpoint("EN-AFTER-GROUP")
	if e := activateRoom(c.Subject, c.Room); e != nil {
		return Result{Error: "db-room"}
	}
	return Result{OK: true, Group: g, State: "active", Gen: newGen, Deadline: dl}
}

func opRenewRoom(c Command) Result {
	g, st, gen, dl, err := roomOf(c)
	if errors.Is(err, sql.ErrNoRows) {
		return Result{Error: "no-such-room"}
	} else if err != nil {
		return Result{Error: "db"}
	}
	if st != "active" {
		return Result{Error: "room-" + st}
	}
	if dl <= time.Now().Unix() {
		return Result{Error: "lease-expired"}
	}
	now := time.Now()
	nd := now.Add(clampTTL(c.TTL)).Unix()
	ng := gen + 1
	res, e := db.Exec(`UPDATE rooms SET gen=?, deadline=?, updated=?
	  WHERE host=? AND room_key=? AND gen=? AND state='active'`,
		ng, nd, now.Unix(), c.Subject, c.Room, gen)
	if e != nil {
		return Result{Error: "db-renew"}
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Result{Error: "lease-raced"}
	}
	return Result{OK: true, Group: g, State: "active", Gen: ng, Deadline: nd}
}

func roomOf(c Command) (string, string, int64, int64, error) {
	var g, st string
	var gen, dl int64
	err := db.QueryRow(`SELECT group_name,state,gen,deadline FROM rooms
	  WHERE host=? AND room_key=?`, c.Subject, c.Room).Scan(&g, &st, &gen, &dl)
	return g, st, gen, dl, err
}

// ticketExpiryFor keeps ordinary invitation tickets short-lived, while a
// call-access token remains usable for the same window as the TURN
// credential it accompanies. This matters after a transient websocket
// loss: the browser needs both credentials in order to reconnect.
func ticketExpiryFor(c Command, l *Limits, deadline int64, now time.Time) time.Time {
	ttl := ticketTTL
	if l != nil && l.TicketTTL > 0 {
		ttl = l.TicketTTL
	}
	if c.Op == "issue-access" || c.Op == "renew-access" {
		ttl = accessTTLDefault
		if l != nil && l.AccessTTL > 0 {
			ttl = l.AccessTTL
		}
	}
	exp := now.Add(ttl)
	if exp.Unix() > deadline {
		exp = time.Unix(deadline, 0)
	}
	return exp
}

func opIssueTicket(c Command) Result {
	l := CurrentLimits()
	if !shipRe.MatchString(c.Participant) {
		return Result{Error: "bad-participant"}
	}
	g, st, gen, dl, err := roomOf(c)
	if errors.Is(err, sql.ErrNoRows) {
		return Result{Error: "no-such-room"}
	} else if err != nil {
		return Result{Error: "db"}
	}
	if st != "active" {
		return Result{Error: "room-" + st}
	}
	if dl <= time.Now().Unix() {
		return Result{Error: "lease-expired"}
	}

	// AT-MOST-ONCE. A resumed command adopts the ticket its crashed
	// predecessor already issued instead of minting a second one. Only a
	// fully ISSUED row may be adopted; a bare reservation is not a ticket.
	var prior, priorGrp string
	var priorExp int64
	if e := db.QueryRow(`SELECT token,group_name,expires FROM tickets
	  WHERE host=? AND req=? AND revoked=0 AND state='issued'`, c.Subject, c.Req).
		Scan(&prior, &priorGrp, &priorExp); e == nil &&
		priorGrp == g && priorExp > time.Now().Unix() {
		log.Printf("event=ticket-adopted host=%s req=%s", c.Subject, c.Req)
		return Result{OK: true, Group: g, Location: gal.Location(g),
			Token: prior, Gen: gen, Deadline: dl}
	}

	exp := ticketExpiryFor(c, l, dl, time.Now())

	// GLOBAL CONNECTED-PARTICIPANT LIMIT. Galene's admin .stats endpoint is
	// a single ~12ms REST call listing only groups that currently have
	// clients, so this is an authoritative LIVE count across managed
	// groups -- not a ticket-count approximation and not a roster
	// websocket cycle. Per-room is enforced natively by Galene's
	// max-clients; this covers the global budget.
	//
	// Honest limitation: a ticket is permission to join, not a join, so
	// this is an ADMISSION gate evaluated at issuance. It is not atomic
	// with respect to joins that happen afterwards.
	if l != nil && l.ParticipantsGlobal > 0 {
		if n, e := gal.ManagedClientCount(); e == nil && n >= l.ParticipantsGlobal {
			ctr.QuotaParticipant.Add(1)
			return Result{Error: "participant-quota"}
		}
	}

	// RESERVE BEFORE MINTING. No external token is ever created after a
	// quota rejection, and concurrent issuance cannot overshoot the cap.
	got, e := reserveTicket(c.Subject, c.Req, g, c.Participant, exp.Unix(), l)
	if e != nil {
		return Result{Error: "db-ticket"}
	}
	if !got {
		ctr.QuotaTicket.Add(1)
		return Result{Error: ticketQuotaBlame(c.Subject, g, l)}
	}

	failpoint("IT-AFTER-RESERVE")
	tok, err := gal.CreateToken(g, c.Participant, []string{"present"}, exp)
	if err != nil {
		ctr.GaleneFailures.Add(1)
		releaseTicketReservation(c.Subject, c.Req)
		return Result{Error: "galene-token"}
	}
	failpoint("IT-AFTER-TOKEN")
	if e := issueTicket(c.Subject, c.Req, tok); e != nil {
		// The token exists but we cannot record it. Revoke it rather than
		// leave a live credential nothing tracks.
		gal.DeleteToken(g, tok)
		releaseTicketReservation(c.Subject, c.Req)
		return Result{Error: "db-ticket"}
	}
	return Result{OK: true, Group: g, Location: gal.Location(g), Token: tok,
		Gen: gen, Deadline: dl}
}

func revokeFor(g, participant string) int {
	rows, err := db.Query(`SELECT token FROM tickets
	  WHERE group_name=? AND participant=? AND revoked=0 AND state='issued'`, g, participant)
	if err != nil {
		return 0
	}
	var toks []string
	for rows.Next() {
		var t string
		if rows.Scan(&t) == nil {
			toks = append(toks, t)
		}
	}
	rows.Close()
	n := 0
	for _, t := range toks {
		if e := gal.DeleteToken(g, t); e == nil || strings.Contains(e.Error(), "404") {
			db.Exec(`UPDATE tickets SET revoked=1 WHERE token=?`, t)
			n++
		}
	}
	return n
}

func revokeAll(g string) int {
	rows, err := db.Query(`SELECT token FROM tickets
	  WHERE group_name=? AND revoked=0 AND state='issued'`, g)
	if err != nil {
		return 0
	}
	var toks []string
	for rows.Next() {
		var t string
		if rows.Scan(&t) == nil {
			toks = append(toks, t)
		}
	}
	rows.Close()
	n := 0
	for _, t := range toks {
		if e := gal.DeleteToken(g, t); e == nil || strings.Contains(e.Error(), "404") {
			db.Exec(`UPDATE tickets SET revoked=1 WHERE token=?`, t)
			n++
		}
	}
	// orphans reconciled into the same sweep, so expiry revokes everything
	if ids, e := gal.ListTokens(g); e == nil {
		for _, id := range ids {
			var known int
			db.QueryRow(`SELECT COUNT(*) FROM tickets WHERE token=?`, id).Scan(&known)
			if known == 0 && gal.DeleteToken(g, id) == nil {
				n++
			}
		}
	}
	return n
}

func opEvict(c Command) Result {
	if !shipRe.MatchString(c.Participant) {
		return Result{Error: "bad-participant"}
	}
	g, st, gen, _, err := roomOf(c)
	if errors.Is(err, sql.ErrNoRows) {
		return Result{Error: "no-such-room"}
	} else if err != nil {
		return Result{Error: "db"}
	}
	if st == "ended" {
		return Result{OK: true, Group: g, State: st}
	}
	// DURABLE INTENT BEFORE EXTERNAL WORK. Revocation stops a participant
	// getting a NEW credential but does not disconnect the session they
	// already hold, so a crash between revoke and kick would otherwise
	// leave them connected with nothing recording that an eviction is
	// owed. The intent is bound to the room generation, so it can never be
	// applied to a later incarnation of a reused room key.
	if e := recordEvictionIntent(c.Subject, c.Room, c.Participant, g, gen); e != nil {
		return Result{Error: "db"}
	}
	failpoint("EV-INTENT")

	rev := revokeFor(g, c.Participant)
	failpoint("EV-AFTER-REVOKE")

	kicked, err := gal.KickUntilAbsent(g, c.Participant)
	if err != nil {
		ctr.GaleneFailures.Add(1)
		// Intent deliberately left in place; the sweeper retries it.
		return Result{Error: "evict-unstable"}
	}
	failpoint("EV-AFTER-KICK")

	clearEvictionIntent(c.Subject, c.Room, c.Participant, gen)
	_, _, gen2, dl2, _ := roomOf(c)
	return Result{OK: true, Group: g, State: st, Revoked: rev, Kicked: kicked,
		Gen: gen2, Deadline: dl2}
}

func endRoomLifecycle(host, roomKey, g string) (int, int, error) {
	// 1. block issuance
	db.Exec(`UPDATE rooms SET state='ending',updated=? WHERE host=? AND room_key=?`,
		time.Now().Unix(), host, roomKey)
	failpoint("ER-AFTER-ENDING")
	// 2. revoke everything, including orphans
	rev := revokeAll(g)
	failpoint("ER-AFTER-REVOKE")
	// 3+4. kick until stably empty
	kicked, err := gal.KickUntilEmpty(g)
	if err != nil {
		return rev, kicked, err
	}
	failpoint("ER-AFTER-KICK")
	// 5. only now delete managed configuration
	gal.DeleteGroup(g)
	failpoint("ER-AFTER-DELETE")
	// 6. durable final state
	db.Exec(`UPDATE rooms SET state='ended',updated=? WHERE host=? AND room_key=?`,
		time.Now().Unix(), host, roomKey)
	return rev, kicked, nil
}
func opEndRoom(c Command) Result {
	g, st, _, _, err := roomOf(c)
	if errors.Is(err, sql.ErrNoRows) {
		return Result{Error: "no-such-room"}
	} else if err != nil {
		return Result{Error: "db"}
	}
	_, _, gen0, dl0, _ := roomOf(c)
	if st == "ended" {
		return Result{OK: true, Group: g, State: "ended", Gen: gen0, Deadline: dl0}
	}
	rev, kicked, e := endRoomLifecycle(c.Subject, c.Room, g)
	if e != nil {
		return Result{Error: "end-unstable"}
	}
	return Result{OK: true, Group: g, State: "ended", Revoked: rev, Kicked: kicked,
		Gen: gen0, Deadline: dl0}
}

func opStatus(c Command) Result {
	g, st, gen, dl, err := roomOf(c)
	if errors.Is(err, sql.ErrNoRows) {
		return Result{Error: "no-such-room"}
	} else if err != nil {
		return Result{Error: "db"}
	}
	n, _ := gal.CountClients(g)
	return Result{OK: true, Group: g, State: st, Clients: n, Gen: gen, Deadline: dl}
}

// ---------- lease sweeper ----------

// sweepLeases finds expired active rooms and finishes them. It runs the
// same lifecycle as end-room. The generation+deadline compare below is
// what makes a stale worker inert after a renewal.
func sweepLeases() {
	now := time.Now().Unix()
	rows, err := db.Query(`SELECT host,room_key,group_name,gen,deadline FROM rooms
	  WHERE state='active' AND deadline>0 AND deadline<=?`, now)
	if err != nil {
		return
	}
	type job struct {
		host, key, grp string
		gen, dl        int64
	}
	var jobs []job
	for rows.Next() {
		var j job
		if rows.Scan(&j.host, &j.key, &j.grp, &j.gen, &j.dl) == nil {
			jobs = append(jobs, j)
		}
	}
	rows.Close()

	for _, j := range jobs {
		rel := rooms.Acquire(j.host + "\x00" + j.key)
		// TRANSACTIONAL STALENESS CHECK: only claim the room if the
		// generation AND deadline are still exactly what we observed. A
		// renewal bumps gen, so this affects 0 rows and we do nothing.
		res, e := db.Exec(`UPDATE rooms SET state='ending',updated=?
		  WHERE host=? AND room_key=? AND gen=? AND deadline=? AND state='active'`,
			time.Now().Unix(), j.host, j.key, j.gen, j.dl)
		if e != nil {
			rel()
			continue
		}
		if n, _ := res.RowsAffected(); n == 0 {
			log.Printf("event=lease-stale host=%s gen=%d", j.host, j.gen)
			rel()
			continue
		}
		ctr.LeaseExpired.Add(1)
		log.Printf("event=lease-expire host=%s gen=%d", j.host, j.gen)
		if _, _, err := endRoomLifecycle(j.host, j.key, j.grp); err != nil {
			log.Printf("event=lease-expire-incomplete host=%s gen=%d", j.host, j.gen)
		}
		rel()
	}
}

// sweepEnding resumes rooms abandoned mid-teardown. endRoomLifecycle is
// idempotent -- re-revoking revoked tickets, kicking an empty or absent
// group, and deleting an absent group are all no-ops -- so a process that
// died between the 'ending' write and the 'ended' write recovers here
// instead of leaving the room stuck forever.
func sweepEnding() {
	rows, err := db.Query(`SELECT host,room_key,group_name FROM rooms
	  WHERE state='ending' AND updated<=?`, time.Now().Add(-endingGrace).Unix())
	if err != nil {
		return
	}
	type job struct{ host, key, grp string }
	var jobs []job
	for rows.Next() {
		var j job
		if rows.Scan(&j.host, &j.key, &j.grp) == nil {
			jobs = append(jobs, j)
		}
	}
	rows.Close()

	for _, j := range jobs {
		rel := rooms.Acquire(j.host + "\x00" + j.key)
		// Re-read under the lock: a live end-room may have finished while
		// this job was queued, and must not be redone.
		var st string
		if e := db.QueryRow(`SELECT state FROM rooms WHERE host=? AND room_key=?`,
			j.host, j.key).Scan(&st); e != nil || st != "ending" {
			rel()
			continue
		}
		if _, _, e := endRoomLifecycle(j.host, j.key, j.grp); e != nil {
			log.Printf("event=ending-recover-incomplete host=%s", j.host)
		} else {
			ctr.EndingRecovered.Add(1)
			log.Printf("event=ending-recovered host=%s", j.host)
		}
		rel()
	}
}

// ---------- orphan reconciliation ----------

func reconcile() {
	groups, err := gal.ListGroups()
	if err != nil {
		log.Printf("event=reconcile-skip reason=list-groups")
		return
	}
	removed := 0
	for _, g := range groups {
		if !isManaged(g) {
			continue // never touch nbdev or anything manual
		}
		var owned int
		db.QueryRow(`SELECT COUNT(*) FROM rooms WHERE group_name=?`, g).Scan(&owned)
		if owned == 0 {
			continue
		}
		ids, err := gal.ListTokens(g)
		if err != nil {
			continue
		}
		for _, id := range ids {
			var known int
			db.QueryRow(`SELECT COUNT(*) FROM tickets WHERE token=?`, id).Scan(&known)
			if known == 0 {
				if gal.DeleteToken(g, id) == nil {
					removed++
				}
			}
		}
	}
	if removed > 0 {
		log.Printf("event=reconcile removed_orphans=%d", removed)
	}
}

// ---------- http ----------

// opClass decides which admission pool an operation belongs to. Meta ops
// are a single sub-20ms Galene REST call; roster ops open one or more fresh
// operator websocket sessions and take seconds.
// rateFor selects the creation-rate bucket for an operation, or nil when
// the operation creates nothing and only the general limiter applies.
func rateFor(op string, l *Limits) (string, int, int, *rateLimiter) {
	switch op {
	case "ensure-room":
		return "rooms", l.RateRoomsPerMin, l.RateRoomsBurst, rlRooms
	case "issue-ticket", "issue-access", "renew-access":
		return "tickets", l.RateTicketsPerMin, l.RateTicketsBurst, rlTickets
	case "room-status", "evict-participant", "end-room":
		return "roster", l.RateRosterPerMin, l.RateRosterBurst, rlRoster
	}
	return "", 0, 0, nil
}

func opClass(op string) string {
	switch op {
	case "room-status", "evict-participant", "end-room":
		return "roster"
	default:
		return "meta"
	}
}

func execute(c Command) Result {
	switch c.Op {
	case "ensure-room":
		return opEnsureRoom(c)
	case "renew-room":
		return opRenewRoom(c)
	case "issue-ticket":
		return opIssueTicket(c)
	case "evict-participant":
		return opEvict(c)
	case "end-room":
		return opEndRoom(c)
	case "room-status":
		return opStatus(c)
	case "issue-access":
		return opIssueAccess(c)
	case "renew-access":
		return opRenewAccess(c)
	}
	return Result{Error: "unknown-op"}
}

// claim atomically reserves [host,req]. Returns (proceed, stableResult).
// This is INDEPENDENT of room locking: idempotency is decided in SQLite.
func claim(c Command, fp string) (bool, *Result) {
	now := time.Now().Unix()
	inserted, capped, err := claimWithCap(c.Subject, c.Req, fp, epoch, CurrentLimits())
	if err != nil {
		return false, &Result{Error: "db"}
	}
	if capped {
		// Refused before any work; no room, ticket or lease state changed.
		ctr.QuotaCommandCap.Add(1)
		return false, &Result{Req: c.Req, Op: c.Op, Subject: c.Subject,
			Error: "command-cap"}
	}
	if inserted {
		return true, nil // we own it
	}
	var state, resp, oldfp, ep string
	if err := db.QueryRow(`SELECT state,COALESCE(response,''),fingerprint,COALESCE(epoch,'')
	  FROM commands WHERE host=? AND req=?`, c.Subject, c.Req).
		Scan(&state, &resp, &oldfp, &ep); err != nil {
		return false, &Result{Error: "db"}
	}
	if oldfp != fp {
		// A conflicting fingerprint stays a conflict in EVERY state,
		// including against a tombstone.
		ctr.CmdConflict.Add(1)
		log.Printf("event=conflict host=%s req=%s", c.Subject, c.Req)
		return false, &Result{Req: c.Req, Op: c.Op, Subject: c.Subject,
			Error: "request-id-reused-with-different-body"}
	}
	// TOMBSTONE. The full result was intentionally pruned, so we do not
	// invent one. The external operation must never run again under this
	// id; the caller is told to use a new request id. Only once the
	// tombstone itself expires may the id be treated as new.
	if state == cmdRetired {
		ctr.CmdRetiredReplay.Add(1)
		log.Printf("event=retired-replay host=%s req=%s op=%s", c.Subject, c.Req, c.Op)
		return false, &Result{Req: c.Req, Op: c.Op, Subject: c.Subject,
			Error: "request-retired"}
	}
	if state == "done" {
		var out Result
		json.Unmarshal([]byte(resp), &out)
		out.Duplicate = true
		ctr.CmdDuplicate.Add(1)
		log.Printf("event=duplicate host=%s req=%s op=%s", c.Subject, c.Req, c.Op)
		return false, &out
	}
	// state == "claimed"
	if ep == epoch {
		// genuinely in flight in THIS process: never start a second
		// external operation for the same key.
		log.Printf("event=in-progress host=%s req=%s op=%s", c.Subject, c.Req, c.Op)
		return false, &Result{Req: c.Req, Op: c.Op, Subject: c.Subject,
			Error: "in-progress"}
	}
	// claimed by a process that is gone: take it over and resume.
	// COALESCE, not a bare comparison: the failure path stores epoch=NULL,
	// and `epoch = ''` never matches NULL in SQL. Without this the takeover
	// affects zero rows and every retry of a FAILED command returns
	// in-progress forever -- the opposite of the intended "failures stay
	// claimable so the same request id may be retried".
	r, err := db.Exec(`UPDATE commands SET epoch=?,updated=?
	  WHERE host=? AND req=? AND COALESCE(epoch,'')=?`,
		epoch, now, c.Subject, c.Req, ep)
	if err != nil {
		return false, &Result{Error: "db"}
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return false, &Result{Error: "in-progress"}
	}
	ctr.CmdTakeover.Add(1)
	log.Printf("event=resume host=%s req=%s op=%s", c.Subject, c.Req, c.Op)
	return true, nil
}

func handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, Result{Error: "method-not-allowed"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(
		r.Header.Get("Authorization"), "Bearer ")), bearer) != 1 {
		writeJSON(w, 401, Result{Error: "unauthorized"})
		return
	}
	if ct := strings.Split(r.Header.Get("Content-Type"), ";")[0]; strings.TrimSpace(ct) != "application/json" {
		writeJSON(w, 415, Result{Error: "unsupported-media-type"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		writeJSON(w, 413, Result{Error: "body-too-large"})
		return
	}
	var c Command
	if json.Unmarshal(body, &c) != nil {
		writeJSON(w, 400, Result{Error: "malformed-json"})
		return
	}
	if !shipRe.MatchString(c.Subject) || !reqRe.MatchString(c.Req) || !roomRe.MatchString(c.Room) {
		writeJSON(w, 400, Result{Error: "bad-request"})
		return
	}

	// ---- admission, in ONE fixed order: per-host -> global -> per-room
	//
	// PER-HOST IS ACQUIRED FIRST, DELIBERATELY. If the global slot were
	// taken first, a request would sit waiting for its host slot while
	// still holding global capacity, and one noisy host could starve
	// unrelated hosts. Two classes now: meta ops are cheap REST calls,
	// roster ops open Galene operator websocket sessions and take seconds.
	lim := CurrentLimits()
	class := opClass(c.Op)
	now := time.Now()

	// General request rate limit: counts EVERY request, duplicates included.
	if !rlRequests.Allow(c.Subject, lim.RateRequestsPerMin, lim.RateRequestsBurst, now) {
		ctr.RateRequests.Add(1)
		writeJSON(w, 200, Result{Req: c.Req, Op: c.Op, Subject: c.Subject,
			Error: "rate-limited-requests"})
		return
	}

	hs, gs, wait := metaHostSem, metaGlobSem, lim.MetaAdmitWait
	if class == "roster" {
		hs, gs, wait = rosterHostSem, rosterGlobSem, lim.RosterAdmitWait
	}
	ctx, cancel := context.WithTimeout(r.Context(), opDeadline)
	defer cancel()

	relHost, ok := hs.Acquire(ctx, c.Subject, wait)
	if !ok {
		if class == "roster" {
			ctr.BusyHostRoster.Add(1)
		} else {
			ctr.BusyHostMeta.Add(1)
		}
		writeJSON(w, 200, Result{Req: c.Req, Op: c.Op, Subject: c.Subject,
			Error: "busy-host"})
		return
	}
	defer relHost()
	if !gs.Acquire(ctx, wait) {
		if class == "roster" {
			ctr.BusyGlobalRoster.Add(1)
		} else {
			ctr.BusyGlobalMeta.Add(1)
		}
		writeJSON(w, 200, Result{Req: c.Req, Op: c.Op, Subject: c.Subject,
			Error: "busy-global"})
		return
	}
	defer gs.Release()
	if class == "roster" {
		ctr.RosterAdmitted.Add(1)
	} else {
		ctr.MetaAdmitted.Add(1)
	}

	fp := fingerprint(c)
	// Idempotency is claimed BEFORE the room lock and independently of it.
	proceed, stable := claim(c, fp)
	if !proceed {
		stable.Req, stable.Op, stable.Subject = c.Req, c.Op, c.Subject
		// A conflict, an in-progress duplicate and a retired request id are
		// DEFINITIVE answers about the request, not gateway failures. They
		// go through statusFor like every other business outcome, so the
		// reason survives the gateway -- which forwards only 200 -- and
		// reaches the calling ship. Hardcoding 409 here made every one of
		// them arrive as an opaque transport error.
		code := statusFor(*stable)
		if stable.Error == "db" {
			code = 500
		}
		writeJSON(w, code, *stable)
		return
	}

	// Creation rate limits apply ONLY to work that is actually new. A
	// cached duplicate returned above never reaches here, so it consumes no
	// room-creation, ticket-creation or roster allowance. If a limit
	// refuses the request we release the claim row we just inserted, so a
	// rejection consumes no unique-command capacity either.
	if cat, perMin, burst, rl := rateFor(c.Op, lim); rl != nil {
		if !rl.Allow(c.Subject, perMin, burst, now) {
			db.Exec(`DELETE FROM commands WHERE host=? AND req=? AND state='claimed' AND epoch=?`,
				c.Subject, c.Req, epoch)
			switch cat {
			case "rooms":
				ctr.RateRooms.Add(1)
			case "tickets":
				ctr.RateTickets.Add(1)
			case "roster":
				ctr.RateRoster.Add(1)
			}
			writeJSON(w, 200, Result{Req: c.Req, Op: c.Op, Subject: c.Subject,
				Error: "rate-limited-" + cat})
			return
		}
	}

	relRoom := rooms.Acquire(c.Subject + "\x00" + c.Room)
	failpoint("CM-AFTER-CLAIM")
	res := execute(c)
	failpoint("CM-AFTER-EXECUTE")
	relRoom() // released BEFORE writing the response

	res.Req, res.Op, res.Subject = c.Req, c.Op, c.Subject
	blob, _ := json.Marshal(res)

	if res.OK {
		if _, e := db.Exec(`UPDATE commands SET state='done',response=?,updated=?
		  WHERE host=? AND req=?`, string(blob), time.Now().Unix(), c.Subject, c.Req); e != nil {
			ctr.DBWriteFailed.Add(1)
			markDBUnhealthy("write-failed")
			writeJSON(w, 500, Result{Error: "db-commit"})
			return
		}
		lastWrite.Store("ok")
	} else {
		// failures stay claimable so the same request id may be retried
		db.Exec(`UPDATE commands SET state='claimed',epoch=NULL,updated=?
		  WHERE host=? AND req=?`, time.Now().Unix(), c.Subject, c.Req)
	}
	log.Printf("event=command host=%s req=%s op=%s ok=%v err=%s",
		c.Subject, c.Req, c.Op, res.OK, res.Error)
	writeJSON(w, statusFor(res), res)
}

// A definitive answer is not a bad gateway. Business outcomes -- the room
// does not exist, the lease expired, the room already ended -- are returned
// as 200 with ok:false so the caller learns the actual reason. 502 is
// reserved for failures where the warden could not complete the operation
// at all. Collapsing both into 502 made every failure reach the ship as an
// opaque transport error.
//
// The map is an allowlist: an error not named here stays 502, so a newly
// added infrastructure failure never silently reads as a clean answer.
var businessErrors = map[string]bool{
	"no-such-room":      true,
	"room-ended":        true,
	"room-ending":       true,
	"room-provisioning": true,
	"lease-expired":     true,
	"bad-participant":   true,
	"unknown-op":        true,
	// 2b.2: admission, rate and quota outcomes are DEFINITIVE answers, not
	// gateway failures. They are returned as 200 with ok:false and a
	// distinct reason so the reason survives the gateway and reaches the
	// ship; the gateway discards the body of any non-200 response.
	"busy-host":                             true,
	"busy-global":                           true,
	"rate-limited-requests":                 true,
	"rate-limited-rooms":                    true,
	"rate-limited-tickets":                  true,
	"rate-limited-roster":                   true,
	"room-quota":                            true,
	"room-quota-host":                       true,
	"room-quota-global":                     true,
	"ticket-quota":                          true,
	"ticket-quota-room":                     true,
	"ticket-quota-host":                     true,
	"command-cap":                           true,
	"request-retired":                       true,
	"participant-quota":                     true,
	"request-id-reused-with-different-body": true,
	"in-progress":                           true,
	"service-unavailable":                   true,
}

func statusFor(res Result) int {
	if res.OK || businessErrors[res.Error] {
		return 200
	}
	return 502
}

// Safe accessors for health: configuration identity only, never the secret.
func turnSafeSFU() string {
	if turnCfg == nil {
		return ""
	}
	return turnCfg.sfuWS
}
func turnSafeRealm() string {
	if turnCfg == nil {
		return ""
	}
	return turnCfg.realm
}
func accessTTLString() string {
	if l := CurrentLimits(); l != nil && l.AccessTTL > 0 {
		return l.AccessTTL.String()
	}
	return accessTTLDefault.String()
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// ---------- health ----------

// probeDB writes a bounded heartbeat so readyz never becomes a competing
// writer on the request path.
// readiness reports only what it actually checked this call. Nothing here
// is cached optimistically: a stale DB probe is reported with its age, and
// Galene is contacted live.
func readiness() (int, map[string]any) {
	p, _ := dbHealth.Load().(dbProbe)
	galOK := true
	if _, e := gal.ListGroups(); e != nil {
		galOK = false
	}
	age := int64(time.Since(p.At).Seconds())
	if p.At.IsZero() {
		age = -1
	}
	metaHostCur, metaHostHW, metaHosts := metaHostSem.Snapshot()
	rosterHostCur, rosterHostHW, rosterHosts := rosterHostSem.Snapshot()
	lim := CurrentLimits()
	cfg := map[string]any{"loaded": false}
	if lim != nil {
		loadedAt, _ := limitsLoaded.Load().(time.Time)
		pending := lim.RestartRequired(BootLimits())
		if pending == nil {
			pending = []string{}
		}
		cfg = map[string]any{
			"loaded":                 true,
			"generation":             limitsGen.Load(),
			"loaded_at":              loadedAt.UTC().Format(time.RFC3339),
			"enforced":               true,
			"failpoints_compiled_in": failpointsCompiledIn,
			"restart_required":       pending,
			// Stated precisely: Galene enforces max-clients per group, so
			// the per-room participant limit is real. There is no global
			// live-client cap; see participant_limits below.
			"participant_limits": map[string]any{
				"per_room_enforced_by": "galene max-clients",
				"per_room":             lim.ParticipantsPerRoom,
				"global_configured":    lim.ParticipantsGlobal,
				"global_enforced":      true,
				"global_enforced_by":   "galene .stats live managed client count, checked at ticket issuance",
				"note":                 "admission gate at issuance; a ticket is permission to join, so it is not atomic with respect to later joins",
			},
		}
	}
	out := map[string]any{
		"configured": true,
		// Readability is probed. Writability is NOT probed; it is
		// reported only as observed from real command writes.
		"db_readable":      p.Readable,
		"db_last_write":    lastWriteState(),
		"db_probe_scope":   "readability probed; writability observed from real writes only",
		"db_ready":         p.OK && lastWriteState() != "failed",
		"db_probe_note":    p.Note,
		"db_probe_age_sec": age,
		"galene_reachable": galOK,
		"ok":               p.OK && galOK && lastWriteState() != "failed",
		"epoch":            epoch,
		"at":               time.Now().UTC().Format(time.RFC3339),
		"access": map[string]any{
			"combined_response": true,
			"sfu":               turnSafeSFU(),
			"turn_realm":        turnSafeRealm(),
			"credential_ttl":    accessTTLString(),
			"note":              "coturn validates the REST expiry at ALLOCATE; an established allocation survives expiry, so the TTL covers setup and re-allocation, not call duration",
		},
		"config": cfg,
		"admission": map[string]any{
			"order": "per-host -> global -> per-room",
			"meta": map[string]any{
				"global_slots": lim.MetaGlobalSlots, "host_slots": lim.MetaHostSlots,
				"global_in_use": metaGlobSem.InUse(), "global_high_water": metaGlobSem.HighWater(),
				"host_max_in_use": metaHostCur, "host_high_water": metaHostHW,
				"hosts_tracked": metaHosts, "admit_wait": lim.MetaAdmitWait.String(),
			},
			"roster": map[string]any{
				"global_slots": lim.RosterGlobalSlots, "host_slots": lim.RosterHostSlots,
				"global_in_use": rosterGlobSem.InUse(), "global_high_water": rosterGlobSem.HighWater(),
				"host_max_in_use": rosterHostCur, "host_high_water": rosterHostHW,
				"hosts_tracked": rosterHosts, "admit_wait": lim.RosterAdmitWait.String(),
			},
		},
		"counters": ctr.snapshot(),
		"rate_buckets": map[string]any{
			"requests": rlRequests.Size(), "rooms": rlRooms.Size(),
			"tickets": rlTickets.Size(), "roster": rlRoster.Size(),
		},
	}
	code := 200
	if !p.OK || !galOK || lastWriteState() == "failed" {
		code = 503
	}
	return code, out
}

// probeDB is READ-ONLY and its scope is stated honestly.
//
// It replaced a periodic UPDATE that wrote to the WAL every cycle purely
// to answer health checks. A BEGIN IMMEDIATE "writability" probe was
// trialled and REMOVED: measured against this driver it reported writable
// whenever the connection opened, so it proved nothing the SELECT did not,
// while taking a write lock on every cycle.
//
// What this probe DOES detect: because the database is in WAL mode, a
// connection must be able to create and write -wal/-shm. A read-only mount
// or lost permissions therefore fails the connection outright and the
// SELECT below fails with it.
//
// What it does NOT detect: a full disk or exhausted quota, where reads
// succeed and only writes fail. That is reported separately and only once
// observed, via db_last_write -- health never claims to have proven
// current writability.
func probeDB() {
	var n int
	if err := db.QueryRow(`SELECT ok FROM health WHERE id=1`).Scan(&n); err != nil {
		dbHealth.Store(dbProbe{OK: false, Readable: false, At: time.Now(), Note: "read-failed"})
		return
	}
	dbHealth.Store(dbProbe{OK: true, Readable: true, At: time.Now(), Note: "ok"})
}

// markDBUnhealthy records a real write failure observed on the command
// path, so readiness stops claiming the database is usable.
func markDBUnhealthy(note string) {
	lastWrite.Store("failed")
	p, _ := dbHealth.Load().(dbProbe)
	p.OK, p.Note, p.At = false, note, time.Now()
	dbHealth.Store(p)
}

// ---------- configuration (2b.1) ----------
//
// Loaded and validated, but NOT ENFORCED in this phase. Admission still
// uses the compiled-in globalSlots/hostSlots constants below; no quota,
// participant limit, rate or retention value here changes any request
// outcome yet. See config.go.

var (
	limitsPath   string
	limitsLoaded atomic.Value // time.Time
	limitsGen    atomic.Int64 // increments on every successful install
)

// reloadLimits validates a whole new snapshot and swaps it atomically.
// On failure the previous snapshot stays live and nothing is mutated, so a
// partial configuration can never become active.
func reloadLimits() {
	l, err := LoadLimits(limitsPath)
	if err != nil {
		// Concise, bounded, and never the file body. Key names are the
		// operator's own and carry no secrets.
		log.Printf("event=config-reload-failed error=%q keeping=last-known-good", err.Error())
		return
	}
	InstallLimits(l)
	limitsLoaded.Store(time.Now())
	gen := limitsGen.Add(1)

	// Truthfulness: a restart-only value that differs from what this
	// process started with has NOT taken effect, and we say so rather than
	// letting the reload look complete.
	if pending := l.RestartRequired(BootLimits()); len(pending) > 0 {
		log.Printf("event=config-reloaded gen=%d applied=live restart_required=%s",
			gen, strings.Join(pending, ","))
	} else {
		log.Printf("event=config-reloaded gen=%d applied=live restart_required=none", gen)
	}
}

func main() {
	dir := os.Getenv("WARDEN_DIR")
	if dir == "" {
		dir = "/etc/noltbook-warden"
	}
	b, err := os.ReadFile(filepath.Join(dir, "bearer"))
	if err != nil {
		log.Fatalf("bearer: %v", err)
	}
	bearer = []byte(strings.TrimSpace(string(b)))

	gal, err = NewGalene(filepath.Join(dir, "galene.env"))
	if err != nil {
		log.Fatalf("galene config: %v", err)
	}
	// TURN master secret: droplet-only, used solely to compute HMACs.
	turnCfg, err = loadTurnConfig(filepath.Join(dir, "turn.env"))
	if err != nil {
		log.Fatalf("turn config: unreadable or incomplete")
	}

	// ---- limits configuration (loaded, validated, not yet enforced)
	limitsPath = os.Getenv("WARDEN_LIMITS")
	if limitsPath == "" {
		limitsPath = filepath.Join(dir, "limits.conf")
	}
	initialLimits, err := LoadLimits(limitsPath)
	if err != nil {
		// Fail loudly: a warden running on a configuration nobody can read
		// is worse than one that refuses to start.
		log.Fatalf("limits: %v", err)
	}
	InstallBootLimits(initialLimits)
	InstallLimits(initialLimits)
	limitsLoaded.Store(time.Now())
	limitsGen.Store(1)
	// Semaphore sizes are fixed for the life of the process. A SIGHUP may
	// change these values in the file, but the running pools keep the sizes
	// they were built with and /health reports that honestly.
	metaGlobSem = NewSemaphore(initialLimits.MetaGlobalSlots)
	metaHostSem = NewHostSemaphores(initialLimits.MetaHostSlots)
	rosterGlobSem = NewSemaphore(initialLimits.RosterGlobalSlots)
	rosterHostSem = NewHostSemaphores(initialLimits.RosterHostSlots)
	log.Printf("event=config-loaded gen=1 meta_slots=%d/%d roster_slots=%d/%d enforced=true",
		initialLimits.MetaGlobalSlots, initialLimits.MetaHostSlots,
		initialLimits.RosterGlobalSlots, initialLimits.RosterHostSlots)

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			reloadLimits()
		}
	}()

	dbPath := os.Getenv("WARDEN_DB")
	if dbPath == "" {
		dbPath = "/var/lib/noltbook-warden/warden.db"
	}
	// PRAGMAs in the DSN apply to EVERY pooled connection, not just the
	// first one. A single startup PRAGMA would not survive pool growth.
	dsn := "file:" + dbPath +
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err = sql.Open("sqlite", dsn)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(8)
	// INTEGRITY GATE. A corrupt or unreadable database must refuse to
	// serve rather than operate on partial state. The message is concise
	// and operator-safe; it never echoes database contents.
	var integrity string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
		ctr.DBIntegrityFailed.Add(1)
		log.Fatalf("integrity: database unreadable")
	}
	if integrity != "ok" {
		ctr.DBIntegrityFailed.Add(1)
		log.Fatalf("integrity: database failed integrity_check (refusing to serve)")
	}
	if err := migrate(); err != nil {
		log.Fatalf("migrate: %v", err)
	}
	if err := migrateEvictions(); err != nil {
		log.Fatalf("migrate-evictions: %v", err)
	}
	dbHealth.Store(dbProbe{OK: false, At: time.Time{}, Note: "starting"})
	probeDB()

	// startup recovery: finish anything already expired, then reconcile.
	sweepLeases()
	sweepEnding()
	sweepReservations()
	sweepEvictions()
	reconcile()

	go func() {
		for range time.Tick(sweepEvery) {
			sweepLeases()
			sweepEnding()
			sweepReservations()
			sweepEvictions()
		}
	}()
	go func() {
		for range time.Tick(2 * time.Minute) {
			reconcile()
			sweepExternalTokenDrift()
		}
	}()
	go pruneLoop(dbPath)
	go func() {
		for range time.Tick(healthProbeFreq) {
			probeDB()
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/command", handle)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "epoch": epoch})
	})
	// /readyz is loopback-only (the whole listener is 127.0.0.1) and serves
	// systemd. /health is the same truth behind the bearer, so nginx can
	// expose it to the gateway without publishing an unauthenticated
	// description of our internal state.
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		code, out := readiness()
		writeJSON(w, code, out)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(
			r.Header.Get("Authorization"), "Bearer ")), bearer) != 1 {
			writeJSON(w, 401, Result{Error: "unauthorized"})
			return
		}
		code, out := readiness()
		writeJSON(w, code, out)
	})

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 120 * time.Second}
	log.Printf("event=start addr=%s namespace=%s epoch=%s global=%d host=%d",
		listenAddr, managedPfx, epoch, globalSlots, hostSlots)
	log.Fatal(srv.Serve(ln))
}

var _ = fmt.Sprintf
