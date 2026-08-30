package main

// Milestone 2b.2 -- quotas, rate limiting and counters.
//
// The central rule here is that capacity is RESERVED atomically in SQLite
// BEFORE any external Galene object is created. A count-then-create
// sequence races: two concurrent requests both read count==limit-1 and both
// proceed. Every reservation below is therefore a single conditional
// INSERT/UPDATE whose WHERE clause contains the count, so SQLite's own
// write serialisation decides the winner. No transaction is ever held
// across network work.

import (
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------- counters

// Counters are bounded aggregates. They deliberately carry NO per-host
// label: an attacker choosing fresh subjects would otherwise grow the
// metric set without limit.
type counters struct {
	MetaAdmitted   atomic.Int64
	RosterAdmitted atomic.Int64

	BusyHostMeta     atomic.Int64
	BusyHostRoster   atomic.Int64
	BusyGlobalMeta   atomic.Int64
	BusyGlobalRoster atomic.Int64

	RateRooms    atomic.Int64
	RateTickets  atomic.Int64
	RateRoster   atomic.Int64
	RateRequests atomic.Int64

	QuotaRoom        atomic.Int64
	QuotaTicket      atomic.Int64
	QuotaParticipant atomic.Int64
	QuotaCommandCap  atomic.Int64

	ReservationReleased  atomic.Int64
	ReservationRecovered atomic.Int64
	ReservationFailed    atomic.Int64

	// 2b.3 retention
	PrunedRooms           atomic.Int64
	PrunedTickets         atomic.Int64
	PrunedCommandsRetired atomic.Int64
	PrunedTombstones      atomic.Int64
	PruneFailed           atomic.Int64
	CheckpointAttempted   atomic.Int64
	CheckpointCompleted   atomic.Int64
	CheckpointBusy        atomic.Int64
	CheckpointFailed      atomic.Int64

	// 2b.4 recovery
	EvictionIntentResumed   atomic.Int64
	EvictionIntentCompleted atomic.Int64
	EvictionIntentFailed    atomic.Int64
	EvictionIntentStale     atomic.Int64
	OrphanTokensReaped      atomic.Int64
	LeaseExpired            atomic.Int64
	EndingRecovered         atomic.Int64

	// command lifecycle
	CmdConflict      atomic.Int64
	CmdDuplicate     atomic.Int64
	CmdRetiredReplay atomic.Int64
	CmdTakeover      atomic.Int64

	// external + storage failures
	GaleneFailures    atomic.Int64
	DBWriteFailed     atomic.Int64
	DBIntegrityFailed atomic.Int64
}

var ctr counters

func (c *counters) snapshot() map[string]any {
	return map[string]any{
		"admitted_meta":   c.MetaAdmitted.Load(),
		"admitted_roster": c.RosterAdmitted.Load(),
		"busy_host": map[string]any{
			"meta": c.BusyHostMeta.Load(), "roster": c.BusyHostRoster.Load()},
		"busy_global": map[string]any{
			"meta": c.BusyGlobalMeta.Load(), "roster": c.BusyGlobalRoster.Load()},
		"rate_limited": map[string]any{
			"rooms": c.RateRooms.Load(), "tickets": c.RateTickets.Load(),
			"roster": c.RateRoster.Load(), "requests": c.RateRequests.Load()},
		"quota_rejected": map[string]any{
			"room": c.QuotaRoom.Load(), "ticket": c.QuotaTicket.Load(),
			"participant": c.QuotaParticipant.Load(), "command_cap": c.QuotaCommandCap.Load()},
		"reservations": map[string]any{
			"released":  c.ReservationReleased.Load(),
			"recovered": c.ReservationRecovered.Load(),
			"failed":    c.ReservationFailed.Load()},
		"pruned": map[string]any{
			"rooms": c.PrunedRooms.Load(), "tickets": c.PrunedTickets.Load(),
			"commands_retired": c.PrunedCommandsRetired.Load(),
			"tombstones":       c.PrunedTombstones.Load(), "failed": c.PruneFailed.Load()},
		"wal_checkpoint": map[string]any{
			"attempted": c.CheckpointAttempted.Load(), "completed": c.CheckpointCompleted.Load(),
			"busy": c.CheckpointBusy.Load(), "failed": c.CheckpointFailed.Load()},
		"recovery": map[string]any{
			"eviction_intent_resumed":   c.EvictionIntentResumed.Load(),
			"eviction_intent_completed": c.EvictionIntentCompleted.Load(),
			"eviction_intent_failed":    c.EvictionIntentFailed.Load(),
			"eviction_intent_stale":     c.EvictionIntentStale.Load(),
			"orphan_tokens_reaped":      c.OrphanTokensReaped.Load(),
			"lease_expired":             c.LeaseExpired.Load(),
			"ending_recovered":          c.EndingRecovered.Load()},
		"commands": map[string]any{
			"conflict": c.CmdConflict.Load(), "duplicate": c.CmdDuplicate.Load(),
			"retired_replay": c.CmdRetiredReplay.Load(), "takeover": c.CmdTakeover.Load()},
		"failures": map[string]any{
			"galene":       c.GaleneFailures.Load(),
			"db_write":     c.DBWriteFailed.Load(),
			"db_integrity": c.DBIntegrityFailed.Load()},
	}
}

// ------------------------------------------------------------ rate limiting

// bucket is a token bucket refilled continuously at ratePerMin.
type bucket struct {
	tokens   float64
	last     time.Time
	lastSeen time.Time
}

// rateLimiter holds one bucket per [host, category]. The map is bounded:
// idle entries are evicted, and at the hard cap the least recently seen
// entry is dropped, so an attacker cycling subjects cannot grow it.
type rateLimiter struct {
	mu   sync.Mutex
	b    map[string]*bucket
	max  int
	idle time.Duration
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{b: map[string]*bucket{}, max: 4096, idle: 30 * time.Minute}
}

// Allow consumes one token. burst is the bucket capacity; perMin the refill
// rate. Returns false when the bucket is empty.
func (r *rateLimiter) Allow(key string, perMin, burst int, now time.Time) bool {
	if perMin <= 0 || burst <= 0 {
		return true // unconfigured means unlimited, not "deny everything"
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	bk, ok := r.b[key]
	if !ok {
		if len(r.b) >= r.max {
			r.evictLocked(now)
		}
		bk = &bucket{tokens: float64(burst), last: now}
		r.b[key] = bk
	}
	// refill
	if el := now.Sub(bk.last).Seconds(); el > 0 {
		bk.tokens += el * (float64(perMin) / 60.0)
		if bk.tokens > float64(burst) {
			bk.tokens = float64(burst)
		}
		bk.last = now
	}
	bk.lastSeen = now
	if bk.tokens < 1 {
		return false
	}
	bk.tokens--
	return true
}

// evictLocked drops idle entries, then the single oldest if still full.
func (r *rateLimiter) evictLocked(now time.Time) {
	var oldestKey string
	var oldest time.Time
	for k, v := range r.b {
		if now.Sub(v.lastSeen) > r.idle {
			delete(r.b, k)
			continue
		}
		if oldest.IsZero() || v.lastSeen.Before(oldest) {
			oldest, oldestKey = v.lastSeen, k
		}
	}
	if len(r.b) >= r.max && oldestKey != "" {
		delete(r.b, oldestKey)
	}
}

func (r *rateLimiter) Size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.b)
}

var (
	rlRequests = newRateLimiter()
	rlRooms    = newRateLimiter()
	rlTickets  = newRateLimiter()
	rlRoster   = newRateLimiter()
)

// ------------------------------------------------------- room reservations

// roomStatesOccupying are the states that consume room capacity. 'ended'
// does not: an ended room key can be reused, which starts a new incarnation.
const roomStatesOccupying = `('active','provisioning','ending')`

// reserveNewRoom atomically claims room capacity by inserting the row in
// 'provisioning' state, but ONLY if both the global and per-host caps still
// permit it. The counts live inside the INSERT, so two concurrent callers
// at the boundary cannot both succeed.
//
// Returns true if this call now owns a durable reservation.
func reserveNewRoom(host, roomKey, group string, gen, deadline int64, l *Limits) (bool, error) {
	now := time.Now().Unix()
	res, err := db.Exec(`
	  INSERT INTO rooms(host,room_key,group_name,state,gen,deadline,created,updated)
	  SELECT ?,?,?,'provisioning',?,?,?,?
	  WHERE (SELECT COUNT(*) FROM rooms WHERE state IN `+roomStatesOccupying+`) < ?
	    AND (SELECT COUNT(*) FROM rooms WHERE host=? AND state IN `+roomStatesOccupying+`) < ?
	  ON CONFLICT(host,room_key) DO NOTHING`,
		host, roomKey, group, gen, deadline, now, now,
		l.RoomsActiveGlobal, host, l.RoomsActivePerHost)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// reactivateRoom claims capacity for an ended/expired key, taking a strictly
// newer generation. Same conditional-count discipline; the row's own state
// is part of the guard so a concurrent reactivation cannot double-count.
func reactivateRoom(host, roomKey, group string, newGen, deadline int64, l *Limits) (bool, error) {
	now := time.Now().Unix()
	res, err := db.Exec(`
	  UPDATE rooms SET state='provisioning', group_name=?, gen=?, deadline=?, updated=?
	  WHERE host=? AND room_key=? AND state NOT IN `+roomStatesOccupying+`
	    AND (SELECT COUNT(*) FROM rooms WHERE state IN `+roomStatesOccupying+`) < ?
	    AND (SELECT COUNT(*) FROM rooms WHERE host=? AND state IN `+roomStatesOccupying+`) < ?`,
		group, newGen, deadline, now,
		host, roomKey, l.RoomsActiveGlobal, host, l.RoomsActivePerHost)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// activateRoom promotes a reservation once the Galene group exists.
func activateRoom(host, roomKey string) error {
	_, err := db.Exec(`UPDATE rooms SET state='active', updated=?
	  WHERE host=? AND room_key=? AND state='provisioning'`,
		time.Now().Unix(), host, roomKey)
	return err
}

// releaseRoomReservation frees capacity after a failed external creation.
// The row is kept (as evidence) in a state that does not occupy quota.
func releaseRoomReservation(host, roomKey string) {
	if _, err := db.Exec(`UPDATE rooms SET state='ended', updated=?
	  WHERE host=? AND room_key=? AND state='provisioning'`,
		time.Now().Unix(), host, roomKey); err != nil {
		ctr.ReservationFailed.Add(1)
		return
	}
	ctr.ReservationReleased.Add(1)
}

// roomQuotaBlame reports which cap rejected a reservation. It is only used
// to label the error and is never part of the admission decision.
func roomQuotaBlame(host string, l *Limits) string {
	var g, h int
	db.QueryRow(`SELECT COUNT(*) FROM rooms WHERE state IN ` + roomStatesOccupying).Scan(&g)
	db.QueryRow(`SELECT COUNT(*) FROM rooms WHERE host=? AND state IN `+roomStatesOccupying, host).Scan(&h)
	if h >= l.RoomsActivePerHost {
		return "room-quota-host"
	}
	if g >= l.RoomsActiveGlobal {
		return "room-quota-global"
	}
	return "room-quota"
}

// ----------------------------------------------------- ticket reservations

// Live tickets are unrevoked and unexpired. Reservations count too: that is
// precisely what stops a burst of concurrent issuance overshooting the cap.
const ticketLive = `revoked=0 AND expires>?`

// reservationToken is the placeholder primary key a reservation holds until
// the real Galene token id replaces it. It is namespaced so it can never
// collide with, or be mistaken for, a real token.
func reservationToken(host, req string) string { return "resv:" + host + "\x00" + req }

// reserveTicket atomically claims ticket capacity before any token is
// minted. The (host,req) placeholder key makes an idempotent retry hit the
// primary key instead of reserving a second time.
func reserveTicket(host, req, group, participant string, expires int64, l *Limits) (bool, error) {
	now := time.Now().Unix()
	res, err := db.Exec(`
	  INSERT INTO tickets(token,group_name,participant,expires,created,host,req,state)
	  SELECT ?,?,?,?,?,?,?,'reserved'
	  WHERE (SELECT COUNT(*) FROM tickets WHERE group_name=? AND `+ticketLive+`) < ?
	    AND (SELECT COUNT(*) FROM tickets WHERE host=? AND `+ticketLive+`) < ?
	  ON CONFLICT(token) DO NOTHING`,
		reservationToken(host, req), group, participant, expires, now, host, req,
		group, now, l.TicketsLivePerRoom, host, now, l.TicketsLivePerHost)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// issueTicket swaps the placeholder for the real token id, atomically.
func issueTicket(host, req, token string) error {
	_, err := db.Exec(`UPDATE tickets SET token=?, state='issued'
	  WHERE token=? AND state='reserved'`, token, reservationToken(host, req))
	return err
}

// releaseTicketReservation frees ticket capacity after a failed mint. The
// placeholder is deleted outright: it never referred to a real credential.
func releaseTicketReservation(host, req string) {
	if _, err := db.Exec(`DELETE FROM tickets WHERE token=? AND state='reserved'`,
		reservationToken(host, req)); err != nil {
		ctr.ReservationFailed.Add(1)
		return
	}
	ctr.ReservationReleased.Add(1)
}

func ticketQuotaBlame(host, group string, l *Limits) string {
	now := time.Now().Unix()
	var perRoom, perHost int
	db.QueryRow(`SELECT COUNT(*) FROM tickets WHERE group_name=? AND `+ticketLive, group, now).Scan(&perRoom)
	db.QueryRow(`SELECT COUNT(*) FROM tickets WHERE host=? AND `+ticketLive, host, now).Scan(&perHost)
	if perRoom >= l.TicketsLivePerRoom {
		return "ticket-quota-room"
	}
	if perHost >= l.TicketsLivePerHost {
		return "ticket-quota-host"
	}
	return "ticket-quota"
}

// --------------------------------------------------- reservation recovery

// reservationGrace is how long a reservation may sit unfinished before it is
// assumed to belong to a process that died. It exceeds opDeadline so a slow
// but living operation is never robbed of its reservation.
const reservationGrace = 90 * time.Second

// sweepReservations releases capacity stranded by a crash. A stale room
// reservation also has its managed group deleted by exact name, so
// releasing quota cannot leave an orphan group behind. Stale ticket
// reservations are simply dropped; any token that was actually minted has
// no ticket row and is reaped by the existing orphan reconciliation.
func sweepReservations() {
	cutoff := time.Now().Add(-reservationGrace).Unix()

	rows, err := db.Query(`SELECT host,room_key,group_name FROM rooms
	  WHERE state='provisioning' AND updated<=?`, cutoff)
	if err == nil {
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
			var st string
			if e := db.QueryRow(`SELECT state FROM rooms WHERE host=? AND room_key=?`,
				j.host, j.key).Scan(&st); e != nil || st != "provisioning" {
				rel()
				continue
			}
			// exact-name delete of a group this row owns; never a blanket sweep
			if isManaged(j.grp) {
				gal.DeleteGroup(j.grp)
			}
			db.Exec(`UPDATE rooms SET state='ended', updated=?
			  WHERE host=? AND room_key=? AND state='provisioning'`,
				time.Now().Unix(), j.host, j.key)
			ctr.ReservationRecovered.Add(1)
			log.Printf("event=reservation-recovered kind=room host=%s", j.host)
			rel()
		}
	}

	if res, e := db.Exec(`DELETE FROM tickets WHERE state='reserved' AND created<=?`,
		cutoff); e == nil {
		if n, _ := res.RowsAffected(); n > 0 {
			ctr.ReservationRecovered.Add(n)
			log.Printf("event=reservation-recovered kind=ticket count=%d", n)
		}
	}
}

// --------------------------------------------------------- command caps

// claimWithCap performs the idempotency claim under the unique-command-row
// caps. Returns inserted=true when this call created the row, capped=true
// when a cap refused it, and neither when the row already existed (a
// duplicate, which consumes no new capacity).
func claimWithCap(host, req, fp, ep string, l *Limits) (inserted, capped bool, err error) {
	now := time.Now().Unix()
	res, err := db.Exec(`
	  INSERT INTO commands(host,req,fingerprint,state,epoch,created,updated)
	  SELECT ?,?,?,'claimed',?,?,?
	  WHERE (SELECT COUNT(*) FROM commands WHERE host=?) < ?
	    AND (SELECT COUNT(*) FROM commands) < ?
	  ON CONFLICT(host,req) DO NOTHING`,
		host, req, fp, ep, now, now, host, l.CapCommandRowsPerHost, capCommandRowsGlobal)
	if err != nil {
		return false, false, err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return true, false, nil
	}
	// Zero rows is ambiguous: either the row already exists (duplicate) or
	// a cap refused the insert. Distinguish by looking.
	var exists int
	if e := db.QueryRow(`SELECT COUNT(*) FROM commands WHERE host=? AND req=?`,
		host, req).Scan(&exists); e != nil {
		return false, false, e
	}
	if exists > 0 {
		return false, false, nil // duplicate; caller reads the stored row
	}
	return false, true, nil
}
