package main

// Milestone 2b.4 -- durable eviction intent.
//
// Revocation stops a participant obtaining a NEW credential; it does not
// disconnect the session they already hold. Before 2b.4 a crash between
// revoke and kick left the participant connected with nothing recording
// that an eviction was owed. The intent below is written BEFORE any
// external work and survives restart, so eviction is retried until the
// participant is stably absent.
//
// The intent is bound to the room INCARNATION (generation). A stale intent
// can therefore never evict someone from a later incarnation of a reused
// room key: the generation guard makes it inert instead.

import (
	"database/sql"
	"errors"
	"log"
	"time"
)

// evictionRetryGrace is how long an in-flight eviction is left alone before
// the sweeper considers it abandoned. It exceeds opDeadline so a slow but
// living eviction is never duplicated.
const evictionRetryGrace = 90 * time.Second

func migrateEvictions() error {
	// Bounded by construction: one row per (host, room, participant), and
	// rows are deleted on completion.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS evictions (
	  host TEXT NOT NULL, room_key TEXT NOT NULL, participant TEXT NOT NULL,
	  gen INTEGER NOT NULL, group_name TEXT NOT NULL,
	  created INTEGER, updated INTEGER, attempts INTEGER NOT NULL DEFAULT 0,
	  PRIMARY KEY (host, room_key, participant))`); err != nil {
		return err
	}
	_, err := db.Exec(`CREATE INDEX IF NOT EXISTS evictions_updated ON evictions(updated)`)
	return err
}

// recordEvictionIntent persists the intent before any external work. It is
// idempotent: a retry of the same eviction refreshes the row rather than
// creating a second one.
func recordEvictionIntent(host, roomKey, participant, group string, gen int64) error {
	now := time.Now().Unix()
	_, err := db.Exec(`
	  INSERT INTO evictions(host,room_key,participant,gen,group_name,created,updated,attempts)
	  VALUES(?,?,?,?,?,?,?,1)
	  ON CONFLICT(host,room_key,participant) DO UPDATE SET
	    gen=excluded.gen, group_name=excluded.group_name, updated=excluded.updated,
	    attempts=evictions.attempts+1`,
		host, roomKey, participant, gen, group, now, now)
	return err
}

// clearEvictionIntent finalises a completed eviction. It is generation-
// guarded so a late completion cannot clear an intent that belongs to a
// newer incarnation.
func clearEvictionIntent(host, roomKey, participant string, gen int64) {
	if _, err := db.Exec(`DELETE FROM evictions
	  WHERE host=? AND room_key=? AND participant=? AND gen=?`,
		host, roomKey, participant, gen); err != nil {
		ctr.EvictionIntentFailed.Add(1)
		return
	}
	ctr.EvictionIntentCompleted.Add(1)
}

// enforceEviction performs the external half: revoke every credential the
// participant holds, then kick until stably absent. Callers must have
// recorded the intent first.
func enforceEviction(group, participant string) (revoked, kicked int, err error) {
	// ORDER: revoke first so a kicked client cannot rejoin mid-sweep.
	revoked = revokeFor(group, participant)
	kicked, err = gal.KickUntilAbsent(group, participant)
	return revoked, kicked, err
}

// sweepEvictions resumes intents left incomplete by a crash or a failure.
// It runs on the normal sweep tick and is bounded by the number of live
// intents, which is itself bounded by participants per room.
func sweepEvictions() {
	cutoff := time.Now().Add(-evictionRetryGrace).Unix()
	rows, err := db.Query(`SELECT host,room_key,participant,gen,group_name
	  FROM evictions WHERE updated<=? LIMIT 200`, cutoff)
	if err != nil {
		return
	}
	type job struct {
		host, key, who, grp string
		gen                 int64
	}
	var jobs []job
	for rows.Next() {
		var j job
		if rows.Scan(&j.host, &j.key, &j.who, &j.gen, &j.grp) == nil {
			jobs = append(jobs, j)
		}
	}
	rows.Close()

	for _, j := range jobs {
		rel := rooms.Acquire(j.host + "\x00" + j.key)

		// The room must still be the SAME incarnation. If the key was
		// reused, the generation moved on and this intent is stale: it is
		// discarded rather than applied to whoever is in the room now.
		var curGen int64
		var curState string
		e := db.QueryRow(`SELECT gen,state FROM rooms WHERE host=? AND room_key=?`,
			j.host, j.key).Scan(&curGen, &curState)
		if errors.Is(e, sql.ErrNoRows) || (e == nil && curGen != j.gen) {
			db.Exec(`DELETE FROM evictions WHERE host=? AND room_key=? AND participant=? AND gen=?`,
				j.host, j.key, j.who, j.gen)
			ctr.EvictionIntentStale.Add(1)
			log.Printf("event=eviction-intent-stale host=%s gen=%d", j.host, j.gen)
			rel()
			continue
		}
		if e != nil {
			rel()
			continue
		}
		// A room that has already ended revoked and kicked everyone.
		if curState == "ended" {
			db.Exec(`DELETE FROM evictions WHERE host=? AND room_key=? AND participant=? AND gen=?`,
				j.host, j.key, j.who, j.gen)
			ctr.EvictionIntentCompleted.Add(1)
			rel()
			continue
		}

		db.Exec(`UPDATE evictions SET updated=?, attempts=attempts+1
		  WHERE host=? AND room_key=? AND participant=? AND gen=?`,
			time.Now().Unix(), j.host, j.key, j.who, j.gen)

		if _, _, err := enforceEviction(j.grp, j.who); err != nil {
			ctr.EvictionIntentFailed.Add(1)
			log.Printf("event=eviction-intent-incomplete host=%s gen=%d", j.host, j.gen)
			rel()
			continue
		}
		clearEvictionIntent(j.host, j.key, j.who, j.gen)
		ctr.EvictionIntentResumed.Add(1)
		log.Printf("event=eviction-intent-resumed host=%s gen=%d", j.host, j.gen)
		rel()
	}
}

// sweepExternalTokenDrift corrects the case the 2b.2 report flagged: the
// database says a ticket is revoked, but its Galene token still exists.
// revoked=1 records that we ASKED for deletion, not that the external
// credential is gone, so recovery must re-attempt the delete rather than
// trust the flag.
//
// It is bounded: it inspects only groups belonging to rooms that are still
// active, and never touches an unmanaged group.
func sweepExternalTokenDrift() {
	rows, err := db.Query(`SELECT DISTINCT group_name FROM rooms
	  WHERE state IN ('active','ending') LIMIT 100`)
	if err != nil {
		return
	}
	var groups []string
	for rows.Next() {
		var g string
		if rows.Scan(&g) == nil && isManaged(g) {
			groups = append(groups, g)
		}
	}
	rows.Close()

	for _, g := range groups {
		ids, err := gal.ListTokens(g)
		if err != nil {
			continue
		}
		for _, id := range ids {
			// Live means: present, unrevoked, and a real issued credential.
			var live int
			db.QueryRow(`SELECT COUNT(*) FROM tickets
			  WHERE token=? AND revoked=0 AND state='issued'`, id).Scan(&live)
			if live > 0 {
				continue
			}
			if gal.DeleteToken(g, id) == nil {
				ctr.OrphanTokensReaped.Add(1)
				log.Printf("event=external-token-drift-corrected group_managed=true")
			}
		}
	}
}
