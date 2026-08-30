package main

// Milestone 2b.3 -- bounded incremental retention, command tombstones and
// threshold-based WAL maintenance.
//
// Every statement here is batch-limited by db.prune_batch. There is no
// unbounded table sweep, no transaction spanning network work, and no
// Galene object is ever touched: pruning only removes local history whose
// external objects are already gone.

import (
	"log"
	"os"
	"time"
)

// Command lifecycle:
//
//	claimed  -> in flight, or failed and retryable
//	done     -> completed, full result body retained
//	retired  -> COMPACT TOMBSTONE: body dropped, fingerprint kept
//	(deleted) -> the request id may be treated as new again
//
// A tombstone lives in the SAME commands table rather than a new one, so
// per-host and global command accounting stays a single bounded count and
// no new unbounded store is introduced.
const (
	cmdClaimed = "claimed"
	cmdDone    = "done"
	cmdRetired = "retired"
)

// pruneStats reports what one cycle actually removed.
type pruneStats struct {
	RoomsDeleted     int64
	TicketsDeleted   int64
	CommandsRetired  int64
	TombstonesPurged int64
	StaleClaimed     int64
}

func (p pruneStats) total() int64 {
	return p.RoomsDeleted + p.TicketsDeleted + p.CommandsRetired +
		p.TombstonesPurged + p.StaleClaimed
}

// batchDelete removes at most `limit` rows matching a condition. The
// subquery bounds the delete without relying on DELETE ... LIMIT, which
// requires a SQLite compile option we must not depend on.
func batchDelete(table, where string, limit int, args ...any) (int64, error) {
	q := `DELETE FROM ` + table + ` WHERE rowid IN (
	        SELECT rowid FROM ` + table + ` WHERE ` + where + ` LIMIT ` + itoa(limit) + `)`
	res, err := db.Exec(q, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func itoa(n int) string {
	if n < 0 {
		n = 0
	}
	b := [20]byte{}
	i := len(b)
	if n == 0 {
		return "0"
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// prune runs one bounded cycle. A busy database simply yields fewer rows
// this cycle: every statement is independent, so contention defers work
// instead of disrupting command processing.
func prune() pruneStats {
	l := CurrentLimits()
	if l == nil {
		return pruneStats{}
	}
	now := time.Now()
	batch := l.PruneBatch
	var st pruneStats

	// 1. Ended rooms past retention. NEVER active/provisioning/ending: the
	//    state filter is the guard, and it is checked in SQL, not in Go.
	if n, err := batchDelete("rooms", `state='ended' AND updated <= ?`, batch,
		now.Add(-l.RetainEndedRooms).Unix()); err == nil {
		st.RoomsDeleted = n
	} else {
		ctr.PruneFailed.Add(1)
	}

	// 2. Revoked/expired tickets past retention. A live, reserved or
	//    unrevoked ticket can never match: it must be revoked AND expired.
	if n, err := batchDelete("tickets",
		`revoked=1 AND state='issued' AND expires <= ? AND created <= ?`, batch,
		now.Unix(), now.Add(-l.RetainTickets).Unix()); err == nil {
		st.TicketsDeleted = n
	} else {
		ctr.PruneFailed.Add(1)
	}

	// 3. Completed commands past the full-result window become COMPACT
	//    TOMBSTONES: the response body is dropped, the fingerprint is kept.
	//    This is an UPDATE, not a delete -- the request id stays known.
	if res, err := db.Exec(`
	  UPDATE commands SET state='`+cmdRetired+`', response=NULL, updated=?
	  WHERE rowid IN (SELECT rowid FROM commands
	    WHERE state='`+cmdDone+`' AND updated <= ? LIMIT `+itoa(batch)+`)`,
		now.Unix(), now.Add(-l.RetainCommandsFull).Unix()); err == nil {
		st.CommandsRetired, _ = res.RowsAffected()
	} else {
		ctr.PruneFailed.Add(1)
	}

	// 4. Stale claimed rows. DOCUMENTED SAFE RULE: a claim older than the
	//    full-result window belongs to a request nobody is still waiting
	//    on -- either it failed (the failure path leaves state='claimed'
	//    with epoch NULL, retryable) or its process died long ago. It is
	//    retired rather than deleted, so the request id cannot be replayed
	//    into a second external execution; the caller is told to use a new
	//    id. Legacy 'pending' rows from Milestone 1 are covered by the same
	//    rule, since they are neither done nor retired.
	if res, err := db.Exec(`
	  UPDATE commands SET state='`+cmdRetired+`', response=NULL, updated=?
	  WHERE rowid IN (SELECT rowid FROM commands
	    WHERE state NOT IN ('`+cmdDone+`','`+cmdRetired+`') AND updated <= ?
	    LIMIT `+itoa(batch)+`)`,
		now.Unix(), now.Add(-l.RetainCommandsFull).Unix()); err == nil {
		st.StaleClaimed, _ = res.RowsAffected()
	} else {
		ctr.PruneFailed.Add(1)
	}

	// 5. Tombstones past their own retention are finally removed. Only
	//    now may the request id be treated as new.
	if n, err := batchDelete("commands", `state='`+cmdRetired+`' AND updated <= ?`, batch,
		now.Add(-l.RetainCommandTombstones).Unix()); err == nil {
		st.TombstonesPurged = n
	} else {
		ctr.PruneFailed.Add(1)
	}

	ctr.PrunedRooms.Add(st.RoomsDeleted)
	ctr.PrunedTickets.Add(st.TicketsDeleted)
	ctr.PrunedCommandsRetired.Add(st.CommandsRetired + st.StaleClaimed)
	ctr.PrunedTombstones.Add(st.TombstonesPurged)

	if st.total() > 0 {
		log.Printf("event=prune rooms=%d tickets=%d retired=%d stale=%d tombstones=%d",
			st.RoomsDeleted, st.TicketsDeleted, st.CommandsRetired,
			st.StaleClaimed, st.TombstonesPurged)
	}
	return st
}

// maybeCheckpoint attempts a bounded WAL truncate ONLY after meaningful
// pruning and ONLY when the WAL has actually grown past the configured
// threshold. It is never run on a bare timer tick, and a busy checkpoint is
// skipped and retried on a later cycle rather than blocking requests.
func maybeCheckpoint(dbPath string, pruned int64) {
	if pruned == 0 {
		return
	}
	l := CurrentLimits()
	if l == nil {
		return
	}
	fi, err := os.Stat(dbPath + "-wal")
	if err != nil || fi.Size() < int64(l.WALTruncateThresholdBytes) {
		return
	}
	ctr.CheckpointAttempted.Add(1)
	var busy, logFrames, checkpointed int
	// TRUNCATE returns busy=1 when readers prevented a full checkpoint.
	if err := db.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).
		Scan(&busy, &logFrames, &checkpointed); err != nil {
		ctr.CheckpointFailed.Add(1)
		log.Printf("event=wal-checkpoint outcome=failed")
		return
	}
	if busy != 0 {
		ctr.CheckpointBusy.Add(1)
		log.Printf("event=wal-checkpoint outcome=busy wal_bytes=%d", fi.Size())
		return
	}
	ctr.CheckpointCompleted.Add(1)
	log.Printf("event=wal-checkpoint outcome=completed wal_bytes_before=%d", fi.Size())
}

// pruneLoop runs retention on the configured interval. The interval is read
// each cycle so a SIGHUP changes it without a restart.
func pruneLoop(dbPath string) {
	for {
		l := CurrentLimits()
		iv := 5 * time.Minute
		if l != nil && l.PruneInterval > 0 {
			iv = l.PruneInterval
		}
		time.Sleep(iv)
		st := prune()
		maybeCheckpoint(dbPath, st.total())
	}
}
