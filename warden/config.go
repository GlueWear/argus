package main

// Milestone 2b.1 -- configuration foundation ONLY.
//
// This file loads, validates and hot-swaps an immutable limits snapshot.
// NOTHING in this phase enforces any of these values: admission still uses
// the compiled-in globalSlots/hostSlots constants, and no quota, retention
// or participant limit is applied anywhere. Externally observable request
// behaviour is unchanged by design.
//
// Notes recorded for later phases, deliberately NOT implemented here:
//   - Room and ticket quota reservations must be ATOMIC in SQLite; a
//     count-then-create sequence races and must not be used.
//   - Prefer a durable provisioning/reservation row BEFORE the external
//     Galene object is created, so a crash leaves a reclaimable intent
//     rather than an orphan.
//   - Participant limits must eventually measure CONNECTED Galene clients,
//     not ticket rows; a ticket is permission to join, not a join.
//   - A cached duplicate request must NOT consume room/ticket creation
//     quota. A general request-rate limiter may still count every HTTP
//     request, including duplicates.
//   - WAL truncation is threshold-based or tied to meaningful pruning,
//     never a fixed short timer.
//   - Command caps, request rates and retention windows must stay
//     internally consistent; see the note on caps.command_rows_per_host.

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Limits is an immutable snapshot. It is never mutated after construction;
// reload builds a whole new value and swaps the pointer, so a request sees
// either the complete old snapshot or the complete new one, never a mix.
type Limits struct {
	// ---- meta admission (cheap ops: ensure-room, renew-room, issue-ticket)
	MetaGlobalSlots int
	MetaHostSlots   int
	MetaAdmitWait   time.Duration

	// ---- roster admission (expensive ops: room-status, evict, end-room)
	RosterGlobalSlots int
	RosterHostSlots   int
	RosterAdmitWait   time.Duration

	// ---- room capacity
	RoomsActiveGlobal  int
	RoomsActivePerHost int

	// ---- connected participants
	ParticipantsGlobal  int
	ParticipantsPerRoom int

	// ---- tickets
	TicketsLivePerRoom int
	TicketsLivePerHost int

	// ---- TTL and lifetime
	LeaseMinTTL      time.Duration
	LeaseDefaultTTL  time.Duration
	LeaseMaxTTL      time.Duration
	RoomMaxLifetime  time.Duration
	TicketTTL        time.Duration
	OperatorTokenTTL time.Duration
	// TURN/Galene combined access credential lifetime
	AccessTTL time.Duration

	// ---- rates (per authenticated host)
	RateRoomsPerMin       int
	RateRoomsBurst        int
	RateTicketsPerMin     int
	RateTicketsBurst      int
	RateRosterPerMin      int
	RateRosterBurst       int
	RateRequestsPerMin    int
	RateRequestsBurst     int
	CapCommandRowsPerHost int

	// ---- retention
	RetainEndedRooms        time.Duration
	RetainTickets           time.Duration
	RetainCommandsFull      time.Duration
	RetainCommandTombstones time.Duration

	// ---- database / WAL maintenance thresholds
	WALTruncateThresholdBytes int
	PruneBatch                int
	PruneInterval             time.Duration
}

// restartOnly names the settings a running process cannot adopt. Resizing a
// live counting semaphore safely is more machinery than this milestone
// warrants, so these are reported honestly as requiring a restart rather
// than silently appearing to have changed.
var restartOnly = []string{
	"meta.global_slots",
	"meta.host_slots",
	"roster.global_slots",
	"roster.host_slots",
}

var (
	limitsPtr  atomic.Pointer[Limits] // the live snapshot
	bootLimits atomic.Pointer[Limits] // what the running process actually started with
)

// CurrentLimits returns the live snapshot. Callers must treat it as
// read-only; it is replaced wholesale, never edited in place.
func CurrentLimits() *Limits { return limitsPtr.Load() }

// BootLimits is what this process started with. Restart-only values in the
// live snapshot may differ from these; that difference is what makes a
// restart necessary, and it is reported rather than hidden.
func BootLimits() *Limits { return bootLimits.Load() }

// ---------------------------------------------------------------- parsing

type parser struct {
	seen map[string]bool
	vals map[string]string
}

// parseFile reads key = value lines. '#' begins a comment. Unknown and
// duplicate keys are rejected: a typo silently falling back to a default is
// exactly how a limit ends up not being the limit anyone believes it is.
func parseFile(path string) (*parser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	p := &parser{seen: map[string]bool{}, vals: map[string]string{}}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		s := sc.Text()
		if i := strings.IndexByte(s, '#'); i >= 0 {
			s = s[:i]
		}
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		eq := strings.IndexByte(s, '=')
		if eq < 0 {
			return nil, fmt.Errorf("line %d: expected key = value", line)
		}
		k := strings.TrimSpace(s[:eq])
		v := strings.TrimSpace(s[eq+1:])
		if k == "" {
			return nil, fmt.Errorf("line %d: empty key", line)
		}
		if p.seen[k] {
			return nil, fmt.Errorf("line %d: duplicate key %q", line, k)
		}
		p.seen[k] = true
		p.vals[k] = v
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return p, nil
}

type fieldErr struct{ msgs []string }

func (e *fieldErr) add(f string, err error) { e.msgs = append(e.msgs, f+": "+err.Error()) }
func (e *fieldErr) addf(format string, a ...any) {
	e.msgs = append(e.msgs, fmt.Sprintf(format, a...))
}
func (e *fieldErr) err() error {
	if len(e.msgs) == 0 {
		return nil
	}
	// Concise and bounded: at most three problems, never the file body.
	if len(e.msgs) > 3 {
		return fmt.Errorf("%s (+%d more)", strings.Join(e.msgs[:3], "; "), len(e.msgs)-3)
	}
	return fmt.Errorf("%s", strings.Join(e.msgs, "; "))
}

func (p *parser) intv(key string, dst *int, fe *fieldErr, used map[string]bool) {
	used[key] = true
	raw, ok := p.vals[key]
	if !ok {
		fe.addf("%s: missing", key)
		return
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		fe.addf("%s: not an integer", key)
		return
	}
	*dst = n
}

func (p *parser) durv(key string, dst *time.Duration, fe *fieldErr, used map[string]bool) {
	used[key] = true
	raw, ok := p.vals[key]
	if !ok {
		fe.addf("%s: missing", key)
		return
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		fe.addf("%s: not a duration", key)
		return
	}
	*dst = d
}

// LoadLimits reads and fully validates a configuration file. It returns a
// complete snapshot or an error; it never returns a partially populated
// value, so a partial configuration can never become active.
func LoadLimits(path string) (*Limits, error) {
	p, err := parseFile(path)
	if err != nil {
		return nil, err
	}
	var l Limits
	fe := &fieldErr{}
	used := map[string]bool{}

	p.intv("meta.global_slots", &l.MetaGlobalSlots, fe, used)
	p.intv("meta.host_slots", &l.MetaHostSlots, fe, used)
	p.durv("meta.admit_wait", &l.MetaAdmitWait, fe, used)

	p.intv("roster.global_slots", &l.RosterGlobalSlots, fe, used)
	p.intv("roster.host_slots", &l.RosterHostSlots, fe, used)
	p.durv("roster.admit_wait", &l.RosterAdmitWait, fe, used)

	p.intv("rooms.active_global", &l.RoomsActiveGlobal, fe, used)
	p.intv("rooms.active_per_host", &l.RoomsActivePerHost, fe, used)

	p.intv("participants.global", &l.ParticipantsGlobal, fe, used)
	p.intv("participants.per_room", &l.ParticipantsPerRoom, fe, used)

	p.intv("tickets.live_per_room", &l.TicketsLivePerRoom, fe, used)
	p.intv("tickets.live_per_host", &l.TicketsLivePerHost, fe, used)

	p.durv("lease.min_ttl", &l.LeaseMinTTL, fe, used)
	p.durv("lease.default_ttl", &l.LeaseDefaultTTL, fe, used)
	p.durv("lease.max_ttl", &l.LeaseMaxTTL, fe, used)
	p.durv("room.max_lifetime", &l.RoomMaxLifetime, fe, used)
	p.durv("ticket.ttl", &l.TicketTTL, fe, used)
	p.durv("operator.token_ttl", &l.OperatorTokenTTL, fe, used)
	p.durv("access.credential_ttl", &l.AccessTTL, fe, used)

	p.intv("rate.rooms_per_host_per_min", &l.RateRoomsPerMin, fe, used)
	p.intv("rate.rooms_burst", &l.RateRoomsBurst, fe, used)
	p.intv("rate.tickets_per_host_per_min", &l.RateTicketsPerMin, fe, used)
	p.intv("rate.tickets_burst", &l.RateTicketsBurst, fe, used)
	p.intv("rate.roster_per_host_per_min", &l.RateRosterPerMin, fe, used)
	p.intv("rate.roster_burst", &l.RateRosterBurst, fe, used)
	p.intv("rate.requests_per_host_per_min", &l.RateRequestsPerMin, fe, used)
	p.intv("rate.requests_burst", &l.RateRequestsBurst, fe, used)
	p.intv("caps.command_rows_per_host", &l.CapCommandRowsPerHost, fe, used)

	p.durv("retain.ended_rooms", &l.RetainEndedRooms, fe, used)
	p.durv("retain.tickets", &l.RetainTickets, fe, used)
	p.durv("retain.commands_full", &l.RetainCommandsFull, fe, used)
	p.durv("retain.command_tombstones", &l.RetainCommandTombstones, fe, used)

	p.intv("db.wal_truncate_threshold_bytes", &l.WALTruncateThresholdBytes, fe, used)
	p.intv("db.prune_batch", &l.PruneBatch, fe, used)
	p.durv("db.prune_interval", &l.PruneInterval, fe, used)

	// Unknown keys are an error. Key names come from the operator's own
	// file and contain no secrets, so naming them is safe and is the only
	// way the operator can find the typo.
	for k := range p.vals {
		if !used[k] {
			fe.addf("unknown key %q", k)
		}
	}
	if err := fe.err(); err != nil {
		return nil, err
	}
	if err := l.validate(); err != nil {
		return nil, err
	}
	return &l, nil
}

// validate enforces every relationship that must hold for the snapshot to
// be safe to adopt.
func (l *Limits) validate() error {
	fe := &fieldErr{}

	posInt := func(name string, v int) {
		if v <= 0 {
			fe.addf("%s must be > 0", name)
		}
	}
	posDur := func(name string, v time.Duration) {
		if v <= 0 {
			fe.addf("%s must be > 0", name)
		}
	}

	posInt("meta.global_slots", l.MetaGlobalSlots)
	posInt("meta.host_slots", l.MetaHostSlots)
	posDur("meta.admit_wait", l.MetaAdmitWait)
	posInt("roster.global_slots", l.RosterGlobalSlots)
	posInt("roster.host_slots", l.RosterHostSlots)
	posDur("roster.admit_wait", l.RosterAdmitWait)
	posInt("rooms.active_global", l.RoomsActiveGlobal)
	posInt("rooms.active_per_host", l.RoomsActivePerHost)
	posInt("participants.global", l.ParticipantsGlobal)
	posInt("participants.per_room", l.ParticipantsPerRoom)
	posInt("tickets.live_per_room", l.TicketsLivePerRoom)
	posInt("tickets.live_per_host", l.TicketsLivePerHost)
	posDur("lease.min_ttl", l.LeaseMinTTL)
	posDur("lease.default_ttl", l.LeaseDefaultTTL)
	posDur("lease.max_ttl", l.LeaseMaxTTL)
	posDur("room.max_lifetime", l.RoomMaxLifetime)
	posDur("ticket.ttl", l.TicketTTL)
	posDur("operator.token_ttl", l.OperatorTokenTTL)
	posDur("access.credential_ttl", l.AccessTTL)
	posInt("rate.rooms_per_host_per_min", l.RateRoomsPerMin)
	posInt("rate.rooms_burst", l.RateRoomsBurst)
	posInt("rate.tickets_per_host_per_min", l.RateTicketsPerMin)
	posInt("rate.tickets_burst", l.RateTicketsBurst)
	posInt("rate.roster_per_host_per_min", l.RateRosterPerMin)
	posInt("rate.roster_burst", l.RateRosterBurst)
	posInt("rate.requests_per_host_per_min", l.RateRequestsPerMin)
	posInt("rate.requests_burst", l.RateRequestsBurst)
	posInt("caps.command_rows_per_host", l.CapCommandRowsPerHost)
	posDur("retain.ended_rooms", l.RetainEndedRooms)
	posDur("retain.tickets", l.RetainTickets)
	posDur("retain.commands_full", l.RetainCommandsFull)
	posDur("retain.command_tombstones", l.RetainCommandTombstones)
	posInt("db.wal_truncate_threshold_bytes", l.WALTruncateThresholdBytes)
	posInt("db.prune_batch", l.PruneBatch)
	posDur("db.prune_interval", l.PruneInterval)

	// A per-host limit at or above its class limit gives that class no
	// per-host isolation at all: one host could occupy the whole class.
	if l.MetaHostSlots >= l.MetaGlobalSlots {
		fe.addf("meta.host_slots (%d) must be < meta.global_slots (%d)",
			l.MetaHostSlots, l.MetaGlobalSlots)
	}
	if l.RosterHostSlots >= l.RosterGlobalSlots {
		fe.addf("roster.host_slots (%d) must be < roster.global_slots (%d)",
			l.RosterHostSlots, l.RosterGlobalSlots)
	}
	if l.ParticipantsPerRoom > l.ParticipantsGlobal {
		fe.addf("participants.per_room (%d) must be <= participants.global (%d)",
			l.ParticipantsPerRoom, l.ParticipantsGlobal)
	}
	if l.RoomsActivePerHost > l.RoomsActiveGlobal {
		fe.addf("rooms.active_per_host (%d) must be <= rooms.active_global (%d)",
			l.RoomsActivePerHost, l.RoomsActiveGlobal)
	}
	// A ticket must never outlive the record of the command that made it,
	// or the adopt-by-(host,req) path loses the row it needs.
	if l.RetainTickets < l.RetainCommandsFull {
		fe.addf("retain.tickets (%s) must be >= retain.commands_full (%s)",
			l.RetainTickets, l.RetainCommandsFull)
	}
	// The tombstone is what stops a pruned request id re-executing, so it
	// must outlast the full record it replaces.
	if l.RetainCommandTombstones < l.RetainCommandsFull {
		fe.addf("retain.command_tombstones (%s) must be >= retain.commands_full (%s)",
			l.RetainCommandTombstones, l.RetainCommandsFull)
	}
	if l.LeaseMinTTL > l.LeaseMaxTTL {
		fe.addf("lease.min_ttl (%s) must be <= lease.max_ttl (%s)", l.LeaseMinTTL, l.LeaseMaxTTL)
	}
	if l.LeaseDefaultTTL < l.LeaseMinTTL || l.LeaseDefaultTTL > l.LeaseMaxTTL {
		fe.addf("lease.default_ttl (%s) must be within [%s, %s]",
			l.LeaseDefaultTTL, l.LeaseMinTTL, l.LeaseMaxTTL)
	}
	// A room must be able to hold a full-length lease without the lifetime
	// cap cutting it short mid-lease.
	if l.RoomMaxLifetime < l.LeaseMaxTTL {
		fe.addf("room.max_lifetime (%s) must be >= lease.max_ttl (%s)",
			l.RoomMaxLifetime, l.LeaseMaxTTL)
	}
	// A credential must never be able to outlive the longest possible lease.
	if l.AccessTTL > l.LeaseMaxTTL {
		fe.addf("access.credential_ttl (%s) must be <= lease.max_ttl (%s)",
			l.AccessTTL, l.LeaseMaxTTL)
	}
	if l.TicketTTL > l.LeaseMaxTTL {
		fe.addf("ticket.ttl (%s) must be <= lease.max_ttl (%s)", l.TicketTTL, l.LeaseMaxTTL)
	}
	return fe.err()
}

// RestartRequired lists restart-only settings whose value in this snapshot
// differs from what the process is actually running. Empty means a reload
// fully took effect.
func (l *Limits) RestartRequired(boot *Limits) []string {
	if boot == nil {
		return nil
	}
	var out []string
	if l.MetaGlobalSlots != boot.MetaGlobalSlots {
		out = append(out, "meta.global_slots")
	}
	if l.MetaHostSlots != boot.MetaHostSlots {
		out = append(out, "meta.host_slots")
	}
	if l.RosterGlobalSlots != boot.RosterGlobalSlots {
		out = append(out, "roster.global_slots")
	}
	if l.RosterHostSlots != boot.RosterHostSlots {
		out = append(out, "roster.host_slots")
	}
	return out
}

// InstallLimits publishes a snapshot atomically. Readers hold a pointer to
// a value that is never mutated, so a concurrent request observes either
// the whole previous snapshot or the whole new one.
func InstallLimits(l *Limits) { limitsPtr.Store(l) }

// InstallBootLimits records what the process actually started with.
func InstallBootLimits(l *Limits) { bootLimits.Store(l) }
