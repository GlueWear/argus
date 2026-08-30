package main

// Production call access: one combined Galene + TURN authorization.
//
// WHY COMBINED. Galene join and TURN relay are needed together by the same
// participant at the same moment. Issuing them as two operations would run
// two authorization passes over the same room, take two idempotency keys,
// and leave a window where one succeeded and the other did not. One
// operation means one quota reservation, one participant check, one
// request id, and one durable record.
//
// TURN CREDENTIAL LIFETIME -- measured, not assumed. coturn validates the
// time-limited REST username during ALLOCATE. An allocation that already
// exists keeps refreshing after the credential expires: a REFRESH sent 5s
// past expiry returned success with a full 600s lifetime. So the credential
// only has to cover call SETUP and any later RE-allocation (a reconnect,
// network change or ICE restart) -- never the whole call. A short TTL plus
// renewal is therefore correct and safe for multi-hour calls.
//
// The coturn master secret is read from a droplet-only file and is used
// solely to compute HMACs here. It is never returned, logged, or stored.

import (
	"crypto/hmac"
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type turnConfig struct {
	secret   []byte
	realm    string
	host     string
	udpPort  string
	tcpPort  string
	tlsPort  string
	stunURLs []string
	sfuWS    string
}

var turnCfg *turnConfig

func loadTurnConfig(path string) (*turnConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	kv := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || !strings.Contains(l, "=") {
			continue
		}
		p := strings.SplitN(l, "=", 2)
		kv[p[0]] = p[1]
	}
	t := &turnConfig{
		secret:  []byte(kv["TURN_SECRET"]),
		realm:   kv["TURN_REALM"],
		host:    kv["TURN_HOST"],
		udpPort: kv["TURN_UDP_PORT"],
		tcpPort: kv["TURN_TCP_PORT"],
		tlsPort: kv["TURN_TLS_PORT"],
		sfuWS:   kv["GALENE_WS_PUBLIC"],
	}
	if s := kv["STUN_URLS"]; s != "" {
		t.stunURLs = strings.Split(s, ",")
	}
	if len(t.secret) == 0 || t.realm == "" || t.host == "" {
		return nil, fmt.Errorf("incomplete turn config")
	}
	return t, nil
}

// ICEServer is exactly what a browser RTCPeerConnection consumes.
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// mintTURN computes a coturn time-limited REST credential.
//
//	username = <unix-expiry>:<context>
//	password = base64(HMAC-SHA1(master-secret, username))
//
// The context binds the credential to a Noltbook identity and room so a
// credential minted for one participant/room is distinguishable in coturn
// logs. coturn itself only enforces the expiry and the HMAC; the context is
// for attribution, and MUST NOT be relied on as an access control.
func (t *turnConfig) mintTURN(context string, expires time.Time) (user, pass string) {
	user = strconv.FormatInt(expires.Unix(), 10) + ":" + context
	m := hmac.New(sha1.New, t.secret)
	m.Write([]byte(user))
	return user, base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// turnURLs is the flat TURN URL list, so a typed client can build its own
// ICE entries without parsing nested objects with optional fields.
func (t *turnConfig) turnURLs() []string {
	return []string{
		"turn:" + t.host + ":" + t.udpPort + "?transport=udp",
		"turn:" + t.host + ":" + t.tcpPort + "?transport=tcp",
		"turns:" + t.host + ":" + t.tlsPort + "?transport=tcp",
	}
}

// iceServers builds the browser-ready list: STUN first, then TURN over UDP,
// TCP and TLS. no-dtls is set on this deployment, so TURN-over-TLS is the
// TCP 5349 listener and there is deliberately no turns: UDP entry.
func (t *turnConfig) iceServers(user, pass string) []ICEServer {
	out := []ICEServer{}
	if len(t.stunURLs) > 0 {
		out = append(out, ICEServer{URLs: t.stunURLs})
	}
	out = append(out, ICEServer{URLs: t.turnURLs(), Username: user, Credential: pass})
	return out
}

// turnContext is the attribution string embedded in the TURN username. It
// contains no secret and is safe in coturn logs.
func turnContext(host, room, participant string) string {
	return sanitizeCtx(participant) + "@" + sanitizeCtx(room)
}

func sanitizeCtx(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32)
		}
	}
	out := b.String()
	if len(out) > 48 {
		out = out[:48]
	}
	if out == "" {
		out = "anon"
	}
	return out
}

// clampAccessTTL bounds the credential lifetime and never lets it outlive
// the room lease: an ended or expired room must not hold usable credentials.
func clampAccessTTL(l *Limits, leaseDeadline int64) time.Duration {
	ttl := accessTTLDefault
	if l != nil && l.AccessTTL > 0 {
		ttl = l.AccessTTL
	}
	exp := time.Now().Add(ttl)
	if exp.Unix() > leaseDeadline {
		d := time.Until(time.Unix(leaseDeadline, 0))
		if d < 0 {
			d = 0
		}
		return d
	}
	return ttl
}

const accessTTLDefault = time.Hour

const accessTokenMinValidity = 30 * time.Second

// activeAccessToken returns the newest still-usable Galene token for this
// participant and room. Token values are bearer secrets: callers may place
// the returned value only in a credential response, never in a log or error.
func activeAccessToken(group, participant string, now time.Time) (string, bool, error) {
	var token string
	err := db.QueryRow(`SELECT token FROM tickets
	  WHERE group_name=? AND participant=? AND revoked=0 AND state='issued'
	    AND expires>?
	  ORDER BY expires DESC LIMIT 1`,
		group, participant, now.Add(accessTokenMinValidity).Unix()).Scan(&token)
	if err == nil {
		return token, true, nil
	}
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	return "", false, err
}

// opIssueAccess authorizes one participant for one room and returns
// everything the browser needs, in one operation.
//
// Order matters: every authorization and quota check happens BEFORE any
// credential exists. A rejected request never mints a Galene token and
// never computes a TURN credential.
func opIssueAccess(c Command) Result {
	l := CurrentLimits()
	if !shipRe.MatchString(c.Participant) {
		return Result{Error: "bad-participant"}
	}
	if turnCfg == nil {
		return Result{Error: "service-unavailable"}
	}
	// Reuses the ticket path in full: room state, lease, adoption,
	// per-room and per-host ticket quota, and the global connected
	// participant limit. It returns a Galene token or a safe error.
	tick := opIssueTicket(c)
	if !tick.OK {
		return tick
	}

	// Only now, after authorization succeeded, is a TURN credential
	// computed. It is pure local HMAC -- no external call, nothing to fail
	// halfway, nothing to reconcile.
	dl := tick.Deadline
	ttl := clampAccessTTL(l, dl)
	if ttl <= 0 {
		return Result{Error: "lease-expired"}
	}
	exp := time.Now().Add(ttl)
	user, pass := turnCfg.mintTURN(turnContext(c.Subject, c.Room, c.Participant), exp)

	res := tick
	res.SFU = turnCfg.sfuWS
	res.Participant = c.Participant
	res.ICE = turnCfg.iceServers(user, pass)
	res.StunURLs = turnCfg.stunURLs
	res.TurnURLs = turnCfg.turnURLs()
	res.TurnUser = user
	res.TurnCredential = pass
	res.AccessExpires = exp.Unix()
	// Renew at half-life: an allocation already established survives
	// expiry, so this only has to be early enough that a RE-allocation
	// during the call still has a valid credential.
	res.RenewAfter = time.Now().Add(ttl / 2).Unix()
	return res
}

// opRenewAccess issues fresh credentials for a participant WITHOUT touching
// the room: no lease change, no generation bump, no Galene group mutation.
// A renewed credential lets a mid-call reconnect allocate again.
func opRenewAccess(c Command) Result {
	l := CurrentLimits()
	if !shipRe.MatchString(c.Participant) {
		return Result{Error: "bad-participant"}
	}
	if turnCfg == nil {
		return Result{Error: "service-unavailable"}
	}
	g, st, gen, dl, err := roomOf(c)
	if err != nil {
		return Result{Error: "no-such-room"}
	}
	// An ended or expired room must never receive new access.
	if st != "active" {
		return Result{Error: "room-" + st}
	}
	if dl <= time.Now().Unix() {
		return Result{Error: "lease-expired"}
	}
	// A renewal response is a COMPLETE browser grant, not merely fresh TURN
	// material. Reuse the participant's current Galene token while it is
	// safely valid; otherwise mint one through the ordinary, quota-checked,
	// crash-adoptable ticket path. Routine renewals therefore do not create
	// tokens, while a reconnect never receives an expired one.
	token, found, err := activeAccessToken(g, c.Participant, time.Now())
	if err != nil {
		return Result{Error: "db-ticket"}
	}
	location := gal.Location(g)
	if !found {
		tick := opIssueTicket(c)
		if !tick.OK {
			return tick
		}
		g, gen, dl = tick.Group, tick.Gen, tick.Deadline
		location, token = tick.Location, tick.Token
	}
	ttl := clampAccessTTL(l, dl)
	if ttl <= 0 {
		return Result{Error: "lease-expired"}
	}
	exp := time.Now().Add(ttl)
	user, pass := turnCfg.mintTURN(turnContext(c.Subject, c.Room, c.Participant), exp)

	return Result{
		OK: true, Group: g, Gen: gen, Deadline: dl,
		Location: location, Token: token,
		SFU: turnCfg.sfuWS, Participant: c.Participant,
		ICE: turnCfg.iceServers(user, pass), StunURLs: turnCfg.stunURLs,
		TurnURLs: turnCfg.turnURLs(),
		TurnUser: user, TurnCredential: pass,
		AccessExpires: exp.Unix(),
		RenewAfter:    time.Now().Add(ttl / 2).Unix(),
	}
}
