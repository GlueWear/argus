package main

import (
	"testing"
	"time"
)

func TestTicketExpiryMatchesCredentialKind(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := &Limits{TicketTTL: 5 * time.Minute, AccessTTL: time.Hour}
	dl := now.Add(2 * time.Hour).Unix()

	ordinary := ticketExpiryFor(Command{Op: "issue-ticket"}, l, dl, now)
	issued := ticketExpiryFor(Command{Op: "issue-access"}, l, dl, now)
	renewed := ticketExpiryFor(Command{Op: "renew-access"}, l, dl, now)
	if ordinary.Sub(now) != 5*time.Minute {
		t.Fatalf("ordinary ticket lifetime = %s", ordinary.Sub(now))
	}
	if issued.Sub(now) != time.Hour || renewed.Sub(now) != time.Hour {
		t.Fatalf("access lifetimes = %s and %s", issued.Sub(now), renewed.Sub(now))
	}
	clamped := ticketExpiryFor(Command{Op: "issue-access"}, l,
		now.Add(10*time.Minute).Unix(), now)
	if clamped.Sub(now) != 10*time.Minute {
		t.Fatalf("lease clamp = %s", clamped.Sub(now))
	}
}

func TestActiveAccessTokenSelection(t *testing.T) {
	testDB(t)
	now := time.Now()
	rows := []struct {
		token, group, participant string
		expires                   int64
		revoked                   int
	}{
		{"expired", "g", "~p", now.Add(-time.Minute).Unix(), 0},
		{"too-close", "g", "~p", now.Add(10 * time.Second).Unix(), 0},
		{"revoked", "g", "~p", now.Add(time.Hour).Unix(), 1},
		{"other", "g", "~q", now.Add(2 * time.Hour).Unix(), 0},
		{"usable", "g", "~p", now.Add(time.Hour).Unix(), 0},
	}
	for i, r := range rows {
		_, err := db.Exec(`INSERT INTO tickets
		  (token,group_name,participant,expires,revoked,created,host,req,state)
		  VALUES (?,?,?,?,?,?,?,?, 'issued')`,
			r.token, r.group, r.participant, r.expires, r.revoked,
			now.Unix(), "~host", string(rune('a'+i)))
		if err != nil {
			t.Fatal(err)
		}
	}
	token, ok, err := activeAccessToken("g", "~p", now)
	if err != nil || !ok || token != "usable" {
		t.Fatalf("got token=%q ok=%v err=%v", token, ok, err)
	}
	if _, ok, err := activeAccessToken("g", "~missing", now); err != nil || ok {
		t.Fatalf("missing token ok=%v err=%v", ok, err)
	}
}

func TestRenewAccessReturnsCompleteGrantWithoutMinting(t *testing.T) {
	testDB(t)
	now := time.Now()
	dl := now.Add(time.Hour).Unix()
	if _, err := db.Exec(`INSERT INTO rooms
	  (host,room_key,group_name,state,created,updated,gen,deadline)
	  VALUES (?,?,?,?,?,?,?,?)`,
		"~host", "room", "managed-group", "active",
		now.Unix(), now.Unix(), 7, dl); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tickets
	  (token,group_name,participant,expires,revoked,created,host,req,state)
	  VALUES (?,?,?,?,?,?,?,?, 'issued')`,
		"existing-token", "managed-group", "~participant",
		now.Add(time.Hour).Unix(), 0, now.Unix(), "~host", "initial"); err != nil {
		t.Fatal(err)
	}

	oldGal, oldTurn, oldLimits := gal, turnCfg, CurrentLimits()
	gal = &Galene{pub: "https://sfu.example"}
	turnCfg = &turnConfig{
		secret: []byte("test-secret"), realm: "turn.example", host: "turn.example",
		udpPort: "3478", tcpPort: "3478", tlsPort: "5349",
		stunURLs: []string{"stun:turn.example:3478"}, sfuWS: "wss://sfu.example/ws",
	}
	limitsPtr.Store(&Limits{AccessTTL: time.Hour})
	t.Cleanup(func() {
		gal, turnCfg = oldGal, oldTurn
		limitsPtr.Store(oldLimits)
	})

	result := opRenewAccess(Command{
		Req: "renew", Op: "renew-access", Room: "room",
		Participant: "~participant", Subject: "~host",
	})
	if !result.OK {
		t.Fatalf("renewal failed: %s", result.Error)
	}
	if result.Group != "managed-group" ||
		result.Location != "https://sfu.example/group/managed-group/" ||
		result.Token != "existing-token" ||
		result.SFU != "wss://sfu.example/ws" ||
		result.Participant != "~participant" ||
		result.Gen != 7 || result.Deadline != dl ||
		result.AccessExpires <= now.Unix() || result.RenewAfter <= now.Unix() ||
		len(result.StunURLs) == 0 || len(result.TurnURLs) == 0 ||
		result.TurnUser == "" || result.TurnCredential == "" {
		t.Fatalf("renewal response was incomplete")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM tickets`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("routine renewal changed ticket count to %d", count)
	}
}
