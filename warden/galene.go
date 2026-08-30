package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// The operator identity is never counted as a participant.
	operatorName = "~warden-operator"
	// How long one fresh observation listens before reporting its roster.
	// This is now only a per-observation read budget; correctness comes
	// from repeated observations, not from this window being "enough".
	rosterSettle = 700 * time.Millisecond
)

// ErrNoGroup reports that the group is absent. For eviction and end-room
// that is the GOAL state, not a failure: there is nobody left to remove.
// Treating it as an error is what left rooms stuck in 'ending' forever.
var ErrNoGroup = errors.New("no-such-group")

// Galene wraps the localhost admin API and the operator websocket.
// Token ids ARE token values, so nothing here may log them.
type Galene struct {
	base string // http://127.0.0.1:8443
	ws   string // ws://127.0.0.1:8443/ws
	pub  string // https://sfu.gluewear.com
	user string
	pass string
	http *http.Client
}

func NewGalene(envPath string) (*Galene, error) {
	f, err := os.ReadFile(envPath)
	if err != nil {
		return nil, err
	}
	kv := map[string]string{}
	for _, l := range strings.Split(string(f), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || !strings.Contains(l, "=") {
			continue
		}
		p := strings.SplitN(l, "=", 2)
		kv[p[0]] = p[1]
	}
	g := &Galene{
		base: kv["GALENE_BASE"], ws: kv["GALENE_WS"], pub: kv["GALENE_PUBLIC"],
		user: kv["GALENE_ADMIN_USER"], pass: kv["GALENE_ADMIN_PASS"],
		http: &http.Client{Timeout: 10 * time.Second},
	}
	if g.base == "" || g.user == "" || g.pass == "" {
		return nil, fmt.Errorf("incomplete galene config")
	}
	return g, nil
}

func (g *Galene) api(method, path string, body any) (int, []byte, http.Header, error) {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, g.base+"/galene-api/v0"+path, rdr)
	if err != nil {
		return 0, nil, nil, err
	}
	req.SetBasicAuth(g.user, g.pass)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := g.http.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer res.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	return res.StatusCode, rb, res.Header, nil
}

func (g *Galene) Location(group string) string {
	return strings.TrimRight(g.pub, "/") + "/group/" + group + "/"
}

func (g *Galene) PutGroup(group string, desc map[string]any) error {
	code, _, _, err := g.api("PUT", "/.groups/"+url.PathEscape(group), desc)
	if err != nil {
		return err
	}
	if code != 200 && code != 201 && code != 204 {
		return fmt.Errorf("%d", code)
	}
	return nil
}

func (g *Galene) DeleteGroup(group string) error {
	code, _, _, err := g.api("DELETE", "/.groups/"+url.PathEscape(group), nil)
	if err != nil {
		return err
	}
	if code != 204 && code != 404 {
		return fmt.Errorf("%d", code)
	}
	return nil
}

func (g *Galene) ListGroups() ([]string, error) {
	code, b, _, err := g.api("GET", "/.groups/", nil)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("%d", code)
	}
	var out []string
	json.Unmarshal(b, &out)
	return out, nil
}

// CreateToken uses POST (server-generated value). PUT panics on Galène 1.1
// when the token does not already exist, so it is deliberately unused.
func (g *Galene) CreateToken(group, username string, perms []string, exp time.Time) (string, error) {
	code, _, hdr, err := g.api("POST", "/.groups/"+url.PathEscape(group)+"/.tokens/",
		map[string]any{
			"username": username, "permissions": perms,
			"expires": exp.UTC().Format(time.RFC3339),
		})
	if err != nil {
		return "", err
	}
	if code == 404 {
		return "", ErrNoGroup
	}
	if code != 200 && code != 201 {
		return "", fmt.Errorf("%d", code)
	}
	loc := strings.TrimSpace(hdr.Get("Location"))
	if loc == "" {
		return "", fmt.Errorf("no location")
	}
	return loc, nil
}

func (g *Galene) DeleteToken(group, token string) error {
	code, _, _, err := g.api("DELETE",
		"/.groups/"+url.PathEscape(group)+"/.tokens/"+url.PathEscape(token), nil)
	if err != nil {
		return err
	}
	if code != 204 && code != 404 {
		return fmt.Errorf("%d", code)
	}
	return nil
}

func (g *Galene) ListTokens(group string) ([]string, error) {
	code, b, _, err := g.api("GET", "/.groups/"+url.PathEscape(group)+"/.tokens/", nil)
	if err != nil {
		return nil, err
	}
	if code == 404 {
		return nil, ErrNoGroup
	}
	if code != 200 {
		return nil, fmt.Errorf("%d", code)
	}
	var out []string
	json.Unmarshal(b, &out)
	return out, nil
}

// ---------- operator websocket ----------

type wsMsg struct {
	Type        string          `json:"type"`
	Kind        string          `json:"kind,omitempty"`
	Group       string          `json:"group,omitempty"`
	Token       string          `json:"token,omitempty"`
	Id          string          `json:"id,omitempty"`
	Username    *string         `json:"username,omitempty"`
	Permissions json.RawMessage `json:"permissions,omitempty"`
	Version     []string        `json:"version,omitempty"`
	Source      string          `json:"source,omitempty"`
	Dest        string          `json:"dest,omitempty"`
	Value       any             `json:"value,omitempty"`
}

// operator connects on demand with an ephemeral op token, collects the
// roster, runs fn, then always leaves and always revokes the credential.
func (g *Galene) operator(group string, fn func(c *opConn) error) error {
	exp := time.Now().Add(opTokenTTL)
	tok, err := g.CreateToken(group, operatorName, []string{"op", "present"}, exp)
	if err != nil {
		return fmt.Errorf("op-token: %w", err)
	}
	defer g.DeleteToken(group, tok) // ALWAYS revoke

	d := websocket.Dialer{HandshakeTimeout: 8 * time.Second}
	conn, _, err := d.Dial(g.ws, nil)
	if err != nil {
		return fmt.Errorf("ws-dial: %w", err)
	}
	defer conn.Close() // ALWAYS close

	c := &opConn{conn: conn, users: map[string]string{}}
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	if err := conn.WriteJSON(wsMsg{Type: "handshake", Version: []string{"2"}, Id: "warden-op"}); err != nil {
		return err
	}
	var m wsMsg
	if err := conn.ReadJSON(&m); err != nil {
		return err
	}
	if err := conn.WriteJSON(wsMsg{Type: "join", Kind: "join", Group: group, Token: tok}); err != nil {
		return err
	}
	if err := c.collect(rosterSettle); err != nil {
		return err
	}
	return fn(c)
}

type opConn struct {
	conn   *websocket.Conn
	users  map[string]string // client id -> username
	joined bool
}

// collect reads for a settle window. Galène emits no "roster complete"
// marker, so completeness is a bounded settle window plus a later recheck.
// The residual race is documented, not hidden.
func (c *opConn) collect(d time.Duration) error {
	deadline := time.Now().Add(d)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil
		}
		c.conn.SetReadDeadline(time.Now().Add(remaining))
		var m wsMsg
		if err := c.conn.ReadJSON(&m); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return nil
			}
			if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
				return nil
			}
			return nil // treat read end as settle
		}
		switch m.Type {
		case "joined":
			if m.Kind == "join" {
				c.joined = true
			} else if m.Kind == "fail" || m.Kind == "redirect" {
				return fmt.Errorf("op-join-refused")
			}
		case "user":
			if m.Username != nil {
				if m.Kind == "delete" {
					delete(c.users, m.Id)
				} else {
					c.users[m.Id] = *m.Username
				}
			} else if m.Kind == "delete" {
				delete(c.users, m.Id)
			}
		}
	}
}

func (c *opConn) idsFor(username string) []string {
	var out []string
	for id, u := range c.users {
		if u == username {
			out = append(out, id)
		}
	}
	return out
}

func (c *opConn) kick(id string) error {
	u := operatorName
	return c.conn.WriteJSON(wsMsg{Type: "useraction", Kind: "kick",
		Source: "warden-op", Username: &u, Dest: id, Value: "warden"})
}

// ---------- bounded roster reconciliation ----------
//
// Galène emits no "roster complete" marker, so a single settle window is
// a guess. Instead: kick, then take FRESH operator observations until two
// consecutive ones agree the target is absent, bounded by a deadline.
// If stable absence cannot be proven we return an honest failure rather
// than a hopeful success.

const (
	reconcileRounds    = 6
	reconcileInterval  = 700 * time.Millisecond
	reconcileDeadline  = 25 * time.Second
	stableObservations = 2
)

// observe opens a FRESH operator session and returns the client ids
// matching username (or, when username is "", every non-operator id).
func (g *Galene) observe(group, username string) ([]string, error) {
	var ids []string
	err := g.operator(group, func(c *opConn) error {
		if username == "" {
			for id, u := range c.users {
				if u != operatorName {
					ids = append(ids, id)
				}
			}
		} else {
			ids = c.idsFor(username)
		}
		return nil
	})
	return ids, err
}

// kickThese kicks the given ids from one fresh session.
func (g *Galene) kickThese(group string, ids []string) (int, error) {
	n := 0
	err := g.operator(group, func(c *opConn) error {
		for _, id := range ids {
			if err := c.kick(id); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// KickUntilAbsent removes every client whose username matches, proving
// absence with consecutive fresh observations. Unrelated users are never
// touched: only ids whose username matches exactly are kicked.
func (g *Galene) KickUntilAbsent(group, username string) (int, error) {
	deadline := time.Now().Add(reconcileDeadline)
	total, stable := 0, 0
	for round := 0; round < reconcileRounds && time.Now().Before(deadline); round++ {
		ids, err := g.observe(group, username)
		if errors.Is(err, ErrNoGroup) {
			return total, nil // absent group holds nobody
		}
		if err != nil {
			return total, err
		}
		if len(ids) == 0 {
			stable++
			if stable >= stableObservations {
				return total, nil
			}
			time.Sleep(reconcileInterval)
			continue
		}
		stable = 0 // someone appeared; the count restarts
		n, err := g.kickThese(group, ids)
		total += n
		if err != nil {
			return total, err
		}
		time.Sleep(reconcileInterval)
	}
	return total, fmt.Errorf("not-stably-absent")
}

// KickUntilEmpty is the same discipline for every non-operator client.
func (g *Galene) KickUntilEmpty(group string) (int, error) {
	deadline := time.Now().Add(reconcileDeadline)
	total, stable := 0, 0
	for round := 0; round < reconcileRounds && time.Now().Before(deadline); round++ {
		ids, err := g.observe(group, "")
		if errors.Is(err, ErrNoGroup) {
			return total, nil // absent group is already empty
		}
		if err != nil {
			return total, err
		}
		if len(ids) == 0 {
			stable++
			if stable >= stableObservations {
				return total, nil
			}
			time.Sleep(reconcileInterval)
			continue
		}
		stable = 0
		n, err := g.kickThese(group, ids)
		total += n
		if err != nil {
			return total, err
		}
		time.Sleep(reconcileInterval)
	}
	return total, fmt.Errorf("not-stably-empty")
}

func (g *Galene) CountClients(group string) (int, error) {
	ids, err := g.observe(group, "")
	if errors.Is(err, ErrNoGroup) {
		return 0, nil
	}
	return len(ids), err
}

// ---------- cheap authoritative connected-client count ----------

// GroupStat is one entry of Galene's admin .stats endpoint.
type GroupStat struct {
	Name    string            `json:"name"`
	Clients []json.RawMessage `json:"clients"`
}

// Stats returns per-group connected clients. This is a single admin REST
// GET (~12ms, tens of bytes) that lists ONLY groups with someone in them,
// so it is an authoritative live count without any roster websocket cycle
// or persistent presence subsystem.
func (g *Galene) Stats() ([]GroupStat, error) {
	code, b, _, err := g.api("GET", "/.stats", nil)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("%d", code)
	}
	var out []GroupStat
	if e := json.Unmarshal(b, &out); e != nil {
		return nil, e
	}
	return out, nil
}

// ManagedClientCount sums connected clients across MANAGED groups only, so
// unmanaged groups such as nbdev never consume the managed global budget.
func (g *Galene) ManagedClientCount() (int, error) {
	st, err := g.Stats()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, s := range st {
		if isManaged(s.Name) {
			n += len(s.Clients)
		}
	}
	return n, nil
}
