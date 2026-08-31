# Running an Argus node

This is the from-zero setup path. Follow it top to bottom.

If you only need to operate a node that already exists — restart it, roll it
back, rotate a secret — you want [`deploy/OPERATIONS.md`](deploy/OPERATIONS.md)
instead. This document builds one; that one runs one.

Read [`SECURITY.md`](SECURITY.md) before you finish. It documents a known,
unmitigated open-relay property in the TURN configuration. Step 5 is where you
create that exposure.

---

## 1. Decide what you are running

There are **two separate installs**, usually on two different machines. Read
this section before provisioning anything.

| | **Call host** | **Broker ship** |
|---|---|---|
| Machine | A public Linux server | Wherever your Urbit ship already runs |
| Runs | warden, Galène, coturn, nginx | the `argus-gateway` sidecar |
| Needs | public IPv4, DNS, TLS certs, root | an existing ship, a Go toolchain |
| Covered in | **Part A**, steps 2–9 | **Part B**, steps 10–14 |
| Rough effort | a few hours | about fifteen minutes |

To offer calls to the network you need both, and **the call host must exist
first** — the gateway refuses to start if it cannot be told where its warden
is. Build in the order given here, not in the order the repository directories
suggest.

One person can run both. They do not have to be the same person: a broker
operator may point at somebody else's call host, given its URL and a bearer
token issued by that host's operator.

---

## 2. Before you start

Have these ready. Every one of them blocks a later step.

- [ ] A Linux server with a **public IPv4 address**. Not behind NAT, or behind
      1:1 DNAT only. TURN cannot be made to work through arbitrary NAT.
- [ ] Root on that server, and `systemd`.
- [ ] A domain, and the ability to add DNS records.
- [ ] **Three DNS A records**, all pointing at the server's public IP. They may
      share one host; they are separate names so the roles can later be split.
- [ ] Go 1.21 or newer, on the call host and on the broker machine.
- [ ] `certbot`, `nginx`, and `coturn` installable from your distribution.
- [ ] An Urbit ship you control, with `%noltbook` installed.

### Placeholders

Fill these in once. Every later step refers back to this table; nothing else in
this document needs editing.

| Placeholder | Meaning | Example |
|---|---|---|
| `calls.example.com` | Warden endpoint. The broker talks to this. | |
| `sfu.example.com` | Galène. Browsers connect here for media. | |
| `turn.example.com` | coturn. Must match the coturn `realm` exactly. | |
| `YOUR.PUBLIC.IP` | The server's public address | |
| `YOUR.PRIVATE.IP` | Its private/anchor address, or the same as above if none | |
| `~yourship` | The Urbit ship that will act as broker | |

Generate the four secrets now, and keep them somewhere you can paste from:

```sh
openssl rand -hex 32   # TURN_SECRET        -> coturn + warden, must match
openssl rand -hex 32   # warden bearer      -> warden + gateway, must match
openssl rand -hex 32   # gateway local key  -> gateway + ship, must match
openssl rand -hex 16   # Galene admin password
```

Three of these are **shared between two places**. Getting one of them
mismatched is the most common way this install fails, and the failure surfaces
as a `401` several steps later. Note down which is which.

---

# Part A — the call host

## 3. Users, directories, firewall

```sh
sudo adduser --system --group --no-create-home wardensvc
sudo adduser --system --group --no-create-home galene

sudo install -d -m 0755 -o wardensvc -g wardensvc /var/lib/noltbook-warden
sudo install -d -m 0750 -o wardensvc -g wardensvc /etc/noltbook-warden
sudo install -d -m 0755 -o galene   -g galene   /var/lib/galene
sudo install -d -m 0755 /opt/noltbook-warden /opt/galene/releases
```

Open exactly these ports. The relay range must match `min-port`/`max-port` in
the coturn config in step 5 — if they disagree, calls fail only for the users
who need a relay, which is the hardest case to notice.

```sh
sudo ufw allow 80,443/tcp          # nginx: ACME, warden, Galene
sudo ufw allow 3478/tcp
sudo ufw allow 3478/udp            # TURN / STUN
sudo ufw allow 5349/tcp            # TURN over TLS
sudo ufw allow 49160:49200/udp     # coturn relay range
sudo ufw allow 50000:50200/udp     # Galene media
sudo ufw enable
```

Nothing else is exposed. The warden and Galène both listen on loopback only
and are reached through nginx.

## 4. TLS certificates

Issue **one** certificate covering all three names, under a fixed nickname.
Everything later — all three nginx vhosts and coturn — points at that single
path, so the name matters:

```sh
sudo certbot certonly --standalone --cert-name noltbook-calls \
  -d calls.example.com -d sfu.example.com -d turn.example.com
```

This lands in `/etc/letsencrypt/live/noltbook-calls/`. Using `--cert-name`
rather than letting certbot derive a directory from the first domain means
the path stays stable if you ever add or drop a name.

`turn.example.com` must be included even though no web server serves it:
coturn reads that certificate directly for TURN over TLS.

`--standalone` needs port 80 free, which it is at this point. After step 8
the redirect vhost serves ACME challenges from a webroot, so renewals work
without stopping nginx.

## 5. coturn

> **Read [`SECURITY.md`](SECURITY.md) now.** This step puts a TURN server on
> the public internet. The configuration below bounds it with quotas, a fixed
> relay range and a denied-peer list covering private space, but a known
> open-relay property remains. It is documented rather than hidden. Decide
> whether you accept it before continuing.

```sh
sudo apt install coturn
sudo cp deploy/coturn/turnserver.conf.example /etc/turnserver.conf
sudo chmod 0600 /etc/turnserver.conf
sudo editor /etc/turnserver.conf
```

Replace `YOUR.PRIVATE.IP`, `YOUR.PUBLIC.IP`, `realm`, and
`static-auth-secret` (with your generated `TURN_SECRET`).

The example file's certificate paths assume a per-name certificate. Point
them at the shared one from step 4 instead:

```
cert=/etc/letsencrypt/live/noltbook-calls/fullchain.pem
pkey=/etc/letsencrypt/live/noltbook-calls/privkey.pem
```

If the server has no private address, set `listening-ip` and `relay-ip` to the
public one and delete the `external-ip` line entirely rather than leaving half
of it.

```sh
sudo systemctl enable --now coturn
sudo systemctl status coturn
```

The bandwidth settings deserve one warning, because it was learned the hard
way and the symptom is misleading: coturn **reserves** `max-bps` per
allocation against `bps-capacity`. So `bps-capacity / max-bps` is a hard cap
on concurrent allocations no matter how little traffic actually flows. Set
them together or bandwidth silently becomes your participant limit — the
error you get is `486 Allocation Bandwidth Quota Reached`, which does not
sound like a configuration problem.

## 6. Galène

Galène is not vendored here. Build upstream 1.1 with the one-line patch in
[`patches/galene/`](patches/galene/) and follow that directory's README —
it carries the pinned commit, the patch hash, and the release layout.

The patch is not optional. Without it, one client leaving a group at the wrong
moment panics the process, and since there is no `recover()` in that package
the panic takes down **every call on the server**, not just that connection.

Note the caveat in that README: `git apply --check` succeeding does *not*
prove you are on the right base commit. Verify the upstream hash explicitly.

Then install the service:

```sh
sudo cp deploy/systemd/galene.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now galene
curl -fsS http://127.0.0.1:8443/public-groups.json >/dev/null && echo reachable
```

Create the Galène administrator account that the warden will use — consult
upstream Galène's documentation for the current mechanism, and use the admin
password you generated in step 2.

## 7. The warden

```sh
cd warden
CGO_ENABLED=0 go build -trimpath -o noltbook-warden ./
sudo install -m 0755 noltbook-warden /opt/noltbook-warden/warden
sudo install -m 0644 limits.conf /etc/noltbook-warden/limits.conf
```

Three configuration files, all mode `0600`, all owned by `wardensvc`:

```sh
sudo cp deploy/config/warden/bearer.example     /etc/noltbook-warden/bearer
sudo cp deploy/config/warden/galene.env.example /etc/noltbook-warden/galene.env
sudo cp deploy/config/warden/turn.env.example   /etc/noltbook-warden/turn.env
sudo chown wardensvc:wardensvc /etc/noltbook-warden/*
sudo chmod 0600 /etc/noltbook-warden/bearer /etc/noltbook-warden/*.env
```

Edit each one, using the table from step 2:

- **`bearer`** — the warden bearer. One line, no trailing newline fuss, no
  quotes. The gateway will send exactly this string.
- **`galene.env`** — leave `GALENE_BASE` as `http://127.0.0.1:8443`. Set
  `GALENE_WS` to `wss://sfu.example.com/ws`, `GALENE_PUBLIC` to
  `https://sfu.example.com`, and the admin credentials from step 6.
- **`turn.env`** — `TURN_SECRET` **must equal coturn's `static-auth-secret`
  byte for byte**. Set `TURN_REALM` and `TURN_HOST` to `turn.example.com`,
  and `GALENE_WS_PUBLIC` to `wss://sfu.example.com/ws`.

Then start it:

```sh
sudo cp -r deploy/systemd/noltbook-warden.service \
           deploy/systemd/noltbook-warden.service.d /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now noltbook-warden
curl -fsS http://127.0.0.1:8900/healthz
```

The warden listens on `127.0.0.1:8900` and serves `/command`, `/healthz` and
`/readyz`. It is never exposed directly.

Defaults it uses, overridable by environment variable if you need to move
things: `WARDEN_DIR` is `/etc/noltbook-warden`, `WARDEN_DB` is
`/var/lib/noltbook-warden/warden.db`, and `WARDEN_LIMITS` points at
`limits.conf`.

`limits.conf` ships with measured values that fit the port ranges in step 3.
Leave it alone on a first install. It reloads on `SIGHUP`; an invalid file is
rejected whole and the last good configuration stays live.

## 8. nginx

nginx terminates TLS for all three names and is the only thing that reaches
the two loopback services. It also does real work beyond proxying: rate
limiting, method restriction, blocking Galene's admin API, and refusing to
confirm to a scanner that any of this exists.

First, a log format that records the path but never the query string, so a
token that ends up in a URL never lands in a logfile. Put it in
`/etc/nginx/conf.d/00-noquery-log.conf`:

```nginx
log_format noquery '$remote_addr - $remote_user [$time_local] '
                   '"$request_method $uri $server_protocol" '
                   '$status $body_bytes_sent "$http_referer" "$http_user_agent"';
```

### Redirect and ACME — `sites-available/00-redirect`

```nginx
server {
    listen 80; listen [::]:80;
    server_name sfu.example.com turn.example.com calls.example.com;
    location /.well-known/acme-challenge/ { root /var/www/html; allow all; }
    location / { return 301 https://$host$request_uri; }
}
```

### The warden — `sites-available/calls.example.com`

```nginx
limit_req_zone $binary_remote_addr zone=wardenreq:1m rate=30r/s;
server {
    listen 443 ssl http2; listen [::]:443 ssl http2;
    server_name calls.example.com;
    ssl_certificate     /etc/letsencrypt/live/noltbook-calls/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/noltbook-calls/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    access_log /var/log/nginx/calls.access.log noquery;
    error_log  /var/log/nginx/calls.error.log warn;

    location = /warden/v1/command {
        limit_req zone=wardenreq burst=20 nodelay;
        limit_except POST { deny all; }
        client_max_body_size 16k;
        proxy_pass http://127.0.0.1:8900/command;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 90s; proxy_send_timeout 90s; proxy_connect_timeout 5s;
    }

    # Authenticated readiness. Proxies to the warden's bearer-gated
    # /health, never to the unauthenticated loopback /readyz.
    location = /warden/v1/readyz {
        limit_req zone=wardenreq burst=10 nodelay;
        limit_except GET { deny all; }
        proxy_pass http://127.0.0.1:8900/health;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 20s; proxy_send_timeout 20s; proxy_connect_timeout 5s;
    }

    location / { return 204; }
}
```

Four things here are deliberate and worth not simplifying away:

**Exactly two paths are exposed, both `location =` exact matches.** The
warden's own `/healthz` and `/readyz` are never publicly reachable. Do not
replace these with a `location /warden/v1/` prefix block — that would publish
every route the warden has, including ones added by a future version.

**`proxy_pass` names the upstream path explicitly** (`/command`, `/health`).
There is no prefix-stripping trailing-slash trick to get subtly wrong.

**`location / { return 204; }` is a dark catch-all.** Every other request gets
an empty 204. A scanner cannot tell a warden lives here, and cannot
distinguish a wrong path from a stopped service. This is why an external
`204` proves nothing about warden health — see step 9.

**`/warden/v1/readyz` proxies to the warden's `/health`, not its `/readyz`.**
The loopback `/readyz` is unauthenticated because the whole listener is
loopback; `/health` is bearer-gated and is the only readiness surface safe to
expose. Getting this pair backwards would publish internal state.

### Galene — `sites-available/sfu.example.com`

```nginx
server {
    listen 443 ssl http2; listen [::]:443 ssl http2;
    server_name sfu.example.com;
    ssl_certificate     /etc/letsencrypt/live/noltbook-calls/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/noltbook-calls/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    access_log /var/log/nginx/sfu.access.log noquery;
    error_log  /var/log/nginx/sfu.error.log warn;

    # Administrative API must never be reachable from the internet.
    location /galene-api/ { return 404; }

    location /ws {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        # Noltbook is served from arbitrary ship origins. Galene 1.x accepts
        # only exact configured origins, so normalise this USER websocket hop
        # to its public SFU origin. Authentication still requires the scoped,
        # short-lived token sent inside the Galene protocol. The admin API is
        # blocked above and is not covered by this location.
        proxy_set_header Origin https://sfu.example.com;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    location / {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

`location /galene-api/ { return 404; }` comes **first** and is not optional.
Those endpoints are the administrator API — the keys to every group on the
server. The warden reaches them over loopback; nothing else may.

The `Origin` rewrite on `/ws` is the non-obvious one. Noltbook is served from
whatever ship origin the user happens to be on, and Galene 1.x will only
accept websocket connections from origins it has been configured with — so
the browser's real origin would be rejected. Normalising it here is safe
because joining still requires the scoped, short-lived token carried inside
the Galene protocol, and because the admin API is blocked above and so is not
covered by this rule. Only `/ws` gets the `Upgrade` headers and the 3600s
timeouts; the static `/` location does not need them.

### TURN's placeholder — `sites-available/placeholder-tls`

`turn.example.com` is in the certificate and resolves to this host, so
something has to answer on 443 or it falls through to whichever vhost nginx
happens to consider default. It serves nothing:

```nginx
server {
    listen 443 ssl http2; listen [::]:443 ssl http2;
    server_name turn.example.com;
    ssl_certificate     /etc/letsencrypt/live/noltbook-calls/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/noltbook-calls/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    access_log /var/log/nginx/placeholder.access.log noquery;
    location / { return 204; }
}
```

TURN itself does not go through nginx. coturn owns 3478 and 5349 directly and
uses the same certificate from disk.

### Enable

```sh
sudo ln -s /etc/nginx/sites-available/00-redirect            /etc/nginx/sites-enabled/
sudo ln -s /etc/nginx/sites-available/calls.example.com      /etc/nginx/sites-enabled/
sudo ln -s /etc/nginx/sites-available/sfu.example.com        /etc/nginx/sites-enabled/
sudo ln -s /etc/nginx/sites-available/placeholder-tls        /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

If `nginx -t` warns `protocol options redefined for 0.0.0.0:443`, that is
because `http2` is repeated across vhosts on one listen address. It is
cosmetic. On nginx 1.25.1+ you can silence it by dropping `http2` from the
`listen` lines and using a single `http2 on;` per server block.

## 9. Verify the host

On the call host itself:

```sh
systemctl is-active nginx coturn galene noltbook-warden
curl -fsS http://127.0.0.1:8443/public-groups.json >/dev/null && echo galene-ok
curl -fsS http://127.0.0.1:8900/healthz && echo warden-ok
```

Then from **another machine**, checking what the internet actually sees. The
expected codes are as important as the successes — several of these are meant
to fail:

```sh
curl -s -o /dev/null -w 'command GET   %{http_code} (want 403)\n' \
     https://calls.example.com/warden/v1/command
curl -s -o /dev/null -w 'command POST  %{http_code} (want 401)\n' \
     -X POST https://calls.example.com/warden/v1/command
curl -s -o /dev/null -w 'readyz  GET   %{http_code} (want 401)\n' \
     https://calls.example.com/warden/v1/readyz
curl -s -o /dev/null -w 'catchall      %{http_code} (want 204)\n' \
     https://calls.example.com/
curl -s -o /dev/null -w 'sfu root      %{http_code} (want 200)\n' \
     https://sfu.example.com/
curl -s -o /dev/null -w 'galene-api    %{http_code} (want 404)\n' \
     https://sfu.example.com/galene-api/v0/
```

Reading these:

- **`403` on `GET /warden/v1/command`** — `limit_except POST` is working. The
  request never reached the warden.
- **`401` on `POST /warden/v1/command`** and on **`GET /warden/v1/readyz`** —
  these are the two that prove the proxy path is correct. A `401` means the
  request reached a handler that evaluates bearer tokens, which is exactly
  what you want from outside. `/warden/v1/readyz` also returns a warden JSON
  body, so seeing `{"ok":false,...,"error":"unauthorized"}` confirms you are
  talking to the warden and not to nginx.
- **`404` on `/galene-api/`** — the administrator API is not reachable from
  the internet. If this returns anything else, stop and fix it before going
  further.

> **A `204` is not a health check.** The catch-all returns `204` for every
> unmatched path, and it will keep returning `204` with the warden stopped,
> with Galene stopped, or with the whole backend removed. It confirms nginx
> and TLS, nothing more. Any URL on `calls.example.com` other than the two
> exact paths above tells you nothing about whether calls work.

Real backend health is only visible through the gateway's authenticated
`/readyz`, which is step 14.

---

# Part B — the broker ship

## 10. Build the gateway

On the machine running your ship:

```sh
git clone https://github.com/GlueWear/argus ~/argus
cd ~/argus/gateway
CGO_ENABLED=0 go build -trimpath -o argus-gateway ./
```

## 11. Configuration and secrets

These live **outside the checkout**, so that `git pull`, `git clean` or a
fresh clone can never touch a secret, and so no secret is ever inside an Urbit
pier.

```sh
install -d -m 0700 ~/.config/argus-gateway/secrets
cp ~/argus/deploy/config/gateway/warden.conf.example ~/.config/argus-gateway/warden.conf
chmod 0600 ~/.config/argus-gateway/warden.conf
```

Set `warden_base` to `https://calls.example.com/warden/v1`. It must be
`https`. There is no compiled-in default — a gateway that does not know where
its warden is refuses to start rather than guessing, which is what stops a
fresh build from pointing at somebody else's warden.

Two secret files, one line each, mode `0600`:

```sh
printf '%s' 'YOUR_GATEWAY_LOCAL_KEY' > ~/.config/argus-gateway/secrets/local.key
printf '%s' 'YOUR_WARDEN_BEARER'     > ~/.config/argus-gateway/secrets/remote.bearer
chmod 0600 ~/.config/argus-gateway/secrets/*
```

`local.key` is shared with your ship. `remote.bearer` must match
`/etc/noltbook-warden/bearer` on the call host, and the ship never sees it.
They are deliberately separate: a compromised ship never learns the warden
bearer.

Use `printf` rather than `echo` — a trailing newline in either file is
compared literally and will fail authentication.

## 12. Run it as a service

On Linux, write a systemd unit. On macOS, start from
[`deploy/launchd/com.gluewear.argus-gateway.plist.example`](deploy/launchd/com.gluewear.argus-gateway.plist.example):

```sh
cp deploy/launchd/com.gluewear.argus-gateway.plist.example \
   ~/Library/LaunchAgents/com.gluewear.argus-gateway.plist
# edit paths inside, then:
launchctl load ~/Library/LaunchAgents/com.gluewear.argus-gateway.plist
```

Confirm it is listening on loopback and nowhere else:

```sh
lsof -nP -iTCP:8899 -sTCP:LISTEN
```

The address must read `127.0.0.1:8899`. If it shows `*:8899`, stop and fix it
before continuing — the gateway holds the warden bearer and performs no
authentication beyond a shared key.

Note that the example is a Launch**Agent**, which requires a GUI login
session. If your ship runs on a headless Mac, convert it to a LaunchDaemon or
it will not start after a reboot.

## 13. Point the ship at the gateway

`%noltbook-calls` ships with both roles in one agent; holding a gateway key is
what makes a ship a broker. Configure it with the same `local.key` value from
step 11, and set the gateway endpoint to `http://127.0.0.1:8899`.

Plain HTTP to loopback is correct here and is not an oversight. The ship
cannot verify TLS, so it makes an unverified request that never leaves the
machine, and the gateway makes the verified one.

## 14. Verify end to end

```sh
curl -s http://127.0.0.1:8899/healthz
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8899/readyz   # expect 401
curl -s -H "X-Argus-Key: $(cat ~/.config/argus-gateway/secrets/local.key)" \
     http://127.0.0.1:8899/readyz
```

The `401` is not a failure — it confirms the gateway rejects unauthenticated
callers. The third command is the real check. Success looks like this, with
every field `true`:

```json
{
  "configured": true,
  "gateway_authenticated": true,
  "warden_reachable": true,
  "warden_authenticated": true,
  "warden_db_ready": true,
  "galene_reachable": true,
  "ok": true
}
```

Do not paste the key into a shell where it lands in history; the substitution
above reads it from the file.

`/readyz` reports each hop separately, so a failure tells you which link is
broken:

| Field | `false` means |
|---|---|
| `configured` | The gateway has no key or no bearer. Step 11. |
| `gateway_authenticated` | Your `X-Argus-Key` does not match `local.key`. |
| `warden_reachable` | DNS, TLS, nginx, or the firewall. Step 8. |
| `warden_authenticated` | `remote.bearer` ≠ the host's `bearer`. Step 7. |
| `warden_db_ready` | The warden cannot write its database. Check ownership of `/var/lib/noltbook-warden`. |
| `galene_reachable` | Galène is down, or `GALENE_BASE` is wrong. Step 6. |

TURN is deliberately never probed, because probing it would mean minting a
credential.

Then place a real call between two ships. `/readyz` proves the control path;
it says nothing about whether media actually flows, which is what the TURN and
relay port configuration in steps 3 and 5 decides.

---

## If something is wrong

Most first-install failures are one of three things:

**A `401` from `/readyz`.** One of the three shared secrets differs between
its two locations. Compare them byte for byte — a trailing newline counts.

**`warden_reachable: false` but the host looks healthy.** Check that
`warden_base` ends in `/warden/v1` with no trailing slash, since the gateway
appends `/command` and `/readyz` to it and nginx matches those two paths
exactly. Then confirm from outside that `POST /warden/v1/command` returns
`401` rather than `204` — a `204` means your request is landing in the
catch-all, so the path is wrong or the vhost is not enabled.

**Calls connect and then fail, or media never arrives.** The control path is
fine and the problem is media. Check that the coturn relay range matches the
firewall exactly, and re-read the bandwidth note in step 5 — `bps-capacity`
divided by `max-bps` caps concurrent allocations regardless of real traffic.

For anything after a successful install — restarts, rebuilds, rollback, secret
rotation — see [`deploy/OPERATIONS.md`](deploy/OPERATIONS.md).

## Before you offer this to anyone

This procedure has been carried out for one deployment, and the nginx
configuration in step 8 is transcribed from that live host rather than
invented. That is not the same as being portable: nothing here has been
independently reviewed, and no second node has been built from this document.
Treat your first one as a test, and read [`SECURITY.md`](SECURITY.md) in full
before pointing anyone else's ship at it.
