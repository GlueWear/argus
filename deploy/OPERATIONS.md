# Operating the gateway

The gateway is a **sidecar**: a separate process beside the broker ship, not
part of Noltbook and not part of `%noltbook-calls`. It exists because the
Urbit runtime's HTTP client does not verify TLS, so the ship speaks plain
HTTP to loopback and the gateway makes the verified outbound request.

## Layout

| | |
|---|---|
| Checkout | `~/argus` |
| Binary | `~/argus/gateway/argus-gateway` (git-ignored) |
| Configuration | `~/.config/argus-gateway` — **outside the checkout**, mode 0700 |
| Launch agent | `~/Library/LaunchAgents/com.gluewear.argus-gateway.plist` |
| Log | `~/Library/Logs/argus-gateway.log` |

Configuration deliberately lives outside the checkout so `git pull`,
`git clean` and a fresh clone can never touch a secret, and so no secret is
ever inside an Urbit pier.

```
~/.config/argus-gateway/          0700
├── warden.conf                   0600   warden_base = https://…/warden/v1
└── secrets/                      0700
    ├── local.key                 0600   shared with the ship (X-Argus-Key)
    └── remote.bearer             0600   the gateway's credential to the warden
```

## Update and rebuild

```sh
cd ~/argus && git pull
cd gateway && CGO_ENABLED=0 go build -trimpath -o argus-gateway ./
shasum -a256 argus-gateway
launchctl kickstart -k gui/$(id -u)/com.gluewear.argus-gateway
```

`kickstart -k` restarts in place; downtime is under a second. The ship
retries, so a brief gap is not user-visible.

## Start, stop, status

```sh
launchctl load   ~/Library/LaunchAgents/com.gluewear.argus-gateway.plist
launchctl unload ~/Library/LaunchAgents/com.gluewear.argus-gateway.plist
launchctl list | grep argus-gateway
lsof -iTCP:8899 -sTCP:LISTEN -P -n          # must be 127.0.0.1 only
```

## Verify

```sh
curl -s http://127.0.0.1:8899/healthz                       # process liveness only
curl -s -o /dev/null -w '%{http_code}\n' \
     http://127.0.0.1:8899/readyz                           # expect 401
curl -s -H "X-Argus-Key: $(cat ~/.config/argus-gateway/secrets/local.key)" \
     http://127.0.0.1:8899/readyz                           # expect 200 + chain
```

`/readyz` reports each hop separately: `gateway_authenticated`,
`warden_reachable`, `warden_authenticated`, `warden_db_ready`,
`galene_reachable`. TURN is never probed, because probing it would mean
minting a credential.

Do not paste the key into a shell where it will land in history; the
substitution above reads it from the file.

## Rollback

The previous deployment is kept verbatim. Two levels:

```sh
# 1. back to the previous hand-run binary
launchctl unload ~/Library/LaunchAgents/com.gluewear.argus-gateway.plist
cd ~/noltbook-call-gateway-poc && ./gateway &

# 2. or restore the whole directory from the archive
tar -C ~ -xf ~/argus-rollback-20260830/gateway-poc-live.tar
```

`~/argus-rollback-20260830/BASELINE.txt` records the pre-change pid, argv,
listener, binary and source hashes, and health state.

## Rotating secrets

Both are single-line files. Rotation is a file write plus a restart; nothing
is compiled in and nothing is cached elsewhere.

```sh
# gateway <-> warden bearer: change the warden's copy FIRST, then here
printf '%s' "$NEW" > ~/.config/argus-gateway/secrets/remote.bearer
chmod 600 ~/.config/argus-gateway/secrets/remote.bearer

# ship <-> gateway key: change BOTH sides, then restart the gateway
printf '%s' "$NEW" > ~/.config/argus-gateway/secrets/local.key
chmod 600 ~/.config/argus-gateway/secrets/local.key

launchctl kickstart -k gui/$(id -u)/com.gluewear.argus-gateway
```

The ship's copy of the local key is configured on the ship, not here. Change
it there in the same window or calls will fail authentication until you do.

Never place either value in the checkout, in a pier, in shell history, or in
a log. Nothing in the gateway ever logs them; `TestGatewayNeverLogsCredentials`
enforces that.

## Moving the warden

Edit `warden_base` in `~/.config/argus-gateway/warden.conf` and restart.
`/command` and `/readyz` are derived from it, so there is one value to change
and the TLS ServerName follows automatically. `ARGUS_WARDEN_BASE` in the
launch agent's environment overrides the file.
