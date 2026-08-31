# Argus

Server-side infrastructure for Noltbook's managed voice and video calls.

The Urbit side lives in a separate repository ([`noltbook`](https://github.com/GlueWear/noltbook)),
because that repository's root *is* the Clay desk and anything added to it
ships to every subscriber. This repository holds everything that runs on a
host rather than on a ship.

> **Want to run one?** Start at **[`INSTALL.md`](INSTALL.md)** — the from-zero
> setup path for a call host and a broker ship. Already running one? See
> [`deploy/OPERATIONS.md`](deploy/OPERATIONS.md).

> **Name.** `%argus` was also the name of the Urbit proof-of-concept agent
> that preceded this work. That agent is gone. Here, Argus means the
> infrastructure.

## What is here

| Component | Runs on | Purpose |
|---|---|---|
| `warden/` | the call host | Authoritative admission control. Owns rooms, tickets, quotas, retention, and the minting of short-lived Galène and TURN credentials. Go + SQLite. |
| `gateway/` | the broker ship's machine | A loopback HTTP hop between an Urbit ship and the warden. It exists because Vere's HTTP client does not verify TLS, so the ship talks plain HTTP to localhost and the gateway makes the verified outbound request. |
| `deploy/systemd/` | the call host | Hardened units for the warden and for Galène. |
| `deploy/coturn/` | the call host | A worked `turnserver.conf`, with measured quota values. |
| `deploy/config/` | both | Example configuration. **Every real value is a placeholder.** |

Galène itself is **not vendored**. It is upstream 1.1 plus a local patch,
deployed under `/opt/galene/releases/<version>` with a `current` symlink.
Pin the version; do not fork it.

## Shape of a call

```
browser ──► its own ship (%noltbook)
                 │  local, typed poke
                 ▼
            %noltbook-calls          ── Ames ──►  broker ship
                                                      │ loopback HTTP
                                                      ▼
                                                   gateway
                                                      │ HTTPS, verified
                                                      ▼
                                                   warden ──► Galène admin API
                                                          └─► coturn (HMAC, local)
```

Only the broker ship talks to a gateway. Ordinary ships ask their configured
broker over Ames and never hold a gateway key.

## Secrets

Nothing in this repository contains a credential, and no Go source has one
compiled in. Everything is read from disk at startup.

| Secret | Lives in | Ever leaves the host? |
|---|---|---|
| coturn `static-auth-secret` | `/etc/turnserver.conf` and `/etc/noltbook-warden/turn.env` | No. Used only to compute HMAC credentials locally. |
| Galène admin user/pass | `/etc/noltbook-warden/galene.env` | No. |
| Warden bearer | `/etc/noltbook-warden/bearer` | Gateway → warden only. |
| Gateway local key | `$GW_DIR/secrets/local.key` | Ship → gateway only. |
| Participant join token, TURN credential | minted per request, short-lived | Yes — to that one participant, over a private path. |

All config files are mode `0600`, owned by their service user. `.gitignore`
blocks `secrets/`, `*.key`, `*.bearer`, and every `*.env` that is not an
`.example`.

## Before you run this yourself

Two things to read first:

1. **See `SECURITY.md`** before exposing a TURN server built from this
   configuration to the public internet. There is a known, unmitigated
   open-relay property. It is documented rather than hidden: the security of
   this system does not depend on the source being secret.
2. **Nothing here has been independently reviewed**, and it has not yet been
   deployed by anyone other than its author.

## Running a node

[`INSTALL.md`](INSTALL.md) is the from-zero path: what to provision, in what
order, and how to verify each stage. It covers both installs — the call host
(warden, Galene, coturn, nginx) and the broker ship's gateway sidecar.

Once a node is up, [`deploy/OPERATIONS.md`](deploy/OPERATIONS.md) covers
layout, update, restart, rollback and secret rotation.

## Protocol

The gateway-warden wire contract is specified, schema'd and tested in
[`protocol/v1/`](protocol/v1/).

## Licence

MIT — see [`LICENSE`](LICENSE). Copyright 2026 GlueWear.

Galène is not vendored; see [`patches/galene/`](patches/galene/) for the
pinned upstream, the deployed patch, and upstream's own licence.

## Status

Working, deployed, and exercised — but not independently reviewed, and not
yet run by anyone outside its original deployment. Treat it as reference
infrastructure rather than a turnkey product.
