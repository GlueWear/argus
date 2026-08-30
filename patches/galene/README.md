# Galène patch set

Galène is **not vendored** here. This directory holds the exact patch applied
to the deployed server, plus everything needed to reproduce that server from
upstream.

Galène is by Juliusz Chroboczek and is MIT licensed; `UPSTREAM-LICENCE` is
upstream's licence file, reproduced for attribution. Upstream:
<https://github.com/jech/galene>.

## Pinned upstream

| | |
|---|---|
| Tag | `galene-1.1` |
| Commit | `da062e782e78dd55df8f17223cae57222bf871ee` |
| Commit date | 2026-06-21 |

The commit hash is the control. See "A caveat about verification" below.

## Patch

| | |
|---|---|
| File | `0001-guard-nil-group-in-pushClientAction.patch` |
| SHA-256 | `8ba3835199215abb4eec3c93bd8146d84c05845a52f288f1dd1d1951242ab103` |
| Touches | `rtpconn/webclient.go`, one line |
| Deployed as | `/opt/galene/releases/1.1-p1` |
| Deployed binary SHA-256 | `a1b0ce2951da7870f55b8a68aeba8e47020f56e573ea9868062b7851b0177e7b` |

### Why it exists

`handleAction` dereferences `c.group` without a nil check when handling
`pushClientAction`. A client that has just left a group sets `c.group` to
nil, but a `pushClientAction` queued before that may still be pending in its
action channel. Dequeuing it then panics on `c.group.Name()`.

There is no `recover()` in that package, so the panic **terminates the whole
process** — dropping every group on the server, not just the one connection
involved. On a shared SFU that is one departing client taking down every
call in progress.

The fix uses the idiom the same handler already uses a few lines further
down:

```go
if c.group == nil || a.group != c.group.Name() {
```

This has not been submitted upstream.

## Reproducing the deployed server

```sh
git clone https://github.com/jech/galene /tmp/galene-src
cd /tmp/galene-src
git checkout da062e782e78dd55df8f17223cae57222bf871ee

# verify before applying
sha256sum patches/galene/0001-guard-nil-group-in-pushClientAction.patch
git apply --check /path/to/0001-guard-nil-group-in-pushClientAction.patch

git apply /path/to/0001-guard-nil-group-in-pushClientAction.patch
CGO_ENABLED=0 go build -trimpath -o galene ./

sudo install -d -m 0755 /opt/galene/releases/1.1-p1
sudo install -m 0755 galene /opt/galene/releases/1.1-p1/galene
sudo cp -a static /opt/galene/releases/1.1-p1/
sudo ln -sfn /opt/galene/releases/1.1-p1 /opt/galene/current
sudo systemctl restart galene
```

The binary hash above was produced by the deployed build. A `go build` on a
different toolchain version will not reproduce it byte for byte; treat it as
an identifier for *that* artifact, not as a reproducible-build claim.

## Verification

```sh
grep -n 'c.group == nil || a.group != c.group.Name()' rtpconn/webclient.go
sha256sum /opt/galene/releases/1.1-p1/galene
systemctl is-active galene
curl -fsS http://127.0.0.1:8443/public-groups.json >/dev/null && echo reachable
```

## Rollback

Releases are separate directories behind a `current` symlink, so rollback is
a symlink swap and a restart — no rebuild, no in-place file edit:

```sh
sudo ln -sfn /opt/galene/releases/<previous> /opt/galene/current
sudo systemctl restart galene
```

## A caveat about verification

`git apply --check` succeeding does **not** prove you are on the right base.
This hunk also applies cleanly to at least one earlier upstream commit,
because the surrounding lines were stable across that range. Verify the
upstream commit hash explicitly; do not treat a clean apply as confirmation.

## What is deliberately absent

No Galène credential, environment file, group definition, token, recording or
database is in this repository. `/etc/galene/*.env` and `/var/lib/galene`
stay on the host.
