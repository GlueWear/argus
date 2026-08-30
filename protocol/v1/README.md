# Argus wire contract, v1

This describes the protocol **as it currently runs**. It is documentation of
an existing format, not a new one: no version field has been added to any
live message, and no runtime behaviour changed when this was written.

"v1" names this directory so a future incompatible change has somewhere to
go. Today, the wire carries no version and both peers ship together.

## Why this exists

The response format desynced once, expensively. The gateway unmarshalled the
warden's answer into a local struct and re-serialised it, which silently
deleted every field that struct did not know about — the entire call-access
grant — and `omitempty` on `clients` deleted `clients: 0`, which the ship
then read as a malformed answer. Both peers believed they agreed.

The gateway therefore no longer knows the response schema. It validates the
envelope and forwards the warden's bytes verbatim. This document and the
tests beside it are what keep that true.

## Path

```
%noltbook-calls ──POST /command──► gateway ──POST {warden_base}/command──► warden
   X-Argus-Key: <local key>          Authorization: Bearer <warden bearer>
```

The two credentials are deliberately different. The ship authenticates to the
gateway; the gateway authenticates to the warden. A compromised ship never
learns the warden bearer.

## Command

Schema: [`schema/command.schema.json`](schema/command.schema.json).
Fixtures: `fixtures/command-*.json`.

| Field | Type | Required | Meaning |
|---|---|---|---|
| `req` | string | yes | Idempotency key, unique per `(subject, req)`. Replay returns the first answer with `duplicate: true`. |
| `op` | enum | yes | See below. |
| `room` | string | yes | Room key within the subject's namespace. |
| `subject` | `~ship` | yes | **Authenticated authority.** |
| `participant` | `~ship` | no | The ship an access grant or eviction is *about*. |
| `ttl` | integer | no | Requested lease seconds; the warden clamps it. |

### Authority

`subject` is derived by `%noltbook-calls` from `src.bowl` — Ames' proof of
who sent the poke — and inserted there. It is never read from a browser, a
header, or any caller-supplied field. The room namespace is keyed by it, so
it decides ownership.

`participant` is separate on purpose. Naming a participant grants *that*
participant access to the *subject's* room; it transfers no authority. A
request never names its own host.

The gateway rebuilds the outbound body from validated fields only and
forwards no caller header.

### Operations

`ensure-room`, `renew-room`, `issue-ticket`, `evict-participant`,
`end-room`, `room-status`, `issue-access`, `renew-access`.

`issue-access` performs the full ticket path and then mints TURN credentials
locally, so authorization completes before any credential exists.
`renew-access` issues fresh credentials without touching the room: no lease
change, no generation bump, no group mutation.

## Result

Schema: [`schema/result.schema.json`](schema/result.schema.json).
Fixtures: `fixtures/result-*.json`.

### Always present, including at zero

`ok`, `req`, `op`, `subject`, `state`, `clients`, `gen`, `deadline`.

These must never carry `omitempty`. `clients: 0` is a real answer — an empty
active room — and its absence is not the same statement.
`fixtures/result-room-status-zero-clients.json` exists solely to hold that
line, and `TestResultKeepsZeroValuedFields` fails if `omitempty` returns.

### Present only when they apply

`duplicate`, `error`, `group`, `location`, `token`, `revoked`, `kicked`, and
the whole access group: `sfu`, `participant`, `ice`, `stun_urls`,
`turn_urls`, `turn_username`, `turn_credential`, `access_expires`,
`renew_after`.

`ice` is browser-ready `RTCIceServer` objects. The flat `stun_urls` /
`turn_urls` / `turn_username` / `turn_credential` forms carry the same
information for a typed consumer that would rather not parse nested optional
objects. Both are emitted.

`renew_after` always precedes `access_expires`. Renewal is advised at
half-life because coturn validates the credential at ALLOCATE only — a
measured REFRESH five seconds past expiry succeeded — so the credential has
to cover setup and re-allocation, not call duration.

## HTTP status

| Outcome | Warden | Gateway |
|---|---|---|
| Success | 200, `ok: true` | 200, body verbatim |
| **Business rejection** | 200, `ok: false`, `error` | 200, body verbatim |
| **Infrastructure failure** | 502 | 502, body discarded, terse category |

This split matters. Quota, rate, admission and lifecycle outcomes are
*definitive answers* — the caller must learn the reason. They are returned as
200 with `ok: false`, because the gateway discards the body of any non-200
response, so a business reason returned as 502 would be erased before it
reached the ship. `businessErrors` in the warden is the allowlist, and it is
fail-safe: an unrecognised error is treated as infrastructure.

The gateway additionally answers 502 for `upstream-unreachable`,
`upstream-oversize`, `upstream-status`, `upstream-malformed` and
`upstream-mismatch`. It rejects any answer whose `req` or `subject` does not
match the request it sent.

## Redaction

`token`, `turn_username`, `turn_credential`, `ice[].username`,
`ice[].credential` and both bearers are secret.

They are never logged, at any level, on any path. The gateway logs an
outcome line carrying only subject, req, op and booleans.
`TestGatewayNeverLogsCredentials` drives a full access response through the
handler with the log captured and fails if any of them appears.

## Tests

| Test | Guarantees |
|---|---|
| `warden/contract_test.go` | zero-valued fields survive; optional fields stay optional; the access fixture round-trips with every field; business and infrastructure statuses are separated; every fixture parses |
| `gateway/contract_test.go` | every field is preserved byte-equal and none is added; `clients: 0` survives; business reasons survive; non-200 bodies are discarded; envelope mismatch is refused; no credential is logged; a wrong local key is refused |

All are hermetic. Fixtures contain only obvious placeholders — no value in
this directory is or ever was a live credential.
