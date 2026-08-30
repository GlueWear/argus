# Gateway secrets

The gateway reads two files from `$GW_DIR/secrets/` (default: the directory
holding the binary). Both are single-line, mode `0600`, and neither may be
committed.

| File            | What it is                                                        |
|-----------------|-------------------------------------------------------------------|
| `local.key`     | Shared with the Urbit ship. Sent as `X-Argus-Key` by `%noltbook-calls` and checked by the gateway on every request. |
| `remote.bearer` | The gateway's own credential to the warden. Never seen by the ship. |

These are deliberately separate. The ship authenticates to the gateway; the
gateway authenticates to the warden. A compromised ship never learns the
warden bearer.
