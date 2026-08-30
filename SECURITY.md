# Security notes

## Open relay to public IPv4 (known, unmitigated)

A valid Noltbook TURN credential can create a permission for **any public
IPv4 address** and relay to it for the credential's lifetime. This was
verified directly: `CreatePermission 1.1.1.1` is granted.

What *is* blocked, by `denied-peer-ip` ranges plus `no-loopback-peers` and
`no-multicast-peers`: private ranges, loopback (`127.0.0.1` → 403),
link-local, and multicast. So the relay cannot be turned inward at the host
or its network.

What is not blocked: arbitrary public destinations. The practical bound is
quota, not destination:

- `user-quota` — allocations per username
- `total-quota` — allocations server-wide
- `max-bps` — **bytes** per second per session, counted separately in and out
- `bps-capacity` — **bytes** per second combined, server-wide

`bps-capacity ÷ max-bps` is a hard ceiling on concurrent allocations. Setting
these carelessly silently caps your call capacity — an early misconfiguration
limited the server to six concurrent allocations and surfaced only as
`486 Allocation Bandwidth Quota Reached`.

Peer restriction was deliberately deferred: forcing relay-only candidates to
a permitted set needs a media-compatibility test that has not been done. If
you deploy this publicly, decide consciously whether that is acceptable.

Note also that **coturn checks credential expiry only at ALLOCATE.** A
measured REFRESH five seconds past expiry succeeded with a full lifetime. A
short credential TTL therefore protects call *setup* and re-allocation, not
call duration — which is why renewal exists and why it does not need to be
aggressive.

## Unknown config keys are ignored silently

coturn does not complain about options it does not recognise. A typo in
`turnserver.conf` is not an error; it is a setting that never takes effect.
Verify limits behaviourally, not by reading the file.

## Reporting

This infrastructure has not had an external security review.
