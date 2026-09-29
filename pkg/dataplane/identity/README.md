# identity

Time-bounded IP to user, host and MAC resolution (B7). A library: no listeners, no goroutines, no clock. Implements
`types.Resolver`. Inputs are `types.IdentityFact` values from identity-source parsers (DHCP, RADIUS accounting, VPN).

```go
r := identity.New(identity.Config{})
inv, err := r.Observe(fact)               // inv: windows whose answer changed (late fact)
entities := r.ResolveAt("10.1.4.9", t)    // user, host, mac valid at t; none if no claim covers t
timeline := r.Timeline("10.1.4.9", from, to)
graph := r.Neighbours("user", "carol", from, to)   // ip-host, ip-user, host-mac edges over time
```

## Rules

- `bind` opens a claim; `release` closes it; a bind by a different holder closes the previous one (DHCP reassignment
  without a release); a repeat bind by the same holder is a renewal and keeps the claim's start.
- A claim nobody closes or refreshes expires `TTL` after its newest bind (dhcp 8h, radius 12h, vpn 12h).
- User comes from radius or vpn claims, host and MAC from dhcp. Two different users overlapping: the newest claim wins
  at confidence 0.7 and both records are cited as evidence. Otherwise confidence is 1.0.
- **No claim covering `t` means no answer.** Never a guess, never the last user carried across a release, including
  after TTL expiry. The PRD's 0.5 "expired but unclosed" confidence is therefore not used.
- Claims are derived from the whole time-sorted fact list on every `Observe`, so arrival order never matters and
  replay is idempotent (a fact seen twice is stored once).
- Only internal addresses (RFC 1918, CGNAT, link-local, ULA by default) are answered; facts for public addresses are
  ignored.
- `Role` on returned entities is empty: the caller knows whether the IP was source or destination.

## Late facts

`ResolveAt` remembers the newest instant asked about per address. When a fact changes who held an address at or before
that instant, `Observe` returns `Invalidation{IP, From, To}` windows so the enrich stage can re-enrich stored events. The
windows are exact, not padded: a property test checks, for random arrival orders, that an instant is inside a returned
window if and only if its answer changed and had already been asked about. A change of `valid_to` alone (a late release
of a claim that already said the same user) is not an invalidation.

## Tests

```sh
go test -race ./pkg/dataplane/identity
go test -run xxx -bench . ./pkg/dataplane/identity
```

- `TestAgainstOracle`: random fact streams in shuffled order against a brute-force scan that shares no code with the resolver.
- `TestInvalidationWindowsAreExact`, `TestConcurrentObserveAndResolve` (`-race`).
- `TestIdentityTruthOnFixtures`: replays `dhcp.log`, `radius.log`, `openvpn.log` (186 facts), then resolves every record
  of `identity_firewall.log` against the manifest: 45 of 45 correct, including the 9 gap records that must resolve to
  no user, and all of `identity_truth.json`'s resolution cases, in forward and reverse arrival order.

## Measured

`BenchmarkResolveAt`, 100000 IPs with a radius and a dhcp claim each, single goroutine, warm, in memory: about 445 ns/op,
about 2.2M lookups/s, 9 allocs/op. Apple M2, macOS, Go 1.27.1. Not a target-hardware number.

## Limits

State is in memory and O(facts): every fact is kept, and an address that was ever queried keeps a small record.
Persistence is deliberately not built: the state is derived data, so after a restart replay the identity-source records
from the vault (`POST /admin/replay` with `scope: source`); `Observe` is idempotent, so replaying is safe. SQLite
(`modernc.org/sqlite`, as PRD 6.3 names) is the upgrade if replay time ever matters. `Neighbours` for a user or host
scans every address (O(addresses)); add a reverse index if the endpoint is polled on a large table.
