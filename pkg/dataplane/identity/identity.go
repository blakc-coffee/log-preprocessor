// Package identity answers "who held this IP at time T" from DHCP, RADIUS and
// VPN facts, correctly across IP reassignment.
//
// It is a library: no listeners, no goroutines, no clock. It implements
// types.Resolver. Inputs are types.IdentityFact values produced by
// identity-source parsers (D8); it never sees raw log text.
//
// Model. Per IP and per kind the resolver keeps the facts, ordered by time, and
// derives claims from them: a bind opens a claim, a release closes it, a newer
// bind by someone else closes it (DHCP reassignment without a release), a
// repeat bind by the same holder refreshes it, and a claim nobody closes or
// refreshes expires after its TTL. Claims are derived from the whole sorted
// fact list every time, so the answer never depends on the order facts arrived
// in: replaying the vault, or a late fact, converges to the same state.
//
// The rule that matters: when no claim covers t there is no answer. The
// resolver never guesses and never carries the last user across a release.
package identity

import (
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	types "github.com/blakc-coffee/sluice/pkg/types"
)

// Kinds of identity fact.
const (
	KindDHCP   = "dhcp"
	KindRADIUS = "radius"
	KindVPN    = "vpn"
)

// ErrInvalidFact is returned by Observe for a fact that cannot be used.
var ErrInvalidFact = errors.New("identity: invalid fact")

// Config tunes the resolver. The zero value is the PRD default.
type Config struct {
	// TTL is the lifetime of a claim that nothing closes or refreshes, per
	// kind. Missing kinds default to dhcp 8h, radius 12h, vpn 12h.
	TTL map[string]time.Duration
	// InternalCIDRs are the ranges the resolver answers for. Default: RFC 1918,
	// CGNAT 100.64/10, link-local, IPv6 ULA and link-local. Any other address
	// resolves to nothing and its facts are ignored.
	InternalCIDRs []netip.Prefix
}

var defaultTTL = map[string]time.Duration{KindDHCP: 8 * time.Hour, KindRADIUS: 12 * time.Hour, KindVPN: 12 * time.Hour}

func defaultCIDRs() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "fc00::/7", "fe80::/10"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

const nShards = 64

// Resolver is safe for concurrent use: Observe from the identity stage, ResolveAt
// from many parse workers.
type Resolver struct {
	ttl    map[string]int64
	cidrs  []netip.Prefix
	shards [nShards]shard
}

var _ types.Resolver = (*Resolver)(nil)

type shard struct {
	mu  sync.RWMutex
	ips map[netip.Addr]*ipState
}

// ipState is everything known about one address.
type ipState struct {
	facts  map[string][]types.IdentityFact // per kind, sorted by (At, RecordID)
	claims map[string][]claim              // derived from facts
	// lastQ is the newest instant ResolveAt was asked about, in unix nanos.
	// Answers up to then may already have been given, which is what makes a
	// later fact "late".
	lastQ atomic.Int64
}

// New returns a resolver. It is empty; call Observe to teach it.
func New(cfg Config) *Resolver {
	r := &Resolver{ttl: map[string]int64{}, cidrs: cfg.InternalCIDRs}
	for k, d := range defaultTTL {
		r.ttl[k] = int64(d)
	}
	for k, d := range cfg.TTL {
		r.ttl[k] = int64(d)
	}
	if len(r.cidrs) == 0 {
		r.cidrs = defaultCIDRs()
	}
	for i := range r.shards {
		r.shards[i].ips = map[netip.Addr]*ipState{}
	}
	return r
}

func (r *Resolver) internal(a netip.Addr) bool {
	for _, p := range r.cidrs {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (r *Resolver) shardFor(a netip.Addr) *shard {
	h := fnv.New32a()
	b := a.As16()
	h.Write(b[:])
	return &r.shards[h.Sum32()%nShards]
}

func parseIP(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return a, fmt.Errorf("%w: ip %q", ErrInvalidFact, s)
	}
	return a.Unmap(), nil
}

func newState() *ipState {
	s := &ipState{facts: map[string][]types.IdentityFact{}, claims: map[string][]claim{}}
	s.lastQ.Store(math.MinInt64)
	return s
}

// Observe records a fact. It returns the windows, up to the newest instant
// already asked about, in which the answer for f.IP has changed: the caller
// re-enriches stored events in exactly those windows. A fact for a public
// address is ignored. Observing the same fact twice is a no-op, so replay from
// the vault is safe.
func (r *Resolver) Observe(f types.IdentityFact) ([]types.Invalidation, error) {
	if f.Kind != KindDHCP && f.Kind != KindRADIUS && f.Kind != KindVPN {
		return nil, fmt.Errorf("%w: kind %q", ErrInvalidFact, f.Kind)
	}
	if f.Action != "bind" && f.Action != "release" {
		return nil, fmt.Errorf("%w: action %q", ErrInvalidFact, f.Action)
	}
	if f.At.IsZero() {
		// time.Time{}.UnixNano() is undefined; refuse rather than invent 1754.
		return nil, fmt.Errorf("%w: zero time", ErrInvalidFact)
	}
	ip, err := parseIP(f.IP)
	if err != nil {
		return nil, err
	}
	if !r.internal(ip) {
		return nil, nil
	}
	f.IP = ip.String()

	sh := r.shardFor(ip)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	st := sh.ips[ip]
	if st == nil {
		st = newState()
		sh.ips[ip] = st
	}
	list := st.facts[f.Kind]
	i := sort.Search(len(list), func(i int) bool { return !before(list[i], f) })
	for j := i; j < len(list) && list[j].At.UnixNano() == f.At.UnixNano(); j++ {
		if sameFact(list[j], f) {
			return nil, nil
		}
	}
	old := st.snapshot()
	list = append(list, types.IdentityFact{})
	copy(list[i+1:], list[i:])
	list[i] = f
	st.facts[f.Kind] = list
	st.claims[f.Kind] = derive(f.Kind, list, r.ttl[f.Kind])

	lq := st.lastQ.Load()
	if lq == math.MinInt64 {
		return nil, nil // nothing has ever been asked about this address
	}
	return changed(ip.String(), old, st.snapshot(), lq), nil
}

func before(a, b types.IdentityFact) bool {
	if an, bn := a.At.UnixNano(), b.At.UnixNano(); an != bn {
		return an < bn
	}
	return a.RecordID < b.RecordID
}

func sameFact(a, b types.IdentityFact) bool {
	return a.Kind == b.Kind && a.Action == b.Action && a.RecordID == b.RecordID && a.User == b.User && a.Host == b.Host && a.MAC == b.MAC
}

// ResolveAt returns the entities valid for ip at t: at most one user, one host
// and one MAC. Role is left empty; the caller knows whether ip was the source
// or destination. No claim covering t means no entities.
func (r *Resolver) ResolveAt(ip string, t time.Time) []types.Entity {
	a, err := parseIP(ip)
	if err != nil || t.IsZero() || !r.internal(a) {
		return nil
	}
	tn := t.UnixNano()
	sh := r.shardFor(a)

	sh.mu.RLock()
	st := sh.ips[a]
	if st != nil {
		out := resolve(st.claims, tn)
		bumpMax(&st.lastQ, tn)
		sh.mu.RUnlock()
		return out
	}
	sh.mu.RUnlock()

	// First question about this address: remember it so a fact that arrives
	// afterwards is recognised as late.
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if st = sh.ips[a]; st == nil {
		st = newState()
		sh.ips[a] = st
	}
	bumpMax(&st.lastQ, tn)
	return resolve(st.claims, tn)
}

func bumpMax(v *atomic.Int64, n int64) {
	for {
		cur := v.Load()
		if n <= cur || v.CompareAndSwap(cur, n) {
			return
		}
	}
}
