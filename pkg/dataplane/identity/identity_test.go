package identity

import (
	"math/rand"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

var t0 = time.Date(2026, 9, 28, 9, 0, 0, 0, time.UTC)

func at(min int) time.Time { return t0.Add(time.Duration(min) * time.Minute) }

func fact(kind, action, ip, user, host, mac string, min int, rec uint64) types.IdentityFact {
	return types.IdentityFact{Kind: kind, Action: action, IP: ip, User: user, Host: host, MAC: mac, At: at(min), RecordID: types.RecordID(rec), SourceID: "test"}
}

func mustObserve(t *testing.T, r *Resolver, fs ...types.IdentityFact) {
	t.Helper()
	for _, f := range fs {
		if _, err := r.Observe(f); err != nil {
			t.Fatal(err)
		}
	}
}

func users(es []types.Entity) string {
	for _, e := range es {
		if e.Type == "user" {
			return e.ID
		}
	}
	return ""
}

func TestBindReleaseAndGap(t *testing.T) {
	r := New(Config{})
	mustObserve(t, r,
		fact("radius", "bind", "10.1.4.7", "alice", "", "aa:aa", 0, 1),
		fact("radius", "release", "10.1.4.7", "", "", "", 60, 2),
		fact("radius", "bind", "10.1.4.7", "frank", "", "bb:bb", 66, 3),
	)
	for _, c := range []struct {
		min  int
		want string
	}{{-1, ""}, {0, "alice"}, {59, "alice"}, {60, ""}, {63, ""}, {66, "frank"}, {500, "frank"}} {
		if got := users(r.ResolveAt("10.1.4.7", at(c.min))); got != c.want {
			t.Errorf("minute %d: got %q want %q", c.min, got, c.want)
		}
	}
}

func TestImplicitCloseOnReassignment(t *testing.T) {
	r := New(Config{})
	mustObserve(t, r,
		fact("dhcp", "bind", "10.1.4.9", "", "laptop-carol", "aa:01", 0, 1),
		fact("dhcp", "bind", "10.1.4.9", "", "laptop-heidi", "aa:02", 30, 2), // no release between
	)
	host := func(min int) string {
		for _, e := range r.ResolveAt("10.1.4.9", at(min)) {
			if e.Type == "host" {
				return e.ID
			}
		}
		return ""
	}
	if host(29) != "laptop-carol" || host(30) != "laptop-heidi" {
		t.Fatalf("got %q then %q", host(29), host(30))
	}
	es := r.ResolveAt("10.1.4.9", at(10))
	for _, e := range es {
		if e.Type == "host" && (e.ValidTo == nil || !e.ValidTo.Equal(at(30))) {
			t.Fatalf("carol's claim should end at the reassignment, valid_to=%v", e.ValidTo)
		}
	}
}

func TestRenewalKeepsStartAndRefreshesTTL(t *testing.T) {
	r := New(Config{TTL: map[string]time.Duration{"dhcp": 2 * time.Hour}})
	for i := 0; i < 6; i++ { // a bind every 90 min, each inside the TTL of the last
		mustObserve(t, r, fact("dhcp", "bind", "10.1.4.5", "", "h", "aa:01", i*90, uint64(i+1)))
	}
	es := r.ResolveAt("10.1.4.5", at(6*90))
	if len(es) == 0 || !es[0].ValidFrom.Equal(at(0)) {
		t.Fatalf("renewals must extend one claim from its first bind: %+v", es)
	}
	if r.ResolveAt("10.1.4.5", at(5*90+121)) != nil {
		t.Fatal("claim must lapse TTL after the last renewal")
	}
}

func TestTTLExpiryNoAnswer(t *testing.T) {
	r := New(Config{})
	mustObserve(t, r, fact("vpn", "bind", "10.8.0.4", "carol", "", "", 0, 1))
	if users(r.ResolveAt("10.8.0.4", at(11*60))) != "carol" {
		t.Fatal("inside the 12h vpn TTL")
	}
	if r.ResolveAt("10.8.0.4", at(12*60)) != nil {
		t.Fatal("the resolver must not guess past the TTL")
	}
}

func TestConflictingUsersLowerConfidence(t *testing.T) {
	r := New(Config{})
	mustObserve(t, r,
		fact("radius", "bind", "10.1.4.9", "carol", "", "", 0, 1),
		fact("vpn", "bind", "10.1.4.9", "mallory", "", "", 10, 2),
	)
	es := r.ResolveAt("10.1.4.9", at(20))
	if users(es) != "mallory" || es[0].Confidence != 0.7 || len(es[0].Evidence) != 2 {
		t.Fatalf("newest claim wins at 0.7 with both pieces of evidence: %+v", es)
	}
	es = r.ResolveAt("10.1.4.9", at(5))
	if users(es) != "carol" || es[0].Confidence != 1 {
		t.Fatalf("single claim is 1.0: %+v", es)
	}
	// agreeing sources are not a conflict
	mustObserve(t, r, fact("vpn", "bind", "10.1.4.20", "dave", "", "", 0, 3), fact("radius", "bind", "10.1.4.20", "dave", "", "", 1, 4))
	if es = r.ResolveAt("10.1.4.20", at(5)); es[0].Confidence != 1 {
		t.Fatalf("same user from two sources: %+v", es)
	}
}

func TestPublicAndInvalid(t *testing.T) {
	r := New(Config{})
	if inv, err := r.Observe(fact("radius", "bind", "8.8.8.8", "x", "", "", 0, 1)); err != nil || inv != nil {
		t.Fatal("public fact is ignored, not an error")
	}
	if r.ResolveAt("8.8.8.8", at(1)) != nil {
		t.Fatal("public address resolves to nothing")
	}
	for _, f := range []types.IdentityFact{
		{Kind: "x", Action: "bind", IP: "10.0.0.1", At: t0},
		{Kind: "dhcp", Action: "x", IP: "10.0.0.1", At: t0},
		{Kind: "dhcp", Action: "bind", IP: "nope", At: t0},
		{Kind: "dhcp", Action: "bind", IP: "10.0.0.1"},
	} {
		if _, err := r.Observe(f); err == nil {
			t.Errorf("accepted %+v", f)
		}
	}
	if r.ResolveAt("nope", t0) != nil || r.ResolveAt("10.0.0.1", time.Time{}) != nil {
		t.Fatal("bad input resolves to nothing")
	}
	// IPv4-mapped IPv6 is the same address
	mustObserve(t, r, fact("radius", "bind", "::ffff:10.1.1.1", "zed", "", "", 0, 9))
	if users(r.ResolveAt("10.1.1.1", at(1))) != "zed" {
		t.Fatal("mapped address")
	}
}

func TestObserveIsIdempotent(t *testing.T) {
	r := New(Config{})
	f := fact("radius", "bind", "10.1.4.7", "alice", "", "", 0, 1)
	mustObserve(t, r, f, f, f)
	if n := len(r.shardFor(mustIP("10.1.4.7")).ips[mustIP("10.1.4.7")].facts["radius"]); n != 1 {
		t.Fatalf("replay stored %d copies", n)
	}
}

func TestLateFactInvalidatesExactlyTheChangedWindow(t *testing.T) {
	r := New(Config{})
	mustObserve(t, r,
		fact("radius", "bind", "10.1.4.7", "alice", "", "", 0, 1),
		fact("radius", "release", "10.1.4.7", "", "", "", 100, 2),
	)
	// events at minute 50 and 90 were answered "alice"; nobody asked past 90
	r.ResolveAt("10.1.4.7", at(50))
	r.ResolveAt("10.1.4.7", at(90))

	// a release for alice arrives late, at minute 40: minutes 40..90 change
	inv, err := r.Observe(fact("radius", "release", "10.1.4.7", "", "", "", 40, 3))
	if err != nil {
		t.Fatal(err)
	}
	if len(inv) != 1 || !inv[0].From.Equal(at(40)) || inv[0].To.Before(at(90)) || inv[0].To.After(at(90).Add(time.Second)) {
		t.Fatalf("want [40min, 90min], got %+v", inv)
	}

	// a fact about a window nobody has asked about invalidates nothing
	inv, _ = r.Observe(fact("radius", "bind", "10.1.4.7", "bob", "", "", 300, 4))
	if len(inv) != 0 {
		t.Fatalf("future fact invalidated %+v", inv)
	}
	// an address never queried: nothing to invalidate
	inv, _ = r.Observe(fact("radius", "bind", "10.1.4.99", "x", "", "", 0, 5))
	if len(inv) != 0 {
		t.Fatalf("unqueried address invalidated %+v", inv)
	}
}

func mustIP(s string) (a netip.Addr) { a, _ = parseIP(s); return }

// --- property tests against a brute-force oracle -------------------------------

var propTTL = map[string]time.Duration{"dhcp": 60 * time.Minute, "radius": 90 * time.Minute, "vpn": 90 * time.Minute}

func randomFacts(rng *rand.Rand, n int) []types.IdentityFact {
	var fs []types.IdentityFact
	holders := []struct{ user, host, mac string }{{"a", "h1", "m1"}, {"b", "h2", "m2"}, {"c", "h1", "m3"}}
	for i := 0; i < n; i++ {
		kind := []string{"dhcp", "radius", "vpn"}[rng.Intn(3)]
		h := holders[rng.Intn(len(holders))]
		f := types.IdentityFact{Kind: kind, Action: "bind", IP: "10.1.4.7", At: at(rng.Intn(400)), RecordID: types.RecordID(i + 1), SourceID: "p"}
		if rng.Intn(3) == 0 {
			f.Action = "release"
		} else if kind == "dhcp" {
			f.Host, f.MAC = h.host, h.mac
		} else {
			f.User, f.MAC = h.user, h.mac
		}
		fs = append(fs, f)
	}
	return fs
}

type want struct {
	user, host, mac string
	conf            float64
	from            int64
	ev              int
}

// oracle answers one query by scanning every fact, sharing no code with derive:
// the newest fact at or before t decides the state, and the claim's start is
// found by walking back through unbroken renewals.
func oracle(fs []types.IdentityFact, t time.Time) want {
	type cl struct {
		user, host, mac string
		from            int64
		rec             types.RecordID
		kind            string
	}
	holderOf := func(f types.IdentityFact) [3]string { return [3]string{f.User, f.Host, f.MAC} }
	var found []cl
	for _, kind := range []string{"dhcp", "radius", "vpn"} {
		var ks []types.IdentityFact
		for _, f := range fs {
			if f.Kind == kind && !f.At.After(t) {
				ks = append(ks, f)
			}
		}
		sort.Slice(ks, func(i, j int) bool { return before(ks[i], ks[j]) })
		if len(ks) == 0 {
			continue
		}
		last := ks[len(ks)-1]
		ttl := propTTL[kind]
		if last.Action != "bind" || !t.Before(last.At.Add(ttl)) {
			continue
		}
		start := last
		for i := len(ks) - 2; i >= 0; i-- {
			p := ks[i]
			if p.Action != "bind" || holderOf(p) != holderOf(last) || !start.At.Before(p.At.Add(ttl)) {
				break
			}
			start = p
		}
		found = append(found, cl{last.User, last.Host, last.MAC, start.At.UnixNano(), start.RecordID, kind})
	}
	var w want
	var winner *cl
	var us []cl
	for i, c := range found {
		if c.kind == "dhcp" {
			w.host, w.mac = c.host, c.mac
			continue
		}
		us = append(us, found[i])
	}
	for i := range us {
		if winner == nil || us[i].from > winner.from || (us[i].from == winner.from && us[i].kind == "radius" && winner.kind != "radius") {
			winner = &us[i]
		}
	}
	if winner != nil {
		w.user, w.conf, w.from, w.ev = winner.user, 1, winner.from, 1
		for _, c := range us {
			if c.user != winner.user {
				w.conf, w.ev = 0.7, w.ev+1
			}
		}
	}
	return w
}

func gotWant(es []types.Entity) want {
	var w want
	for _, e := range es {
		switch e.Type {
		case "user":
			w.user, w.conf, w.from, w.ev = e.ID, e.Confidence, e.ValidFrom.UnixNano(), len(e.Evidence)
		case "host":
			w.host = e.ID
		case "mac":
			w.mac = e.ID
		}
	}
	return w
}

func TestAgainstOracle(t *testing.T) {
	for seed := int64(1); seed <= 150; seed++ {
		rng := rand.New(rand.NewSource(seed))
		fs := randomFacts(rng, 5+rng.Intn(40))
		shuffled := append([]types.IdentityFact(nil), fs...)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

		r := New(Config{TTL: propTTL})
		for _, f := range shuffled {
			if _, err := r.Observe(f); err != nil {
				t.Fatal(err)
			}
		}
		for m := -5; m < 600; m += 7 {
			for _, q := range []time.Time{at(m), at(m).Add(-time.Nanosecond), at(m).Add(30 * time.Second)} {
				if g, w := gotWant(r.ResolveAt("10.1.4.7", q)), oracle(fs, q); g != w {
					t.Fatalf("seed %d at %v:\n got %+v\nwant %+v", seed, q.Sub(t0), g, w)
				}
			}
		}
	}
}

// The property that makes late facts safe: for any arrival order, the windows
// Observe returns are exactly the instants (already asked about) whose answer
// changed. Not a superset (wasted re-enrichment), not a subset (stale events).
func TestInvalidationWindowsAreExact(t *testing.T) {
	for seed := int64(1); seed <= 40; seed++ {
		rng := rand.New(rand.NewSource(seed))
		fs := randomFacts(rng, 6+rng.Intn(25))
		r := New(Config{TTL: propTTL})
		ip := mustIP("10.1.4.7")
		var queried time.Time
		haveQ := false
		for _, f := range fs {
			if rng.Intn(2) == 0 {
				q := at(rng.Intn(500))
				r.ResolveAt("10.1.4.7", q)
				if !haveQ || q.After(queried) {
					queried, haveQ = q, true
				}
			}
			sh := r.shardFor(ip)
			grid := func() map[int]string {
				m := map[int]string{}
				st := sh.ips[ip]
				for s := -30; s <= 1200; s++ { // half-minute grid, minutes -15..600
					tn := at(0).Add(time.Duration(s) * 30 * time.Second).UnixNano()
					if st == nil {
						m[s] = ""
					} else {
						m[s] = key(resolve(st.claims, tn))
					}
				}
				return m
			}
			sh.mu.RLock()
			before := grid()
			sh.mu.RUnlock()
			inv, err := r.Observe(f)
			if err != nil {
				t.Fatal(err)
			}
			sh.mu.RLock()
			after := grid()
			sh.mu.RUnlock()
			for s := -30; s <= 1200; s++ {
				tt := at(0).Add(time.Duration(s) * 30 * time.Second)
				covered := false
				for _, w := range inv {
					if !tt.Before(w.From) && tt.Before(w.To) {
						covered = true
					}
				}
				should := haveQ && !tt.After(queried) && before[s] != after[s]
				if covered != should {
					t.Fatalf("seed %d fact %d at grid %d: covered=%v should=%v (queried up to %v) windows %+v", seed, f.RecordID, s, covered, should, queried.Sub(t0), inv)
				}
			}
		}
	}
}

func TestConcurrentObserveAndResolve(t *testing.T) {
	r := New(Config{})
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(2)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				ip := "10.1.4." + itoa(i%50)
				_, _ = r.Observe(fact("radius", "bind", ip, "u"+itoa(w), "", "", i, uint64(w*1000+i+1)))
			}
		}(w)
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				r.ResolveAt("10.1.4."+itoa(i%50), at(i%500))
			}
		}()
	}
	wg.Wait()
}

func itoa(i int) string { return strconv.Itoa(i) }

func BenchmarkResolveAt(b *testing.B) {
	r := New(Config{})
	const n = 100000
	ips := make([]string, n)
	for i := 0; i < n; i++ {
		ips[i] = "10." + itoa(i>>16&255) + "." + itoa(i>>8&255) + "." + itoa(i&255)
		_, _ = r.Observe(fact("radius", "bind", ips[i], "user", "", "aa:bb", 0, uint64(i+1)))
		_, _ = r.Observe(fact("dhcp", "bind", ips[i], "", "host", "aa:bb", 0, uint64(n+i+1)))
	}
	q := at(30)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(r.ResolveAt(ips[i%n], q)) == 0 {
			b.Fatal("no answer")
		}
	}
}

func TestTimelineShowsReassignment(t *testing.T) {
	r := New(Config{})
	mustObserve(t, r,
		fact("radius", "bind", "10.1.4.9", "carol", "", "", 0, 1),
		fact("radius", "release", "10.1.4.9", "", "", "", 40, 2),
		fact("radius", "bind", "10.1.4.9", "heidi", "", "", 70, 3),
	)
	tl := r.Timeline("10.1.4.9", time.Time{}, time.Time{})
	if len(tl) != 2 || tl[0].User != "carol" || tl[1].User != "heidi" || tl[0].ValidTo == nil || !tl[0].ValidTo.Equal(at(40)) || tl[1].ValidTo != nil {
		t.Fatalf("%+v", tl)
	}
	if got := r.Timeline("10.1.4.9", at(45), at(60)); len(got) != 0 {
		t.Fatalf("the gap has no bindings: %+v", got)
	}
	if got := r.Timeline("10.1.4.9", at(30), at(80)); len(got) != 2 {
		t.Fatalf("window across the reassignment: %+v", got)
	}
}

func TestGraphNeighbours(t *testing.T) {
	r := New(Config{})
	mustObserve(t, r,
		fact("dhcp", "bind", "10.1.4.9", "", "laptop-carol", "aa:01", 0, 1),
		fact("radius", "bind", "10.1.4.9", "carol", "", "", 1, 2),
		fact("dhcp", "release", "10.1.4.9", "", "", "", 40, 3),
		fact("radius", "release", "10.1.4.9", "", "", "", 41, 4),
		fact("dhcp", "bind", "10.1.4.9", "", "laptop-heidi", "aa:02", 70, 5),
		fact("radius", "bind", "10.1.4.9", "heidi", "", "", 71, 6),
		fact("radius", "bind", "10.1.4.20", "carol", "", "", 100, 7),
	)
	g := r.Neighbours("ip", "10.1.4.9", time.Time{}, time.Time{})
	if len(g.Edges) != 6 { // two tenants x (ip-host, host-mac, ip-user)
		t.Fatalf("ip neighbourhood: %+v", g.Edges)
	}
	g = r.Neighbours("user", "carol", time.Time{}, time.Time{})
	ips := map[string]bool{}
	for _, e := range g.Edges {
		if e.Type != "ip-user" || e.B != "carol" {
			t.Fatalf("unexpected edge %+v", e)
		}
		ips[e.A] = true
	}
	if !ips["10.1.4.9"] || !ips["10.1.4.20"] {
		t.Fatalf("carol used two addresses: %v", ips)
	}
	// interval filter: only heidi's tenancy
	g = r.Neighbours("ip", "10.1.4.9", at(60), time.Time{})
	for _, e := range g.Edges {
		if e.B == "carol" || e.B == "laptop-carol" {
			t.Fatalf("carol's tenancy is outside the window: %+v", e)
		}
	}
	if g = r.Neighbours("host", "laptop-heidi", time.Time{}, time.Time{}); len(g.Edges) != 2 {
		t.Fatalf("host: ip-host + host-mac, got %+v", g.Edges)
	}
	if g = r.Neighbours("ip", "nope", time.Time{}, time.Time{}); len(g.Nodes) != 0 {
		t.Fatal("bad ip")
	}
}
