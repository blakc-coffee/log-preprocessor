package identity

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	types "github.com/blakc-coffee/sluice/pkg/types"
)

// claim is one holder's tenure of an address under one kind of evidence,
// covering the half-open interval [from, end).
type claim struct {
	kind            string
	user, host, mac string
	from, seen      int64 // seen: newest bind of this holder, the TTL anchor
	end             int64 // exclusive
	closed          bool  // an explicit release or a newer holder ended it, before the TTL did
	rec             types.RecordID
}

func (c claim) covers(t int64) bool { return c.from <= t && t < c.end }

func (c claim) sameHolder(f types.IdentityFact) bool {
	return c.user == f.User && c.host == f.Host && c.mac == f.MAC
}

// derive folds a kind's time-sorted facts into claims.
//
//	bind, nothing open          open a claim
//	bind, same holder, in TTL   refresh (renewal); the claim keeps its start
//	bind, anyone else           close the open claim at this instant, open a new one
//	release                     close the open claim at this instant
//
// Whatever ends a claim, it never outlives its newest bind plus the TTL.
func derive(kind string, facts []types.IdentityFact, ttl int64) []claim {
	var out []claim
	closer := []int64{} // explicit end per claim, -1 if none
	open := -1
	for _, f := range facts {
		at := f.At.UnixNano()
		switch f.Action {
		case "bind":
			if open >= 0 && out[open].sameHolder(f) && at < out[open].seen+ttl {
				if at > out[open].seen {
					out[open].seen = at
				}
				continue
			}
			if open >= 0 {
				closer[open] = at
			}
			out = append(out, claim{kind: kind, user: f.User, host: f.Host, mac: f.MAC, from: at, seen: at, rec: f.RecordID})
			closer = append(closer, -1)
			open = len(out) - 1
		case "release":
			if open >= 0 {
				closer[open] = at
				open = -1
			}
		}
	}
	res := out[:0]
	for i, c := range out {
		lim := c.seen + ttl
		switch {
		case closer[i] >= 0 && closer[i] <= lim:
			c.end, c.closed = closer[i], true
		default:
			c.end = lim
		}
		if c.end > c.from {
			res = append(res, c)
		}
	}
	return res
}

// snapshot copies the derived claims so a later change can be compared.
func (s *ipState) snapshot() map[string][]claim {
	m := make(map[string][]claim, len(s.claims))
	for k, v := range s.claims {
		m[k] = append([]claim(nil), v...)
	}
	return m
}

func ts(n int64) *time.Time { t := time.Unix(0, n).UTC(); return &t }

// resolve is the answer for one instant. User comes from radius or vpn, host
// and MAC from dhcp. Where two users overlap the newest claim wins and the
// confidence drops to 0.7. Otherwise 1.0.
func resolve(claims map[string][]claim, t int64) []types.Entity {
	var out []types.Entity

	var users []claim
	for _, k := range []string{KindRADIUS, KindVPN} {
		for _, c := range claims[k] {
			if c.user != "" && c.covers(t) {
				users = append(users, c)
			}
		}
	}
	if len(users) > 0 {
		win := users[0]
		for _, c := range users[1:] {
			if c.from > win.from || (c.from == win.from && c.kind == KindRADIUS && win.kind != KindRADIUS) {
				win = c
			}
		}
		conf := 1.0
		ev := []types.EvidenceRef{{RecordID: win.rec, Kind: win.kind}}
		for _, c := range users {
			if c.user != win.user {
				conf = 0.7
				ev = append(ev, types.EvidenceRef{RecordID: c.rec, Kind: c.kind})
			}
		}
		out = append(out, entity("user", win.user, win, conf, ev))
	}

	for _, c := range claims[KindDHCP] {
		if !c.covers(t) {
			continue
		}
		ev := []types.EvidenceRef{{RecordID: c.rec, Kind: KindDHCP}}
		if c.host != "" {
			out = append(out, entity("host", c.host, c, 1, ev))
		}
		if c.mac != "" {
			out = append(out, entity("mac", strings.ToLower(c.mac), c, 1, ev))
		}
		break
	}
	return out
}

func entity(typ, id string, c claim, conf float64, ev []types.EvidenceRef) types.Entity {
	e := types.Entity{Type: typ, ID: id, ValidFrom: ts(c.from), Confidence: conf, Evidence: ev}
	if c.closed {
		e.ValidTo = ts(c.end)
	}
	return e
}

// key makes an answer comparable for invalidation: who, how sure, and on what
// evidence. valid_from and valid_to are deliberately left out. A late release
// changes a claim's valid_to without changing who held the address, and an
// event enriched with the right user does not need re-enriching for that.
func key(es []types.Entity) string {
	var b strings.Builder
	for _, e := range es {
		fmt.Fprintf(&b, "%s|%s|%.3f", e.Type, e.ID, e.Confidence)
		for _, ev := range e.Evidence {
			fmt.Fprintf(&b, "|%s:%d", ev.Kind, ev.RecordID)
		}
		b.WriteString(";")
	}
	return b.String()
}

// changed lists the windows, no later than lastQ, whose answer differs between
// two claim sets. The windows are exact: elementary intervals between every
// claim boundary in either set, compared and merged.
func changed(ip string, old, cur map[string][]claim, lastQ int64) []types.Invalidation {
	set := map[int64]bool{}
	for _, m := range []map[string][]claim{old, cur} {
		for _, cs := range m {
			for _, c := range cs {
				set[c.from], set[c.end] = true, true
			}
		}
	}
	pts := make([]int64, 0, len(set))
	for p := range set {
		pts = append(pts, p)
	}
	sort.Slice(pts, func(i, j int) bool { return pts[i] < pts[j] })

	var out []types.Invalidation
	var start int64
	in := false
	flush := func(end int64) {
		if end > lastQ+1 {
			end = lastQ + 1
		}
		if end > start {
			out = append(out, types.Invalidation{IP: ip, From: time.Unix(0, start).UTC(), To: time.Unix(0, end).UTC()})
		}
		in = false
	}
	for _, p := range pts {
		if p > lastQ {
			break
		}
		differs := key(resolve(old, p)) != key(resolve(cur, p))
		switch {
		case differs && !in:
			start, in = p, true
		case !differs && in:
			flush(p)
		}
	}
	if in {
		flush(math.MaxInt64)
	}
	return out
}
