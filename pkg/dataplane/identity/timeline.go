package identity

import (
	"sort"
	"time"

	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

// Binding is one claim as the admin timeline shows it.
type Binding struct {
	Kind       string
	User, Host string
	MAC        string
	ValidFrom  time.Time
	ValidTo    *time.Time // nil while open-ended
	Confidence float64    // 0.7 where another user's claim overlaps this one
	Evidence   []types.EvidenceRef
}

// Timeline lists every claim on ip that overlaps [from, to), oldest first.
// A zero from or to leaves that side unbounded. Consecutive bindings with
// different users are a reassignment.
func (r *Resolver) Timeline(ip string, from, to time.Time) []Binding {
	a, err := parseIP(ip)
	if err != nil || !r.internal(a) {
		return nil
	}
	sh := r.shardFor(a)
	sh.mu.RLock()
	defer sh.mu.RUnlock()
	st := sh.ips[a]
	if st == nil {
		return nil
	}
	var all []claim
	for _, cs := range st.claims {
		all = append(all, cs...)
	}
	var out []Binding
	for _, c := range all {
		if !from.IsZero() && c.end <= from.UnixNano() || !to.IsZero() && c.from >= to.UnixNano() {
			continue
		}
		conf := 1.0
		for _, o := range all {
			if o.user != "" && c.user != "" && o.user != c.user && o.from < c.end && c.from < o.end {
				conf = 0.7
			}
		}
		b := Binding{Kind: c.kind, User: c.user, Host: c.host, MAC: c.mac, ValidFrom: *ts(c.from), Confidence: conf,
			Evidence: []types.EvidenceRef{{RecordID: c.rec, Kind: c.kind}}}
		if c.closed {
			b.ValidTo = ts(c.end)
		}
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].ValidFrom.Equal(out[j].ValidFrom) {
			return out[i].ValidFrom.Before(out[j].ValidFrom)
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}
