package identity

import (
	"sort"
	"time"
)

// Node is an ip, host, user or mac in the entity graph.
type Node struct{ Type, ID string }

// Edge links two nodes over an interval. Type is "ip-host", "ip-user" or
// "host-mac"; A and B follow the type's order.
type Edge struct {
	Type      string
	A, B      string
	ValidFrom time.Time
	ValidTo   *time.Time // nil while open-ended
}

// Graph is the neighbourhood of one node.
type Graph struct {
	Nodes []Node
	Edges []Edge
}

// Neighbours returns the edges touching the node (typ is "ip", "user" or
// "host"), restricted to those overlapping [from, to) (a zero bound is
// unbounded), plus the host-mac edges of any host reached. The graph is derived
// from the claims on demand: an ip-host edge per dhcp claim, an ip-user edge
// per radius or vpn claim, a host-mac edge per dhcp claim that names both.
//
// ponytail: a user or host lookup scans every address, O(addresses). Add a
// reverse index if the admin graph endpoint is ever polled on a large table.
func (r *Resolver) Neighbours(typ, id string, from, to time.Time) Graph {
	var edges []Edge
	overlaps := func(c claim) bool {
		return !(!from.IsZero() && c.end <= from.UnixNano() || !to.IsZero() && c.from >= to.UnixNano())
	}
	edge := func(t, a, b string, c claim) Edge {
		e := Edge{Type: t, A: a, B: b, ValidFrom: *ts(c.from)}
		if c.closed {
			e.ValidTo = ts(c.end)
		}
		return e
	}
	collect := func(ip string, st *ipState) {
		for _, c := range st.claims[KindDHCP] {
			if overlaps(c) && c.host != "" {
				edges = append(edges, edge("ip-host", ip, c.host, c))
				if c.mac != "" {
					edges = append(edges, edge("host-mac", c.host, c.mac, c))
				}
			}
		}
		for _, k := range []string{KindRADIUS, KindVPN} {
			for _, c := range st.claims[k] {
				if overlaps(c) && c.user != "" {
					edges = append(edges, edge("ip-user", ip, c.user, c))
				}
			}
		}
	}

	if typ == "ip" {
		a, err := parseIP(id)
		if err != nil {
			return Graph{}
		}
		sh := r.shardFor(a)
		sh.mu.RLock()
		if st := sh.ips[a]; st != nil {
			collect(a.String(), st)
		}
		sh.mu.RUnlock()
	} else {
		for i := range r.shards {
			sh := &r.shards[i]
			sh.mu.RLock()
			for a, st := range sh.ips {
				collect(a.String(), st)
			}
			sh.mu.RUnlock()
		}
	}

	touches := func(e Edge) bool {
		switch typ {
		case "ip":
			return e.Type != "host-mac" && e.A == id
		case "user":
			return e.Type == "ip-user" && e.B == id
		case "host":
			return e.Type == "ip-host" && e.B == id || e.Type == "host-mac" && e.A == id
		}
		return false
	}
	hosts := map[string]bool{}
	var keep []Edge
	for _, e := range edges {
		if touches(e) {
			keep = append(keep, e)
			if e.Type == "ip-host" {
				hosts[e.B] = true
			}
		}
	}
	if typ != "host" {
		for _, e := range edges {
			if e.Type == "host-mac" && hosts[e.A] {
				keep = append(keep, e)
			}
		}
	}

	sort.Slice(keep, func(i, j int) bool {
		a, b := keep[i], keep[j]
		if !a.ValidFrom.Equal(b.ValidFrom) {
			return a.ValidFrom.Before(b.ValidFrom)
		}
		return a.Type+a.A+a.B < b.Type+b.A+b.B
	})
	// one edge per (type, a, b, valid_from): dhcp renewals and duplicate claims collapse
	var uniq []Edge
	seen := map[string]bool{}
	nodes := map[Node]bool{}
	for _, e := range keep {
		k := e.Type + "|" + e.A + "|" + e.B + "|" + e.ValidFrom.String()
		if seen[k] {
			continue
		}
		seen[k] = true
		uniq = append(uniq, e)
		ta, tb := endpoints(e.Type)
		nodes[Node{ta, e.A}], nodes[Node{tb, e.B}] = true, true
	}
	g := Graph{Edges: uniq}
	for n := range nodes {
		g.Nodes = append(g.Nodes, n)
	}
	sort.Slice(g.Nodes, func(i, j int) bool {
		if g.Nodes[i].Type != g.Nodes[j].Type {
			return g.Nodes[i].Type < g.Nodes[j].Type
		}
		return g.Nodes[i].ID < g.Nodes[j].ID
	})
	return g
}

func endpoints(edgeType string) (string, string) {
	switch edgeType {
	case "ip-host":
		return "ip", "host"
	case "ip-user":
		return "ip", "user"
	}
	return "host", "mac"
}
