// Package enrich applies temporal identity claims to normalized network events.
package enrich

import (
	"sync"
	"time"

	"github.com/blakc-coffee/sluice/pkg/dataplane/store"
	types "github.com/blakc-coffee/sluice/pkg/types"
)

type Enricher struct {
	resolver types.Resolver
	store    *store.Store

	mu  sync.Mutex
	vpn map[string]string // user@peer address -> tunnel address it last Learned
}

func New(resolver types.Resolver, events *store.Store) *Enricher {
	return &Enricher{resolver: resolver, store: events, vpn: map[string]string{}}
}

// completeVPN gives a VPN client-instance exit its tunnel address. That line
// names only the peer, so without this the binding created by "MULTI: Learn"
// would never be released and the user would keep the address until the TTL.
// It reports whether the fact is usable.
func (e *Enricher) completeVPN(f *types.IdentityFact) bool {
	if f.Kind != "vpn" {
		return true
	}
	key := f.User + "@" + f.Host
	e.mu.Lock()
	defer e.mu.Unlock()
	switch {
	case f.Action == "bind" && f.IP != "":
		e.vpn[key] = f.IP
	case f.Action == "release" && f.IP == "":
		f.IP = e.vpn[key]
		delete(e.vpn, key)
	}
	return f.IP != ""
}

func (e *Enricher) Apply(event *types.NormalizedEvent) error {
	if event.Identity != nil && !e.completeVPN(event.Identity) {
		event.Identity = nil // a release for a session never seen: nothing to release
	}
	if event.Identity != nil {
		invalidations, err := e.resolver.Observe(*event.Identity)
		if err != nil {
			return err
		}
		for _, window := range invalidations {
			e.store.Reenrich(window.IP, window.From, window.To, e.resolver.ResolveAt)
		}
	}
	if event.EventTime == nil {
		return nil
	}
	entities := []types.Entity{} // the contract says array, never null
	for _, pair := range []struct{ role, ip string }{{"src", endpointIP(event.OCSF, "src_endpoint")}, {"dst", endpointIP(event.OCSF, "dst_endpoint")}} {
		for _, entity := range e.resolver.ResolveAt(pair.ip, *event.EventTime) {
			entity.Role = pair.role
			entities = append(entities, entity)
		}
	}
	event.Entities = entities
	return nil
}
func endpointIP(ocsf map[string]any, key string) string {
	endpoint, _ := ocsf[key].(map[string]any)
	ip, _ := endpoint["ip"].(string)
	return ip
}

var _ = time.Time{}
