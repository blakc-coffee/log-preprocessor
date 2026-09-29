// Package enrich applies temporal identity claims to normalized network events.
package enrich

import (
	"time"

	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/store"
	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

type Enricher struct {
	resolver types.Resolver
	store    *store.Store
}

func New(resolver types.Resolver, events *store.Store) *Enricher {
	return &Enricher{resolver: resolver, store: events}
}
func (e *Enricher) Apply(event *types.NormalizedEvent) error {
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
	var entities []types.Entity
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
