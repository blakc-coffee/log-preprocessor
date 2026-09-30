// Package app wires parsing, normalization, identity, storage and sinks.
package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/dark-14100/sluice/pkg/dataplane/enrich"
	"github.com/dark-14100/sluice/pkg/dataplane/normalizer"
	"github.com/dark-14100/sluice/pkg/dataplane/quarantine"
	"github.com/dark-14100/sluice/pkg/dataplane/registry"
	"github.com/dark-14100/sluice/pkg/dataplane/store"
	"github.com/dark-14100/sluice/pkg/dataplane/telemetry"
	types "github.com/dark-14100/sluice/pkg/types"
)

type App struct {
	Registry   *registry.Registry
	Events     *store.Store
	Quarantine *quarantine.Store
	Enricher   *enrich.Enricher
	Metrics    *telemetry.Metrics
	Sinks      []types.Sink
}

func New(reg *registry.Registry, events *store.Store, q *quarantine.Store, enricher *enrich.Enricher, sinks ...types.Sink) *App {
	if events == nil {
		events = store.New()
	}
	if q == nil {
		q = quarantine.New()
	}
	return &App{Registry: reg, Events: events, Quarantine: q, Enricher: enricher, Metrics: telemetry.New(), Sinks: sinks}
}
func (a *App) Process(ctx context.Context, raw types.RawEvent) error {
	for _, parser := range a.Registry.Active() {
		result, err := parser.Parse(raw.Raw, raw.ReceivedAt)
		if err != nil {
			return a.quarantine(raw, "extract", err.Error())
		}
		if result == nil {
			continue
		}
		event := normalizer.Build(raw, parser, result)
		if a.Enricher != nil {
			if err := a.Enricher.Apply(&event); err != nil {
				return a.quarantine(raw, "normalize", err.Error())
			}
		}
		// Sinks are written before the store: a crash or sink failure between the two
		// then replays into a duplicate export (at-least-once), never a missing one.
		_, getErr := a.Events.Get(event.EventID)
		if getErr != nil && !errors.Is(getErr, store.ErrNotFound) {
			return fmt.Errorf("event store: %w", getErr)
		}
		if getErr != nil { // not stored yet
			for _, sink := range a.Sinks {
				if err := sink.Write(ctx, []types.NormalizedEvent{event}); err != nil {
					return fmt.Errorf("sink %s: %w", sink.Name(), err)
				}
			}
			if a.Events.Put(event) {
				a.Metrics.Event(raw.SourceID)
			}
		}
		a.Quarantine.Resolve(raw.ID, event.EventID)
		return nil
	}
	return a.quarantine(raw, "detect", "no parser matched")
}
func (a *App) quarantine(raw types.RawEvent, stage, reason string) error {
	if a.Quarantine.Put(types.QuarantineRecord{RecordID: raw.ID, SourceID: raw.SourceID, FailureStage: stage, Error: reason, ReceivedAt: raw.ReceivedAt, Status: "open"}) {
		a.Metrics.Quarantine(raw.SourceID)
	}
	return nil
}
func (a *App) Run(ctx context.Context, in <-chan types.RawEvent) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case raw, ok := <-in:
			if !ok {
				return nil
			}
			if err := a.Process(ctx, raw); err != nil {
				return err
			}
		}
	}
}
func (a *App) Close() error {
	var errs []error
	for _, sink := range a.Sinks {
		errs = append(errs, sink.Flush(context.Background()), sink.Close())
	}
	return errors.Join(errs...)
}
