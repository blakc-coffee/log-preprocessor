package app

import (
	"context"
	"errors"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"io"
	"log/slog"

	builtin "github.com/blakc-coffee/log-preprocessor/parsers"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/source"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/parsers"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/registry"
	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

// LoadBuiltins activates the embedded parsers that are not already in the
// registry, so a version approved at runtime (data/parsers.d) is not overwritten.
func LoadBuiltins(engine *parsers.Engine, reg *registry.Registry) error {
	entries, err := builtin.FS.ReadDir(".")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		src, err := builtin.FS.ReadFile(entry.Name())
		if err != nil {
			return err
		}
		p, err := engine.Load(src)
		if err != nil {
			return fmt.Errorf("%s: %w", entry.Name(), err)
		}
		if !reg.Has(p.ID()) {
			if _, err := reg.Add(src, true); err != nil {
				return fmt.Errorf("%s: %w", entry.Name(), err)
			}
		}
	}
	return nil
}

// Live is a running ingest side: sources -> vault -> this App.
type Live struct {
	Sources int
	done    chan struct{}
	closeFn func()
}

// StartIngest feeds the App from the sources in cfg. Records reach Process only
// after the vault has made them durable (ingest.Pipeline's guarantee). Both
// goroutines end when ctx is cancelled; a failure of either calls stop so the
// caller shuts down instead of running half a pipeline.
func (a *App) StartIngest(ctx context.Context, stop context.CancelFunc, v types.Vault, cfg *ingest.FileConfig, errOut io.Writer, reg prometheus.Registerer) (*Live, error) {
	log := slog.New(slog.NewJSONHandler(errOut, nil))
	out := make(chan types.RawEvent, cfg.OutBuffer)
	ing, err := ingest.New(ingest.Config{OutBuffer: cfg.OutBuffer, Registerer: reg}, v, out, log)
	if err != nil {
		return nil, err
	}
	healthy := func() bool { _, _, err := v.Head(context.Background()); return err == nil }
	srcs, closeSources, err := source.Build(cfg, ing.Metrics(), healthy, log)
	if err != nil {
		return nil, err
	}
	for _, s := range srcs {
		ing.AddSource(s)
	}
	l := &Live{Sources: len(srcs), done: make(chan struct{}), closeFn: closeSources}
	pending := make(chan struct{}, 2)
	go func() {
		defer func() { pending <- struct{}{} }()
		if err := ing.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			fmt.Fprintln(errOut, "ingest:", err)
			stop()
		}
	}()
	go func() {
		defer func() { pending <- struct{}{} }()
		if err := a.Run(context.Background(), out); err != nil {
			fmt.Fprintln(errOut, "pipeline:", err)
			stop()
		}
	}()
	go func() { <-pending; <-pending; close(l.done) }()
	return l, nil
}

// Wait blocks until ingest has drained and every accepted record was processed.
// Call it after cancelling the context given to StartIngest.
func (l *Live) Wait() {
	<-l.done
	l.closeFn()
}
