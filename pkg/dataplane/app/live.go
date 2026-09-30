package app

import (
	"context"
	"errors"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"io"
	"log/slog"
	"sync"

	builtin "github.com/dark-14100/sluice/parsers"
	"github.com/dark-14100/sluice/pkg/dataplane/ingest"
	"github.com/dark-14100/sluice/pkg/dataplane/ingest/source"
	"github.com/dark-14100/sluice/pkg/dataplane/parsers"
	"github.com/dark-14100/sluice/pkg/dataplane/registry"
	types "github.com/dark-14100/sluice/pkg/types"
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

	mu  sync.Mutex
	err error
}

// fail latches the first fatal error so the caller can exit non-zero.
func (l *Live) fail(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err == nil {
		l.err = err
	}
}

// Err is the first fatal error of either goroutine, or nil. Read it after Wait.
func (l *Live) Err() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.err
}

// StartIngest feeds the App from the sources in cfg. Records reach Process only
// after the vault has made them durable (ingest.Pipeline's guarantee). Both
// goroutines end when ctx is cancelled; a failure of either calls stop so the
// caller shuts down instead of running half a pipeline, and is reported by Err.
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
			l.fail(fmt.Errorf("ingest: %w", err))
			stop()
		}
	}()
	go func() {
		defer func() { pending <- struct{}{} }()
		if err := a.Run(context.Background(), out); err != nil {
			fmt.Fprintln(errOut, "pipeline:", err)
			l.fail(fmt.Errorf("pipeline: %w", err))
			stop()
			// Nobody reads out any more. Drain it so ingest's closing flush cannot block
			// forever on a full channel; these records are durable and replay on restart.
			for range out {
			}
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
