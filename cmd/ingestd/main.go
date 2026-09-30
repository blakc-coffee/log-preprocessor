// Command ingestd receives logs and stores them in the hash-chained vault.
//
//	ingestd --config configs/ingest.dev.yaml [--emit none|stdout|jsonl:/path] [--once]
//	ingestd --healthcheck --config ...
//
// It is the standalone ingest+vault daemon. In the full data plane the parsing
// workstream's binary wires Pipeline.Out to the parser instead, and --emit is
// how this one is useful on its own.
//
// # Exit codes
//
//	0  clean shutdown, or --once finished
//	1  the vault failed, or a source died
//	2  bad configuration or usage
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/source"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault"
	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

const (
	exitOK     = 0
	exitFailed = 1
	exitUsage  = 2
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	// `ingestd certs` generates development certificates and exits. It takes
	// no config, so it is dispatched before any of the daemon's flags.
	if len(args) > 0 && args[0] == "certs" {
		return generateCerts(args[1:], stdout, stderr)
	}

	fs := flag.NewFlagSet("ingestd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to the configuration file")
	emitFlag := fs.String("emit", "", "override the config's emit: none, stdout or jsonl:<path>")
	once := fs.Bool("once", false, "exit when every `mode: once` file source has finished")
	healthcheck := fs.Bool("healthcheck", false, "probe a running daemon's /healthz and exit")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *configPath == "" {
		fmt.Fprintln(stderr, "ingestd: --config is required")
		fs.PrintDefaults()
		return exitUsage
	}

	cfg, err := ingest.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "ingestd: %v\n", err)
		return exitUsage
	}
	if *emitFlag != "" {
		cfg.Emit = *emitFlag
		if err := cfg.Validate(); err != nil {
			fmt.Fprintf(stderr, "ingestd: %v\n", err)
			return exitUsage
		}
	}

	// --healthcheck is how a container probes this process without a shell in
	// the image.
	if *healthcheck {
		return probeHealth(cfg, stdout, stderr)
	}

	log := newLogger(cfg.LogLevel, stderr)

	code, err := serve(cfg, *once, log, stdout)
	if err != nil {
		log.Error("ingestd stopped", "err", err)
		fmt.Fprintf(stderr, "ingestd: %v\n", err)
	}
	return code
}

func newLogger(level string, w io.Writer) *slog.Logger {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: l}))
}

func serve(cfg *ingest.FileConfig, once bool, log *slog.Logger, stdout io.Writer) (int, error) {
	reg := prometheus.NewRegistry()
	// Go runtime and process collectors: heap growth and open file
	// descriptors are the first two things to look at when ingest slows down.
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	v, err := vault.Open(vault.Options{
		Dir:                 cfg.Vault.Dir,
		Sync:                vault.SyncMode(cfg.Vault.Sync),
		SyncInterval:        cfg.Vault.SyncInterval.Std(),
		GroupCommitMaxDelay: cfg.Vault.GroupCommitMaxDelay.Std(),
		GroupCommitMaxBytes: int(cfg.Vault.GroupCommitMaxBytes),
		SegmentMaxBytes:     int64(cfg.Vault.SegmentMaxBytes),
		SegmentMaxRecords:   cfg.Vault.SegmentMaxRecords,
		SealInterval:        cfg.Vault.SealInterval.Std(),
		Compact:             cfg.Vault.CompactEnabled(),
		CompactBlockBytes:   int(cfg.Vault.CompactBlockBytes),
		ZstdLevel:           cfg.Vault.ZstdLevel,
		DisableHashIndex:    !cfg.Vault.HashIndexEnabled(),
		MaxFrameBytes:       int(cfg.Limits.MaxFrameBytes),
		Logger:              log,
		Registerer:          reg,
	})
	if err != nil {
		return exitUsage, fmt.Errorf("opening the vault: %w", err)
	}
	// Close seals the active segment, so no record is left outside the chain.
	defer func() {
		if err := v.Close(); err != nil {
			log.Error("closing the vault", "err", err)
		}
	}()

	out := make(chan types.RawEvent, cfg.OutBuffer)
	p, err := ingest.New(ingest.Config{OutBuffer: cfg.OutBuffer, Registerer: reg}, v, out, log)
	if err != nil {
		return exitUsage, err
	}

	healthy := func() bool {
		_, _, err := v.Head(context.Background())
		return err == nil
	}

	srcs, closeSources, err := source.Build(cfg, p.Metrics(), healthy, log)
	if err != nil {
		return exitUsage, err
	}
	defer closeSources()

	emit, closeEmit, err := newEmitter(cfg.Emit, stdout)
	if err != nil {
		return exitUsage, err
	}
	defer closeEmit()

	// SIGINT and SIGTERM stop accepting; the pipeline then drains what it has
	// already taken. --once cancels the same way when the file sources finish,
	// so both paths shut down through exactly one code path.
	sigCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(sigCtx)
	defer cancel()

	// --once means "exit when every `mode: once` file source has finished".
	// Network listeners never finish on their own, so the file sources'
	// completion is what cancels the context, and shutdown then runs through
	// the same path a signal would take.
	if once {
		var pending sync.WaitGroup
		watched := 0
		for i, s := range srcs {
			f, ok := s.(*source.File)
			if !ok || f.Mode() != source.ModeOnce {
				continue
			}
			pending.Add(1)
			watched++
			srcs[i] = onceWatcher{Source: s, done: pending.Done}
		}
		if watched == 0 {
			return exitUsage, errors.New("--once was given but no `mode: once` file source is configured")
		}
		go func() {
			pending.Wait()
			log.Info("every one-shot file source finished", "sources", watched)
			cancel()
		}()
	}

	for _, s := range srcs {
		p.AddSource(s)
	}

	stopMetrics := serveMetrics(cfg.MetricsAddr, reg, healthy, log)
	defer stopMetrics()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ev := range out {
			emit(ev)
		}
	}()

	log.Info("ingestd started",
		"vault", cfg.Vault.Dir, "sync", cfg.Vault.Sync,
		"sources", len(srcs), "emit", cfg.Emit, "once", once)

	runErr := make(chan error, 1)
	go func() { runErr <- p.Run(ctx) }()

	var err2 error
	select {
	case err2 = <-runErr:
		// Every source returned. With --once that is the expected end; without
		// it, a source died and that is a failure.
	case <-ctx.Done():
		log.Info("shutting down", "timeout", cfg.ShutdownTimeout.Std())
		select {
		case err2 = <-runErr:
		case <-time.After(cfg.ShutdownTimeout.Std()):
			// Exiting non-zero matters: a shutdown that did not finish may
			// have left records accepted but not durable, and a supervisor
			// treating that as a clean stop would hide it.
			wg.Wait()
			return exitFailed, fmt.Errorf("shutdown timed out after %s", cfg.ShutdownTimeout.Std())
		}
	}
	wg.Wait()

	if err2 != nil && !errors.Is(err2, context.Canceled) {
		return exitFailed, err2
	}
	if _, _, err := v.Head(context.Background()); err != nil {
		return exitFailed, fmt.Errorf("vault is unhealthy at exit: %w", err)
	}
	log.Info("ingestd stopped cleanly")
	return exitOK, nil
}

// onceWatcher signals when a one-shot source has finished, so --once knows
// when there is nothing left to read.
type onceWatcher struct {
	ingest.Source
	done func()
}

func (o onceWatcher) Run(ctx context.Context, sink ingest.Sink) error {
	defer o.done()
	return o.Source.Run(ctx, sink)
}

// newEmitter decides what happens to records once they are durable.
//
// In the real data plane this channel goes to the parser. Standalone, it is
// either discarded, printed, or written as JSON Lines — with the payload
// base64-encoded, because a raw log line is attacker-controlled and printing
// it unescaped into a terminal or a log file is log injection.
func newEmitter(spec string, stdout io.Writer) (func(types.RawEvent), func(), error) {
	switch {
	case spec == "none":
		return func(types.RawEvent) {}, func() {}, nil

	case spec == "stdout":
		enc := json.NewEncoder(stdout)
		var mu sync.Mutex
		return func(ev types.RawEvent) {
			mu.Lock()
			defer mu.Unlock()
			_ = enc.Encode(toJSON(ev))
		}, func() {}, nil

	case strings.HasPrefix(spec, "jsonl:"):
		path := strings.TrimPrefix(spec, "jsonl:")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, nil, err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, nil, err
		}
		enc := json.NewEncoder(f)
		var mu sync.Mutex
		return func(ev types.RawEvent) {
				mu.Lock()
				defer mu.Unlock()
				_ = enc.Encode(toJSON(ev))
			}, func() {
				f.Sync()
				f.Close()
			}, nil
	}
	return nil, nil, fmt.Errorf("unknown emit %q", spec)
}

// eventJSON is the debug shape of a RawEvent.
type eventJSON struct {
	RecordID   uint64 `json:"record_id"`
	Segment    uint64 `json:"segment"`
	RawSHA256  string `json:"raw_sha256"`
	SourceID   string `json:"source_id"`
	ReceivedAt string `json:"received_at"`
	OriginKind uint8  `json:"origin_kind"`
	OriginAddr string `json:"origin_addr"`
	OriginOff  uint64 `json:"origin_offset"`
	Terminator uint8  `json:"terminator"`
	Fragment   uint8  `json:"fragment"`
	Hint       string `json:"hint"`
	// RawBase64 keeps a hostile payload from reaching a terminal or a log
	// aggregator unescaped.
	RawBase64 string `json:"raw_base64"`
	RawBytes  int    `json:"raw_bytes"`
}

func toJSON(ev types.RawEvent) eventJSON {
	return eventJSON{
		RecordID:   uint64(ev.ID),
		Segment:    ev.Segment,
		RawSHA256:  fmt.Sprintf("%x", ev.RawSHA256),
		SourceID:   ev.SourceID,
		ReceivedAt: ev.ReceivedAt.Format(time.RFC3339Nano),
		OriginKind: uint8(ev.Origin.Kind),
		OriginAddr: ev.Origin.Addr,
		OriginOff:  ev.Origin.Offset,
		Terminator: uint8(ev.Term),
		Fragment:   uint8(ev.Frag),
		Hint:       string(ev.Hint),
		RawBase64:  base64.StdEncoding.EncodeToString(ev.Raw),
		RawBytes:   len(ev.Raw),
	}
}

// serveMetrics exposes /metrics and /healthz on the loopback metrics address.
// It is deliberately a separate listener from the ingest ports: scraping and
// ingesting have different exposure, and /metrics must never be reachable
// wherever devices are.
func serveMetrics(addr string, reg *prometheus.Registry, healthy func() bool, log *slog.Logger) func() {
	if addr == "" {
		return func() {}
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		// A scrape failure should be visible in the scrape, not swallowed.
		ErrorHandling: promhttp.HTTPErrorOnError,
	}))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		if !healthy() {
			http.Error(w, "vault unavailable", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, `{"status":"ok"}`)
	})

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Warn("metrics listener stopped", "addr", addr, "err", err)
		}
	}()
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}

// probeHealth is the --healthcheck path: a container needs to probe this
// process without a shell in the image.
func probeHealth(cfg *ingest.FileConfig, stdout, stderr io.Writer) int {
	if cfg.MetricsAddr == "" {
		fmt.Fprintln(stderr, "ingestd: --healthcheck needs metrics_addr to be configured")
		return exitUsage
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + cfg.MetricsAddr + "/healthz")
	if err != nil {
		fmt.Fprintf(stderr, "ingestd: %v\n", err)
		return exitFailed
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "ingestd: unhealthy (status %d)\n", resp.StatusCode)
		return exitFailed
	}
	fmt.Fprintln(stdout, "ok")
	return exitOK
}
