//go:build !windows

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blakc-coffee/log-preprocessor/contracts"
	"github.com/blakc-coffee/log-preprocessor/pkg/control/adminclient"
	controlregistry "github.com/blakc-coffee/log-preprocessor/pkg/control/registry"
	controlserver "github.com/blakc-coffee/log-preprocessor/pkg/control/server"
	"github.com/blakc-coffee/log-preprocessor/pkg/control/ui"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/admin"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/app"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/enrich"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/identity"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/parsers"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/quarantine"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/registry"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/replay"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/store"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault"
	"github.com/blakc-coffee/log-preprocessor/pkg/sinks/ecs"
	"github.com/blakc-coffee/log-preprocessor/pkg/sinks/fanout"
	"github.com/blakc-coffee/log-preprocessor/pkg/sinks/ocsfjson"
	parquetsink "github.com/blakc-coffee/log-preprocessor/pkg/sinks/parquet"
	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

const (
	dataPlaneAddress = "127.0.0.1:9000"
	controlAddress   = "127.0.0.1:8000"
)

type runtimeConfig struct {
	DataDir           string   `yaml:"data_dir"`
	DataPlaneListen   string   `yaml:"dataplane_listen"`
	ControlListen     string   `yaml:"control_listen"`
	IncludeRawExports bool     `yaml:"include_raw_exports"`
	Sinks             []string `yaml:"sinks"`
}

func loadRuntimeConfig(path string) (runtimeConfig, error) {
	cfg := runtimeConfig{
		DataDir:         "/data",
		DataPlaneListen: dataPlaneAddress,
		ControlListen:   controlAddress,
		Sinks:           []string{"parquet", "ocsfjson", "ecs"},
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return runtimeConfig{}, err
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return runtimeConfig{}, err
	}
	if cfg.DataDir == "" {
		return runtimeConfig{}, errors.New("config: data_dir is required")
	}
	if cfg.DataPlaneListen != dataPlaneAddress || cfg.ControlListen != controlAddress {
		return runtimeConfig{}, fmt.Errorf("config: fixed listeners are %s and %s", dataPlaneAddress, controlAddress)
	}
	if len(cfg.Sinks) == 0 {
		cfg.Sinks = []string{"parquet", "ocsfjson", "ecs"}
	}
	return cfg, nil
}

type unifiedRuntime struct {
	cfg         runtimeConfig
	vault       *vault.Vault
	pipeline    *app.App
	control     *controlserver.Server
	controlReg  *controlregistry.Registry
	adminHTTP   *http.Server
	controlHTTP *http.Server
}

func newUnifiedRuntime(cfg runtimeConfig, stderr io.Writer) (_ *unifiedRuntime, err error) {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	v, err := vault.Open(vault.Options{Dir: filepath.Join(cfg.DataDir, "vault"), Sync: vault.SyncAlways, Compact: true})
	if err != nil {
		return nil, err
	}
	rt := &unifiedRuntime{cfg: cfg, vault: v}
	defer func() {
		if err != nil {
			_ = rt.close()
		}
	}()

	engine := parsers.New()
	reg := registry.New(engine, filepath.Join(cfg.DataDir, "parsers.d"))
	if err = reg.LoadDir(); err != nil {
		return nil, err
	}
	if err = loadBuiltinParsers(engine, reg); err != nil {
		return nil, err
	}
	events := store.New()
	quarantined := quarantine.New()
	resolver := identity.New(identity.Config{})
	targets, sinkErr := configuredSinks(cfg, v)
	if sinkErr != nil {
		return nil, sinkErr
	}
	f, sinkErr := fanout.New(targets, fanout.Config{SpoolRoot: filepath.Join(cfg.DataDir, "spool")})
	if sinkErr != nil {
		for _, target := range targets {
			_ = target.Close()
		}
		return nil, sinkErr
	}
	rt.pipeline = app.New(reg, events, quarantined, enrich.New(resolver, events), f)
	if err = v.Scan(context.Background(), 0, func(record types.RawRecord, receipt types.Receipt) error {
		return rt.pipeline.Process(context.Background(), types.RawEvent{RawRecord: record, Receipt: receipt})
	}); err != nil {
		return nil, err
	}
	replays := replay.New(v, rt.pipeline)
	adminHandler := admin.New(v, rt.pipeline, reg, replays, resolver)
	rt.adminHTTP = &http.Server{Addr: cfg.DataPlaneListen, Handler: adminHandler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}

	controlDir := filepath.Join(cfg.DataDir, "control")
	if err = os.MkdirAll(controlDir, 0o700); err != nil {
		return nil, err
	}
	rt.controlReg, err = controlregistry.Open(filepath.Join(controlDir, "registry.db"))
	if err != nil {
		return nil, err
	}
	client, err := adminclient.New("http://" + cfg.DataPlaneListen)
	if err != nil {
		return nil, err
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))
	rt.control, err = controlserver.New(controlserver.Config{Admin: client, Registry: rt.controlReg, UI: ui.Dist(), Logger: log})
	if err != nil {
		return nil, err
	}
	rt.controlHTTP = &http.Server{Addr: cfg.ControlListen, Handler: rt.control, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}
	return rt, nil
}

func loadBuiltinParsers(engine *parsers.Engine, reg *registry.Registry) error {
	entries, err := contracts.DSLExamples.ReadDir("dsl/examples")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		src, err := contracts.DSLExamples.ReadFile("dsl/examples/" + entry.Name())
		if err != nil {
			return err
		}
		p, err := engine.Load(src)
		if err != nil {
			return err
		}
		if !reg.Has(p.ID()) {
			if _, err := reg.Add(src, true); err != nil {
				return err
			}
		}
	}
	return nil
}

func configuredSinks(cfg runtimeConfig, v types.Vault) ([]types.Sink, error) {
	exports := filepath.Join(cfg.DataDir, "exports")
	if err := os.MkdirAll(exports, 0o750); err != nil {
		return nil, err
	}
	rawProvider := func(ctx context.Context, event types.NormalizedEvent) ([]byte, error) {
		record, _, err := v.Get(ctx, event.RecordID)
		if err != nil {
			return nil, err
		}
		return append([]byte(nil), record.Raw...), nil
	}
	var targets []types.Sink
	closeTargets := func() {
		for _, target := range targets {
			_ = target.Close()
		}
	}
	for _, name := range cfg.Sinks {
		switch name {
		case "parquet":
			sink, err := parquetsink.New(parquetsink.Config{Root: filepath.Join(cfg.DataDir, "lake")})
			if err != nil {
				closeTargets()
				return nil, err
			}
			targets = append(targets, sink)
		case "ocsfjson":
			f, err := os.OpenFile(filepath.Join(exports, "ocsf.ndjson"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
			if err != nil {
				closeTargets()
				return nil, err
			}
			targets = append(targets, ocsfjson.New(f, ocsfjson.Options{IncludeRaw: cfg.IncludeRawExports, RawProvider: rawProvider}))
		case "ecs":
			f, err := os.OpenFile(filepath.Join(exports, "ecs.ndjson"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
			if err != nil {
				closeTargets()
				return nil, err
			}
			targets = append(targets, ecs.New(f, ecs.Options{Bulk: true, Index: "ulpf", IncludeRaw: cfg.IncludeRawExports, RawProvider: rawProvider}))
		default:
			closeTargets()
			return nil, fmt.Errorf("config: unsupported local sink %q", name)
		}
	}
	return targets, nil
}

func (rt *unifiedRuntime) serve(ctx context.Context, stdout io.Writer) error {
	adminLn, err := net.Listen("tcp", rt.cfg.DataPlaneListen)
	if err != nil {
		return fmt.Errorf("data plane listen: %w", err)
	}
	controlLn, err := net.Listen("tcp", rt.cfg.ControlListen)
	if err != nil {
		adminLn.Close()
		return fmt.Errorf("control plane listen: %w", err)
	}
	fmt.Fprintf(stdout, "ULPF data plane on http://%s\n", adminLn.Addr())
	fmt.Fprintf(stdout, "ULPF control plane on http://%s\n", controlLn.Addr())
	type serveResult struct {
		name string
		err  error
	}
	errCh := make(chan serveResult, 2)
	go func() { errCh <- serveResult{"data plane", rt.adminHTTP.Serve(adminLn)} }()
	go func() { errCh <- serveResult{"control plane", rt.controlHTTP.Serve(controlLn)} }()

	var serveErr error
	select {
	case <-ctx.Done():
	case result := <-errCh:
		if !errors.Is(result.err, http.ErrServerClosed) {
			serveErr = fmt.Errorf("%s: %w", result.name, result.err)
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return errors.Join(serveErr, rt.adminHTTP.Shutdown(shutdownCtx), rt.controlHTTP.Shutdown(shutdownCtx))
}

func (rt *unifiedRuntime) close() error {
	var errs []error
	if rt.control != nil {
		errs = append(errs, rt.control.Close())
	}
	if rt.controlReg != nil {
		errs = append(errs, rt.controlReg.Close())
	}
	if rt.pipeline != nil {
		errs = append(errs, rt.pipeline.Close())
	}
	if rt.vault != nil {
		errs = append(errs, rt.vault.Close())
	}
	return errors.Join(errs...)
}

func runStart(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "configs/demo.yaml", "shared ULPF YAML configuration")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	cfg, err := loadRuntimeConfig(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, "ulpf:", err)
		return exitFailure
	}
	rt, err := newUnifiedRuntime(cfg, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "ulpf:", err)
		return exitFailure
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serveErr := rt.serve(ctx, stdout)
	closeErr := rt.close()
	if err := errors.Join(serveErr, closeErr); err != nil {
		fmt.Fprintln(stderr, "ulpf:", err)
		return exitFailure
	}
	return exitOK
}
