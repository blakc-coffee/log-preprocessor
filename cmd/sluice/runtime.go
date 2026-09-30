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
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"

	"github.com/dark-14100/sluice/pkg/control/adminclient"
	controlregistry "github.com/dark-14100/sluice/pkg/control/registry"
	controlserver "github.com/dark-14100/sluice/pkg/control/server"
	"github.com/dark-14100/sluice/pkg/control/ui"
	"github.com/dark-14100/sluice/pkg/dataplane/admin"
	"github.com/dark-14100/sluice/pkg/dataplane/app"
	"github.com/dark-14100/sluice/pkg/dataplane/enrich"
	"github.com/dark-14100/sluice/pkg/dataplane/identity"
	"github.com/dark-14100/sluice/pkg/dataplane/ingest"
	"github.com/dark-14100/sluice/pkg/dataplane/parsers"
	"github.com/dark-14100/sluice/pkg/dataplane/quarantine"
	"github.com/dark-14100/sluice/pkg/dataplane/registry"
	"github.com/dark-14100/sluice/pkg/dataplane/replay"
	"github.com/dark-14100/sluice/pkg/dataplane/store"
	"github.com/dark-14100/sluice/pkg/dataplane/vault"
	"github.com/dark-14100/sluice/pkg/sinks/ecs"
	"github.com/dark-14100/sluice/pkg/sinks/fanout"
	"github.com/dark-14100/sluice/pkg/sinks/ocsfjson"
	parquetsink "github.com/dark-14100/sluice/pkg/sinks/parquet"
	types "github.com/dark-14100/sluice/pkg/types"
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
	// IngestConfig is an ingestd-format YAML whose sources and limits feed the
	// pipeline. Empty means no listeners: the vault is only replayed.
	IngestConfig string `yaml:"ingest_config"`
	// AuthUsersFile turns on sign-in for the control plane (see `sluice passwd`).
	AuthUsersFile string `yaml:"auth_users_file"`
	// TLSCert and TLSKey serve the control plane over HTTPS.
	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`
	// AllowInsecure permits the control plane on 0.0.0.0 with no sign-in. For demos.
	AllowInsecure bool `yaml:"allow_insecure"`
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
	// The ports are fixed. The host is 127.0.0.1 natively; inside a container it must be
	// 0.0.0.0 or the published port cannot reach it (the compose files publish on the
	// host's loopback only).
	// The admin API can approve parsers and has no sign-in of its own, so it never leaves
	// loopback; the control plane is the only door, and it may bind 0.0.0.0.
	if cfg.DataPlaneListen != dataPlaneAddress {
		return runtimeConfig{}, fmt.Errorf("config: dataplane_listen is fixed at %s", dataPlaneAddress)
	}
	if cfg.ControlListen != controlAddress && cfg.ControlListen != "0.0.0.0:8000" {
		return runtimeConfig{}, fmt.Errorf("config: control_listen is %s or 0.0.0.0:8000", controlAddress)
	}
	if strings.HasPrefix(cfg.ControlListen, "0.0.0.0:") && cfg.AuthUsersFile == "" && !cfg.AllowInsecure {
		return runtimeConfig{}, errors.New("config: control_listen 0.0.0.0 without auth_users_file exposes the UI to anyone who can reach it; set auth_users_file, or allow_insecure: true for a demo")
	}
	if strings.HasPrefix(cfg.ControlListen, "0.0.0.0:") && cfg.AuthUsersFile != "" && cfg.TLSCert == "" && !cfg.AllowInsecure {
		return runtimeConfig{}, errors.New("config: sign-in on 0.0.0.0 without tls_cert sends passwords in cleartext; set tls_cert and tls_key, or allow_insecure: true behind a TLS-terminating proxy")
	}
	if (cfg.TLSCert == "") != (cfg.TLSKey == "") {
		return runtimeConfig{}, errors.New("config: tls_cert and tls_key go together")
	}
	if len(cfg.Sinks) == 0 {
		cfg.Sinks = []string{"parquet", "ocsfjson", "ecs"}
	}
	return cfg, nil
}

// defaultIngestYAML is what `sluice all` uses with no --config: syslog on 5514 (UDP and TCP) and
// HTTP ingest on 8080, loopback only.
const defaultIngestYAML = `sources:
  - {id: syslog-udp, type: udp, listen: "127.0.0.1:5514", readers: 1}
  - {id: syslog-tcp, type: tcp, listen: "127.0.0.1:5514", framing: auto}
  - {id: http, type: http, listen: "127.0.0.1:8080", dynamic_sources: true}
`

// defaultRuntimeConfig runs Sluice with no files at all: data under ~/.sluice, everything on
// loopback, no sign-in (nothing is reachable from another machine).
func defaultRuntimeConfig() (runtimeConfig, error) {
	dir := filepath.Join(".", "sluice-data")
	if home, err := os.UserHomeDir(); err == nil {
		dir = filepath.Join(home, ".sluice", "data")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return runtimeConfig{}, err
	}
	ingestPath := filepath.Join(dir, "ingest.yaml")
	if _, err := os.Stat(ingestPath); errors.Is(err, os.ErrNotExist) { // never overwrite the user's edits
		if err := os.WriteFile(ingestPath, []byte(defaultIngestYAML), 0o600); err != nil {
			return runtimeConfig{}, err
		}
	}
	return runtimeConfig{
		DataDir:         dir,
		DataPlaneListen: dataPlaneAddress,
		ControlListen:   controlAddress,
		Sinks:           []string{"parquet", "ocsfjson", "ecs"},
		IngestConfig:    ingestPath,
	}, nil
}

type unifiedRuntime struct {
	cfg         runtimeConfig
	vault       *vault.Vault
	pipeline    *app.App
	live        *app.Live
	events      *store.Store
	metrics     *prometheus.Registry
	users       controlserver.Users
	ingestCfg   *ingest.FileConfig
	control     *controlserver.Server
	controlReg  *controlregistry.Registry
	adminHTTP   *http.Server
	controlHTTP *http.Server
}

func newUnifiedRuntime(cfg runtimeConfig, stderr io.Writer) (_ *unifiedRuntime, err error) {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	reg0 := prometheus.NewRegistry()
	reg0.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	v, err := vault.Open(vault.Options{Dir: filepath.Join(cfg.DataDir, "vault"), Sync: vault.SyncAlways, Compact: true, SealInterval: 5 * time.Second, Registerer: reg0})
	if err != nil {
		return nil, err
	}
	rt := &unifiedRuntime{cfg: cfg, vault: v, metrics: reg0}
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
	if err = app.LoadBuiltins(engine, reg); err != nil {
		return nil, err
	}
	events, err := store.Open(filepath.Join(cfg.DataDir, "store.db"))
	if err != nil {
		return nil, err
	}
	rt.events = events
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
	if cfg.IngestConfig != "" {
		if rt.ingestCfg, err = ingest.LoadFile(cfg.IngestConfig); err != nil {
			return nil, err
		}
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
	client, err := adminclient.New("http://" + dataPlaneAddress)
	if err != nil {
		return nil, err
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))
	if cfg.AuthUsersFile != "" {
		if rt.users, err = controlserver.LoadUsers(cfg.AuthUsersFile); err != nil {
			return nil, err
		}
	}
	rt.control, err = controlserver.New(controlserver.Config{Admin: client, Registry: rt.controlReg, UI: ui.Dist(), Logger: log,
		Users: rt.users, Metrics: promhttp.HandlerFor(rt.metrics, promhttp.HandlerOpts{})})
	if err != nil {
		return nil, err
	}
	rt.controlHTTP = &http.Server{Addr: cfg.ControlListen, Handler: rt.control, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}
	return rt, nil
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
	ctx, stopIngest := context.WithCancel(ctx)
	defer stopIngest()
	if rt.ingestCfg != nil {
		if rt.live, err = rt.pipeline.StartIngest(ctx, stopIngest, rt.vault, rt.ingestCfg, os.Stderr, rt.metrics); err != nil {
			adminLn.Close()
			controlLn.Close()
			return fmt.Errorf("ingest: %w", err)
		}
		fmt.Fprintf(stdout, "Sluice ingest: %d sources\n", rt.live.Sources)
	}
	fmt.Fprintf(stdout, "Sluice data plane on http://%s\n", adminLn.Addr())
	scheme := "http"
	if rt.cfg.TLSCert != "" {
		scheme = "https"
	}
	fmt.Fprintf(stdout, "Sluice control plane on %s://%s (sign-in %s)\n", scheme, controlLn.Addr(), map[bool]string{true: "on", false: "OFF"}[rt.users != nil])
	type serveResult struct {
		name string
		err  error
	}
	errCh := make(chan serveResult, 2)
	go func() { errCh <- serveResult{"data plane", rt.adminHTTP.Serve(adminLn)} }()
	go func() {
		if rt.cfg.TLSCert != "" {
			errCh <- serveResult{"control plane", rt.controlHTTP.ServeTLS(controlLn, rt.cfg.TLSCert, rt.cfg.TLSKey)}
			return
		}
		errCh <- serveResult{"control plane", rt.controlHTTP.Serve(controlLn)}
	}()

	var serveErr error
	select {
	case <-ctx.Done():
	case result := <-errCh:
		if !errors.Is(result.err, http.ErrServerClosed) {
			serveErr = fmt.Errorf("%s: %w", result.name, result.err)
		}
	}
	stopIngest()
	if rt.live != nil {
		rt.live.Wait() // drain before the pipeline and vault close
		serveErr = errors.Join(serveErr, rt.live.Err())
	}
	// Created after the drain, or a slow drain would leave Shutdown an expired context.
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
	if rt.events != nil {
		errs = append(errs, rt.events.Close())
	}
	if rt.vault != nil {
		errs = append(errs, rt.vault.Close())
	}
	return errors.Join(errs...)
}

func runStart(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "YAML configuration (default: built-in, data in ~/.sluice)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	var cfg runtimeConfig
	var err error
	if *configPath == "" {
		cfg, err = defaultRuntimeConfig()
		if err == nil {
			fmt.Fprintf(stdout, "Sluice: no --config given, using built-in defaults. Data is kept in %s\n", cfg.DataDir)
			fmt.Fprintln(stdout, "        Open http://127.0.0.1:8000, or run `sluice tui` in another terminal. Ctrl+C stops.")
		}
	} else {
		cfg, err = loadRuntimeConfig(*configPath)
	}
	if err != nil {
		fmt.Fprintln(stderr, "sluice:", err)
		return exitFailure
	}
	rt, err := newUnifiedRuntime(cfg, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "sluice:", err)
		return exitFailure
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serveErr := rt.serve(ctx, stdout)
	closeErr := rt.close()
	if err := errors.Join(serveErr, closeErr); err != nil {
		fmt.Fprintln(stderr, "sluice:", err)
		return exitFailure
	}
	return exitOK
}
