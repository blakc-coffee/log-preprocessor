// Command dataplane runs the parser, normalizer, replay and admin service.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blakc-coffee/log-preprocessor/contracts"
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
	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("dataplane", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "shared ULPF YAML configuration")
	dataDir := fs.String("data-dir", "data", "vault and parser registry directory")
	listen := fs.String("listen", "127.0.0.1:9000", "admin API listen address")
	syncMode := fs.String("sync", "always", "vault sync mode: always, interval, none")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *configPath != "" {
		var cfg struct {
			DataDir         string `yaml:"data_dir"`
			DataplaneListen string `yaml:"dataplane_listen"`
		}
		src, err := os.ReadFile(*configPath)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := yaml.Unmarshal(src, &cfg); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if cfg.DataDir != "" && *dataDir == "data" {
			*dataDir = cfg.DataDir
		}
		if cfg.DataplaneListen != "" && *listen == "127.0.0.1:9000" {
			*listen = cfg.DataplaneListen
		}
	}
	v, err := vault.Open(vault.Options{Dir: filepath.Join(*dataDir, "vault"), Sync: vault.SyncMode(*syncMode), Compact: true})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer v.Close()
	engine := parsers.New()
	reg := registry.New(engine, filepath.Join(*dataDir, "parsers.d"))
	if err := reg.LoadDir(); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	entries, err := contracts.DSLExamples.ReadDir("dsl/examples")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	for _, entry := range entries {
		src, readErr := contracts.DSLExamples.ReadFile("dsl/examples/" + entry.Name())
		if readErr != nil {
			fmt.Fprintln(stderr, readErr)
			return 1
		}
		p, loadErr := engine.Load(src)
		if loadErr != nil {
			fmt.Fprintln(stderr, loadErr)
			return 1
		}
		if !reg.Has(p.ID()) {
			if _, addErr := reg.Add(src, true); addErr != nil {
				fmt.Fprintln(stderr, addErr)
				return 1
			}
		}
	}
	events := store.New()
	quarantined := quarantine.New()
	resolver := identity.New(identity.Config{})
	pipeline := app.New(reg, events, quarantined, nil)
	pipeline.Enricher = enrich.New(resolver, events)
	if err := v.Scan(context.Background(), 0, func(record types.RawRecord, receipt types.Receipt) error {
		return pipeline.Process(context.Background(), types.RawEvent{RawRecord: record, Receipt: receipt})
	}); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	replays := replay.New(v, pipeline)
	handler := admin.New(v, pipeline, reg, replays, resolver)
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	fmt.Fprintf(stdout, "dataplane listening on %s\n", *listen)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := pipeline.Close(); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
