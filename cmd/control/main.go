// Command control serves the ULPF control plane: the UI and the control API
// on 127.0.0.1:8000, in front of the data plane's admin API.
//
//	control --admin-url http://127.0.0.1:9000         against a running data plane
//	control --mock                                    self-contained demo, no data plane
//	control --healthcheck                             for container health checks (no shell in the image)
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

	"github.com/blakc-coffee/log-preprocessor/pkg/control/adminclient"
	"github.com/blakc-coffee/log-preprocessor/pkg/control/mock"
	"github.com/blakc-coffee/log-preprocessor/pkg/control/registry"
	"github.com/blakc-coffee/log-preprocessor/pkg/control/server"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("control", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", "127.0.0.1:8000", "address for the UI and control API")
	adminURL := fs.String("admin-url", "http://127.0.0.1:9000", "data plane admin API")
	useMock := fs.Bool("mock", false, "serve a built-in mock admin API (demo scenario, no data plane needed)")
	seed := fs.Uint64("mock-seed", 20260928, "seed for --mock")
	tick := fs.Duration("mock-tick", time.Second, "how often the --mock clock advances one second; 0 stops it")
	regPath := fs.String("registry-db", "data/control/registry.db", "approval registry (SQLite); \":memory:\" keeps nothing")
	health := fs.Bool("healthcheck", false, "GET /healthz on --listen and exit 0 if it answers 200")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *health {
		return healthcheck(*listen, stderr)
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))

	var admin *adminclient.Client
	var mux *http.ServeMux
	if *useMock {
		m := mock.New(mock.Options{Seed: *seed})
		admin = adminclient.NewInProcess(m.Handler())
		mux = http.NewServeMux()
		mux.Handle("/mock/", m.Handler())
		if *tick > 0 {
			go func() {
				for range time.Tick(*tick) {
					m.Tick()
				}
			}()
		}
		log.Info("mock admin API enabled", "seed", *seed, "advance", "POST /mock/advance")
	} else {
		var err error
		if admin, err = adminclient.New(*adminURL); err != nil {
			fmt.Fprintln(stderr, "control:", err)
			return 2
		}
	}

	if *regPath != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(*regPath), 0o700); err != nil {
			fmt.Fprintln(stderr, "control:", err)
			return 1
		}
	}
	reg, err := registry.Open(*regPath)
	if err != nil {
		fmt.Fprintln(stderr, "control:", err)
		return 1
	}
	defer reg.Close()

	srv, err := server.New(server.Config{Admin: admin, Registry: reg, Logger: log})
	if err != nil {
		fmt.Fprintln(stderr, "control:", err)
		return 1
	}
	var handler http.Handler = srv
	if mux != nil {
		mux.Handle("/", srv)
		handler = mux
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(stderr, "control:", err)
		return 1
	}
	hs := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}
	fmt.Fprintf(stdout, "ULPF control plane on http://%s (no authentication: keep it on loopback)\n", ln.Addr())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- hs.Serve(ln) }()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(stderr, "control:", err)
			return 1
		}
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}
	return 0
}

func healthcheck(listen string, stderr io.Writer) int {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		fmt.Fprintln(stderr, "control: --listen:", err)
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		fmt.Fprintln(stderr, "control: healthcheck:", err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(stderr, "control: healthcheck: status", resp.StatusCode)
		return 1
	}
	return 0
}
