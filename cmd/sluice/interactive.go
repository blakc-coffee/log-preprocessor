//go:build !windows

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// runInteractive is what a bare `sluice` does in a terminal: make sure a Sluice is running (start
// one in this process if not), confirm that the web UI and the terminal UI are both up, and show
// the terminal UI. Quitting the TUI stops the Sluice this process started.
func runInteractive(stdout, stderr io.Writer) int {
	c := newTUIClient("http://127.0.0.1:8000", "http://127.0.0.1:8080", "", "", false)

	if c.do("GET", "/api/telemetry", nil, nil) == nil { // one is already running: just attach
		fmt.Fprintf(stdout, "✓ Sluice is already running. Web UI: %s\n", c.base)
		return runTUIWith(c, "✓ web UI live at "+c.base+"  ·  ✓ terminal UI ready  ·  attached to a running Sluice", stdout, stderr)
	}

	cfg, err := defaultRuntimeConfig()
	if err != nil {
		fmt.Fprintln(stderr, "sluice:", err)
		return exitFailure
	}
	// The runtime logs while the terminal UI owns the screen, so its output goes to a file.
	logPath := filepath.Join(filepath.Dir(cfg.DataDir), "sluice.log")
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		fmt.Fprintln(stderr, "sluice:", err)
		return exitFailure
	}
	defer logf.Close()

	rt, err := newUnifiedRuntime(cfg, logf)
	if err != nil {
		fmt.Fprintf(stderr, "sluice: cannot start: %v\n(details in %s)\n", err, logPath)
		return exitFailure
	}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	served := make(chan error, 1)
	go func() { served <- rt.serve(ctx, logf) }()

	ready := false
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline) && !ready; {
		select {
		case err := <-served: // it stopped before it was ready, usually a port already in use
			_ = rt.close()
			fmt.Fprintf(stderr, "sluice: could not start: %v\nIs something else using port 8000, 8080, 9000 or 5514? Details: %s\n", err, logPath)
			return exitFailure
		default:
		}
		if c.do("GET", "/api/telemetry", nil, nil) == nil {
			ready = true
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if !ready {
		stop()
		<-served
		_ = rt.close()
		fmt.Fprintf(stderr, "sluice: did not become ready in 20s. Details: %s\n", logPath)
		return exitFailure
	}

	fmt.Fprintf(stdout, "✓ Web UI is live:   %s   (open it in your browser)\n", c.base)
	fmt.Fprintf(stdout, "✓ Terminal UI:      starting now\n  Send logs to syslog 127.0.0.1:5514 (UDP/TCP) or HTTP 127.0.0.1:8080. Data: %s\n", cfg.DataDir)
	code := runTUIWith(c, "✓ web UI live at "+c.base+"  ·  ✓ terminal UI ready  ·  o opens the web UI", stdout, stderr)

	stop()
	if err := <-served; err != nil && err != context.Canceled {
		fmt.Fprintln(stderr, "sluice:", err)
	}
	if err := rt.close(); err != nil {
		fmt.Fprintln(stderr, "sluice:", err)
	}
	fmt.Fprintf(stdout, "Sluice stopped. Your data is kept in %s\n", cfg.DataDir)
	return code
}
