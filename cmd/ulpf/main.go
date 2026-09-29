// Command ulpf is the unified offline operator entry point.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	version = "dev"
	commit  = "unknown"
	builtAt = "unknown"
)

const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "ulpf %s commit=%s built=%s\n", version, commit, builtAt)
		return exitOK
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "selftest":
		return runSelftest(args[1:], stdout, stderr)
	case "all", "start":
		fmt.Fprintln(stderr, "ulpf: all-in-one runtime unavailable until pkg/dataplane/app and pkg/control/server are merged")
		return exitFailure
	default:
		fmt.Fprintf(stderr, "ulpf: unknown command %q\n", args[0])
		usage(stderr)
		return exitUsage
	}
}

func usage(w io.Writer) { fmt.Fprintln(w, "usage: ulpf <all|start|selftest|verify|version> [options]") }

type check struct {
	name string
	err  error
}

func runSelftest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("selftest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pipeline := fs.Bool("pipeline", false, "check the complete offline pipeline")
	egress := fs.Bool("egress", false, "prove public egress attempts fail")
	ui := fs.Bool("ui", false, "scan UI assets for external resources")
	uiDir := fs.String("ui-dir", "/opt/ulpf/ui", "embedded UI distribution directory")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if !*pipeline && !*egress && !*ui {
		*pipeline = true
		*egress = true
		*ui = true
	}
	var checks []check
	if *pipeline {
		checks = append(checks, check{"pipeline", errors.New("pkg/dataplane/app is not linked in this branch")})
	}
	if *egress {
		checks = append(checks, egressChecks()...)
	}
	if *ui {
		checks = append(checks, check{"ui", scanUI(*uiDir)})
	}
	failed := false
	for _, c := range checks {
		if c.err != nil {
			failed = true
			fmt.Fprintf(stdout, "FAIL %-16s %v\n", c.name, c.err)
		} else {
			fmt.Fprintf(stdout, "PASS %-16s\n", c.name)
		}
	}
	if failed {
		return exitFailure
	}
	return exitOK
}

func egressChecks() []check {
	dialer := net.Dialer{Timeout: 2 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	blocked := func(network, address string) error {
		conn, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil
		}
		conn.Close()
		return fmt.Errorf("egress unexpectedly reached %s", address)
	}
	dnsResolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "udp", "8.8.8.8:53")
	}}
	dnsErr := error(nil)
	if _, err := dnsResolver.LookupHost(ctx, "example.com"); err == nil {
		dnsErr = errors.New("public DNS unexpectedly succeeded")
	}
	transport := &http.Transport{DialContext: dialer.DialContext}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	httpErr := error(nil)
	resp, err := client.Get("http://1.1.1.1/")
	if err == nil {
		resp.Body.Close()
		httpErr = errors.New("public HTTP unexpectedly succeeded")
	}
	return []check{{"egress-dns", dnsErr}, {"egress-tcp-443", blocked("tcp", "1.1.1.1:443")}, {"egress-tcp-53", blocked("tcp", "8.8.8.8:53")}, {"egress-http", httpErr}}
}

var externalURL = regexp.MustCompile(`https?://[^\s"'<>]+`)

func scanUI(root string) error {
	info, err := os.Stat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("UI path is not a directory")
	}
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, raw := range externalURL.FindAllString(string(b), -1) {
			if strings.Contains(raw, "localhost") || strings.Contains(raw, "127.0.0.1") || strings.Contains(raw, "w3.org/") {
				continue
			}
			return fmt.Errorf("external URL in %s: %s", path, raw)
		}
		return nil
	})
}
