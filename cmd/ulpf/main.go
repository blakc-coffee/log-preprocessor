// Command ulpf is the unified offline operator entry point.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	pathpkg "path"
	"regexp"
	"strings"
	"time"

	controlregistry "github.com/blakc-coffee/log-preprocessor/pkg/control/registry"
	controlserver "github.com/blakc-coffee/log-preprocessor/pkg/control/server"
	controlui "github.com/blakc-coffee/log-preprocessor/pkg/control/ui"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault/memvault"
	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
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
	case "passwd":
		return runPasswd(args[1:], os.Stdin, stdout, stderr)
	case "healthcheck":
		return runHealthcheck(stderr)
	case "all", "start":
		return runStart(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "ulpf: unknown command %q\n", args[0])
		usage(stderr)
		return exitUsage
	}
}

func runHealthcheck(stderr io.Writer) int {
	plain := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 3 * time.Second}
	// The control plane may serve TLS; this probes our own loopback listener, so it is not verified.
	secure := &http.Client{Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 3 * time.Second} //nolint:gosec
	for _, endpoint := range []string{"127.0.0.1:9000/healthz", "127.0.0.1:8000/healthz"} {
		var last error
		ok := false
		for _, try := range []struct {
			c      *http.Client
			scheme string
		}{{plain, "http://"}, {secure, "https://"}} {
			resp, err := try.c.Get(try.scheme + endpoint)
			if err != nil {
				last = err
				continue
			}
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ok = true
				break
			}
			last = fmt.Errorf("%s%s returned %s", try.scheme, endpoint, resp.Status)
		}
		if !ok {
			fmt.Fprintln(stderr, "ulpf healthcheck:", last)
			return exitFailure
		}
	}
	return exitOK
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: ulpf <all|start|passwd|selftest|verify|version> [options]")
}

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
	uiDir := fs.String("ui-dir", "", "optional UI distribution directory; empty scans embedded assets")
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
		checks = append(checks, check{"vault-memory", selftestVault()}, check{"sqlite", selftestSQLite()})
	}
	if *egress {
		checks = append(checks, egressChecks()...)
	}
	if *ui {
		if *uiDir == "" {
			checks = append(checks, check{"ui", scanUIFS(controlui.Dist())})
		} else {
			checks = append(checks, check{"ui", scanUI(*uiDir)})
		}
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

func selftestVault() error {
	ctx := context.Background()
	v := memvault.New(memvault.Options{SealEvery: 2})
	defer v.Close()
	want := [][]byte{{0x00, 0xff, '\r', '\n'}, []byte("sacred raw bytes")}
	for i, raw := range want {
		if _, err := v.Put(ctx, types.RawRecord{SourceID: "selftest", ReceivedAt: time.Unix(int64(i), 0).UTC(), Raw: append([]byte(nil), raw...)}); err != nil {
			return err
		}
	}
	for i, raw := range want {
		got, _, err := v.Get(ctx, types.RecordID(i+1))
		if err != nil {
			return err
		}
		if !bytes.Equal(got.Raw, raw) {
			return fmt.Errorf("record %d changed", i+1)
		}
	}
	report, err := v.VerifyChain(ctx, true)
	if err != nil {
		return err
	}
	if !report.OK || report.Records != uint64(len(want)) {
		return fmt.Errorf("deep verification failed: %+v", report)
	}
	return nil
}

func selftestSQLite() error {
	r, err := controlregistry.Open(":memory:")
	if err != nil {
		return err
	}
	return r.Close()
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
	return []check{{"loopback", loopbackCheck()}, {"egress-dns", dnsErr}, {"egress-tcp-443", blocked("tcp", "1.1.1.1:443")}, {"egress-tcp-53", blocked("tcp", "8.8.8.8:53")}, {"egress-http", httpErr}}
}

func loopbackCheck() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()
	accepted := make(chan error, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr == nil {
			acceptErr = conn.Close()
		}
		accepted <- acceptErr
	}()
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		return err
	}
	if err := conn.Close(); err != nil {
		return err
	}
	return <-accepted
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
	return scanUIFS(os.DirFS(root))
}

func scanUIFS(root fs.FS) error {
	return fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(pathpkg.Ext(path)) {
		case ".html", ".js", ".css", ".json", ".svg", ".map":
		default:
			return nil
		}
		b, err := fs.ReadFile(root, path)
		if err != nil {
			return err
		}
		for _, loc := range externalURL.FindAllIndex(b, -1) {
			if insideBlockComment(b, loc[0]) {
				continue
			}
			raw := string(b[loc[0]:loc[1]])
			if allowedUIURL(raw) {
				continue
			}
			return fmt.Errorf("external URL in %s: %s", path, raw)
		}
		return nil
	})
}

func allowedUIURL(raw string) bool {
	return strings.Contains(raw, "localhost") ||
		strings.Contains(raw, "127.0.0.1") ||
		strings.Contains(raw, "w3.org/") ||
		strings.HasPrefix(raw, "https://reactjs.org/docs/error-decoder.html") ||
		strings.HasPrefix(raw, "https://reactrouter.com/v6/upgrading/future")
}

func insideBlockComment(content []byte, offset int) bool {
	prefix := content[:offset]
	cssOpen, cssClose := bytes.LastIndex(prefix, []byte("/*")), bytes.LastIndex(prefix, []byte("*/"))
	if cssOpen > cssClose {
		return true
	}
	htmlOpen, htmlClose := bytes.LastIndex(prefix, []byte("<!--")), bytes.LastIndex(prefix, []byte("-->"))
	return htmlOpen > htmlClose
}

// runPasswd prints a users-file line: ulpf passwd <name> <approver|viewer> < password-on-stdin.
// The password comes from stdin so it never appears in argv or shell history.
func runPasswd(args []string, in io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "usage: ulpf passwd <name> <approver|viewer>   (password on stdin)")
		return exitUsage
	}
	pw, err := bufio.NewReader(in).ReadString('\n')
	pw = strings.TrimRight(pw, "\r\n")
	if (err != nil && err != io.EOF) || len(pw) < 12 {
		fmt.Fprintln(stderr, "ulpf passwd: read a password of at least 12 characters from stdin")
		return exitUsage
	}
	if strings.ContainsAny(args[0], ":\n ") || (args[1] != "approver" && args[1] != "viewer") {
		fmt.Fprintln(stderr, "ulpf passwd: name has no ':' or spaces; role is approver or viewer")
		return exitUsage
	}
	h, err := controlserver.HashPassword(pw)
	if err != nil {
		fmt.Fprintln(stderr, "ulpf passwd:", err)
		return exitFailure
	}
	fmt.Fprintf(stdout, "%s:%s:%s\n", args[0], args[1], h)
	return exitOK
}
