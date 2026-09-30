package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dark-14100/sluice/pkg/dataplane/vault"
)

// exec runs ingestd in-process and returns its exit code and output.
func exec(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// writeConfig materialises a config pointing at a temp vault.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ingest.yaml")
	body = strings.ReplaceAll(body, "{{DIR}}", dir)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const corpus = "../../testdata"

// TestOnceIngestsFixtures is the `--once` contract: read the files, store
// them, exit 0 without waiting for a signal. CI and the round-trip harness
// both depend on it terminating on its own.
func TestOnceIngestsFixtures(t *testing.T) {
	if _, err := os.Stat(filepath.Join(corpus, "cisco_asa.log")); err != nil {
		t.Skipf("no corpus: %v", err)
	}
	asa, err := filepath.Abs(filepath.Join(corpus, "cisco_asa.log"))
	if err != nil {
		t.Fatal(err)
	}

	cfg := writeConfig(t, fmt.Sprintf(`
data_dir: {{DIR}}
metrics_addr: ""
vault:
  dir: {{DIR}}/vault
  segment_max_records: 500
sources:
  - {id: asa, type: file, paths: [%q], mode: once}
`, asa))

	jsonl := filepath.Join(filepath.Dir(cfg), "events.jsonl")
	code, _, errOut := exec(t, "--config", cfg, "--once", "--emit", "jsonl:"+jsonl)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}

	body, err := os.ReadFile(jsonl)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) != 2000 {
		t.Fatalf("emitted %d events, want 2000", len(lines))
	}

	// The emitted payload is base64, so a hostile log line never reaches a
	// terminal or a log aggregator unescaped.
	var first eventJSON
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(first.RawBase64)
	if err != nil {
		t.Fatalf("raw_base64 is not base64: %v", err)
	}
	src, err := os.ReadFile(asa)
	if err != nil {
		t.Fatal(err)
	}
	wantFirst := strings.SplitN(string(src), "\n", 2)[0]
	if string(raw) != wantFirst {
		t.Errorf("the first emitted record is not the file's first line")
	}
	if first.RecordID != 1 {
		t.Errorf("first record id is %d, want 1", first.RecordID)
	}
	if first.RawBytes != len(raw) {
		t.Errorf("raw_bytes is %d, decoded %d", first.RawBytes, len(raw))
	}
}

// TestOnceWithNoOneShotSourceIsAnError: `--once` against a config of only
// listeners would hang forever. Saying so beats hanging.
func TestOnceWithNoOneShotSourceIsAnError(t *testing.T) {
	cfg := writeConfig(t, `
data_dir: {{DIR}}
metrics_addr: ""
vault: {dir: "{{DIR}}/vault"}
sources:
  - {id: udp, type: udp, listen: "127.0.0.1:0"}
`)
	code, _, errOut := exec(t, "--config", cfg, "--once")
	if code == exitOK {
		t.Fatal("--once with no one-shot source exited 0")
	}
	if !strings.Contains(errOut, "once") {
		t.Errorf("the error does not explain the problem: %s", errOut)
	}
}

// TestExitCodes pins the contract a supervisor branches on.
func TestExitCodes(t *testing.T) {
	t.Run("no config is a usage error", func(t *testing.T) {
		if code, _, _ := exec(t); code != exitUsage {
			t.Errorf("exit %d, want 2", code)
		}
	})

	t.Run("missing config file is a usage error", func(t *testing.T) {
		if code, _, _ := exec(t, "--config", "/nonexistent/x.yaml"); code != exitUsage {
			t.Errorf("exit %d, want 2", code)
		}
	})

	t.Run("invalid config is a usage error", func(t *testing.T) {
		cfg := writeConfig(t, "sources:\n  - {id: a, type: carrier-pigeon}\n")
		code, _, errOut := exec(t, "--config", cfg)
		if code != exitUsage {
			t.Errorf("exit %d, want 2", code)
		}
		if !strings.Contains(errOut, "carrier-pigeon") {
			t.Errorf("the error does not name the problem: %s", errOut)
		}
	})

	t.Run("unknown key is a usage error", func(t *testing.T) {
		cfg := writeConfig(t, "nonsense: 1\nsources:\n  - {id: a, type: udp, listen: \"127.0.0.1:0\"}\n")
		if code, _, _ := exec(t, "--config", cfg); code != exitUsage {
			t.Errorf("exit %d, want 2", code)
		}
	})

	t.Run("bad emit override is a usage error", func(t *testing.T) {
		cfg := writeConfig(t, `
data_dir: {{DIR}}
metrics_addr: ""
vault: {dir: "{{DIR}}/vault"}
sources:
  - {id: udp, type: udp, listen: "127.0.0.1:0"}
`)
		if code, _, _ := exec(t, "--config", cfg, "--emit", "telepathy"); code != exitUsage {
			t.Errorf("exit %d, want 2", code)
		}
	})
}

// TestPortConflictIsAStartupError: binding in the source constructor means a
// clash is reported before anything is running, not after.
func TestPortConflictIsAStartupError(t *testing.T) {
	cfg := writeConfig(t, `
data_dir: {{DIR}}
metrics_addr: ""
vault: {dir: "{{DIR}}/vault"}
sources:
  - {id: a, type: tcp, listen: "127.0.0.1:5514"}
  - {id: b, type: tcp, listen: "127.0.0.1:5514"}
`)
	code, _, errOut := exec(t, "--config", cfg, "--once")
	if code == exitOK {
		t.Fatal("two listeners on one port started successfully")
	}
	if !strings.Contains(errOut, "source b") && !strings.Contains(errOut, "address already in use") {
		t.Logf("error was: %s", errOut)
	}
}

// TestTLSIsRefusedRatherThanIgnored: a `type: tls` listener that quietly
// served plaintext would be a security failure disguised as a working config.
func TestTLSIsRefusedRatherThanIgnored(t *testing.T) {
	cfg := writeConfig(t, `
data_dir: {{DIR}}
metrics_addr: ""
vault: {dir: "{{DIR}}/vault"}
sources:
  - {id: tls, type: tls, listen: "127.0.0.1:0", cert: c.pem, key: k.pem}
`)
	code, _, errOut := exec(t, "--config", cfg, "--once")
	if code == exitOK {
		t.Fatal("a tls listener started without TLS support")
	}
	if !strings.Contains(errOut, "tls") {
		t.Errorf("the error does not mention tls: %s", errOut)
	}
}

// TestHealthcheckNeedsAnAddress: --healthcheck exists so a container can probe
// without a shell in the image, and it cannot probe nothing.
func TestHealthcheckNeedsAnAddress(t *testing.T) {
	cfg := writeConfig(t, `
data_dir: {{DIR}}
metrics_addr: ""
vault: {dir: "{{DIR}}/vault"}
sources:
  - {id: udp, type: udp, listen: "127.0.0.1:0"}
`)
	if code, _, _ := exec(t, "--config", cfg, "--healthcheck"); code != exitUsage {
		t.Errorf("exit %d, want 2", code)
	}
}

func TestHealthcheckAgainstNothingFails(t *testing.T) {
	cfg := writeConfig(t, `
data_dir: {{DIR}}
metrics_addr: "127.0.0.1:59999"
vault: {dir: "{{DIR}}/vault"}
sources:
  - {id: udp, type: udp, listen: "127.0.0.1:0"}
`)
	if code, _, _ := exec(t, "--config", cfg, "--healthcheck"); code != exitFailed {
		t.Errorf("exit %d, want 1: probing a daemon that is not running must fail", code)
	}
}

// TestSecondDaemonOnOneVaultIsRefused: two writers sharing a vault directory
// would interleave into the same segments, and no amount of hashing afterwards
// would sort that out. The flock makes it a startup failure.
func TestSecondDaemonOnOneVaultIsRefused(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "in.log")
	if err := os.WriteFile(logPath, []byte("one\ntwo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`
data_dir: %s
metrics_addr: ""
vault: {dir: "%s/vault"}
sources:
  - {id: f, type: file, paths: [%q], mode: once}
`, dir, dir, logPath)

	path := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// The first run completes and releases the lock.
	if code, _, errOut := exec(t, "--config", path, "--once"); code != exitOK {
		t.Fatalf("first run exit %d: %s", code, errOut)
	}

	v, err := openVaultForTest(filepath.Join(dir, "vault"))
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	// Now the directory is held open, so ingestd must refuse.
	code, _, errOut := exec(t, "--config", path, "--once")
	if code == exitOK {
		t.Fatal("a second writer opened a vault another process holds")
	}
	if !strings.Contains(errOut, "already open") {
		t.Errorf("the error does not explain the conflict: %s", errOut)
	}
}

// openVaultForTest holds a vault directory open so the lock can be tested.
func openVaultForTest(dir string) (*vault.Vault, error) {
	return vault.Open(vault.Options{Dir: dir})
}
