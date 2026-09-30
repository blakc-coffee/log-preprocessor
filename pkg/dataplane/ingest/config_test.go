package ingest_test

import (
	"strings"
	"testing"
	"time"

	"github.com/blakc-coffee/sluice/pkg/dataplane/ingest"
	"github.com/blakc-coffee/sluice/pkg/dataplane/vault"
)

const minimalConfig = `
sources:
  - {id: asa-file, type: file, paths: ["testdata/cisco_asa.log"]}
`

func TestParseMinimal(t *testing.T) {
	cfg, err := ingest.Parse([]byte(minimalConfig))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DataDir != "./data" {
		t.Errorf("data_dir default is %q", cfg.DataDir)
	}
	if cfg.Vault.Dir != "./data/vault" {
		t.Errorf("vault.dir default is %q", cfg.Vault.Dir)
	}
	if cfg.Vault.Sync != "always" {
		t.Errorf("vault.sync default is %q; durability must be the default", cfg.Vault.Sync)
	}
	if cfg.Limits.MaxFrameBytes != 1<<20 {
		t.Errorf("max_frame_bytes default is %d", cfg.Limits.MaxFrameBytes)
	}
}

// TestUnknownKeysAreAnError is the property that matters most. A typo in
// `segment_max_records` that silently left the default in place would be
// discovered as a performance mystery weeks later, not as a startup failure.
func TestUnknownKeysAreAnError(t *testing.T) {
	cases := map[string]string{
		"top level": "nonsense: 1\n" + minimalConfig,
		"nested":    minimalConfig + "vault:\n  segment_max_recrods: 10\n",
		"source":    "sources:\n  - {id: a, type: udp, listen: \"127.0.0.1:0\", nonsense: 1}\n",
		// A plausible key for a feature that does not exist. Accepting and
		// ignoring it would leave an operator certain it was on - which is
		// exactly why compact, compact_block_bytes, zstd_level and hash_index
		// were rejected here until compaction existed.
		"a key for an unbuilt feature": minimalConfig + "vault:\n  snapshot_interval: 1h\n",
	}
	for name, in := range cases {
		if _, err := ingest.Parse([]byte(in)); err == nil {
			t.Errorf("%s: an unknown key was accepted", name)
		}
	}
}

func TestSizesAndDurations(t *testing.T) {
	cfg, err := ingest.Parse([]byte(`
vault:
  segment_max_bytes: 64MiB
  group_commit_max_delay: 2ms
  seal_interval: 30s
limits:
  max_frame_bytes: 1MiB
  max_octet_len: 16MiB
  http_max_body: 1GiB
  idle_timeout: 5m
shutdown_timeout: 15s
` + minimalConfig))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Vault.SegmentMaxBytes != 64<<20 {
		t.Errorf("64MiB parsed as %d", cfg.Vault.SegmentMaxBytes)
	}
	if cfg.Limits.HTTPMaxBody != 1<<30 {
		t.Errorf("1GiB parsed as %d", cfg.Limits.HTTPMaxBody)
	}
	if cfg.Limits.IdleTimeout.Std() != 5*time.Minute {
		t.Errorf("5m parsed as %s", cfg.Limits.IdleTimeout.Std())
	}
	if cfg.Vault.GroupCommitMaxDelay.Std() != 2*time.Millisecond {
		t.Errorf("2ms parsed as %s", cfg.Vault.GroupCommitMaxDelay.Std())
	}
	if got := cfg.Vault.SegmentMaxBytes.String(); got != "64MiB" {
		t.Errorf("64MiB renders as %q", got)
	}
}

func TestSizeUnits(t *testing.T) {
	for in, want := range map[string]int64{
		"1024": 1024, "1KiB": 1024, "1 KiB": 1024, "1MiB": 1 << 20,
		"1GiB": 1 << 30, "1KB": 1000, "1MB": 1000000, "512B": 512,
	} {
		cfg, err := ingest.Parse([]byte("limits:\n  max_frame_bytes: " + in + "\n" + minimalConfig))
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if int64(cfg.Limits.MaxFrameBytes) != want {
			t.Errorf("%q parsed as %d, want %d", in, cfg.Limits.MaxFrameBytes, want)
		}
	}
	for _, in := range []string{"1XB", "abc", "1..2MiB", "-"} {
		if _, err := ingest.Parse([]byte("limits:\n  max_frame_bytes: \"" + in + "\"\n" + minimalConfig)); err == nil {
			t.Errorf("%q was accepted as a size", in)
		}
	}
}

// TestSyncNoneNeedsAnExplicitOptIn. sync=none means acknowledgements stop
// meaning anything, so it must never be chosen by accident.
func TestSyncNoneNeedsAnExplicitOptIn(t *testing.T) {
	in := "vault:\n  sync: none\n" + minimalConfig
	_, err := ingest.Parse([]byte(in))
	if err == nil {
		t.Fatal("sync: none was accepted without an opt-in")
	}
	if !strings.Contains(err.Error(), "NOT durable") {
		t.Errorf("the error does not say what is at stake: %v", err)
	}

	t.Setenv("ULPF_ALLOW_SYNC_NONE", "1")
	if _, err := ingest.Parse([]byte(in)); err != nil {
		t.Errorf("the opt-in did not work: %v", err)
	}
}

// TestFieldsFromTheWrongSourceTypeAreRejected. Accepting `paths` on a UDP
// listener and ignoring it is how an operator ends up certain a file is being
// read when it is not.
func TestFieldsFromTheWrongSourceTypeAreRejected(t *testing.T) {
	cases := map[string]string{
		"paths on udp":       `- {id: a, type: udp, listen: "127.0.0.1:0", paths: ["x.log"]}`,
		"listen on file":     `- {id: a, type: file, paths: ["x.log"], listen: "127.0.0.1:0"}`,
		"framing on udp":     `- {id: a, type: udp, listen: "127.0.0.1:0", framing: lf}`,
		"framing on http":    `- {id: a, type: http, listen: "127.0.0.1:0", framing: lf}`,
		"cert on tcp":        `- {id: a, type: tcp, listen: "127.0.0.1:0", cert: c.pem, key: k.pem}`,
		"tls without cert":   `- {id: a, type: tls, listen: "127.0.0.1:0"}`,
		"unknown type":       `- {id: a, type: carrier-pigeon}`,
		"missing type":       `- {id: a}`,
		"missing id":         `- {type: udp, listen: "127.0.0.1:0"}`,
		"bad framing":        `- {id: a, type: tcp, listen: "127.0.0.1:0", framing: telepathy}`,
		"bad file mode":      `- {id: a, type: file, paths: ["x"], mode: sideways}`,
		"bad multiline re":   `- {id: a, type: file, paths: ["x"], multiline: {start: "([unclosed"}}`,
		"multiline no start": `- {id: a, type: file, paths: ["x"], multiline: {max_lines: 5}}`,
	}
	for name, entry := range cases {
		if _, err := ingest.Parse([]byte("sources:\n  " + entry + "\n")); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDuplicateSourceIDsRejected(t *testing.T) {
	in := `
sources:
  - {id: dup, type: udp, listen: "127.0.0.1:1"}
  - {id: dup, type: tcp, listen: "127.0.0.1:2"}
`
	if _, err := ingest.Parse([]byte(in)); err == nil {
		t.Error("duplicate source ids were accepted")
	}
}

func TestNoSourcesRejected(t *testing.T) {
	if _, err := ingest.Parse([]byte("data_dir: ./data\n")); err == nil {
		t.Error("a config with no sources was accepted")
	}
}

func TestEmitValidation(t *testing.T) {
	for _, ok := range []string{"none", "stdout", "jsonl:/tmp/x.jsonl"} {
		if _, err := ingest.Parse([]byte("emit: " + ok + "\n" + minimalConfig)); err != nil {
			t.Errorf("emit %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"telepathy", "jsonl:", "jsonl"} {
		if _, err := ingest.Parse([]byte("emit: \"" + bad + "\"\n" + minimalConfig)); err == nil {
			t.Errorf("emit %q accepted", bad)
		}
	}
}

// TestAllErrorsAreReportedAtOnce: an operator fixing a config one restart at a
// time is an operator wasting an afternoon.
func TestAllErrorsAreReportedAtOnce(t *testing.T) {
	_, err := ingest.Parse([]byte(`
log_level: shouting
sources:
  - {id: a, type: carrier-pigeon}
  - {id: b, type: file}
`))
	if err == nil {
		t.Fatal("accepted")
	}
	msg := err.Error()
	for _, want := range []string{"log_level", "carrier-pigeon", "paths is required"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error does not mention %q:\n%s", want, msg)
		}
	}
}

// TestPeerMapConfig. peer_map was rejected as an unknown key until the feature
// existed; now it parses, and a malformed entry is a startup error rather than
// a mapping that silently never matches.
func TestPeerMapConfig(t *testing.T) {
	cfg, err := ingest.Parse([]byte(`
peer_map:
  - {cidr: "10.1.0.0/16", source_id: site-a}
  - {cidr: "10.1.4.0/24", source_id: site-a-dmz}
` + minimalConfig))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.PeerMap) != 2 {
		t.Fatalf("parsed %d peer map entries, want 2", len(cfg.PeerMap))
	}
	if cfg.PeerMap[0].SourceID != "site-a" || cfg.PeerMap[0].CIDR != "10.1.0.0/16" {
		t.Errorf("first entry is %+v", cfg.PeerMap[0])
	}

	for name, entry := range map[string]string{
		"not a cidr":   `- {cidr: "nonsense", source_id: x}`,
		"bare address": `- {cidr: "10.1.0.0", source_id: x}`,
		"no source_id": `- {cidr: "10.1.0.0/16"}`,
		"no cidr":      `- {source_id: x}`,
		"unknown key":  `- {cidr: "10.1.0.0/16", source_id: x, nonsense: 1}`,
	} {
		if _, err := ingest.Parse([]byte("peer_map:\n  " + entry + "\n" + minimalConfig)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestCompactionConfig: the four keys that were rejected as unimplemented until
// compaction existed.
func TestCompactionConfig(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg, err := ingest.Parse([]byte(minimalConfig))
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.Vault.CompactEnabled() {
			t.Error("compaction is off by default; disk usage would grow without bound")
		}
		if !cfg.Vault.HashIndexEnabled() {
			t.Error("the hash index is off by default")
		}
		if cfg.Vault.CompactBlockBytes != 256<<10 || cfg.Vault.ZstdLevel != 3 {
			t.Errorf("defaults are %s / level %d", cfg.Vault.CompactBlockBytes, cfg.Vault.ZstdLevel)
		}
	})

	t.Run("explicit values", func(t *testing.T) {
		cfg, err := ingest.Parse([]byte(`
vault:
  compact: false
  compact_block_bytes: 1MiB
  zstd_level: 9
  hash_index: false
` + minimalConfig))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Vault.CompactEnabled() || cfg.Vault.HashIndexEnabled() {
			t.Error("an explicit false was ignored: a pointer must distinguish false from absent")
		}
		if cfg.Vault.CompactBlockBytes != 1<<20 || cfg.Vault.ZstdLevel != 9 {
			t.Errorf("parsed %s / level %d", cfg.Vault.CompactBlockBytes, cfg.Vault.ZstdLevel)
		}
	})

	for name, bad := range map[string]string{
		"block too small": "compact_block_bytes: 512",
		"block too large": "compact_block_bytes: 64MiB",
		"level too high":  "zstd_level: 99",
	} {
		if _, err := ingest.Parse([]byte("vault:\n  " + bad + "\n" + minimalConfig)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestConfigLimitsMatchVault: the config package cannot import the vault, so it
// mirrors two limits. This keeps them honest.
func TestConfigLimitsMatchVault(t *testing.T) {
	if _, err := ingest.Parse([]byte("vault:\n  compact_block_bytes: 16MiB\n" + minimalConfig)); err != nil {
		t.Errorf("the vault's own maximum block size is rejected by the config: %v", err)
	}
	if _, err := ingest.Parse([]byte("vault:\n  compact_block_bytes: 17MiB\n" + minimalConfig)); err == nil {
		t.Error("a block size above the vault's maximum was accepted by the config")
	}
	if vault.MaxCompactBlockBytes != 16<<20 {
		t.Errorf("vault.MaxCompactBlockBytes is %d; the config package hard-codes 16MiB", vault.MaxCompactBlockBytes)
	}
}
