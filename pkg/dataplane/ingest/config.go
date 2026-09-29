package ingest

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Configuration file handling.
//
// Three rules, all of them about failing loudly rather than surprisingly:
//
//   - Unknown keys are an error. A typo in `segment_max_records` that silently
//     left the default in place would be discovered as a performance mystery
//     weeks later, not as a startup failure.
//   - No environment interpolation. A config file says what it says; working
//     out what a daemon actually loaded should not require reconstructing the
//     environment it started in.
//   - Everything is validated before anything is opened, so a bad config
//     cannot half-start a daemon.

// Size is a byte count that accepts "64MiB", "8 KiB", "1GiB" or a plain
// number of bytes.
type Size int64

var sizePattern = regexp.MustCompile(`^\s*([0-9]+(?:\.[0-9]+)?)\s*([KMGT]i?B|B)?\s*$`)

var sizeUnits = map[string]int64{
	"":    1,
	"B":   1,
	"KB":  1000,
	"MB":  1000 * 1000,
	"GB":  1000 * 1000 * 1000,
	"TB":  1000 * 1000 * 1000 * 1000,
	"KiB": 1 << 10,
	"MiB": 1 << 20,
	"GiB": 1 << 30,
	"TiB": 1 << 40,
}

// UnmarshalYAML parses a size.
func (s *Size) UnmarshalYAML(n *yaml.Node) error {
	var raw string
	if err := n.Decode(&raw); err != nil {
		var num int64
		if err2 := n.Decode(&num); err2 != nil {
			return fmt.Errorf("line %d: %q is not a size", n.Line, n.Value)
		}
		*s = Size(num)
		return nil
	}

	m := sizePattern.FindStringSubmatch(raw)
	if m == nil {
		return fmt.Errorf("line %d: %q is not a size; use bytes or a unit like 64MiB", n.Line, raw)
	}
	value, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return fmt.Errorf("line %d: %q is not a size", n.Line, raw)
	}
	unit, ok := sizeUnits[m[2]]
	if !ok {
		return fmt.Errorf("line %d: unknown size unit %q", n.Line, m[2])
	}
	*s = Size(int64(value * float64(unit)))
	return nil
}

// String renders a size the way it would be written.
func (s Size) String() string {
	for _, u := range []struct {
		name string
		n    int64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}} {
		if int64(s) >= u.n && int64(s)%u.n == 0 {
			return fmt.Sprintf("%d%s", int64(s)/u.n, u.name)
		}
	}
	return strconv.FormatInt(int64(s), 10)
}

// Duration is a time.Duration in Go syntax ("100ms", "30s", "5m").
type Duration time.Duration

// UnmarshalYAML parses a duration.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var raw string
	if err := n.Decode(&raw); err != nil {
		return fmt.Errorf("line %d: %q is not a duration", n.Line, n.Value)
	}
	v, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("line %d: %q is not a duration; use Go syntax like 100ms or 30s", n.Line, raw)
	}
	*d = Duration(v)
	return nil
}

// Std returns the standard library duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// FileConfig is the whole ingestd configuration file.
//
// Only settings that are actually implemented appear here. A key for an
// unimplemented feature would be accepted and ignored, which is the worst of
// both worlds: the operator believes it took effect. Compaction, the peer map
// and the metrics registry arrive with their implementations.
type FileConfig struct {
	DataDir         string   `yaml:"data_dir"`
	LogLevel        string   `yaml:"log_level"`
	MetricsAddr     string   `yaml:"metrics_addr"`
	Emit            string   `yaml:"emit"`
	OutBuffer       int      `yaml:"out_buffer"`
	ShutdownTimeout Duration `yaml:"shutdown_timeout"`

	Vault   VaultConfig    `yaml:"vault"`
	Limits  LimitsConfig   `yaml:"limits"`
	PeerMap []PeerMapEntry `yaml:"peer_map"`
	Sources []SourceEntry  `yaml:"sources"`
}

// PeerMapEntry maps a sender's network to a source_id. Longest prefix wins,
// and a peer matching nothing keeps the listener's own id.
type PeerMapEntry struct {
	CIDR     string `yaml:"cidr"`
	SourceID string `yaml:"source_id"`
}

// VaultConfig mirrors the vault's options.
type VaultConfig struct {
	Dir                 string   `yaml:"dir"`
	Sync                string   `yaml:"sync"`
	SyncInterval        Duration `yaml:"sync_interval"`
	GroupCommitMaxDelay Duration `yaml:"group_commit_max_delay"`
	GroupCommitMaxBytes Size     `yaml:"group_commit_max_bytes"`
	SegmentMaxBytes     Size     `yaml:"segment_max_bytes"`
	SegmentMaxRecords   int      `yaml:"segment_max_records"`
	SealInterval        Duration `yaml:"seal_interval"`

	// Compact rewrites sealed segments from WAL to zstd in the background.
	// A pointer so an absent key means the default (on) rather than false.
	Compact           *bool `yaml:"compact"`
	CompactBlockBytes Size  `yaml:"compact_block_bytes"`
	ZstdLevel         int   `yaml:"zstd_level"`
	// HashIndex enables GetByHash. It costs memory proportional to the record
	// count for segments still stored as WALs, and 40 bytes per record on disk
	// for compacted ones. Absent means on.
	HashIndex *bool `yaml:"hash_index"`
}

// Limits mirrored from the vault package, which this package deliberately does
// not import. TestConfigLimitsMatchVault keeps them from drifting.
const (
	maxCompactBlockBytes = 16 << 20
	minCompactBlockBytes = 4 << 10
	maxZstdLevel         = 22
)

// CompactEnabled reports whether background compaction is on.
func (v VaultConfig) CompactEnabled() bool { return v.Compact == nil || *v.Compact }

// HashIndexEnabled reports whether GetByHash is on.
func (v VaultConfig) HashIndexEnabled() bool { return v.HashIndex == nil || *v.HashIndex }

// LimitsConfig bounds what a sender can make this process do.
type LimitsConfig struct {
	MaxFrameBytes Size     `yaml:"max_frame_bytes"`
	MaxOctetLen   Size     `yaml:"max_octet_len"`
	MaxConns      int      `yaml:"max_conns"`
	IdleTimeout   Duration `yaml:"idle_timeout"`
	HTTPMaxBody   Size     `yaml:"http_max_body"`
}

// SourceEntry is one entry in the sources list. The fields that apply depend
// on Type, and Validate rejects any that do not.
type SourceEntry struct {
	ID   string `yaml:"id"`
	Type string `yaml:"type"`

	// Network sources.
	Listen     string `yaml:"listen"`
	Framing    string `yaml:"framing"`
	Readers    int    `yaml:"readers"`
	RecvBuffer Size   `yaml:"recv_buffer"`

	// TLS.
	Cert     string `yaml:"cert"`
	Key      string `yaml:"key"`
	ClientCA string `yaml:"client_ca"`

	// HTTP.
	DynamicSources bool     `yaml:"dynamic_sources"`
	AllowedSources []string `yaml:"allowed_sources"`

	// File.
	Paths           []string         `yaml:"paths"`
	Mode            string           `yaml:"mode"`
	From            string           `yaml:"from"`
	CheckpointDir   string           `yaml:"checkpoint_dir"`
	CheckpointEvery int              `yaml:"checkpoint_every"`
	Poll            Duration         `yaml:"poll"`
	Multiline       *MultilineConfig `yaml:"multiline"`
}

// MultilineConfig groups lines into one record.
type MultilineConfig struct {
	Start    string   `yaml:"start"`
	MaxLines int      `yaml:"max_lines"`
	Timeout  Duration `yaml:"timeout"`
}

// LoadFile reads and validates a configuration file.
func LoadFile(path string) (*FileConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Parse decodes and validates a configuration.
func Parse(raw []byte) (*FileConfig, error) {
	cfg := &FileConfig{}

	dec := yaml.NewDecoder(bytes.NewReader(raw))
	// The whole point: a misspelled key is a startup error, not a silent
	// default.
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	cfg.setDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *FileConfig) setDefaults() {
	if c.DataDir == "" {
		c.DataDir = "./data"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.Emit == "" {
		c.Emit = "none"
	}
	if c.OutBuffer <= 0 {
		c.OutBuffer = DefaultOutBuffer
	}
	if c.ShutdownTimeout <= 0 {
		c.ShutdownTimeout = Duration(15 * time.Second)
	}
	if c.Vault.Dir == "" {
		c.Vault.Dir = c.DataDir + "/vault"
	}
	if c.Vault.Sync == "" {
		c.Vault.Sync = "always"
	}
	if c.Vault.CompactBlockBytes <= 0 {
		c.Vault.CompactBlockBytes = 256 << 10
	}
	if c.Vault.ZstdLevel <= 0 {
		c.Vault.ZstdLevel = 3
	}
	if c.Limits.MaxFrameBytes <= 0 {
		c.Limits.MaxFrameBytes = 1 << 20
	}
	if c.Limits.MaxOctetLen <= 0 {
		c.Limits.MaxOctetLen = 16 << 20
	}
	if c.Limits.HTTPMaxBody <= 0 {
		c.Limits.HTTPMaxBody = 1 << 30
	}
}

// Validate checks everything before anything is opened.
func (c *FileConfig) Validate() error {
	var errs []error

	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("log_level %q: want debug, info, warn or error", c.LogLevel))
	}
	switch c.Vault.Sync {
	case "always", "interval", "none":
	default:
		errs = append(errs, fmt.Errorf("vault.sync %q: want always, interval or none", c.Vault.Sync))
	}
	if c.Vault.Sync == "none" {
		// Not an error - benchmarks need it - but it must never be chosen by
		// accident, because acknowledgements stop meaning anything.
		errs = append(errs, errors.New(
			"vault.sync is \"none\": acknowledged records are NOT durable. "+
				"If this is a benchmark, set ULPF_ALLOW_SYNC_NONE=1"))
		if os.Getenv("ULPF_ALLOW_SYNC_NONE") == "1" {
			errs = errs[:len(errs)-1]
		}
	}
	if b := int64(c.Vault.CompactBlockBytes); b < minCompactBlockBytes || b > maxCompactBlockBytes {
		errs = append(errs, fmt.Errorf(
			"vault.compact_block_bytes %s: want between 4KiB and 16MiB. Smaller blocks give zstd "+
				"too little to work with; larger ones make every random read decompress more",
			c.Vault.CompactBlockBytes))
	}
	if c.Vault.ZstdLevel < 1 || c.Vault.ZstdLevel > maxZstdLevel {
		errs = append(errs, fmt.Errorf("vault.zstd_level %d: want 1-%d", c.Vault.ZstdLevel, maxZstdLevel))
	}
	if err := validateEmit(c.Emit); err != nil {
		errs = append(errs, err)
	}

	for i, e := range c.PeerMap {
		if e.CIDR == "" || e.SourceID == "" {
			errs = append(errs, fmt.Errorf("peer_map[%d]: cidr and source_id are both required", i))
			continue
		}
		if _, err := netip.ParsePrefix(e.CIDR); err != nil {
			errs = append(errs, fmt.Errorf("peer_map[%d]: %q is not a CIDR", i, e.CIDR))
		}
	}

	if len(c.Sources) == 0 {
		errs = append(errs, errors.New("no sources configured"))
	}
	seen := map[string]bool{}
	for i, s := range c.Sources {
		if s.ID == "" {
			errs = append(errs, fmt.Errorf("sources[%d]: id is required", i))
		} else if seen[s.ID] {
			errs = append(errs, fmt.Errorf("sources[%d]: duplicate id %q", i, s.ID))
		}
		seen[s.ID] = true
		if err := s.validate(); err != nil {
			errs = append(errs, fmt.Errorf("sources[%d] (%s): %w", i, s.ID, err))
		}
	}
	return errors.Join(errs...)
}

func validateEmit(emit string) error {
	switch {
	case emit == "none", emit == "stdout":
		return nil
	case strings.HasPrefix(emit, "jsonl:"):
		if strings.TrimPrefix(emit, "jsonl:") == "" {
			return errors.New(`emit "jsonl:" needs a path`)
		}
		return nil
	}
	return fmt.Errorf("emit %q: want none, stdout or jsonl:<path>", emit)
}

// validate checks one source entry, including that no field belonging to a
// different source type was set. Accepting `paths` on a UDP listener and
// ignoring it is how an operator ends up certain a file is being read when it
// is not.
func (s SourceEntry) validate() error {
	var errs []error

	network := func() {
		if s.Listen == "" {
			errs = append(errs, errors.New("listen is required"))
		}
		if len(s.Paths) > 0 {
			errs = append(errs, errors.New("paths does not apply to a network source"))
		}
		if s.Mode != "" {
			errs = append(errs, errors.New("mode does not apply to a network source"))
		}
	}
	noTLS := func() {
		if s.Cert != "" || s.Key != "" || s.ClientCA != "" {
			errs = append(errs, fmt.Errorf("cert, key and client_ca apply only to type tls, not %q", s.Type))
		}
	}

	switch s.Type {
	case "udp":
		network()
		noTLS()
		if s.Framing != "" {
			errs = append(errs, errors.New(
				"framing does not apply to udp: one datagram is one record"))
		}
	case "tcp":
		network()
		noTLS()
		errs = append(errs, validateFraming(s.Framing))
	case "tls":
		network()
		if s.Cert == "" || s.Key == "" {
			errs = append(errs, errors.New("cert and key are required for type tls"))
		}
		errs = append(errs, validateFraming(s.Framing))
	case "http":
		network()
		noTLS()
		if s.Framing != "" {
			errs = append(errs, errors.New(
				"framing is chosen per request by ?framing=, not in the config"))
		}
	case "file":
		noTLS()
		if len(s.Paths) == 0 {
			errs = append(errs, errors.New("paths is required for type file"))
		}
		if s.Listen != "" {
			errs = append(errs, errors.New("listen does not apply to a file source"))
		}
		switch s.Mode {
		case "", "once", "tail":
		default:
			errs = append(errs, fmt.Errorf("mode %q: want once or tail", s.Mode))
		}
		switch s.From {
		case "", "beginning", "end":
		default:
			errs = append(errs, fmt.Errorf("from %q: want beginning or end", s.From))
		}
		if s.Mode != "tail" {
			// These only mean something for a tail. Accepting them on a
			// one-shot read and ignoring them would suggest a restart
			// resumes, when it re-reads the file every time.
			if s.CheckpointDir != "" || s.CheckpointEvery != 0 || s.Poll != 0 {
				errs = append(errs, errors.New(
					"checkpoint_dir, checkpoint_every and poll apply only to mode: tail"))
			}
		}
		errs = append(errs, validateFraming(s.Framing))
		if s.Multiline != nil {
			if s.Multiline.Start == "" {
				errs = append(errs, errors.New("multiline.start is required"))
			} else if _, err := regexp.Compile(s.Multiline.Start); err != nil {
				errs = append(errs, fmt.Errorf("multiline.start: %w", err))
			}
		}
	case "":
		errs = append(errs, errors.New("type is required"))
	default:
		errs = append(errs, fmt.Errorf("unknown type %q: want udp, tcp, tls, http or file", s.Type))
	}

	return errors.Join(errs...)
}

func validateFraming(f string) error {
	switch f {
	case "", "lf", "crlf", "lines", "nul", "octet", "auto":
		return nil
	}
	return fmt.Errorf("framing %q: want lf, crlf, lines, nul, octet or auto", f)
}
