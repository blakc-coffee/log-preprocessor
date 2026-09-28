// Package gen builds the ULPF synthetic fixture corpus.
//
// Everything it produces is synthetic. The log lines are faithful
// approximations of vendor formats, not real captures, and the corpus is
// labelled as such in testdata/README.md and in the manifest.
//
// Determinism is a hard requirement: the same seed must produce byte-identical
// output on any machine. That rules out time.Now, map iteration order,
// goroutines, and the running toolchain version. Every byte offset and hash in
// the manifest is computed while writing, never hand-typed.
package gen

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Version is the fixture generator version, recorded in the manifest.
const Version = "1.0.0"

// GoVersion is the language version declared in go.mod. It is deliberately a
// constant rather than runtime.Version(): the generator must produce identical
// bytes regardless of which toolchain patch release runs it.
const GoVersion = "go1.22"

// IST is the fixed +05:30 zone every fixture is written in. Formats that carry
// no zone of their own (ASA, DHCP, RADIUS) declare it via the manifest's
// generator.base_time instead. Clock-skew inference is out of scope.
var IST = time.FixedZone("IST", 5*3600+30*60)

// BaseTime is the fixed instant the corpus starts at.
var BaseTime = time.Date(2026, 9, 28, 9, 0, 0, 0, IST)

// Terminator names as they appear in the manifest.
const (
	TermLF   = "LF"
	TermCRLF = "CRLF"
	TermNone = "NONE"
)

// Expect holds the ground truth a parser is expected to produce for one
// record. Zero values mean "no expectation" and marshal to JSON null.
type Expect struct {
	// Expect is "parse", "raw_only" or "unknown_format".
	Expect  string
	Vendor  string
	SrcIP   string
	DstIP   string
	SrcPort int
	DstPort int
	Proto   string
	Action  string
	User    string
	Time    time.Time
	// Fragments is the expected fragment count at max_frame_bytes=1MiB. Zero
	// means the record fits in one frame and the key is omitted.
	Fragments int
}

// Record is one manifest entry. byte_end is exclusive and excludes the
// terminator; expected_sha256 covers bytes[byte_start:byte_end] only.
type Record struct {
	RecordID       string  `json:"record_id"`
	SourceFile     string  `json:"source_file"`
	ByteStart      int     `json:"byte_start"`
	ByteEnd        int     `json:"byte_end"`
	Terminator     string  `json:"terminator"`
	ExpectedSHA256 string  `json:"expected_sha256"`
	Expect         string  `json:"expect"`
	Vendor         string  `json:"vendor"`
	ExpectedSrcIP  *string `json:"expected_src_ip"`
	ExpectedDstIP  *string `json:"expected_dst_ip"`
	ExpectedSrcPrt *int    `json:"expected_src_port"`
	ExpectedDstPrt *int    `json:"expected_dst_port"`
	ExpectedProto  *string `json:"expected_proto"`
	ExpectedAction *string `json:"expected_action"`
	ExpectedTime   *string `json:"expected_time"`
	ExpectedUser   *string `json:"expected_user"`
	ExpectedFrags  *int    `json:"expected_fragments,omitempty"`
}

// FileInfo is the per-file summary in the manifest.
type FileInfo struct {
	Bytes      int    `json:"bytes"`
	SHA256     string `json:"sha256"`
	Records    int    `json:"records"`
	Terminator string `json:"terminator"`
}

// Generator records how the corpus was produced.
type Generator struct {
	Version   string `json:"version"`
	Seed      uint64 `json:"seed"`
	Go        string `json:"go"`
	BaseTime  string `json:"base_time"`
	Synthetic bool   `json:"synthetic"`
}

// Manifest is schema v1, frozen at sample delivery.
type Manifest struct {
	Generator Generator           `json:"generator"`
	Files     map[string]FileInfo `json:"files"`
	Records   []Record            `json:"records"`
}

// Writer accumulates one fixture file and its manifest records, tracking byte
// offsets and hashes as it goes.
type Writer struct {
	name     string
	idPrefix string
	defTerm  string
	buf      bytes.Buffer
	recs     []Record
}

// Emit appends one record and its terminator, and records the manifest entry.
// term overrides the file's default terminator; pass "" to use the default.
// line is stored byte-for-byte: it is never trimmed, re-encoded or validated.
func (w *Writer) Emit(line []byte, term string, e Expect) {
	if term == "" {
		term = w.defTerm
	}
	start := w.buf.Len()
	w.buf.Write(line)
	end := w.buf.Len()
	switch term {
	case TermLF:
		w.buf.WriteByte('\n')
	case TermCRLF:
		w.buf.WriteString("\r\n")
	case TermNone:
	default:
		panic("gen: unknown terminator " + term)
	}

	sum := sha256.Sum256(line)
	r := Record{
		RecordID:       fmt.Sprintf("%s-%04d", w.idPrefix, len(w.recs)+1),
		SourceFile:     w.name,
		ByteStart:      start,
		ByteEnd:        end,
		Terminator:     term,
		ExpectedSHA256: hex.EncodeToString(sum[:]),
		Expect:         e.Expect,
		Vendor:         e.Vendor,
	}
	if e.SrcIP != "" {
		r.ExpectedSrcIP = &e.SrcIP
	}
	if e.DstIP != "" {
		r.ExpectedDstIP = &e.DstIP
	}
	if e.SrcPort != 0 {
		r.ExpectedSrcPrt = &e.SrcPort
	}
	if e.DstPort != 0 {
		r.ExpectedDstPrt = &e.DstPort
	}
	if e.Proto != "" {
		r.ExpectedProto = &e.Proto
	}
	if e.Action != "" {
		r.ExpectedAction = &e.Action
	}
	if e.User != "" {
		r.ExpectedUser = &e.User
	}
	if !e.Time.IsZero() {
		s := e.Time.Format(time.RFC3339)
		r.ExpectedTime = &s
	}
	if e.Fragments != 0 {
		r.ExpectedFrags = &e.Fragments
	}
	w.recs = append(w.recs, r)
}

// EmitString is Emit for records that are valid text.
func (w *Writer) EmitString(line string, term string, e Expect) {
	w.Emit([]byte(line), term, e)
}

// Source is one fixture file in the corpus.
type Source struct {
	// Name is the output file name, e.g. "cisco_asa.log".
	Name string
	// IDPrefix prefixes the manifest record_id, e.g. "asa" gives "asa-0001".
	// It is a manifest identifier only, unrelated to the vault's RecordID.
	IDPrefix string
	// Term is the file's default terminator.
	Term string
	// Full and Sample are the record counts for each profile.
	Full, Sample int
	// Emit writes n records. rng is seeded from (seed, hash(Name)) so adding a
	// source never shifts the output of the others.
	Emit func(w *Writer, rng *rand.Rand, n int)
}

// Sources is the corpus, in manifest order. Order is fixed, never map-derived.
func Sources() []*Source {
	return []*Source{
		asaSource(),
		fortinetSource(),
		suricataSource(),
	}
}

// rngFor seeds a PCG generator from the corpus seed and the stream name, so
// each source draws from an independent, stable stream.
func rngFor(seed uint64, stream string) *rand.Rand {
	h := fnv.New64a()
	_, _ = h.Write([]byte(stream))
	return rand.New(rand.NewPCG(seed, h.Sum64()))
}

// Options configures a corpus run.
type Options struct {
	Seed uint64
	Out  string
	// Sample selects the ~50-records-per-source profile.
	Sample bool
	// Only, when non-empty, restricts the run to these file names.
	Only []string
}

// Run writes the corpus and its manifest to opts.Out.
func Run(opts Options) error {
	if err := os.MkdirAll(opts.Out, 0o755); err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, n := range opts.Only {
		keep[n] = true
	}

	m := Manifest{
		Generator: Generator{
			Version:   Version,
			Seed:      opts.Seed,
			Go:        GoVersion,
			BaseTime:  BaseTime.Format(time.RFC3339),
			Synthetic: true,
		},
		Files:   map[string]FileInfo{},
		Records: []Record{},
	}

	for _, s := range Sources() {
		if len(keep) > 0 && !keep[s.Name] {
			continue
		}
		n := s.Full
		if opts.Sample {
			n = s.Sample
		}
		w := &Writer{name: s.Name, idPrefix: s.IDPrefix, defTerm: s.Term}
		s.Emit(w, rngFor(opts.Seed, s.Name), n)

		body := w.buf.Bytes()
		if err := os.WriteFile(filepath.Join(opts.Out, s.Name), body, 0o644); err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		m.Files[s.Name] = FileInfo{
			Bytes:      len(body),
			SHA256:     hex.EncodeToString(sum[:]),
			Records:    len(w.recs),
			Terminator: s.Term,
		}
		m.Records = append(m.Records, w.recs...)
	}

	if err := writeJSON(filepath.Join(opts.Out, "manifest.json"), m); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(opts.Out, "README.md"), []byte(readme(opts)), 0o644)
}

// writeJSON marshals v indented, with HTML escaping off so log payloads stay
// readable, and a trailing newline so the file is diff-friendly.
func writeJSON(path string, v any) error {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	return os.WriteFile(path, b.Bytes(), 0o644)
}

func readme(opts Options) string {
	names := make([]string, 0, len(Sources()))
	for _, s := range Sources() {
		names = append(names, s.Name)
	}
	sort.Strings(names)
	profile := "full"
	if opts.Sample {
		profile = "sample"
	}
	b := &bytes.Buffer{}
	fmt.Fprintf(b, "# ULPF fixture corpus (SYNTHETIC)\n\n")
	fmt.Fprintf(b, "**Every file in this directory is synthetic.** Nothing here is a real capture\n")
	fmt.Fprintf(b, "from a real device or a real network. The log lines are faithful approximations\n")
	fmt.Fprintf(b, "of the vendors' documented formats, written so parsers can be developed and\n")
	fmt.Fprintf(b, "tested offline. All addresses come from the ranges reserved for documentation\n")
	fmt.Fprintf(b, "(RFC 5737) and private use (RFC 1918). All user names are invented.\n\n")
	fmt.Fprintf(b, "Regenerate with:\n\n    make fixtures        # full profile\n    make fixtures-sample # ~50 records per source\n\n")
	fmt.Fprintf(b, "`make fixtures-check` proves the generator is deterministic.\n\n")
	fmt.Fprintf(b, "| Field | Value |\n|---|---|\n")
	fmt.Fprintf(b, "| generator version | %s |\n| seed | %d |\n| profile | %s |\n| base time | %s |\n",
		Version, opts.Seed, profile, BaseTime.Format(time.RFC3339))
	fmt.Fprintf(b, "\nEvery timestamp is IST (+05:30). Formats that carry no zone of their own\n")
	fmt.Fprintf(b, "(ASA, DHCP, RADIUS) declare it through `manifest.json` -> `generator.base_time`.\n\n")
	fmt.Fprintf(b, "## Files\n\n")
	for _, n := range names {
		fmt.Fprintf(b, "- `%s`\n", n)
	}
	fmt.Fprintf(b, "- `manifest.json` — ground truth: byte ranges, SHA-256s and expected parse results.\n")
	return b.String()
}
