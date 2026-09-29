package conformance_test

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blakc-coffee/log-preprocessor/contracts/conformance"
)

// pyEngine drives the sidecar's Python reference evaluator (intel/ulpf_intel/dsl_cli.py) as an Engine.
// It is not the data-plane engine; it is an independent implementation that proves the harness and the
// cases agree with each other, so that the first failure Parsing sees is a real one.
type pyEngine struct {
	in  io.WriteCloser
	out *bufio.Reader
}

func startPython(t *testing.T) *pyEngine {
	root := "../.."
	py, _ := filepath.Abs(filepath.Join(root, "intel", ".venv", "bin", "python"))
	if _, err := os.Stat(py); err != nil {
		t.Skip("intel/.venv not set up (see intel/README.md): the Python reference engine is unavailable")
	}
	cmd := exec.Command(py, "-m", "ulpf_intel.dsl_cli")
	cmd.Dir = filepath.Join(root, "intel")
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close(); cmd.Wait() })
	return &pyEngine{in: in, out: bufio.NewReaderSize(out, 1<<20)}
}

func (e *pyEngine) call(req map[string]any) (map[string]any, error) {
	b, _ := json.Marshal(req)
	if _, err := e.in.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	line, err := e.out.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var resp map[string]any
	return resp, json.Unmarshal(line, &resp)
}

type pyParser struct {
	e    *pyEngine
	yaml string
}

func (e *pyEngine) Load(y []byte) (conformance.Parser, error) {
	resp, err := e.call(map[string]any{"yaml": string(y), "raw": ""})
	if err != nil {
		return nil, err
	}
	if msg, ok := resp["load_error"].(string); ok {
		return nil, errors.New(msg)
	}
	return &pyParser{e, string(y)}, nil
}

func (p *pyParser) Parse(raw []byte, at time.Time) (*conformance.Result, error) {
	resp, err := p.e.call(map[string]any{"yaml": p.yaml, "raw": string(raw), "received_at": at.UTC().Format(time.RFC3339)})
	if err != nil {
		return nil, err
	}
	if m, _ := resp["matched"].(bool); !m {
		return nil, nil
	}
	r := &conformance.Result{ExtractorID: resp["extractor"].(string)}
	r.OCSF, _ = resp["ocsf"].(map[string]any)
	r.Unmapped, _ = resp["unmapped"].(map[string]any)
	for _, f := range resp["flags"].([]any) {
		r.Flags = append(r.Flags, f.(string))
	}
	return r, nil
}

// The harness against a real, independent engine: every case the Python evaluator models, every DSL example
// vector, and the whole fixture corpus with the manifest as ground truth.
func TestHarnessAgainstThePythonReferenceEngine(t *testing.T) {
	conformance.Run(t, startPython(t), conformance.Options{
		Skip: func(name string, pythonModelled bool) bool { return !pythonModelled },
	})
}

// A harness that cannot fail proves nothing. Each engine below is wrong in exactly one way, and the
// run must fail in the place that way should be caught.
type broken struct {
	*pyEngine
	mutate func(y string) string
	after  func(*conformance.Result)
}

func (b broken) Load(y []byte) (conformance.Parser, error) {
	if b.mutate != nil {
		y = []byte(b.mutate(string(y)))
	}
	p, err := b.pyEngine.Load(y)
	if err != nil || b.after == nil {
		return p, err
	}
	return wrapped{p, b.after}, nil
}

type wrapped struct {
	conformance.Parser
	after func(*conformance.Result)
}

func (w wrapped) Parse(raw []byte, at time.Time) (*conformance.Result, error) {
	r, err := w.Parser.Parse(raw, at)
	if r != nil {
		w.after(r)
	}
	return r, err
}

func TestHarnessRejectsBrokenEngines(t *testing.T) {
	py := startPython(t)
	cases, _ := conformance.Cases()
	find := func(sub string) conformance.Case {
		for _, c := range cases {
			if strings.Contains(c.Name, sub) {
				return c
			}
		}
		t.Fatalf("no case %q", sub)
		return conformance.Case{}
	}
	run := func(e conformance.Engine, c conformance.Case) (failed bool) {
		defer func() { recover() }()
		p, err := e.Load([]byte(c.Parser))
		if c.LoadError != "" {
			return err == nil || !strings.Contains(err.Error(), c.LoadError)
		}
		if err != nil {
			return true
		}
		r, _ := p.Parse([]byte(c.Raw), time.Date(2026, 9, 28, 4, 0, 0, 0, time.UTC))
		if r != nil {
			return conformance.CheckForTest(c.Expect, r, len(c.Raw)) != ""
		}
		return c.Expect.Matched
	}

	if run(py, find("enum matching is exact")) {
		t.Fatal("the honest engine failed a case: test bug")
	}
	// a case-insensitive enum
	lenient := broken{pyEngine: py, after: func(r *conformance.Result) {
		if _, ok := r.OCSF["connection_info"]; ok {
			r.OCSF["connection_info"] = map[string]any{"protocol_num": 6.0}
		}
	}}
	if !run(lenient, find("enum is case-sensitive")) {
		t.Error("the harness accepted an engine with a case-insensitive enum")
	}
	// an engine that puts an empty value in unmapped
	empties := broken{pyEngine: py, after: func(r *conformance.Result) { r.Unmapped["user"] = "" }}
	if !run(empties, find("an empty value is absent")) {
		t.Error("the harness accepted an engine that keeps empty values")
	}
	// an engine that accepts what the spec says to reject
	if !run(broken{pyEngine: py, mutate: func(y string) string { return strings.ReplaceAll(y, "(?=a)", "") }}, find("lookaround")) {
		t.Error("the harness accepted an engine that loads a lookaround pattern")
	}
	// an engine that lets a quoted value inject a key
	inject := broken{pyEngine: py, after: func(r *conformance.Result) { r.Unmapped["dstip"] = "8.8.8.8" }}
	if !run(inject, find("never re-scanned")) {
		t.Error("the harness accepted an engine that injects keys from values")
	}
}

// Matching is the first thing checked: an engine that quarantines everything, or accepts everything, must fail.
func TestMatchedIsEnforcedBothWays(t *testing.T) {
	if conformance.CheckForTest(conformance.Expect{Matched: true}, nil, 0) == "" {
		t.Error("an engine that matches nothing passed a case that must match")
	}
	if conformance.CheckForTest(conformance.Expect{Matched: false}, &conformance.Result{}, 0) == "" {
		t.Error("an engine that matches everything passed a case that must be quarantined")
	}
}
