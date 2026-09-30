package parsers_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	builtin "github.com/dark-14100/sluice/parsers"

	"github.com/dark-14100/sluice/contracts/conformance"
	"github.com/dark-14100/sluice/pkg/dataplane/parsers"
)

type rec struct {
	ID      string  `json:"record_id"`
	File    string  `json:"source_file"`
	Start   int     `json:"byte_start"`
	End     int     `json:"byte_end"`
	Expect  string  `json:"expect"`
	SrcIP   *string `json:"expected_src_ip"`
	DstIP   *string `json:"expected_dst_ip"`
	SrcPort *int    `json:"expected_src_port"`
	DstPort *int    `json:"expected_dst_port"`
	Proto   *string `json:"expected_proto"`
	Time    *string `json:"expected_time"`
	User    *string `json:"expected_user"`
}

// TestBuiltinsAgainstManifest routes every record of the frozen fixture corpus
// through the built-in parsers the way the data plane does (first parser that
// matches wins) and holds the result to the manifest: a record marked
// "parse" must produce an event that agrees with every non-null expected_*,
// and a record marked anything else must not produce one.
func TestBuiltinsAgainstManifest(t *testing.T) {
	engine := parsers.New()
	var loaded []*parsers.Parser
	names, _ := builtin.FS.ReadDir(".")
	sort.Slice(names, func(i, j int) bool { return names[i].Name() < names[j].Name() })
	for _, n := range names {
		src, err := builtin.FS.ReadFile(n.Name())
		if err != nil {
			t.Fatal(err)
		}
		p, err := engine.Load(src)
		if err != nil {
			t.Fatalf("%s: %v", n.Name(), err)
		}
		loaded = append(loaded, p)
	}
	for _, dir := range []string{"../../../testdata/sample", "../../../testdata"} {
		var man struct{ Records []rec }
		b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &man); err != nil {
			t.Fatal(err)
		}
		files := map[string][]byte{}
		bad := map[string][]string{}
		total := map[string]int{}
		for _, r := range man.Records {
			data, ok := files[r.File]
			if !ok {
				data, _ = os.ReadFile(filepath.Join(dir, r.File))
				files[r.File] = data
			}
			raw := data[r.Start:r.End]
			total[r.File]++
			var res *parsers.Result
			var perr error
			at := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
			for _, p := range loaded {
				res, perr = p.Parse(raw, at)
				if res != nil || perr != nil {
					break
				}
			}
			switch {
			case r.Expect != "parse":
				if res != nil && perr == nil {
					bad[r.File] = append(bad[r.File], r.ID+": parsed, manifest says "+r.Expect)
				}
			case perr != nil:
				bad[r.File] = append(bad[r.File], r.ID+": "+perr.Error())
			case res == nil:
				bad[r.File] = append(bad[r.File], r.ID+": no parser matched")
			default:
				if d := disagree(r, res); d != "" {
					bad[r.File] = append(bad[r.File], r.ID+": "+d)
				}
			}
		}
		for f, list := range bad {
			t.Errorf("%s/%s: %d of %d records wrong, e.g. %s", filepath.Base(dir), f, len(list), total[f], strings.Join(list[:min(3, len(list))], " | "))
		}
	}
}

func disagree(r rec, res *parsers.Result) string {
	o := conformance.Flatten(res.OCSF)
	var bad []string
	chk := func(path string, want any) {
		if !conformance.Equal(o[path], want) {
			bad = append(bad, fmt.Sprintf("%s = %v, want %v", path, o[path], want))
		}
	}
	if r.SrcIP != nil {
		chk("src_endpoint.ip", *r.SrcIP)
	}
	if r.DstIP != nil {
		chk("dst_endpoint.ip", *r.DstIP)
	}
	if r.SrcPort != nil {
		chk("src_endpoint.port", *r.SrcPort)
	}
	if r.DstPort != nil {
		chk("dst_endpoint.port", *r.DstPort)
	}
	if r.Proto != nil {
		chk("connection_info.protocol_name", *r.Proto)
	}
	if r.Time != nil {
		if t, err := time.Parse(time.RFC3339, *r.Time); err == nil {
			if got, ok := toInt(o["time"]); !ok || got/1000 != t.Unix() {
				bad = append(bad, fmt.Sprintf("time = %v, want %d s", o["time"], t.Unix()))
			}
		}
	}
	return strings.Join(bad, "; ")
}

func toInt(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case float64:
		return int64(n), true
	}
	return 0, false
}
