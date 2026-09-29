package sniff_test

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/sniff"
	types "github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/testutil/types"
)

func TestDetect(t *testing.T) {
	cases := map[string]struct {
		in   string
		want types.FormatHint
	}{
		// Rule 1: syslog priority headers.
		"asa syslog": {
			"<166>Sep 28 2026 09:00:01 asa01 : %ASA-6-302013: Built inbound TCP connection",
			types.HintSyslog3164,
		},
		"rfc5424": {
			"<134>1 2026-09-28T09:00:01.000+05:30 host app 1234 ID47 - message",
			types.HintSyslog5424,
		},
		"pri with one digit":    {"<1>a message here", types.HintSyslog3164},
		"pri with three digits": {"<191>a message here", types.HintSyslog3164},

		// A syslog-framed CEF message is CEF: the transport is incidental,
		// the payload is what a parser has to read.
		"syslog-framed cef": {
			"<134>Sep 28 09:00:01 host CEF:0|Vendor|Product|1.0|100|Sign|5|src=10.1.4.7",
			types.HintCEF,
		},
		"syslog-framed leef": {
			"<134>Sep 28 09:00:01 host LEEF:2.0|Vendor|Product|1.0|100|src=10.1.4.7",
			types.HintLEEF,
		},

		// Rule 2: bare CEF and LEEF.
		"bare cef":  {"CEF:0|Vendor|Product|1.0|100|Sign|5|src=10.1.4.7 dst=1.2.3.4", types.HintCEF},
		"bare leef": {"LEEF:2.0|Vendor|Product|1.0|100|src=10.1.4.7", types.HintLEEF},

		// Rule 3: structured markup.
		"json object":      {`{"timestamp":"2026-09-28T09:00:00","event_type":"alert"}`, types.HintJSON},
		"json array":       {`[{"a":1},{"b":2}]`, types.HintJSON},
		"json with spaces": {`   {"a":1}`, types.HintJSON},
		"xml declaration":  {`<?xml version="1.0"?><event/>`, types.HintXML},
		"xml element":      {`<Event xmlns="http://example"><System/></Event>`, types.HintXML},

		// Rule 4: key=value.
		"fortinet kv": {
			`date=2026-09-28 time=09:00:02 devname="FG-01" srcip=10.1.4.25 action="deny"`,
			types.HintKV,
		},
		"drift kv": {
			`eventtime=1790566202000000000 tz=+0530 src=10.3.0.75 sport=41832 action=passed`,
			types.HintKV,
		},
		"radius kv": {
			`Acct-Status-Type=Start User-Name="alice" Framed-IP-Address=10.1.4.7`,
			types.HintKV,
		},

		// Rule 5: positional CSV.
		"palo alto csv": {
			",2026/09/28 09:00:02,001801010001,TRAFFIC,drop,2049,2026/09/28 09:00:02,10.1.4.60,203.0.113.25",
			types.HintCSV,
		},

		// Rule 6: everything else.
		"plain text": {"the quick brown fox jumped over the lazy dog", types.HintUnknown},
		"iso log":    {"2026-09-28T09:00:43.262+05:30 ERROR [vpn-gw] session setup failed", types.HintUnknown},
		"dhcp":       {"Sep 28 09:00:00 dhcp01 dhcpd[1123]: DHCPACK on 10.1.4.7 to aa:bb:cc:00:00:01", types.HintUnknown},
		"openvpn":    {"Sep 28 09:05:12 vpn01 openvpn[3301]: alice/203.0.113.44:51820 MULTI: Learn: 10.8.0.6", types.HintUnknown},
		"empty":      {"", types.HintUnknown},
		"one comma":  {"a,b", types.HintUnknown},
		"one equals": {"a=b", types.HintUnknown},
		"two equals": {"a=b c=d", types.HintUnknown},

		// Near misses that must not be mistaken for a priority header.
		"angle bracket no digits": {"<hello world this is not syslog>", types.HintXML},
		"unclosed pri":            {"<166 Sep 28 missing the close", types.HintUnknown},
		"four digit pri":          {"<1666>not a valid priority", types.HintUnknown},
		"empty pri":               {"<>nothing here", types.HintUnknown},

		// CSV needs no '=' anywhere, or it is kv-shaped data with commas.
		"csv with equals is not csv": {"a=1,b,c,d,e,f,g", types.HintUnknown},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := sniff.Detect([]byte(c.in)); got != c.want {
				t.Errorf("Detect(%.60q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestNeverPanics: the input is attacker-controlled, and a sniffer that
// panicked would take the whole daemon down over a malformed log line.
func TestNeverPanics(t *testing.T) {
	inputs := [][]byte{
		nil, {}, {'<'}, {'<', '1'}, {'<', '1', '6'}, {'<', '>'},
		{0xFF, 0xFE}, {0x00}, {'{'}, {'<', '?'}, {'='},
		bytes.Repeat([]byte{'<'}, 1000),
		bytes.Repeat([]byte{'='}, 1000),
		bytes.Repeat([]byte{','}, 1000),
		allBytes(),
	}
	for i, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("input %d panicked: %v", i, r)
				}
			}()
			sniff.Detect(in)
		}()
	}
}

func allBytes() []byte {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// TestOnlyTheWindowMatters: a megabyte-long line must cost the same as a short
// one, because this runs on every record.
func TestOnlyTheWindowMatters(t *testing.T) {
	head := `{"a":1}`
	long := head + strings.Repeat("x", 1<<20)
	if got := sniff.Detect([]byte(long)); got != types.HintJSON {
		t.Errorf("got %q for a long line, want json", got)
	}

	// Something that would change the answer, placed past the window.
	padded := strings.Repeat(" ", sniff.Window+10) + `{"a":1}`
	if got := sniff.Detect([]byte(padded)); got == types.HintJSON {
		t.Error("content past the window changed the answer")
	}
}

// TestDoesNotModifyItsInput. Working rule 4: any code that touches Raw needs a
// test proving it does not change it.
func TestDoesNotModifyItsInput(t *testing.T) {
	original := []byte(`<166>Sep 28 CEF:0|a|b|c|d|e|f|src=1.2.3.4,x,y,z`)
	cp := append([]byte(nil), original...)
	sniff.Detect(original)
	if !bytes.Equal(original, cp) {
		t.Error("Detect modified its input")
	}
}

// TestFuzzCorpusShapes runs the sniffer over every line of every fixture and
// asserts it returns a valid hint and never panics. The corpus is the closest
// thing to real input this project has.
func TestEveryFixtureLine(t *testing.T) {
	const testdata = "../../../../testdata"
	entries, err := os.ReadDir(testdata)
	if err != nil {
		t.Skipf("no corpus: %v", err)
	}

	valid := map[types.FormatHint]bool{
		types.HintUnknown: true, types.HintSyslog3164: true, types.HintSyslog5424: true,
		types.HintCEF: true, types.HintLEEF: true, types.HintJSON: true,
		types.HintXML: true, types.HintKV: true, types.HintCSV: true,
	}

	lines := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || name == "manifest.json" || name == "identity_truth.json" ||
			name == "merkle_vectors.json" || !strings.Contains(name, ".") {
			continue
		}
		f, err := os.Open(filepath.Join(testdata, name))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 1<<20), 4<<20)
		for sc.Scan() {
			h := sniff.Detect(sc.Bytes())
			if !valid[h] {
				t.Fatalf("%s: returned an unknown hint %q", name, h)
			}
			lines++
		}
		f.Close()
	}
	if lines == 0 {
		t.Fatal("no lines checked")
	}
	t.Logf("sniffed %d fixture lines", lines)
}

// TestFixtureExpectations is the table PRD 12.2 asks for: the expected hint
// per fixture file, checked against the first record of each.
//
// These are the formats the parser registry will actually meet, so a change in
// the sniffer that silently reclassified a whole vendor shows up here.
func TestFixtureExpectations(t *testing.T) {
	const testdata = "../../../../testdata"

	want := map[string]types.FormatHint{
		"cisco_asa.log":         types.HintSyslog3164,
		"identity_firewall.log": types.HintSyslog3164,
		"oversize.log":          types.HintSyslog3164,
		"fortinet.log":          types.HintKV,
		"fortinet_drift.log":    types.HintKV,
		"crlf.log":              types.HintKV,
		"radius.log":            types.HintKV,
		"suricata.json":         types.HintJSON,
		"palo_alto_unknown.log": types.HintCSV,
		// Nothing about these is machine-readable at a glance, which is the
		// honest answer rather than a wrong one.
		"multiline.log": types.HintUnknown,
		"dhcp.log":      types.HintUnknown,
		"openvpn.log":   types.HintUnknown,
	}

	for name, expect := range want {
		t.Run(name, func(t *testing.T) {
			f, err := os.Open(filepath.Join(testdata, name))
			if err != nil {
				t.Skipf("no corpus: %v", err)
			}
			defer f.Close()

			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 0, 1<<20), 4<<20)
			if !sc.Scan() {
				t.Fatal("empty file")
			}
			line := bytes.TrimSuffix(sc.Bytes(), []byte("\r"))

			if got := sniff.Detect(line); got != expect {
				t.Errorf("first record sniffed as %q, want %q\n  %.100q", got, expect, line)
			}
		})
	}
}

func BenchmarkDetect(b *testing.B) {
	line := []byte(`<166>Sep 28 2026 09:00:01 asa01 : %ASA-6-302013: Built inbound TCP connection 1001 for outside:203.0.113.183/389 to inside:10.2.2.73/43857`)
	b.ReportAllocs()
	b.SetBytes(int64(len(line)))
	for i := 0; i < b.N; i++ {
		if sniff.Detect(line) != types.HintSyslog3164 {
			b.Fatal("wrong hint")
		}
	}
}
