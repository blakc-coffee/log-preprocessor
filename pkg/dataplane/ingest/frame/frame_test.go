package frame

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	types "github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/testutil/types"
)

// collect drains a decoder.
func collect(t *testing.T, mode Mode, in []byte, o Options) ([]Frame, error) {
	t.Helper()
	d, err := New(mode, bytes.NewReader(in), o)
	if err != nil {
		t.Fatal(err)
	}
	var out []Frame
	for {
		f, err := d.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, f)
	}
}

// chunkReader hands out the stream in fixed-size pieces.
type chunkReader struct {
	b []byte
	n int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.b) == 0 {
		return 0, io.EOF
	}
	n := c.n
	if n > len(c.b) {
		n = len(c.b)
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, c.b[:n])
	c.b = c.b[n:]
	return n, nil
}

// randomChunkReader hands out the stream in deterministic random pieces.
type randomChunkReader struct {
	b   []byte
	rng *rand.Rand
}

func (c *randomChunkReader) Read(p []byte) (int, error) {
	if len(c.b) == 0 {
		return 0, io.EOF
	}
	n := 1 + c.rng.IntN(len(c.b))
	if n > len(p) {
		n = len(p)
	}
	copy(p, c.b[:n])
	c.b = c.b[n:]
	return n, nil
}

func drain(d Decoder) ([]Frame, error) {
	var out []Frame
	for {
		f, err := d.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, f)
	}
}

func framesEqual(a, b []Frame) error {
	if len(a) != len(b) {
		return fmt.Errorf("%d frames vs %d", len(a), len(b))
	}
	for i := range a {
		if !bytes.Equal(a[i].Raw, b[i].Raw) {
			return fmt.Errorf("frame %d: raw %q vs %q", i, a[i].Raw, b[i].Raw)
		}
		if a[i].Term != b[i].Term || a[i].Frag != b[i].Frag || a[i].Offset != b[i].Offset {
			return fmt.Errorf("frame %d: %+v vs %+v", i,
				Frame{Term: a[i].Term, Frag: a[i].Frag, Offset: a[i].Offset},
				Frame{Term: b[i].Term, Frag: b[i].Frag, Offset: b[i].Offset})
		}
	}
	return nil
}

// TestChunkingInvariance is the property this package lives or dies by.
//
// A decoder must give identical output regardless of how the reader chops the
// stream. A framer that only works when reads happen to align with record
// boundaries passes every hand-written test and then fails against a real TCP
// socket, where a record routinely arrives in three pieces and three records
// arrive in one.
func TestChunkingInvariance(t *testing.T) {
	inputs := map[string]struct {
		mode Mode
		in   string
		opts Options
	}{
		"lf":                 {ModeLF, "alpha\nbeta\ngamma\n", Options{}},
		"lf unterminated":    {ModeLF, "alpha\nbeta\ngamma", Options{}},
		"lf empty lines":     {ModeLF, "\n\na\n\n\nb\n", Options{}},
		"lf lone CR kept":    {ModeLF, "a\rb\nc\rd\n", Options{}},
		"crlf":               {ModeCRLF, "alpha\r\nbeta\r\n", Options{}},
		"crlf lone LF kept":  {ModeCRLF, "a\nb\r\nc\n\r\n", Options{}},
		"lines mixed":        {ModeLines, "alpha\r\nbeta\ngamma\r\n", Options{}},
		"nul":                {ModeNUL, "alpha\x00beta\x00", Options{}},
		"nul empty":          {ModeNUL, "\x00\x00a\x00", Options{}},
		"octet":              {ModeOctet, "5 alpha4 beta", Options{}},
		"octet with spaces":  {ModeOctet, "11 hello world5 there", Options{}},
		"binary":             {ModeLF, "\xff\xfe\x00\x01\nmore\x00\xff\n", Options{}},
		"fragmenting lf":     {ModeLF, strings.Repeat("x", 25) + "\n" + "short\n", Options{MaxFrameBytes: 10}},
		"fragmenting octet":  {ModeOctet, "25 " + strings.Repeat("y", 25), Options{MaxFrameBytes: 10}},
		"fragment then term": {ModeLF, strings.Repeat("z", 20) + "\n", Options{MaxFrameBytes: 7}},
		"exact boundary":     {ModeLF, strings.Repeat("e", 10) + "\n", Options{MaxFrameBytes: 10}},
		"crlf fragmenting":   {ModeCRLF, strings.Repeat("c", 23) + "\r\n", Options{MaxFrameBytes: 8}},
	}

	for name, tc := range inputs {
		t.Run(name, func(t *testing.T) {
			want, err := collect(t, tc.mode, []byte(tc.in), tc.opts)
			if err != nil {
				t.Fatalf("reference read: %v", err)
			}

			t.Run("one byte at a time", func(t *testing.T) {
				d, err := New(tc.mode, iotest.OneByteReader(strings.NewReader(tc.in)), tc.opts)
				if err != nil {
					t.Fatal(err)
				}
				got, err := drain(d)
				if err != nil {
					t.Fatal(err)
				}
				if err := framesEqual(want, got); err != nil {
					t.Error(err)
				}
			})

			t.Run("fixed chunk sizes", func(t *testing.T) {
				for _, n := range []int{1, 2, 3, 5, 7, 8, 11, 16, 64, 1024} {
					d, err := New(tc.mode, &chunkReader{b: []byte(tc.in), n: n}, tc.opts)
					if err != nil {
						t.Fatal(err)
					}
					got, err := drain(d)
					if err != nil {
						t.Fatalf("chunk %d: %v", n, err)
					}
					if err := framesEqual(want, got); err != nil {
						t.Errorf("chunk %d: %v", n, err)
					}
				}
			})

			t.Run("random chunk sizes", func(t *testing.T) {
				for seed := uint64(1); seed <= 25; seed++ {
					r := &randomChunkReader{b: []byte(tc.in), rng: rand.New(rand.NewPCG(seed, 0x1F))}
					d, err := New(tc.mode, r, tc.opts)
					if err != nil {
						t.Fatal(err)
					}
					got, err := drain(d)
					if err != nil {
						t.Fatalf("seed %d: %v", seed, err)
					}
					if err := framesEqual(want, got); err != nil {
						t.Errorf("seed %d: %v", seed, err)
					}
				}
			})

			t.Run("data-error reader", func(t *testing.T) {
				// iotest.DataErrReader returns the final bytes together with
				// io.EOF rather than on a separate call, which is legal and
				// which naive decoders drop the last record on.
				d, err := New(tc.mode, iotest.DataErrReader(strings.NewReader(tc.in)), tc.opts)
				if err != nil {
					t.Fatal(err)
				}
				got, err := drain(d)
				if err != nil {
					t.Fatal(err)
				}
				if err := framesEqual(want, got); err != nil {
					t.Error(err)
				}
			})
		})
	}
}

// TestTerminatorsAreRecordedNotStored is rule one. A terminator in Raw would
// make the vault's bytes differ from the manifest's byte range, and the whole
// round-trip claim with it.
func TestTerminatorsAreRecordedNotStored(t *testing.T) {
	cases := []struct {
		mode  Mode
		in    string
		raws  []string
		terms []types.Terminator
	}{
		{ModeLF, "a\nb\n", []string{"a", "b"}, []types.Terminator{types.TermLF, types.TermLF}},
		{ModeLF, "a\nb", []string{"a", "b"}, []types.Terminator{types.TermLF, types.TermNone}},
		{ModeCRLF, "a\r\nb\r\n", []string{"a", "b"}, []types.Terminator{types.TermCRLF, types.TermCRLF}},
		{ModeNUL, "a\x00b\x00", []string{"a", "b"}, []types.Terminator{types.TermNUL, types.TermNUL}},
		{ModeLines, "a\r\nb\n", []string{"a", "b"}, []types.Terminator{types.TermCRLF, types.TermLF}},
		{ModeOctet, "1 a1 b", []string{"a", "b"}, []types.Terminator{types.TermNone, types.TermNone}},
	}
	for _, c := range cases {
		got, err := collect(t, c.mode, []byte(c.in), Options{})
		if err != nil {
			t.Fatalf("%s %q: %v", c.mode, c.in, err)
		}
		if len(got) != len(c.raws) {
			t.Fatalf("%s %q: %d frames, want %d", c.mode, c.in, len(got), len(c.raws))
		}
		for i := range got {
			if string(got[i].Raw) != c.raws[i] {
				t.Errorf("%s %q: frame %d raw %q, want %q", c.mode, c.in, i, got[i].Raw, c.raws[i])
			}
			if got[i].Term != c.terms[i] {
				t.Errorf("%s %q: frame %d term %d, want %d", c.mode, c.in, i, got[i].Term, c.terms[i])
			}
		}
	}
}

// TestBytesArePreservedExactly walks the payloads testdata/malformed.log is
// built from. The framer is the first thing to touch hostile input, and it
// must not clean any of it up.
func TestBytesArePreservedExactly(t *testing.T) {
	payloads := [][]byte{
		{0xFF, 0xFE},               // invalid UTF-8
		{0xC3, 0x28},               // truncated multi-byte sequence
		{'a', 0x00, 'b'},           // embedded NUL
		{'a', '\r', 'b'},           // bare CR
		{'\r'},                     // lone CR
		{0x1b, '[', '3', '1', 'm'}, // terminal escape
		{},                         // empty
		allBytesExcept('\n'),       // every byte value the delimiter allows
	}

	var in []byte
	for _, p := range payloads {
		in = append(in, p...)
		in = append(in, '\n')
	}

	got, err := collect(t, ModeLF, in, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(payloads) {
		t.Fatalf("%d frames, want %d", len(got), len(payloads))
	}
	for i, want := range payloads {
		if !bytes.Equal(got[i].Raw, want) {
			t.Errorf("frame %d: got %x, want %x", i, got[i].Raw, want)
		}
	}
}

func allBytesExcept(skip byte) []byte {
	var out []byte
	for i := 0; i < 256; i++ {
		if byte(i) != skip {
			out = append(out, byte(i))
		}
	}
	return out
}

// TestOffsets: Frame.Offset becomes Origin.Offset, which is the de-duplication
// key after an at-least-once file replay. If it drifts, a crash produces
// duplicates nothing downstream can collapse.
func TestOffsets(t *testing.T) {
	in := "alpha\nbeta\n\ngamma\n"
	got, err := collect(t, ModeLF, []byte(in), Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []uint64{0, 6, 11, 12}
	if len(got) != len(want) {
		t.Fatalf("%d frames, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i].Offset != want[i] {
			t.Errorf("frame %d offset %d, want %d", i, got[i].Offset, want[i])
		}
		// And the offset must actually point at the record in the stream.
		if !bytes.HasPrefix([]byte(in[got[i].Offset:]), got[i].Raw) {
			t.Errorf("frame %d: offset %d does not point at %q", i, got[i].Offset, got[i].Raw)
		}
	}
}

// TestEmptyRecordsAreEmitted. Whether to drop a blank line is a downstream
// decision; ingest's job is to not decide it. testdata/malformed.log has ten
// of them and the manifest describes every one.
func TestEmptyRecordsAreEmitted(t *testing.T) {
	got, err := collect(t, ModeLF, []byte("\n\n\n"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("%d frames, want 3", len(got))
	}
	for i, f := range got {
		if len(f.Raw) != 0 {
			t.Errorf("frame %d is %q, want empty", i, f.Raw)
		}
		if f.Term != types.TermLF {
			t.Errorf("frame %d term %d, want LF", i, f.Term)
		}
	}
}

func TestEmptyStream(t *testing.T) {
	for _, mode := range []Mode{ModeLF, ModeCRLF, ModeLines, ModeNUL, ModeOctet} {
		got, err := collect(t, mode, nil, Options{})
		if err != nil {
			t.Errorf("%s: %v", mode, err)
		}
		if len(got) != 0 {
			t.Errorf("%s: %d frames from an empty stream", mode, len(got))
		}
	}
}

// TestDetect covers the auto-framing guess a syslog listener has to make,
// because RFC 6587 allows octet counting and newline framing on the same port.
func TestDetect(t *testing.T) {
	cases := map[string]Mode{
		// Real syslog always starts with "<PRI>", never a digit, which is
		// what makes the guess safe for syslog specifically.
		"<166>Sep 28 2026 09:00:01 asa01 : %ASA-6-302013: Built": ModeLF,
		"<134>1 2026-09-28T09:00:01+05:30 host app - - -":        ModeLF,
		"date=2026-09-28 time=09:00:02 devname=\"FG-01\"":        ModeLF,
		"{\"timestamp\":\"2026-09-28T09:00:00\"}":                ModeLF,

		"30 <134>Sep 28 10:14:02 h app: hi": ModeOctet,
		"5 alpha":                           ModeOctet,
		"123456 x":                          ModeOctet, // six digits, the documented limit

		"1234567 x":      ModeLF, // seven digits is too many to be a length
		" 5 leading":     ModeLF, // a space with no digits before it
		"":               ModeLF,
		"12":             ModeLF, // ran out of bytes mid-guess
		"12x34 not":      ModeLF,
		"\x00\x01binary": ModeLF,
	}
	for in, want := range cases {
		if got := Detect([]byte(in)); got != want {
			t.Errorf("Detect(%q) = %q, want %q", truncateStr(in, 40), got, want)
		}
	}
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// TestDetectOnEveryFixture is the check that matters: the corpus is what the
// listeners will actually see, and a wrong guess on a real vendor format would
// consume the stream.
func TestDetectOnEveryFixture(t *testing.T) {
	const testdata = "../../../../testdata"
	entries, err := os.ReadDir(testdata)
	if err != nil {
		t.Skipf("no corpus: %v", err)
	}
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".log") && !strings.HasSuffix(name, ".json") {
			continue
		}
		if name == "manifest.json" || name == "identity_truth.json" || name == "merkle_vectors.json" {
			continue
		}
		body, err := os.ReadFile(filepath.Join(testdata, name))
		if err != nil || len(body) == 0 {
			continue
		}
		head := body
		if len(head) > 256 {
			head = head[:256]
		}
		// No fixture is octet-counted, so a listener in auto mode must choose
		// line framing for every one of them. Choosing octet would read a
		// length out of log text and swallow the connection.
		if got := Detect(head); got != ModeLF {
			t.Errorf("%s: Detect chose %q, want line framing", name, got)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no fixtures checked")
	}
	t.Logf("checked %d fixtures", checked)
}
