package frame

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	types "github.com/dark-14100/sluice/pkg/types"
)

// reassemble concatenates a fragment run and checks the flags are coherent.
// This is the operation the whole fragmentation design exists to support:
// nothing is ever truncated, so the original record must come back exactly.
func reassemble(t *testing.T, frames []Frame) []byte {
	t.Helper()
	var out []byte
	for i, f := range frames {
		first, last := i == 0, i == len(frames)-1
		if first && f.Frag&types.FragCont != 0 {
			t.Errorf("fragment 0 is marked FragCont")
		}
		if !first && f.Frag&types.FragCont == 0 {
			t.Errorf("fragment %d is not marked FragCont", i)
		}
		if last && f.Frag&types.FragMore != 0 {
			t.Errorf("the last fragment is marked FragMore")
		}
		if !last && f.Frag&types.FragMore == 0 {
			t.Errorf("fragment %d is not marked FragMore", i)
		}
		if !last && f.Term != types.TermNone {
			t.Errorf("non-final fragment %d carries terminator %d", i, f.Term)
		}
		out = append(out, f.Raw...)
	}
	return out
}

// TestFragmentBoundary pins the rule testdata/oversize.log was generated
// against, and that the manifest's expected_fragments already commits to:
// a record of exactly MaxFrameBytes is ONE record, not two.
//
// Without the one-byte lookahead, a record whose length lands exactly on the
// limit emits a full fragment plus a trailing zero-length FragCont fragment.
// That is not wrong, but it is a boundary case every consumer would have to
// know about forever, and a byte of lookahead is cheaper than that.
func TestFragmentBoundary(t *testing.T) {
	const max = 16

	cases := []struct {
		size, want int
	}{
		{1, 1},
		{max - 1, 1},
		{max, 1}, // exactly at the limit: one record
		{max + 1, 2},
		{2 * max, 2},
		{2*max + 1, 3},
		{3 * max, 3},
	}

	for _, c := range cases {
		payload := bytes.Repeat([]byte("x"), c.size)
		in := append(append([]byte{}, payload...), '\n')

		got, err := collect(t, ModeLF, in, Options{MaxFrameBytes: max})
		if err != nil {
			t.Fatalf("size %d: %v", c.size, err)
		}
		if len(got) != c.want {
			t.Errorf("size %d produced %d fragments, want %d", c.size, len(got), c.want)
			continue
		}
		if back := reassemble(t, got); !bytes.Equal(back, payload) {
			t.Errorf("size %d: reassembly produced %d bytes, want %d", c.size, len(back), c.size)
		}
		if last := got[len(got)-1]; last.Term != types.TermLF {
			t.Errorf("size %d: the final fragment carries terminator %d, want LF", c.size, last.Term)
		}
	}
}

// TestFragmentsAreBoundedInMemory proves fragmentation actually does its job.
// A record far larger than the buffer must stream through rather than be
// accumulated, or a single hostile line takes the process down.
func TestFragmentsAreBoundedInMemory(t *testing.T) {
	const max = 1024
	payload := bytes.Repeat([]byte("y"), 100*max+7)
	in := append(append([]byte{}, payload...), '\n')

	got, err := collect(t, ModeLF, in, Options{MaxFrameBytes: max, BufferSize: 64})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 101 {
		t.Fatalf("%d fragments, want 101", len(got))
	}
	for i, f := range got[:len(got)-1] {
		if len(f.Raw) != max {
			t.Errorf("fragment %d is %d bytes, want exactly %d", i, len(f.Raw), max)
		}
	}
	if !bytes.Equal(reassemble(t, got), payload) {
		t.Error("reassembly did not reproduce the record")
	}
}

// TestFragmentOffsetsAreContiguous: an oversize record's fragments must tile
// the stream, or reassembly downstream cannot trust the origin offsets.
func TestFragmentOffsetsAreContiguous(t *testing.T) {
	const max = 8
	in := append(bytes.Repeat([]byte("z"), 30), '\n')

	got, err := collect(t, ModeLF, in, Options{MaxFrameBytes: max})
	if err != nil {
		t.Fatal(err)
	}
	var want uint64
	for i, f := range got {
		if f.Offset != want {
			t.Errorf("fragment %d starts at %d, want %d", i, f.Offset, want)
		}
		want += uint64(len(f.Raw))
	}
}

// TestFragmentedThenNormal proves the fragment state resets: a record after an
// oversize one must not inherit FragCont.
func TestFragmentedThenNormal(t *testing.T) {
	const max = 8
	in := []byte(strings.Repeat("a", 20) + "\nshort\n" + strings.Repeat("b", 17) + "\ntiny\n")

	got, err := collect(t, ModeLF, in, Options{MaxFrameBytes: max})
	if err != nil {
		t.Fatal(err)
	}
	// 3 + 1 + 3 + 1
	if len(got) != 8 {
		t.Fatalf("%d frames, want 8", len(got))
	}
	for _, i := range []int{3, 7} {
		if got[i].Frag != types.FragNone {
			t.Errorf("frame %d has flags %d, want none", i, got[i].Frag)
		}
	}
	if string(got[3].Raw) != "short" || string(got[7].Raw) != "tiny" {
		t.Errorf("small records after fragmentation came back as %q and %q", got[3].Raw, got[7].Raw)
	}
}

// TestUnterminatedOversizeAtEOF: a huge final record with no terminator must
// still be fragmented and still be emitted, not dropped.
func TestUnterminatedOversizeAtEOF(t *testing.T) {
	const max = 8
	payload := bytes.Repeat([]byte("q"), 21)

	got, err := collect(t, ModeLF, payload, Options{MaxFrameBytes: max})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("%d fragments, want 3", len(got))
	}
	if last := got[2]; last.Term != types.TermNone {
		t.Errorf("the final fragment carries terminator %d, want none", last.Term)
	}
	if !bytes.Equal(reassemble(t, got), payload) {
		t.Error("reassembly did not reproduce the record")
	}
}

// ------------------------------------------------------------- octet counting

func TestOctet(t *testing.T) {
	t.Run("reads a sequence", func(t *testing.T) {
		got, err := collect(t, ModeOctet, []byte("5 alpha3 bcd11 hello world"), Options{})
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"alpha", "bcd", "hello world"}
		if len(got) != len(want) {
			t.Fatalf("%d frames, want %d", len(got), len(want))
		}
		for i := range want {
			if string(got[i].Raw) != want[i] {
				t.Errorf("frame %d is %q, want %q", i, got[i].Raw, want[i])
			}
		}
	})

	t.Run("a message may contain anything", func(t *testing.T) {
		// The length is the delimiter, so newlines, NULs and spaces inside a
		// message are content. That is the whole point of octet counting.
		msg := "line1\nline2\x00 with spaces"
		got, err := collect(t, ModeOctet, []byte("24 "+msg), Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || string(got[0].Raw) != msg {
			t.Errorf("got %q, want %q", got, msg)
		}
	})

	t.Run("rejects a hostile length", func(t *testing.T) {
		for _, in := range []string{
			"99999999999999 x", // more digits than any length needs
			"0 ",               // zero length
		} {
			if _, err := collect(t, ModeOctet, []byte(in), Options{MaxOctetLen: 1000}); err == nil {
				t.Errorf("%q was accepted", in)
			}
		}
		// A length over the cap must be a length error specifically, because
		// the source closes the connection and counts it.
		_, err := collect(t, ModeOctet, []byte("5000 x"), Options{MaxOctetLen: 1000})
		if !errors.Is(err, ErrOctetLength) {
			t.Errorf("got %v, want ErrOctetLength", err)
		}
	})

	t.Run("rejects a malformed header", func(t *testing.T) {
		for _, in := range []string{
			"notanumber hello",
			" 5 hello",
			"12x34 hello",
		} {
			if _, err := collect(t, ModeOctet, []byte(in), Options{}); !errors.Is(err, ErrOctetMalformed) {
				t.Errorf("%q: got %v, want ErrOctetMalformed", in, err)
			}
		}
	})

	t.Run("a truncated message keeps what arrived, then reports the violation", func(t *testing.T) {
		// The sender declared 20 bytes and delivered 5, then closed. Two
		// things have to be true at once: the 5 bytes are kept, because
		// discarding data the vault could have stored is the one thing
		// ingest must never do; and the caller is told the stream was cut,
		// so the source can close the connection and count it rather than
		// treating a truncated message as a clean end.
		//
		// Go's convention applies: the data comes back first, the error on
		// the following call.
		d, err := New(ModeOctet, bytes.NewReader([]byte("20 hello")), Options{})
		if err != nil {
			t.Fatal(err)
		}

		f, err := d.Next()
		if err != nil {
			t.Fatalf("the delivered bytes were lost: %v", err)
		}
		if string(f.Raw) != "hello" {
			t.Errorf("got %q, want %q", f.Raw, "hello")
		}
		if f.Frag&types.FragMore == 0 {
			t.Error("the partial message is not marked FragMore, so nothing downstream can tell it is incomplete")
		}

		if _, err := d.Next(); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("got %v, want io.ErrUnexpectedEOF", err)
		}
	})

	t.Run("an oversize message is fragmented, not rejected", func(t *testing.T) {
		// PRD 5.1: lengths above max_frame_bytes are fragmented; only lengths
		// above max_octet_len are refused.
		payload := strings.Repeat("m", 25)
		got, err := collect(t, ModeOctet, []byte("25 "+payload),
			Options{MaxFrameBytes: 10, MaxOctetLen: 1000})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 3 {
			t.Fatalf("%d fragments, want 3", len(got))
		}
		if string(reassemble(t, got)) != payload {
			t.Error("reassembly did not reproduce the message")
		}
	})
}

// FuzzOctet is the PRD's required fuzz target. The octet header is a length
// read straight off the wire, which is the classic unbounded-allocation bug.
// It must never panic and never allocate on a hostile length.
func FuzzOctet(f *testing.F) {
	for _, seed := range []string{
		"", "5 alpha", "0 ", "999999999999 x", "abc def", "12", "12 ",
		"3 abc3 def", " 1 a", "1 \x00",
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := New(ModeOctet, bytes.NewReader(data), Options{
			MaxFrameBytes: 64, MaxOctetLen: 4096, BufferSize: 16,
		})
		if err != nil {
			t.Fatal(err)
		}
		total := 0
		for i := 0; i < 1000; i++ {
			fr, err := d.Next()
			if err != nil {
				break
			}
			// Nothing may be conjured that was not in the input.
			total += len(fr.Raw)
			if total > len(data) {
				t.Fatalf("emitted %d bytes from a %d byte input", total, len(data))
			}
			if len(fr.Raw) > 64 {
				t.Fatalf("frame of %d bytes exceeds MaxFrameBytes", len(fr.Raw))
			}
		}
	})
}

// FuzzDelim covers the line-oriented decoders with the same guarantees.
func FuzzDelim(f *testing.F) {
	for _, seed := range []string{"", "\n", "a\nb", "\r\n", "a\x00b", strings.Repeat("x", 100)} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		for _, mode := range []Mode{ModeLF, ModeCRLF, ModeLines, ModeNUL} {
			d, err := New(mode, bytes.NewReader(data), Options{MaxFrameBytes: 32, BufferSize: 8})
			if err != nil {
				t.Fatal(err)
			}
			var rebuilt []byte
			for {
				fr, err := d.Next()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatalf("%s: %v", mode, err)
				}
				if len(fr.Raw) > 32 {
					t.Fatalf("%s: frame of %d bytes exceeds MaxFrameBytes", mode, len(fr.Raw))
				}
				rebuilt = append(rebuilt, fr.Raw...)
				switch fr.Term {
				case types.TermLF:
					rebuilt = append(rebuilt, '\n')
				case types.TermCRLF:
					rebuilt = append(rebuilt, '\r', '\n')
				case types.TermNUL:
					rebuilt = append(rebuilt, 0)
				}
			}
			// Raw plus the recorded terminators must reconstruct the input
			// byte for byte. This is the losslessness claim, checked against
			// arbitrary input rather than against examples.
			if !bytes.Equal(rebuilt, data) {
				t.Fatalf("%s: reconstruction differs\n got %x\nwant %x", mode, rebuilt, data)
			}
		}
	})
}

// TestOversizeFixtureMatchesTheManifest closes the loop with the corpus.
//
// testdata/oversize.log was generated against a fragmentation rule, and its
// manifest records expected_fragments at max_frame_bytes = 1 MiB. This asserts
// the framer actually produces those counts and that concatenating the
// fragments reproduces the source bytes exactly. If the generator and the
// framer ever disagree about the boundary, this fails rather than the failure
// surfacing as a mysterious round-trip mismatch at M3.6.
func TestOversizeFixtureMatchesTheManifest(t *testing.T) {
	const testdata = "../../../../testdata"

	raw, err := os.ReadFile(filepath.Join(testdata, "manifest.json"))
	if err != nil {
		t.Skipf("no corpus: %v (run `make fixtures`)", err)
	}
	var m struct {
		Records []struct {
			RecordID  string `json:"record_id"`
			File      string `json:"source_file"`
			Start     int    `json:"byte_start"`
			End       int    `json:"byte_end"`
			Fragments *int   `json:"expected_fragments"`
		} `json:"records"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(testdata, "oversize.log"))
	if err != nil {
		t.Fatal(err)
	}

	checked := 0
	for _, r := range m.Records {
		if r.File != "oversize.log" || r.Fragments == nil {
			continue
		}
		want := body[r.Start:r.End]

		got, err := collect(t, ModeLF, append(append([]byte{}, want...), '\n'),
			Options{MaxFrameBytes: 1 << 20})
		if err != nil {
			t.Fatalf("%s: %v", r.RecordID, err)
		}
		if len(got) != *r.Fragments {
			t.Errorf("%s (%d bytes): framer produced %d fragments, manifest says %d",
				r.RecordID, len(want), len(got), *r.Fragments)
			continue
		}
		if !bytes.Equal(reassemble(t, got), want) {
			t.Errorf("%s: reassembled fragments differ from the source bytes", r.RecordID)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no oversize records carried expected_fragments; the check proved nothing")
	}
	t.Logf("checked %d oversize records against the manifest", checked)
}
