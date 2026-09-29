package record

import (
	"bytes"
	"errors"
	"testing"
	"time"

	types "github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/testutil/types"
)

func sample() types.RawRecord {
	return types.RawRecord{
		SourceID:   "syslog-udp",
		ReceivedAt: time.Unix(1790566201, 123456789).UTC(),
		Origin:     types.Origin{Kind: types.OriginUDP, Addr: "10.1.4.7:51544", Offset: 4096},
		Term:       types.TermLF,
		Frag:       types.FragNone,
		Raw:        []byte("<166>Sep 28 2026 09:00:01 asa01 : %ASA-6-302013: Built"),
	}
}

// roundTrip is the property the vault's byte-exactness claim rests on: what
// comes out of the codec is what went in, for every input, including the ones
// that are not text.
func roundTrip(t *testing.T, seq types.RecordID, in types.RawRecord) {
	t.Helper()
	body, err := Encode(nil, seq, in)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if got := EncodedLen(in); got != len(body) {
		t.Errorf("EncodedLen = %d, encoded %d bytes", got, len(body))
	}
	gotSeq, out, err := Decode(body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if gotSeq != seq {
		t.Errorf("seq = %d, want %d", gotSeq, seq)
	}
	if !bytes.Equal(out.Raw, in.Raw) {
		t.Errorf("raw changed:\n got %q\nwant %q", out.Raw, in.Raw)
	}
	if out.SourceID != in.SourceID || out.Term != in.Term || out.Frag != in.Frag {
		t.Errorf("header changed: got %+v, want %+v", out, in)
	}
	if out.Origin != in.Origin {
		t.Errorf("origin = %+v, want %+v", out.Origin, in.Origin)
	}
	if !out.ReceivedAt.Equal(in.ReceivedAt) {
		t.Errorf("received_at = %s, want %s", out.ReceivedAt, in.ReceivedAt)
	}
}

func TestRoundTrip(t *testing.T) {
	cases := map[string]func(*types.RawRecord){
		"plain":           func(r *types.RawRecord) {},
		"empty raw":       func(r *types.RawRecord) { r.Raw = []byte{} },
		"nil raw":         func(r *types.RawRecord) { r.Raw = nil },
		"invalid utf-8":   func(r *types.RawRecord) { r.Raw = []byte{0xFF, 0xFE, 'a', 0xC3, 0x28} },
		"embedded NUL":    func(r *types.RawRecord) { r.Raw = []byte("a\x00b\x00c") },
		"embedded CR LF":  func(r *types.RawRecord) { r.Raw = []byte("line\r\nmore\nend\r") },
		"all byte values": func(r *types.RawRecord) { r.Raw = allBytes() },
		"crlf terminator": func(r *types.RawRecord) { r.Term = types.TermCRLF },
		"nul terminator":  func(r *types.RawRecord) { r.Term = types.TermNUL },
		"no terminator":   func(r *types.RawRecord) { r.Term = types.TermNone },
		"fragment first":  func(r *types.RawRecord) { r.Frag = types.FragMore },
		"fragment middle": func(r *types.RawRecord) { r.Frag = types.FragMore | types.FragCont },
		"fragment last":   func(r *types.RawRecord) { r.Frag = types.FragCont },
		"empty source id": func(r *types.RawRecord) { r.SourceID = "" },
		"empty addr":      func(r *types.RawRecord) { r.Origin.Addr = "" },
		"file origin": func(r *types.RawRecord) {
			r.Origin = types.Origin{Kind: types.OriginFile, Addr: "/var/log/x.log", Offset: 1 << 40}
		},
		"unknown origin":  func(r *types.RawRecord) { r.Origin = types.Origin{} },
		"max offset":      func(r *types.RawRecord) { r.Origin.Offset = ^uint64(0) },
		"zero time":       func(r *types.RawRecord) { r.ReceivedAt = time.Unix(0, 0).UTC() },
		"long source id":  func(r *types.RawRecord) { r.SourceID = string(bytes.Repeat([]byte("s"), 0xFFFF)) },
		"one MiB payload": func(r *types.RawRecord) { r.Raw = bytes.Repeat([]byte("A"), 1<<20) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := sample()
			mutate(&r)
			roundTrip(t, 1, r)
		})
	}
}

func allBytes() []byte {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// TestSeqRoundTrip covers the boundaries of the sequence number, which is the
// vault's record identity and therefore has to survive exactly.
func TestSeqRoundTrip(t *testing.T) {
	for _, seq := range []types.RecordID{0, 1, 255, 256, 1 << 32, ^types.RecordID(0)} {
		roundTrip(t, seq, sample())
	}
}

// TestEncodeIsDeterministic matters because the Merkle leaf is a hash of the
// body. Two encodings of the same record that differed by a byte would give
// two different leaves and break every proof over that segment.
func TestEncodeIsDeterministic(t *testing.T) {
	r := sample()
	a, err := Encode(nil, 7, r)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encode(nil, 7, r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("two encodings of the same record differ")
	}
}

// TestEncodeDoesNotAliasRaw proves the codec keeps its hands off the caller's
// payload. Working rule 4: any code that touches Raw needs a test proving it
// does not change it.
func TestEncodeDoesNotAliasRaw(t *testing.T) {
	r := sample()
	original := append([]byte(nil), r.Raw...)

	body, err := Encode(nil, 1, r)
	if err != nil {
		t.Fatal(err)
	}
	// Scribble over the whole encoded body; the caller's slice must be intact.
	for i := range body {
		body[i] = 0xAA
	}
	if !bytes.Equal(r.Raw, original) {
		t.Error("Encode wrote through to the caller's Raw slice")
	}

	// And the other way: a decoded record must not alias the body it came from.
	body, _ = Encode(nil, 1, r)
	_, out, err := Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	decoded := append([]byte(nil), out.Raw...)
	for i := range body {
		body[i] = 0x55
	}
	if !bytes.Equal(out.Raw, decoded) {
		t.Error("Decode returned a Raw slice that aliases the input body")
	}
}

func TestDecodeRejects(t *testing.T) {
	good, err := Encode(nil, 1, sample())
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		body []byte
		want error
	}{
		"empty":            {nil, ErrTruncated},
		"one byte":         {[]byte{Version}, ErrTruncated},
		"wrong version":    {withByte(good, 0, Version+1), ErrMalformed},
		"unknown flag bit": {withByte(good, 1, 0xF0), ErrMalformed},
		"trailing bytes":   {append(append([]byte{}, good...), 0x00), ErrMalformed},
		"truncated tail":   {good[:len(good)-1], ErrTruncated},
		"truncated head":   {good[:4], ErrTruncated},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Decode(c.body); !errors.Is(err, c.want) {
				t.Errorf("got %v, want %v", err, c.want)
			}
		})
	}

	t.Run("bad origin kind", func(t *testing.T) {
		// origin_kind sits after version, flags, seq, received_at, source_len
		// and the source id itself.
		at := 2 + 8 + 8 + 2 + len(sample().SourceID)
		if _, _, err := Decode(withByte(good, at, 99)); !errors.Is(err, ErrMalformed) {
			t.Errorf("got %v, want ErrMalformed", err)
		}
	})

	t.Run("truncated at every offset", func(t *testing.T) {
		// Recovery truncates a torn tail at the last good boundary, so a body
		// cut anywhere must be reported, never accepted and never panic.
		for i := 0; i < len(good); i++ {
			if _, _, err := Decode(good[:i]); err == nil {
				t.Fatalf("accepted a body truncated to %d of %d bytes", i, len(good))
			}
		}
	})
}

func withByte(b []byte, at int, v byte) []byte {
	out := append([]byte(nil), b...)
	out[at] = v
	return out
}

func TestFramed(t *testing.T) {
	body, err := Encode(nil, 42, sample())
	if err != nil {
		t.Fatal(err)
	}
	buf := AppendFramed(nil, body)
	max := MaxBodyBytes(1 << 20)

	got, n, err := ParseFramed(buf, max)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(buf) {
		t.Errorf("consumed %d bytes, want %d", n, len(buf))
	}
	if !bytes.Equal(got, body) {
		t.Error("framed body round-trip changed the bytes")
	}

	t.Run("detects a flipped byte", func(t *testing.T) {
		// One bit anywhere in the body must be caught by the CRC. This is the
		// per-record half of the tamper claim; the Merkle root is the other.
		for i := FrameOverhead; i < len(buf); i++ {
			bad := append([]byte(nil), buf...)
			bad[i] ^= 0x01
			if _, _, err := ParseFramed(bad, max); !errors.Is(err, ErrCRC) {
				t.Fatalf("byte %d flipped: got %v, want ErrCRC", i, err)
			}
		}
	})

	t.Run("truncated at every offset", func(t *testing.T) {
		for i := 0; i < len(buf); i++ {
			if _, _, err := ParseFramed(buf[:i], max); !errors.Is(err, ErrTruncated) {
				t.Fatalf("truncated to %d of %d: got %v, want ErrTruncated", i, len(buf), err)
			}
		}
	})

	t.Run("caps a hostile length", func(t *testing.T) {
		// The cap is checked before the buffer is consulted, so a huge
		// declared length can never drive an allocation.
		bad := AppendFramed(nil, body)
		bad[0], bad[1], bad[2], bad[3] = 0xFF, 0xFF, 0xFF, 0xFF
		if _, _, err := ParseFramed(bad, max); !errors.Is(err, ErrTooLarge) {
			t.Errorf("got %v, want ErrTooLarge", err)
		}
	})

	t.Run("reads a sequence", func(t *testing.T) {
		var all []byte
		for i := 1; i <= 5; i++ {
			b, err := Encode(nil, types.RecordID(i), sample())
			if err != nil {
				t.Fatal(err)
			}
			all = AppendFramed(all, b)
		}
		var seqs []types.RecordID
		for off := 0; off < len(all); {
			b, n, err := ParseFramed(all[off:], max)
			if err != nil {
				t.Fatal(err)
			}
			s, _, err := Decode(b)
			if err != nil {
				t.Fatal(err)
			}
			seqs = append(seqs, s)
			off += n
		}
		if len(seqs) != 5 {
			t.Fatalf("read %d records, want 5", len(seqs))
		}
		for i, s := range seqs {
			if s != types.RecordID(i+1) {
				t.Errorf("record %d has seq %d", i, s)
			}
		}
	})
}

func TestEncodeRejects(t *testing.T) {
	t.Run("oversize source id", func(t *testing.T) {
		r := sample()
		r.SourceID = string(bytes.Repeat([]byte("s"), 0x10000))
		if _, err := Encode(nil, 1, r); !errors.Is(err, ErrTooLarge) {
			t.Errorf("got %v, want ErrTooLarge", err)
		}
	})
	t.Run("oversize addr", func(t *testing.T) {
		r := sample()
		r.Origin.Addr = string(bytes.Repeat([]byte("a"), 0x10000))
		if _, err := Encode(nil, 1, r); !errors.Is(err, ErrTooLarge) {
			t.Errorf("got %v, want ErrTooLarge", err)
		}
	})
	t.Run("bad terminator", func(t *testing.T) {
		r := sample()
		r.Term = types.Terminator(9)
		if _, err := Encode(nil, 1, r); !errors.Is(err, ErrMalformed) {
			t.Errorf("got %v, want ErrMalformed", err)
		}
	})
}

// FuzzRecordDecode is the PRD's required fuzz target: the decoder must never
// panic and must never accept a body with a bad CRC, whatever it is handed.
// Raw input is hostile by assumption, and this is the first thing that touches
// it after framing.
func FuzzRecordDecode(f *testing.F) {
	for _, seed := range [][]byte{nil, {}, {1}, {1, 0}, allBytes()} {
		f.Add(seed)
	}
	if body, err := Encode(nil, 1, sample()); err == nil {
		f.Add(body)
		f.Add(AppendFramed(nil, body))
	}

	max := MaxBodyBytes(1 << 20)
	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic, and anything it accepts must re-encode identically:
		// a decoder that accepted two spellings of one record would give that
		// record two Merkle leaves.
		if seq, r, err := Decode(data); err == nil {
			again, err := Encode(nil, seq, r)
			if err != nil {
				t.Fatalf("re-encoding an accepted record failed: %v", err)
			}
			if !bytes.Equal(again, data) {
				t.Fatalf("accepted a body that does not re-encode to itself:\n got %x\nwant %x", again, data)
			}
		}

		// And the framed reader must never accept a body whose CRC is wrong.
		if body, _, err := ParseFramed(data, max); err == nil {
			if got := binaryBE32(data[4:]); got != CRC(body) {
				t.Fatalf("accepted a frame with a bad CRC")
			}
		}
	})
}

func binaryBE32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// TestZeroTimeDoesNotBecomeAPlausibleDate is a regression test.
//
// Timestamps are stored as int64 Unix nanoseconds, and time.Time.UnixNano()
// is undefined outside 1678-2262: the zero time silently overflows to
// 1754-08-30. A record whose ReceivedAt was never set would therefore have
// come back carrying a confident, wrong, eighteenth-century date - which is
// worse than an obviously empty one, because nothing downstream would
// question it.
func TestZeroTimeDoesNotBecomeAPlausibleDate(t *testing.T) {
	if got := TimeToNanos(time.Time{}); got != 0 {
		t.Errorf("the zero time stores as %d, want 0", got)
	}

	r := sample()
	r.ReceivedAt = time.Time{}
	body, err := Encode(nil, 1, r)
	if err != nil {
		t.Fatal(err)
	}
	_, out, err := Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Unix(0, 0).UTC(); !out.ReceivedAt.Equal(want) {
		t.Errorf("a zero ReceivedAt came back as %s, want the epoch %s", out.ReceivedAt, want)
	}
	if y := out.ReceivedAt.Year(); y == 1754 {
		t.Errorf("the zero time overflowed to %d, the bug this test exists for", y)
	}
}

// TestTimeIsClampedNotCorrupted covers the other end. Ordering in this system
// comes from the sequence number, never from a timestamp, so a nonsense clock
// must not make a record unstorable - but it must not wrap around either.
func TestTimeIsClampedNotCorrupted(t *testing.T) {
	for name, tm := range map[string]time.Time{
		"far future": time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC),
		"far past":   time.Date(1000, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		t.Run(name, func(t *testing.T) {
			r := sample()
			r.ReceivedAt = tm
			body, err := Encode(nil, 1, r)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := Decode(body); err != nil {
				t.Fatalf("a record with an absurd timestamp became unreadable: %v", err)
			}
		})
	}

	// Round-trip must be exact everywhere inside the representable range.
	for _, tm := range []time.Time{
		time.Unix(0, 0).UTC(),
		time.Unix(1790566201, 123456789).UTC(),
		time.Date(1700, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2261, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		if got := TimeFromNanos(TimeToNanos(tm)); !got.Equal(tm) {
			t.Errorf("%s round-tripped to %s", tm, got)
		}
	}
}
