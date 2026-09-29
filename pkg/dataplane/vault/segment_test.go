package vault

import (
	"bytes"
	"errors"
	"testing"
	"time"

	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

func sampleHeader() header {
	var prev [32]byte
	for i := range prev {
		prev[i] = byte(i)
	}
	return header{
		Segment:   7,
		FirstSeq:  1234,
		PrevChain: prev,
		CreatedAt: time.Unix(1790566200, 123456789).UTC(),
	}
}

func sampleFooter() footer {
	var root, chain [32]byte
	for i := range root {
		root[i] = byte(0xA0 + i)
		chain[i] = byte(0x50 + i)
	}
	return footer{
		Count:    1000,
		LastSeq:  2233,
		Root:     root,
		Chain:    chain,
		SealedAt: time.Unix(1790566999, 987654321).UTC(),
	}
}

// TestSizesAreFixed pins the on-disk sizes. docs/vault-format.md publishes
// them and Packaging's tamper tests seek by them, so a change here is a
// format change, not a refactor.
func TestSizesAreFixed(t *testing.T) {
	// The literals are spelled out on purpose: the constants must not be
	// quietly redefined to whatever the structs happen to encode to.
	if HeaderSize != 72 || FooterSize != 100 {
		t.Fatalf("sizes changed: header %d, footer %d, want 72 and 100", HeaderSize, FooterSize)
	}
	if got := len(sampleHeader().encode()); got != HeaderSize {
		t.Errorf("header encodes to %d bytes, want %d", got, HeaderSize)
	}
	if got := len(sampleFooter().encode()); got != FooterSize {
		t.Errorf("footer encodes to %d bytes, want %d", got, FooterSize)
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	cases := map[string]header{
		"sample": sampleHeader(),
		// A zero CreatedAt stores as the Unix epoch: see record.TimeToNanos.
		"zero":       {CreatedAt: time.Unix(0, 0).UTC()},
		"first":      {Segment: 1, FirstSeq: 1, CreatedAt: time.Unix(0, 0).UTC()},
		"max values": {Segment: ^uint64(0), FirstSeq: ^types.RecordID(0), CreatedAt: time.Unix(0, 1<<62).UTC()},
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := decodeHeader(want.encode())
			if err != nil {
				t.Fatal(err)
			}
			if got.Segment != want.Segment || got.FirstSeq != want.FirstSeq || got.PrevChain != want.PrevChain {
				t.Errorf("got %+v, want %+v", got, want)
			}
			if !got.CreatedAt.Equal(want.CreatedAt) {
				t.Errorf("created_at %s, want %s", got.CreatedAt, want.CreatedAt)
			}
		})
	}
}

func TestFooterRoundTrip(t *testing.T) {
	want := sampleFooter()
	got, err := decodeFooter(want.encode())
	if err != nil {
		t.Fatal(err)
	}
	if got.Count != want.Count || got.LastSeq != want.LastSeq || got.Root != want.Root || got.Chain != want.Chain {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if !got.SealedAt.Equal(want.SealedAt) {
		t.Errorf("sealed_at %s, want %s", got.SealedAt, want.SealedAt)
	}
}

// TestEncodeIsDeterministic matters because a segment header is rewritten
// nowhere: it is fsynced once and read back after a crash. Two encodings of
// the same header that differed would make recovery's cross-checks unreliable.
func TestEncodeIsDeterministic(t *testing.T) {
	h := sampleHeader()
	if !bytes.Equal(h.encode(), h.encode()) {
		t.Error("two encodings of the same header differ")
	}
	f := sampleFooter()
	if !bytes.Equal(f.encode(), f.encode()) {
		t.Error("two encodings of the same footer differ")
	}
}

// TestHeaderRejects covers every way a header can be wrong. The distinction
// that matters is ErrShort (came back with fewer bytes than a header) versus
// ErrBadMagic and ErrBadCRC (this is not, or is no longer, a valid segment) -
// recovery treats them differently.
func TestHeaderRejects(t *testing.T) {
	good := sampleHeader().encode()

	t.Run("short", func(t *testing.T) {
		for i := 0; i < HeaderSize; i++ {
			if _, err := decodeHeader(good[:i]); !errors.Is(err, ErrShort) {
				t.Fatalf("truncated to %d: got %v, want ErrShort", i, err)
			}
		}
	})

	t.Run("bad magic", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		bad[0] = 'X'
		if _, err := decodeHeader(bad); !errors.Is(err, ErrBadMagic) {
			t.Errorf("got %v, want ErrBadMagic", err)
		}
	})

	t.Run("wrong version", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		bad[9] = FormatVersion + 1
		if _, err := decodeHeader(bad); !errors.Is(err, ErrBadVersion) {
			t.Errorf("got %v, want ErrBadVersion", err)
		}
	})

	t.Run("any flipped byte is caught", func(t *testing.T) {
		// A silently corrupt header would give the whole segment the wrong
		// place in the chain, so every covered byte must be checksummed.
		for i := 8; i < 68; i++ {
			bad := append([]byte(nil), good...)
			bad[i] ^= 0x01
			_, err := decodeHeader(bad)
			if errors.Is(err, ErrBadCRC) || errors.Is(err, ErrBadVersion) {
				continue
			}
			t.Errorf("byte %d flipped: got %v, want ErrBadCRC", i, err)
		}
	})

	t.Run("flipped crc itself is caught", func(t *testing.T) {
		for i := 68; i < HeaderSize; i++ {
			bad := append([]byte(nil), good...)
			bad[i] ^= 0x01
			if _, err := decodeHeader(bad); !errors.Is(err, ErrBadCRC) {
				t.Errorf("crc byte %d flipped: got %v, want ErrBadCRC", i, err)
			}
		}
	})
}

func TestFooterRejects(t *testing.T) {
	good := sampleFooter().encode()

	t.Run("short means still active", func(t *testing.T) {
		// This is the normal path, not an error path: a segment with no
		// footer is the one recovery has to repair.
		for i := 0; i < FooterSize; i++ {
			if _, err := decodeFooter(good[:i]); !errors.Is(err, ErrShort) {
				t.Fatalf("truncated to %d: got %v, want ErrShort", i, err)
			}
		}
	})

	t.Run("bad magic", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		bad[7] = 'X'
		if _, err := decodeFooter(bad); !errors.Is(err, ErrBadMagic) {
			t.Errorf("got %v, want ErrBadMagic", err)
		}
	})

	t.Run("any flipped byte is caught", func(t *testing.T) {
		// The footer carries the segment root and the chain hash. Editing a
		// footer root is one row of the tamper matrix, and it has to be
		// caught here before VerifyChain ever compares it to the ledger.
		for i := 8; i < FooterSize; i++ {
			bad := append([]byte(nil), good...)
			bad[i] ^= 0x01
			if _, err := decodeFooter(bad); !errors.Is(err, ErrBadCRC) {
				t.Errorf("byte %d flipped: got %v, want ErrBadCRC", i, err)
			}
		}
	})
}

// TestMagicsDiffer proves a header can never be mistaken for a footer. They
// are read from the two ends of the same file, and confusing them would let a
// truncated segment look sealed.
func TestMagicsDiffer(t *testing.T) {
	if headerMagic == footerMagic {
		t.Fatal("header and footer magics are identical")
	}
	if _, err := decodeFooter(append(sampleHeader().encode(), make([]byte, 28)...)); !errors.Is(err, ErrBadMagic) {
		t.Errorf("a header parsed as a footer: got %v, want ErrBadMagic", err)
	}
}

func TestSegmentName(t *testing.T) {
	cases := map[uint64]string{
		1:       "seg-000000000001.wal",
		42:      "seg-000000000042.wal",
		1 << 20: "seg-000001048576.wal",
	}
	for id, want := range cases {
		if got := segmentName(id, "wal"); got != want {
			t.Errorf("segmentName(%d) = %q, want %q", id, got, want)
		}
	}

	// Fixed width means a lexical sort is also a numeric sort, which recovery
	// and `vaultctl ls` both rely on.
	if a, b := segmentName(9, "wal"), segmentName(10, "wal"); !(a < b) {
		t.Errorf("segment names do not sort numerically: %q is not before %q", a, b)
	}
	if a, b := segmentName(99, "wal"), segmentName(100, "wal"); !(a < b) {
		t.Errorf("segment names do not sort numerically: %q is not before %q", a, b)
	}
}
