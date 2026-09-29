package vault

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"time"

	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault/record"
	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

// On-disk segment framing. A segment file is:
//
//	header (72 bytes, raw)
//	framed record * n          (see pkg/dataplane/vault/record)
//	footer (100 bytes, raw)    present only once the segment is sealed
//
// All integers are big-endian. Header and footer each carry their own CRC-32C,
// so a torn or corrupt boundary is distinguishable from a torn record tail:
// the first is fatal corruption, the second is the ordinary outcome of a
// crash and is repaired by truncation.
//
// The absence of a valid footer is what marks a segment as still active. That
// is deliberate: it means "sealed" is a fact on disk rather than a fact in an
// index that could disagree with the file.

const (
	// HeaderSize is the fixed size of a segment header. Fixed by the format:
	// docs/vault-format.md publishes it and tamper tests seek by it.
	HeaderSize = 72
	// FooterSize is the fixed size of a segment footer. A valid footer at the
	// end of a file is what "sealed" means.
	FooterSize = 100

	headerMagic = "ULPFSEG1"
	footerMagic = "ULPFEND1"

	// FormatVersion is the segment layout version.
	FormatVersion = 1
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// Format errors.
var (
	// ErrBadMagic means the file is not a ULPF segment at all.
	ErrBadMagic = errors.New("vault: not a segment file")
	// ErrBadVersion means the segment was written by a different format
	// version. The vault refuses rather than guessing at the layout.
	ErrBadVersion = errors.New("vault: unsupported segment version")
	// ErrBadCRC means a header or footer failed its checksum.
	ErrBadCRC = errors.New("vault: header or footer crc mismatch")
	// ErrShort means the buffer is smaller than the structure it should hold.
	// For a footer this is the normal reading of "still active".
	ErrShort = errors.New("vault: truncated header or footer")
)

// header is a segment's opening record. prevChain ties the segment to the
// chain before it has any content, so a segment file on its own says where it
// belongs in the ledger.
type header struct {
	Segment   uint64
	FirstSeq  types.RecordID
	PrevChain [32]byte
	CreatedAt time.Time
}

// encode returns the 72-byte header.
func (h header) encode() []byte {
	b := make([]byte, HeaderSize)
	copy(b[0:8], headerMagic)
	binary.BigEndian.PutUint16(b[8:10], FormatVersion)
	binary.BigEndian.PutUint16(b[10:12], 0) // reserved
	binary.BigEndian.PutUint64(b[12:20], h.Segment)
	binary.BigEndian.PutUint64(b[20:28], uint64(h.FirstSeq))
	copy(b[28:60], h.PrevChain[:])
	binary.BigEndian.PutUint64(b[60:68], uint64(record.TimeToNanos(h.CreatedAt)))
	binary.BigEndian.PutUint32(b[68:72], crc32.Checksum(b[:68], castagnoli))
	return b
}

// decodeHeader parses a segment header.
func decodeHeader(b []byte) (header, error) {
	var h header
	if len(b) < HeaderSize {
		return h, fmt.Errorf("%w: header is %d bytes, want %d", ErrShort, len(b), HeaderSize)
	}
	if string(b[0:8]) != headerMagic {
		return h, fmt.Errorf("%w: magic is %q", ErrBadMagic, b[0:8])
	}
	if v := binary.BigEndian.Uint16(b[8:10]); v != FormatVersion {
		return h, fmt.Errorf("%w: version %d, want %d", ErrBadVersion, v, FormatVersion)
	}
	if got, want := crc32.Checksum(b[:68], castagnoli), binary.BigEndian.Uint32(b[68:72]); got != want {
		return h, fmt.Errorf("%w: header computed %08x, stored %08x", ErrBadCRC, got, want)
	}
	h.Segment = binary.BigEndian.Uint64(b[12:20])
	h.FirstSeq = types.RecordID(binary.BigEndian.Uint64(b[20:28]))
	copy(h.PrevChain[:], b[28:60])
	h.CreatedAt = record.TimeFromNanos(int64(binary.BigEndian.Uint64(b[60:68])))
	return h, nil
}

// footer is written when a segment is sealed. Its presence, and only its
// presence, means the segment is closed.
type footer struct {
	Count    uint64
	LastSeq  types.RecordID
	Root     [32]byte
	Chain    [32]byte
	SealedAt time.Time
}

// encode returns the 100-byte footer.
func (f footer) encode() []byte {
	b := make([]byte, FooterSize)
	copy(b[0:8], footerMagic)
	binary.BigEndian.PutUint64(b[8:16], f.Count)
	binary.BigEndian.PutUint64(b[16:24], uint64(f.LastSeq))
	copy(b[24:56], f.Root[:])
	copy(b[56:88], f.Chain[:])
	binary.BigEndian.PutUint64(b[88:96], uint64(record.TimeToNanos(f.SealedAt)))
	binary.BigEndian.PutUint32(b[96:100], crc32.Checksum(b[:96], castagnoli))
	return b
}

// decodeFooter parses a segment footer.
//
// ErrShort or ErrBadMagic here is the normal reading of "this segment is still
// active", not corruption: recovery uses exactly that to find the segment it
// has to repair.
func decodeFooter(b []byte) (footer, error) {
	var f footer
	if len(b) < FooterSize {
		return f, fmt.Errorf("%w: footer is %d bytes, want %d", ErrShort, len(b), FooterSize)
	}
	if string(b[0:8]) != footerMagic {
		return f, fmt.Errorf("%w: footer magic is %q", ErrBadMagic, b[0:8])
	}
	if got, want := crc32.Checksum(b[:96], castagnoli), binary.BigEndian.Uint32(b[96:100]); got != want {
		return f, fmt.Errorf("%w: footer computed %08x, stored %08x", ErrBadCRC, got, want)
	}
	f.Count = binary.BigEndian.Uint64(b[8:16])
	f.LastSeq = types.RecordID(binary.BigEndian.Uint64(b[16:24]))
	copy(f.Root[:], b[24:56])
	copy(f.Chain[:], b[56:88])
	f.SealedAt = record.TimeFromNanos(int64(binary.BigEndian.Uint64(b[88:96])))
	return f, nil
}

// segmentName is the file name for a segment id. The width is fixed so a
// plain lexical sort of the directory is also a numeric sort, which keeps
// recovery and `vaultctl ls` from needing to parse before they can order.
func segmentName(id uint64, ext string) string {
	return fmt.Sprintf("seg-%012d.%s", id, ext)
}
