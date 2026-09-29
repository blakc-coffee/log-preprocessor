// Package record encodes and decodes the vault's self-describing record
// format.
//
// It is a package of its own rather than a file inside the vault so that
// memvault can produce byte-identical encodings, and therefore identical leaf
// hashes and segment roots, without importing the on-disk vault. That is what
// makes memvault a reference implementation rather than a lookalike: a
// component developed against memvault sees the same proofs it will see
// against the real one.
//
// Wire format, all integers big-endian:
//
//	framed record
//	  len   u32   length of body
//	  crc   u32   CRC-32C (Castagnoli) of body
//	  body  ...
//
//	body
//	  version      u8    = 1
//	  flags        u8    bits 0-1 terminator, bit 2 FragMore, bit 3 FragCont
//	  seq          u64
//	  received_at  i64   unix nanoseconds
//	  source_len   u16 | source_id
//	  origin_kind  u8
//	  addr_len     u16 | addr
//	  origin_off   u64
//	  raw_len      u32 | raw
//
// The Merkle leaf is SHA-256(0x00 || body), so the record's source, origin,
// sequence number and terminator are all covered by the tree, not just its
// payload. Receipt.RawSHA256 is a separate hash over Raw alone, which is what
// lineage and GetByHash key on.
package record

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"time"

	types "github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/testutil/types"
)

// Version is the record body version. A decoder rejects anything else rather
// than guessing: a vault that silently reinterprets an unknown layout is worse
// than one that refuses to open.
const Version = 1

// FrameOverhead is the length and CRC prefix ahead of each body.
const FrameOverhead = 8

// fixedLen is the body's fixed-width part, before the three variable fields.
const fixedLen = 1 + 1 + 8 + 8 + 2 + 1 + 2 + 8 + 4

// Slack is how much a body may exceed max_frame_bytes: enough for the header
// plus a long source id and origin address.
const Slack = 4 << 10

// Flag bit layout within the body's flags byte.
const (
	termMask     = 0x03
	flagFragMore = 1 << 2
	flagFragCont = 1 << 3
	// flagsKnown is every bit this version defines. Unknown bits are rejected
	// so a future flag cannot be silently ignored by an old reader.
	flagsKnown = termMask | flagFragMore | flagFragCont
)

// Decode errors. Callers match with errors.Is.
var (
	// ErrTruncated means the buffer ended mid-record. During recovery this is
	// the expected outcome at a torn tail, not corruption.
	ErrTruncated = errors.New("record: truncated")
	// ErrCRC means the body did not match its checksum.
	ErrCRC = errors.New("record: crc mismatch")
	// ErrMalformed means the body decoded structurally but is not valid.
	ErrMalformed = errors.New("record: malformed")
	// ErrTooLarge means the declared length exceeds the configured cap. It is
	// checked before any allocation, so a hostile length field cannot make the
	// decoder allocate.
	ErrTooLarge = errors.New("record: too large")
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// CRC returns the CRC-32C of a body.
func CRC(body []byte) uint32 { return crc32.Checksum(body, castagnoli) }

// MaxBodyBytes is the largest body permitted for a given max_frame_bytes.
func MaxBodyBytes(maxFrameBytes int) int { return maxFrameBytes + Slack }

// EncodedLen returns the body length r will encode to.
func EncodedLen(r types.RawRecord) int {
	return fixedLen + len(r.SourceID) + len(r.Origin.Addr) + len(r.Raw)
}

// Encode appends the encoded body of r, at sequence number seq, to dst and
// returns the extended slice. It never modifies r.Raw.
//
// It returns an error only for inputs that cannot be represented: a source id
// or origin address longer than 64 KiB, or a payload above 4 GiB.
func Encode(dst []byte, seq types.RecordID, r types.RawRecord) ([]byte, error) {
	if len(r.SourceID) > 0xFFFF {
		return nil, fmt.Errorf("%w: source_id is %d bytes, max 65535", ErrTooLarge, len(r.SourceID))
	}
	if len(r.Origin.Addr) > 0xFFFF {
		return nil, fmt.Errorf("%w: origin addr is %d bytes, max 65535", ErrTooLarge, len(r.Origin.Addr))
	}
	if int64(len(r.Raw)) > 0xFFFFFFFF {
		return nil, fmt.Errorf("%w: raw is %d bytes", ErrTooLarge, len(r.Raw))
	}
	if r.Term > types.TermNUL {
		return nil, fmt.Errorf("%w: terminator %d", ErrMalformed, r.Term)
	}
	if r.Frag&^(types.FragMore|types.FragCont) != 0 {
		return nil, fmt.Errorf("%w: fragment flags %#x", ErrMalformed, r.Frag)
	}

	flags := byte(r.Term) & termMask
	if r.Frag&types.FragMore != 0 {
		flags |= flagFragMore
	}
	if r.Frag&types.FragCont != 0 {
		flags |= flagFragCont
	}

	dst = append(dst, Version, flags)
	dst = binary.BigEndian.AppendUint64(dst, uint64(seq))
	dst = binary.BigEndian.AppendUint64(dst, uint64(r.ReceivedAt.UnixNano()))
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(r.SourceID)))
	dst = append(dst, r.SourceID...)
	dst = append(dst, byte(r.Origin.Kind))
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(r.Origin.Addr)))
	dst = append(dst, r.Origin.Addr...)
	dst = binary.BigEndian.AppendUint64(dst, r.Origin.Offset)
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(r.Raw)))
	dst = append(dst, r.Raw...)
	return dst, nil
}

// Decode parses a body. The returned RawRecord owns copies of its variable
// fields, so the caller may reuse or free body afterwards. Decode never
// panics, whatever body contains.
func Decode(body []byte) (types.RecordID, types.RawRecord, error) {
	var r types.RawRecord

	// Every read goes through these, so a hostile length can only ever make
	// the decoder stop early.
	p := 0
	need := func(n int) bool { return n >= 0 && len(body)-p >= n }

	if !need(fixedLen - 2 - 2 - 4) { // the smallest possible body
		return 0, r, ErrTruncated
	}
	if body[p] != Version {
		return 0, r, fmt.Errorf("%w: version %d, want %d", ErrMalformed, body[p], Version)
	}
	flags := body[p+1]
	if flags&^flagsKnown != 0 {
		return 0, r, fmt.Errorf("%w: unknown flag bits %#x", ErrMalformed, flags&^flagsKnown)
	}
	p += 2

	if !need(8) {
		return 0, r, ErrTruncated
	}
	seq := types.RecordID(binary.BigEndian.Uint64(body[p:]))
	p += 8

	if !need(8) {
		return 0, r, ErrTruncated
	}
	nanos := int64(binary.BigEndian.Uint64(body[p:]))
	p += 8

	if !need(2) {
		return 0, r, ErrTruncated
	}
	srcLen := int(binary.BigEndian.Uint16(body[p:]))
	p += 2
	if !need(srcLen) {
		return 0, r, ErrTruncated
	}
	sourceID := string(body[p : p+srcLen])
	p += srcLen

	if !need(1) {
		return 0, r, ErrTruncated
	}
	kind := types.OriginKind(body[p])
	p++
	if kind > types.OriginHTTP {
		return 0, r, fmt.Errorf("%w: origin kind %d", ErrMalformed, kind)
	}

	if !need(2) {
		return 0, r, ErrTruncated
	}
	addrLen := int(binary.BigEndian.Uint16(body[p:]))
	p += 2
	if !need(addrLen) {
		return 0, r, ErrTruncated
	}
	addr := string(body[p : p+addrLen])
	p += addrLen

	if !need(8) {
		return 0, r, ErrTruncated
	}
	off := binary.BigEndian.Uint64(body[p:])
	p += 8

	if !need(4) {
		return 0, r, ErrTruncated
	}
	rawLen := int(binary.BigEndian.Uint32(body[p:]))
	p += 4
	if !need(rawLen) {
		return 0, r, ErrTruncated
	}
	raw := make([]byte, rawLen)
	copy(raw, body[p:p+rawLen])
	p += rawLen

	if p != len(body) {
		return 0, r, fmt.Errorf("%w: %d trailing bytes", ErrMalformed, len(body)-p)
	}

	r = types.RawRecord{
		SourceID:   sourceID,
		ReceivedAt: time.Unix(0, nanos).UTC(),
		Origin:     types.Origin{Kind: kind, Addr: addr, Offset: off},
		Term:       types.Terminator(flags & termMask),
		Raw:        raw,
	}
	if flags&flagFragMore != 0 {
		r.Frag |= types.FragMore
	}
	if flags&flagFragCont != 0 {
		r.Frag |= types.FragCont
	}
	return seq, r, nil
}

// AppendFramed appends body with its length and CRC prefix.
func AppendFramed(dst, body []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(body)))
	dst = binary.BigEndian.AppendUint32(dst, CRC(body))
	return append(dst, body...)
}

// ParseFramed reads one framed record from the front of buf. It returns the
// body, the total number of bytes consumed, and an error.
//
// The body it returns aliases buf, so callers that keep it must copy. maxBody
// caps the declared length, and is checked before the buffer is even
// consulted, so a corrupt or hostile length field cannot drive an allocation.
//
// ErrTruncated means "come back with more bytes". Anything else means the
// record is not recoverable, which during recovery is where the segment gets
// truncated.
func ParseFramed(buf []byte, maxBody int) (body []byte, n int, err error) {
	if len(buf) < FrameOverhead {
		return nil, 0, ErrTruncated
	}
	length := int(binary.BigEndian.Uint32(buf))
	want := binary.BigEndian.Uint32(buf[4:])

	if length > maxBody {
		return nil, 0, fmt.Errorf("%w: declared %d bytes, cap is %d", ErrTooLarge, length, maxBody)
	}
	if len(buf)-FrameOverhead < length {
		return nil, 0, ErrTruncated
	}
	body = buf[FrameOverhead : FrameOverhead+length]
	if got := CRC(body); got != want {
		return nil, 0, fmt.Errorf("%w: computed %08x, stored %08x", ErrCRC, got, want)
	}
	return body, FrameOverhead + length, nil
}
