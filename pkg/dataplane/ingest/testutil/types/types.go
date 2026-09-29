// Package types is a local, temporary copy of the frozen ULPF contract.
//
// # Why this exists
//
// The real contract lives in pkg/types and is owned by the Contracts
// workstream. It does not exist yet. The Ingestion & Vault workstream may not
// write pkg/types (PRD_INGESTION_vault_SCOPED section 0 and 9.6 step 2), but
// it cannot build a vault without the Vault interface either, so this copy
// stands in until the real one lands.
//
// The declarations below are copied from PRD_INGESTION_vault_SCOPED section 3,
// which PRD_CONTRACTS section 2.1 instructs the Contracts workstream to take
// verbatim. As of this writing the two documents agree, so there is no
// mismatch to report.
//
// # When the real pkg/types lands
//
//  1. Diff it against this file and record any difference in DECISIONS.log.
//     Where they disagree, the contract wins and this workstream adapts.
//  2. Rewrite the import path in every package here and delete this one.
//
// Nothing outside this workstream should import this package.
package types

import (
	"context"
	"errors"
	"time"
)

// RecordID is the vault's global, monotonic record number. It starts at 1 and
// is contiguous across segments (D3), which is what makes replay stable: the
// same raw bytes keep the same identity forever.
type RecordID uint64

// OriginKind says which kind of source produced a record.
type OriginKind uint8

// The origin kinds. OriginUnknown is the zero value so an unset Origin is
// obviously unset rather than silently claiming to be a file.
const (
	OriginUnknown OriginKind = iota
	OriginFile
	OriginUDP
	OriginTCP
	OriginTLS
	OriginHTTP
)

// Origin describes where the bytes came from. It is used for tracing and, for
// file sources, for de-duplication after an at-least-once replay.
type Origin struct {
	Kind OriginKind
	// Addr is the peer "ip:port" for network sources, or the absolute path
	// for files.
	Addr string
	// Offset is the byte offset of the first raw byte: within the file for
	// file sources, within the connection or body for streams, and 0 for UDP
	// where a datagram has no position.
	Offset uint64
}

// Terminator is the framing delimiter that ended the record. It is recorded
// rather than stored: it is deliberately NOT part of Raw, so that a record's
// bytes are the event's bytes and nothing else.
type Terminator uint8

// The terminator kinds. TermNone covers datagrams, whole-body HTTP reads, and
// a final unterminated line.
const (
	TermNone Terminator = iota
	TermLF
	TermCRLF
	TermNUL
)

// Fragment marks the pieces of a record longer than max_frame_bytes.
// Concatenating the Raw of consecutive fragments from the same source, with
// contiguous RecordIDs, restores the original record exactly. Oversize input
// is fragmented; it is never truncated.
type Fragment uint8

// The fragment flags.
const (
	FragNone Fragment = 0
	FragMore Fragment = 1 << 0 // more fragments follow
	FragCont Fragment = 1 << 1 // this continues a previous fragment
)

// FormatHint is the ingest-side guess at a record's format. It is advisory
// only: it never affects Raw or storage, it may be wrong, and parsers are free
// to ignore it.
type FormatHint string

// The format hints.
const (
	HintUnknown    FormatHint = "unknown"
	HintSyslog3164 FormatHint = "syslog3164"
	HintSyslog5424 FormatHint = "syslog5424"
	HintCEF        FormatHint = "cef"
	HintLEEF       FormatHint = "leef"
	HintJSON       FormatHint = "json"
	HintXML        FormatHint = "xml"
	HintKV         FormatHint = "kv"
	HintCSV        FormatHint = "csv"
)

// RawRecord is one event exactly as it arrived. Raw is opaque: nothing in the
// ingest or vault path interprets, trims, re-encodes or normalizes it.
type RawRecord struct {
	SourceID string
	// ReceivedAt is stamped in UTC by ingest when the frame completed.
	ReceivedAt time.Time
	Origin     Origin
	Term       Terminator
	Frag       Fragment
	Raw        []byte
}

// Receipt is the vault's acknowledgement of one record.
type Receipt struct {
	ID RecordID
	// RawSHA256 is the SHA-256 of Raw alone, not of the encoded record. It is
	// what lineage and GetByHash are keyed on.
	RawSHA256 [32]byte
	Segment   uint64
}

// RawEvent is what ingest emits downstream once the vault has confirmed the
// record is durable. Nothing reaches a parser before this point.
type RawEvent struct {
	RawRecord
	Receipt
	Hint FormatHint
}

// InclusionProof is an RFC 6962 inclusion proof for one record, plus the chain
// link that ties its segment to the previous one.
type InclusionProof struct {
	Segment   uint64
	LeafIndex uint64
	// TreeSize is the segment's record count.
	TreeSize  uint64
	LeafHash  [32]byte
	Path      [][32]byte
	Root      [32]byte
	PrevChain [32]byte
	Chain     [32]byte
}

// SegmentSeal is the ledger entry written when a segment is sealed.
type SegmentSeal struct {
	Segment  uint64
	FirstSeq uint64
	LastSeq  uint64
	Count    uint64
	Root     [32]byte
	Prev     [32]byte
	Chain    [32]byte
	SealedAt time.Time
	// Recovered is true when the segment was sealed by crash recovery rather
	// than by a clean seal.
	Recovered bool
}

// VerifyResult is the outcome of verifying a single record.
type VerifyResult struct {
	OK     bool
	Sealed bool
	// Reason is empty when OK, and names the specific failure otherwise.
	Reason string
	Proof  *InclusionProof
}

// ChainReport is the outcome of verifying the whole chain.
type ChainReport struct {
	OK       bool
	Deep     bool
	Segments int
	Records  uint64
	Head     [32]byte
	// FirstBad is the first segment that failed, or 0 when OK.
	FirstBad uint64
	Reason   string
}

// Vault errors. Callers match with errors.Is.
var (
	ErrNotFound       = errors.New("vault: record not found")
	ErrNotSealed      = errors.New("vault: segment not sealed yet")
	ErrClosed         = errors.New("vault: closed")
	ErrRecordTooLarge = errors.New("vault: record exceeds max size")
	// ErrFailed is terminal: a write or fsync failed, so the vault refuses
	// every later call and the process must restart. It is never retried,
	// because after a failed fsync the kernel may already have dropped the
	// dirty pages and a retry that "succeeded" would be a lie.
	ErrFailed = errors.New("vault: failed state, restart required")
)

// Vault is the durable, hash-chained store for raw records. Every
// implementation must satisfy the same conformance suite.
type Vault interface {
	// Put stores one record and returns only once it is durable in the
	// configured sync mode.
	Put(ctx context.Context, r RawRecord) (Receipt, error)
	// PutBatch stores several records atomically. They receive contiguous
	// RecordIDs, and the call returns only once they are durable.
	PutBatch(ctx context.Context, rs []RawRecord) ([]Receipt, error)
	// Get returns a record byte-for-byte as it was stored.
	Get(ctx context.Context, id RecordID) (RawRecord, Receipt, error)
	// GetByHash returns the raw bytes whose SHA-256 is sum.
	GetByHash(ctx context.Context, sum [32]byte) ([]byte, error)
	// Scan walks records in RecordID order from id, for replay. It stops and
	// returns the error if fn returns one.
	Scan(ctx context.Context, from RecordID, fn func(RawRecord, Receipt) error) error
	// Proof returns an inclusion proof. It returns ErrNotSealed while the
	// record's segment is still active, because an unsealed segment has no
	// root yet.
	Proof(ctx context.Context, id RecordID) (InclusionProof, error)
	// Verify checks one record against its segment root and the chain.
	Verify(ctx context.Context, id RecordID) (VerifyResult, error)
	// VerifyChain checks the whole ledger. A deep check also re-reads every
	// record and recomputes every segment root.
	VerifyChain(ctx context.Context, deep bool) (ChainReport, error)
	// Seals returns the ledger, oldest first.
	Seals(ctx context.Context) ([]SegmentSeal, error)
	// Head returns the current chain head and the highest sealed RecordID.
	// Exporting the head elsewhere is what turns tamper-evidence into
	// something an attacker with write access cannot paper over.
	Head(ctx context.Context) (chain [32]byte, sealedThrough RecordID, err error)
	// Close seals the active segment and releases the directory lock.
	Close() error
}
