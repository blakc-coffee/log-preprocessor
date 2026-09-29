package types

import (
	"context"
	"errors"
	"time"
)

// ============================================================================
// 1. Ingestion & Vault Core Types (per Ingestion PRD §3 & Master PRD)
// ============================================================================

type RecordID uint64

type OriginKind uint8

const (
	OriginUnknown OriginKind = iota
	OriginFile
	OriginUDP
	OriginTCP
	OriginTLS
	OriginHTTP
)

type Origin struct {
	Kind   OriginKind `json:"kind"`
	Addr   string     `json:"addr"`   // "ip:port" or absolute file path
	Offset uint64     `json:"offset"` // byte offset in file/stream; 0 for UDP
}

type Terminator uint8

const (
	TermNone Terminator = iota
	TermLF
	TermCRLF
	TermNUL
)

type Fragment uint8

const (
	FragNone Fragment = 0
	FragMore Fragment = 1 << 0
	FragCont Fragment = 1 << 1
)

type FormatHint string

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

type RawRecord struct {
	SourceID   string     `json:"source_id"`
	ReceivedAt time.Time  `json:"received_at"`
	Origin     Origin     `json:"origin"`
	Term       Terminator `json:"term"`
	Frag       Fragment   `json:"frag"`
	Raw        []byte     `json:"raw"`
}

type Receipt struct {
	ID        RecordID `json:"id"`
	RawSHA256 [32]byte `json:"raw_sha256"`
	Segment   uint64   `json:"segment"`
}

// RawEvent is emitted by B1 Ingest to B3 Parser after vault durability confirmation.
type RawEvent struct {
	RawRecord
	Receipt
	Hint FormatHint `json:"hint"`
}

type InclusionProof struct {
	Segment   uint64     `json:"segment"`
	LeafIndex uint64     `json:"leaf_index"`
	TreeSize  uint64     `json:"tree_size"`
	LeafHash  [32]byte   `json:"leaf_hash"`
	Path      [][32]byte `json:"path"`
	Root      [32]byte   `json:"root"`
	PrevChain [32]byte   `json:"prev_chain"`
	Chain     [32]byte   `json:"chain"`
}

type SegmentSeal struct {
	Segment   uint64    `json:"segment"`
	FirstSeq  uint64    `json:"first_seq"`
	LastSeq   uint64    `json:"last_seq"`
	Count     uint64    `json:"count"`
	Root      [32]byte  `json:"root"`
	Prev      [32]byte  `json:"prev"`
	Chain     [32]byte  `json:"chain"`
	SealedAt  time.Time `json:"sealed_at"`
	Recovered bool      `json:"recovered"`
}

type VerifyResult struct {
	OK     bool            `json:"ok"`
	Sealed bool            `json:"sealed"`
	Reason string          `json:"reason,omitempty"`
	Proof  *InclusionProof `json:"proof,omitempty"`
}

type ChainReport struct {
	OK       bool     `json:"ok"`
	Deep     bool     `json:"deep"`
	Segments int      `json:"segments"`
	Records  uint64   `json:"records"`
	Head     [32]byte `json:"head"`
	FirstBad uint64   `json:"first_bad,omitempty"`
	Reason   string   `json:"reason,omitempty"`
}

var (
	ErrNotFound       = errors.New("vault: record not found")
	ErrNotSealed      = errors.New("vault: segment not sealed yet")
	ErrClosed         = errors.New("vault: closed")
	ErrRecordTooLarge = errors.New("vault: record exceeds max size")
	ErrFailed         = errors.New("vault: failed state, restart required")
)

type Vault interface {
	Put(ctx context.Context, r RawRecord) (Receipt, error)
	PutBatch(ctx context.Context, rs []RawRecord) ([]Receipt, error)
	Get(ctx context.Context, id RecordID) (RawRecord, Receipt, error)
	GetByHash(ctx context.Context, sum [32]byte) ([]byte, error)
	Scan(ctx context.Context, from RecordID, fn func(RawRecord, Receipt) error) error
	Proof(ctx context.Context, id RecordID) (InclusionProof, error)
	Verify(ctx context.Context, id RecordID) (VerifyResult, error)
	VerifyChain(ctx context.Context, deep bool) (ChainReport, error)
	Seals(ctx context.Context) ([]SegmentSeal, error)
	Head(ctx context.Context) (chain [32]byte, sealedThrough RecordID, err error)
	Close() error
}

// ============================================================================
// 2. Normalized Event & UEF Envelope (per Contracts PRD §2.1)
// ============================================================================

type NormalizedEvent struct {
	EventID         string         `json:"event_id"` // "<RecordID>.<parser_id>@<version>"
	RecordID        RecordID       `json:"record_id"`
	Segment         uint64         `json:"segment"`
	RawSHA256       string         `json:"raw_sha256"` // lowercase hex
	SourceID        string         `json:"source_id"`
	Vendor          string         `json:"vendor"`
	Product         string         `json:"product"`
	ParserID        string         `json:"parser_id"`
	ParserVersion   string         `json:"parser_version"`
	TemplateID      string         `json:"template_id"` // "<parser_id>/<extractor_id>" for Parquet
	SchemaVersion   string         `json:"schema_version"`
	ReceivedAt      time.Time      `json:"received_at"`
	EventTime       *time.Time     `json:"event_time"`
	TimeFromReceipt bool           `json:"time_from_receipt"`
	ParseConfidence float64        `json:"parse_confidence"`
	IntegrityFlags  []string       `json:"integrity_flags"`
	OCSF            map[string]any `json:"ocsf"`
	Unmapped        map[string]any `json:"unmapped"`
	Entities        []Entity       `json:"entities"`
	Identity        *IdentityFact  `json:"identity,omitempty"`
	Coverage        Coverage       `json:"coverage"`
	Current         bool           `json:"current"`
}

type Entity struct {
	Type       string        `json:"type"` // user | host | ip | mac
	ID         string        `json:"id"`
	Role       string        `json:"role"` // src | dst | observer
	ValidFrom  *time.Time    `json:"valid_from"`
	ValidTo    *time.Time    `json:"valid_to"`
	Confidence float64       `json:"confidence"`
	Evidence   []EvidenceRef `json:"evidence"`
}

type EvidenceRef struct {
	RecordID RecordID `json:"record_id"`
	Kind     string   `json:"kind"` // dhcp | radius | vpn
}

type IdentityFact struct {
	Kind     string    `json:"kind"`   // dhcp | radius | vpn
	Action   string    `json:"action"` // bind | release
	IP       string    `json:"ip"`
	MAC      string    `json:"mac,omitempty"`
	Host     string    `json:"host,omitempty"`
	User     string    `json:"user,omitempty"`
	At       time.Time `json:"at"`
	RecordID RecordID  `json:"record_id"`
	SourceID string    `json:"source_id"`
}

type Coverage struct {
	Applicable     bool  `json:"applicable"`
	RenderBackOK   *bool `json:"render_back_ok"`
	MappedBytes    int   `json:"mapped_bytes"`
	UnmappedBytes  int   `json:"unmapped_bytes"`
	ConstantBytes  int   `json:"constant_bytes"`
	UncoveredBytes int   `json:"uncovered_bytes"`
	MappedFields   int   `json:"mapped_fields"`
	UnmappedFields int   `json:"unmapped_fields"`
}

// Integrity flag closed constants
const (
	FlagInvalidUTF8         = "invalid_utf8"
	FlagControlChars        = "control_chars"
	FlagOversizeField       = "oversize_field"
	FlagTooManyFields       = "too_many_fields"
	FlagDuplicateKey        = "duplicate_key"
	FlagNestedTooDeep       = "nested_too_deep"
	FlagKeyInjectionSuspect = "key_injection_suspect"
	FlagFragmentRecord      = "fragment_record"
	FlagTimeUnparseable     = "time_unparseable"
	FlagRenderBackMismatch  = "render_back_mismatch"
	FlagLowConfidence       = "low_confidence"
	FlagTruncatedInput      = "truncated_input"
)

// ============================================================================
// 3. Pipeline, Intelligence & Control Plane Types
// ============================================================================

type QuarantineRecord struct {
	RecordID     RecordID  `json:"record_id"`
	SourceID     string    `json:"source_id"`
	FailureStage string    `json:"failure_stage"` // detect | extract | normalize | integrity
	Error        string    `json:"error"`
	ReceivedAt   time.Time `json:"received_at"`
	Status       string    `json:"status"` // open | resolved | ignored
	ResolvedBy   string    `json:"resolved_by,omitempty"`
}

type DriftAlert struct {
	ID             string    `json:"id"`
	SourceID       string    `json:"source_id"`
	ParserID       string    `json:"parser_id"`
	Score          float64   `json:"score"`
	Signals        []string  `json:"signals"`
	QuarantineRate float64   `json:"quarantine_rate"`
	FirstSeen      time.Time `json:"first_seen"`
	Status         string    `json:"status"` // open | proposed | resolved | dismissed
}

type TypedField struct {
	Field        string   `json:"field"`
	OCSFPath     string   `json:"ocsf_path"`
	Type         string   `json:"type"`
	Confidence   float64  `json:"confidence"`
	Evidence     string   `json:"evidence"`
	Alternatives []string `json:"alternatives,omitempty"`
}

type FieldStat struct {
	Present  int      `json:"present"`
	Distinct int      `json:"distinct"`
	Sample   []string `json:"sample"`
}

type DryRunResult struct {
	Samples          int                  `json:"samples"`
	Parsed           int                  `json:"parsed"`
	Failed           int                  `json:"failed"`
	MatchRate        float64              `json:"match_rate"`
	MeanCoverage     float64              `json:"mean_coverage"`
	RenderBackOKRate *float64             `json:"render_back_ok_rate"`
	FieldStats       map[string]FieldStat `json:"field_stats"`
	Failures         []DryRunFailure      `json:"failures"`
	Warnings         []string             `json:"warnings"`
}

type DryRunFailure struct {
	RecordID RecordID `json:"record_id"`
	Error    string   `json:"error"`
}

type Proposal struct {
	ID              string        `json:"id"`
	Kind            string        `json:"kind"` // new | patch
	ParserID        string        `json:"parser_id"`
	BaseVersion     string        `json:"base_version"`
	SourceID        string        `json:"source_id"`
	YAML            string        `json:"yaml"`
	DriftAlertID    string        `json:"drift_alert_id,omitempty"`
	ClusterSize     int           `json:"cluster_size"`
	Templates       []string      `json:"templates"`
	SampleRecordIDs []RecordID    `json:"sample_record_ids"`
	TypedFields     []TypedField  `json:"typed_fields"`
	DryRun          *DryRunResult `json:"dry_run"`
	Status          string        `json:"status"` // pending | approved | rejected | stale
	CreatedAt       time.Time     `json:"created_at"`
}

// ============================================================================
// 4. Cross-Workstream Interfaces
// ============================================================================

type Sink interface {
	Name() string
	Write(ctx context.Context, batch []NormalizedEvent) error
	Flush(ctx context.Context) error
	Close() error
}

type Invalidation struct {
	IP       string
	From, To time.Time
}

type Resolver interface {
	Observe(f IdentityFact) ([]Invalidation, error)
	ResolveAt(ip string, t time.Time) []Entity
}
