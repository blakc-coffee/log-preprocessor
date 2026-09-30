// Package integration turns the linking checklist in docs/integration.md into code.
//
// Each Step function takes an API (the data plane's admin API) and the fixture manifest and returns a Report
// listing every gate with its verdict and the evidence. Nothing here starts a process: point it at whatever is
// running. The HTTP implementation validates every response against admin.openapi.yaml, so a step also fails on
// a response the contract does not describe.
//
// The gates were first run against a synthetic "perfect data plane" built from the manifest and a real vault, and
// against copies of it with one deliberate defect each (see checks_test.go), so a green report means something.
package integration

import (
	"time"

	types "github.com/dark-14100/sluice/pkg/types"
)

// API is the slice of the admin API the steps use.
type API interface {
	Telemetry() (Telemetry, error)
	Events() ([]types.NormalizedEvent, error) // every current event, paginated internally
	Raw(eventID string) (RawResponse, error)
	Quarantined() ([]Sample, error) // the raw bytes of every open quarantine record
	Lineage(eventID string) (Lineage, error)
	VerifyChain(deep bool) (types.ChainReport, error)
	Timeline(ip string) ([]Binding, error)
	Parsers() ([]ParserInfo, error)
	DryRun(yaml, sourceID string) (types.DryRunResult, error)
	Approve(yaml, by string, replay bool) (Activation, error)
	StartReplay(scope, sourceID string) (ReplayJob, error)
	Replay(jobID string) (ReplayJob, error)
	DriftAlerts() ([]types.DriftAlert, error)
	Proposals() ([]types.Proposal, error)
}

// Telemetry holds the fields of GET /admin/telemetry the steps read.
type Telemetry struct {
	EventsTotal      int `json:"events_total"`
	QuarantinedTotal int `json:"quarantined_total"`
	QuarantineOpen   int `json:"quarantine_open"`
	Vault            struct {
		Records  uint64 `json:"records"`
		Segments int    `json:"segments"`
	} `json:"vault"`
}

// RawResponse is GET /admin/events/{id}/raw.
type RawResponse struct {
	RecordID   types.RecordID   `json:"record_id"`
	Segment    uint64           `json:"segment"`
	RawBase64  string           `json:"raw_base64"`
	RawSHA256  string           `json:"raw_sha256"`
	ShaMatch   bool             `json:"sha_match"`
	Origin     types.Origin     `json:"origin"`
	Terminator types.Terminator `json:"terminator"`
	Fragment   types.Fragment   `json:"fragment"`
	ReceivedAt time.Time        `json:"received_at"`
}

// Sample is one raw record from GET /admin/samples.
type Sample struct {
	RecordID types.RecordID `json:"record_id"`
	SourceID string         `json:"source_id"`
	Raw      []byte
	Status   string `json:"status"`
	ParserID string `json:"parser_id"`
}

// Lineage is GET /admin/lineage/{id}.
type Lineage struct {
	EventID   string                `json:"event_id"`
	RecordID  types.RecordID        `json:"record_id"`
	RawSHA256 string                `json:"raw_sha256"`
	Sealed    bool                  `json:"sealed"`
	Proof     *types.InclusionProof `json:"proof"`
	Chain     struct {
		Head          string `json:"head"`
		SealedThrough uint64 `json:"sealed_through"`
	} `json:"chain"`
}

// Binding is one entry of GET /admin/identity/timeline.
type Binding struct {
	Kind      string     `json:"kind"`
	User      string     `json:"user"`
	Host      string     `json:"host"`
	ValidFrom time.Time  `json:"valid_from"`
	ValidTo   *time.Time `json:"valid_to"`
}

// ParserInfo is one entry of GET /admin/parsers.
type ParserInfo struct {
	ID            string `json:"id"`
	ActiveVersion string `json:"active_version"`
}

// Activation is the result of approve.
type Activation struct {
	ParserID    string  `json:"parser_id"`
	Version     string  `json:"version"`
	ReplayJobID *string `json:"replay_job_id"`
}

// ReplayJob is a replay's progress.
type ReplayJob struct {
	JobID     string `json:"job_id"`
	State     string `json:"state"`
	Processed int    `json:"processed"`
	Succeeded int    `json:"succeeded"`
	Failed    int    `json:"failed"`
}
