package identity

import (
	"context"
	"fmt"

	types "github.com/dark-14100/sluice/pkg/types"
)

// FactExtractor turns one stored record into an identity fact, or nil if the record is not one. In the data
// plane this is the identity-source parser (the DSL `identity:` block); here it is whatever the caller supplies.
type FactExtractor func(rec types.RawRecord, rc types.Receipt) (*types.IdentityFact, error)

// ReplayStats counts what a replay did.
type ReplayStats struct {
	Scanned, Facts, Skipped, Invalidated int
}

// Replay rebuilds resolver state from the vault: it scans records from `from`, and for each record from one of
// `sources` (empty means all) extracts a fact and observes it. State is derived data, so this is how it is
// recovered after a restart instead of persisting it. Observe is idempotent and order independent, so replaying
// over a resolver that already holds some facts, or twice, is safe.
func Replay(ctx context.Context, v types.Vault, from types.RecordID, sources map[string]bool, x FactExtractor, r *Resolver) (ReplayStats, error) {
	var st ReplayStats
	err := v.Scan(ctx, from, func(rec types.RawRecord, rc types.Receipt) error {
		st.Scanned++
		if len(sources) > 0 && !sources[rec.SourceID] {
			st.Skipped++
			return nil
		}
		f, err := x(rec, rc)
		if err != nil {
			return fmt.Errorf("identity: record %d: %w", rc.ID, err)
		}
		if f == nil {
			st.Skipped++
			return nil
		}
		f.RecordID, f.SourceID = rc.ID, rec.SourceID
		inv, err := r.Observe(*f)
		if err != nil {
			return fmt.Errorf("identity: record %d: %w", rc.ID, err)
		}
		st.Facts++
		st.Invalidated += len(inv)
		return nil
	})
	return st, err
}
