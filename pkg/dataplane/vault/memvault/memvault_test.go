package memvault_test

import (
	"context"
	"testing"
	"time"

	types "github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/testutil/types"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault/memvault"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault/vaulttest"
)

// fixedNow keeps seal timestamps deterministic.
func fixedNow() func() time.Time {
	n := int64(0)
	return func() time.Time {
		n++
		return time.Unix(1790566200+n, 0).UTC()
	}
}

// TestConformance is the contract. The on-disk vault will run this same suite,
// which is what keeps the two implementations from drifting apart.
func TestConformance(t *testing.T) {
	vaulttest.Run(t, vaulttest.Factory{
		SealEvery: 8,
		New: func(t *testing.T) types.Vault {
			return memvault.New(memvault.Options{SealEvery: 8, Now: fixedNow()})
		},
	})
}

// TestConformanceTinySegments runs the suite again with the smallest legal
// segment size, where nearly every write seals. Segment-boundary bugs hide at
// this size.
func TestConformanceTinySegments(t *testing.T) {
	vaulttest.Run(t, vaulttest.Factory{
		SealEvery: 2,
		New: func(t *testing.T) types.Vault {
			return memvault.New(memvault.Options{SealEvery: 2, Now: fixedNow()})
		},
	})
}

func TestDefaults(t *testing.T) {
	v := memvault.New(memvault.Options{})
	defer v.Close()

	// With the default segment size, a handful of records seals nothing.
	rc, err := v.Put(context.Background(), types.RawRecord{Raw: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Proof(context.Background(), rc.ID); err != types.ErrNotSealed {
		t.Errorf("got %v, want ErrNotSealed", err)
	}
}

// TestRecordTooLarge proves the cap is enforced rather than silently
// truncating, which would break the byte-exactness claim.
func TestRecordTooLarge(t *testing.T) {
	v := memvault.New(memvault.Options{MaxFrameBytes: 1024})
	defer v.Close()

	r := types.RawRecord{Raw: make([]byte, 64<<10)}
	if _, err := v.Put(context.Background(), r); err == nil {
		t.Fatal("accepted a record far over the cap")
	} else if err.Error() == "" {
		t.Fatal("rejected the record without saying why")
	}
}

// TestBatchIsAtomic proves a bad record in the middle of a batch leaves
// nothing behind. The real vault writes a batch as one write and one fsync, so
// a partially applied batch is not a state it can be in.
func TestBatchIsAtomic(t *testing.T) {
	v := memvault.New(memvault.Options{MaxFrameBytes: 1024})
	defer v.Close()

	batch := []types.RawRecord{
		{Raw: []byte("fine")},
		{Raw: make([]byte, 64<<10)}, // over the cap
		{Raw: []byte("also fine")},
	}
	if _, err := v.PutBatch(context.Background(), batch); err == nil {
		t.Fatal("accepted a batch containing an oversize record")
	}

	// Nothing from the failed batch may be stored, and the next record must
	// still get id 1.
	if _, _, err := v.Get(context.Background(), 1); err != types.ErrNotFound {
		t.Errorf("a record from the rejected batch was stored: %v", err)
	}
	rc, err := v.Put(context.Background(), types.RawRecord{Raw: []byte("next")})
	if err != nil {
		t.Fatal(err)
	}
	if rc.ID != 1 {
		t.Errorf("the rejected batch consumed ids: next record got %d, want 1", rc.ID)
	}
}

// TestDeterministicRoots is what makes memvault a reference implementation
// rather than a lookalike: the same records in the same order must always
// produce the same chain head, because the on-disk vault will produce that
// same head from the same input.
func TestDeterministicRoots(t *testing.T) {
	build := func() [32]byte {
		v := memvault.New(memvault.Options{SealEvery: 4, Now: fixedNow()})
		defer v.Close()
		for i := 0; i < 16; i++ {
			_, err := v.Put(context.Background(), types.RawRecord{
				SourceID:   "src",
				ReceivedAt: time.Unix(1790566200+int64(i), 0).UTC(),
				Origin:     types.Origin{Kind: types.OriginFile, Addr: "/x.log", Offset: uint64(i)},
				Term:       types.TermLF,
				Raw:        []byte{byte(i)},
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		head, _, err := v.Head(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return head
	}
	if a, b := build(), build(); a != b {
		t.Errorf("the same records produced two different chain heads:\n %x\n %x", a, b)
	}
}
