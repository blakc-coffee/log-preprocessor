package spool

import (
	"context"
	"errors"
	"testing"

	"github.com/blakc-coffee/log-preprocessor/pkg/sinks"
	"github.com/blakc-coffee/log-preprocessor/pkg/types"
)

func TestQueueSurvivesReopenAndIsBounded(t *testing.T) {
	d := t.TempDir()
	q, err := Open(Config{Dir: d, MaxBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	want := []types.NormalizedEvent{{EventID: "1.p@1", RawSHA256: "abc", OCSF: map[string]any{"message": "unchanged"}}}
	if err = q.Enqueue(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	if err = q.Close(); err != nil {
		t.Fatal(err)
	}
	q, err = Open(Config{Dir: d, MaxBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	got, err := q.Peek(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got[0].EventID != want[0].EventID {
		t.Fatalf("got %q", got[0].EventID)
	}
	if err = q.Ack(); err != nil {
		t.Fatal(err)
	}
	if q.Len() != 0 {
		t.Fatal("ack did not remove segment")
	}
	tiny, err := Open(Config{Dir: t.TempDir(), MaxBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err = tiny.Enqueue(context.Background(), want); !errors.Is(err, sinks.ErrSpoolFull) {
		t.Fatalf("got %v", err)
	}
}
