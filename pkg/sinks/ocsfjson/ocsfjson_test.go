package ocsfjson

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dark-14100/sluice/pkg/types"
)

func TestWriteIsIdempotentAndDoesNotMutateOCSF(t *testing.T) {
	var out bytes.Buffer
	s := New(&out, Options{})
	e := types.NormalizedEvent{EventID: "1.p@1", RawSHA256: strings.Repeat("a", 64), OCSF: map[string]any{"message": "hello"}}
	if err := s.Write(context.Background(), []types.NormalizedEvent{e, e}); err != nil {
		t.Fatal(err)
	}
	if lines := bytes.Count(out.Bytes(), []byte{'\n'}); lines != 1 {
		t.Fatalf("got %d lines", lines)
	}
	if _, ok := e.OCSF["metadata"]; ok {
		t.Fatal("source OCSF map was mutated")
	}
	var got map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &got); err != nil {
		t.Fatal(err)
	}
	if got["raw_data"] != nil {
		t.Fatal("raw data exported by default")
	}
}
