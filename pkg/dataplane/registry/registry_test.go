package registry_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/parsers"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/registry"
)

const parserV1 = `id: registry_test
version: 1.0.0
vendor: test
product: registry
timezone: "+00:00"
match: {signature: .}
ocsf_defaults: {class_uid: 1001, category_uid: 1, activity_id: 0, type_uid: 100100}
extractors:
  - id: event
    kind: kv
    map: []
`

func TestApproveRequiresActiveBaseAndPersistsActivation(t *testing.T) {
	dir := t.TempDir()
	r := registry.New(parsers.New(), dir)
	if _, err := r.Add([]byte(parserV1), true); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Approve([]byte(parserV1)); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("approval without base_version: %v, want ErrConflict", err)
	}
	patch := strings.Replace(parserV1, "version: 1.0.0", "version: 9.9.9\nbase_version: 1.0.0", 1)
	p, err := r.Approve([]byte(patch))
	if err != nil {
		t.Fatal(err)
	}
	if p.Version() != "1.0.1" {
		t.Fatalf("approved version = %s, want 1.0.1", p.Version())
	}

	reloaded := registry.New(parsers.New(), dir)
	if err := reloaded.LoadDir(); err != nil {
		t.Fatal(err)
	}
	got, _, err := reloaded.Get("registry_test", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Version() != "1.0.1" {
		t.Fatalf("reloaded active version = %s, want 1.0.1", got.Version())
	}
	if _, err := reloaded.Rollback("registry_test", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	again := registry.New(parsers.New(), dir)
	if err := again.LoadDir(); err != nil {
		t.Fatal(err)
	}
	got, _, err = again.Get("registry_test", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Version() != "1.0.0" {
		t.Fatalf("active version after persisted rollback = %s, want 1.0.0", got.Version())
	}
}
