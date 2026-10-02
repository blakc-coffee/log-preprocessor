package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const yamlV = `id: demo_json
version: 1.0.0
vendor: acme
product: fw
timezone: "+00:00"
match: {signature: '^\{'}
ocsf_defaults: {class_uid: 4001, category_uid: 4}
extractors:
  - id: e
    kind: json
    map:
      - {from: src, to: src_endpoint.ip, type: ip}
`

// An approved parser must still be active after a restart, and nothing half-written may be left.
func TestApprovedParserSurvivesReload(t *testing.T) {
	dir := t.TempDir()
	r := New(nil, dir)
	p, err := r.Approve([]byte(yamlV))
	if err != nil {
		t.Fatal(err)
	}
	reloaded := New(nil, dir)
	if err := reloaded.LoadDir(); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range reloaded.Active() {
		found = found || (a.ID() == p.ID() && a.Version() == p.Version())
	}
	if !found {
		t.Fatalf("approved parser %s@%s is not active after a reload", p.ID(), p.Version())
	}
	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err == nil && strings.Contains(d.Name(), ".tmp-") {
			t.Errorf("a temporary file was left behind: %s", path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}
